/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - hash_verify unit tests
 *
 * Tests:
 *   1. hash_verify_file on known content (compare with sha256sum)
 *   2. hash_verify_file on empty file
 *   3. hash_verify_file rejects relative path
 *   4. hash_verify_file rejects nonexistent file
 *   5. hash_verify_file rejects directory
 *   6. hash_verify_event cache miss -> hit
 *   7. hash_verify_event cache invalidation on fingerprint change
 *   8. hash_verify_event rejects relative path
 *   9. LRU eviction with small cache
 *  10. hash_verify_stats correctness
 *  11. hash_verify_file on large file (1 MB, multiple chunks)
 *
 * Build:
 *   gcc -Wall -Wextra -Werror -O2 -g -Iinclude -D_GNU_SOURCE \
 *       -o build/test_hash_verify tests/test_hash_verify.c \
 *       src/agent/hash_verify.c -lcrypto
 *
 * Run:
 *   ./build/test_hash_verify
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../include/lota.h"
#include "../src/agent/hash_verify.h"

static int tests_run;
static int tests_passed;

#define TEST(name)                                                             \
  do {                                                                         \
    tests_run++;                                                               \
    printf("  [%2d] %-50s ", tests_run, name);                                 \
  } while (0)

#define PASS()                                                                 \
  do {                                                                         \
    tests_passed++;                                                            \
    printf("PASS\n");                                                          \
  } while (0)

#define FAIL(msg)                                                              \
  do {                                                                         \
    printf("FAIL: %s\n", msg);                                                 \
  } while (0)

#define ASSERT(cond, msg)                                                      \
  do {                                                                         \
    if (!(cond)) {                                                             \
      FAIL(msg);                                                               \
      return;                                                                  \
    }                                                                          \
  } while (0)

/* format 32-byte hash to hex string */
static void hex_str(const uint8_t h[32], char *out) {
  for (int i = 0; i < 32; i++)
    snprintf(out + i * 2, 3, "%02x", h[i]);
}

/* create a temporary file with given content */
static char *create_tmp_file(const char *content, size_t len) {
  char *path = strdup("/tmp/lota_test_hash_XXXXXX");
  int fd = mkstemp(path);
  if (fd < 0) {
    free(path);
    return NULL;
  }
  if (len > 0) {
    ssize_t w = write(fd, content, len);
    (void)w;
  }
  close(fd);
  return path;
}

/* compute expected SHA-256 using sha256sum CLI and return hex string */
static int sha256sum_file(const char *path, char *hex_out) {
  char cmd[512];
  FILE *f;
  int n;

  snprintf(cmd, sizeof(cmd), "sha256sum '%s'", path);
  f = popen(cmd, "r");
  if (!f)
    return -1;
  n = fscanf(f, "%64s", hex_out);
  pclose(f);
  return (n == 1) ? 0 : -1;
}

/* parse hex string to bytes */
static void hex_to_bytes(const char *hex, uint8_t *out, int len)
    __attribute__((unused));
static void hex_to_bytes(const char *hex, uint8_t *out, int len) {
  for (int i = 0; i < len; i++) {
    unsigned int b;
    sscanf(hex + i * 2, "%2x", &b);
    out[i] = (uint8_t)b;
  }
}

static void test_hash_known_content(void) {
  const char *data = "Hello, LOTA hash verification!\n";
  char *path;
  uint8_t hash[LOTA_HASH_SIZE];
  char our_hex[65];
  char expected_hex[65];

  TEST("hash_verify_file on known content");

  path = create_tmp_file(data, strlen(data));
  ASSERT(path != NULL, "failed to create temp file");

  int ret = hash_verify_file(path, hash);
  ASSERT(ret == 0, "hash_verify_file failed");

  hex_str(hash, our_hex);

  /* verify against sha256sum */
  ret = sha256sum_file(path, expected_hex);
  unlink(path);
  free(path);
  ASSERT(ret == 0, "sha256sum failed");
  ASSERT(strcmp(our_hex, expected_hex) == 0, "hash mismatch with sha256sum");

  PASS();
}

static void test_hash_empty_file(void) {
  char *path;
  uint8_t hash[LOTA_HASH_SIZE];
  char our_hex[65];
  char expected_hex[65];

  TEST("hash_verify_file on empty file");

  path = create_tmp_file("", 0);
  ASSERT(path != NULL, "failed to create temp file");

  int ret = hash_verify_file(path, hash);
  ASSERT(ret == 0, "hash_verify_file failed on empty file");

  hex_str(hash, our_hex);

  ret = sha256sum_file(path, expected_hex);
  unlink(path);
  free(path);
  ASSERT(ret == 0, "sha256sum failed");
  ASSERT(strcmp(our_hex, expected_hex) == 0, "empty file hash mismatch");

  PASS();
}

static void test_hash_relative_path(void) {
  uint8_t hash[LOTA_HASH_SIZE];
  int ret;

  TEST("hash_verify_file rejects relative path");

  ret = hash_verify_file("relative/path.txt", hash);
  ASSERT(ret == -ENOENT, "expected -ENOENT for relative path");

  PASS();
}

static void test_hash_nonexistent(void) {
  uint8_t hash[LOTA_HASH_SIZE];
  int ret;

  TEST("hash_verify_file rejects nonexistent file");

  ret = hash_verify_file("/tmp/lota_test_nonexistent_12345678", hash);
  ASSERT(ret < 0, "expected error for nonexistent file");

  PASS();
}

static void test_hash_directory(void) {
  uint8_t hash[LOTA_HASH_SIZE];
  int ret;

  TEST("hash_verify_file rejects directory");

  ret = hash_verify_file("/tmp", hash);
  ASSERT(ret == -EINVAL, "expected -EINVAL for directory");

  PASS();
}

static void test_event_cache_miss_then_hit(void) {
  struct hash_verify_ctx ctx;
  struct lota_exec_event event;
  uint8_t hash1[LOTA_HASH_SIZE], hash2[LOTA_HASH_SIZE];
  uint64_t hits, misses, errors;
  char *path;
  int ret;

  TEST("hash_verify_event cache miss -> hit");

  ret = hash_verify_init(&ctx, 64);
  ASSERT(ret == 0, "init failed");

  path = create_tmp_file("cache test content", 18);
  ASSERT(path != NULL, "failed to create temp file");

  memset(&event, 0, sizeof(event));
  event.event_type = LOTA_EVENT_EXEC;
  strncpy(event.filename, path, sizeof(event.filename) - 1);
  /* fake metadata fingerprint */
  memset(event.hash, 0xAA, LOTA_HASH_SIZE);

  /* cache miss */
  ret = hash_verify_event(&ctx, &event, hash1);
  ASSERT(ret == 0, "first hash_verify_event failed");

  hash_verify_stats(&ctx, &hits, &misses, &errors);
  ASSERT(misses == 1, "expected 1 miss");
  ASSERT(hits == 0, "expected 0 hits after first call");

  /* cache hit */
  ret = hash_verify_event(&ctx, &event, hash2);
  ASSERT(ret == 0, "second hash_verify_event failed");

  hash_verify_stats(&ctx, &hits, &misses, &errors);
  ASSERT(hits == 1, "expected 1 hit");
  ASSERT(misses == 1, "expected misses unchanged");

  /* hashes must be identical */
  ASSERT(memcmp(hash1, hash2, LOTA_HASH_SIZE) == 0,
         "cached hash differs from computed hash");

  unlink(path);
  free(path);
  hash_verify_cleanup(&ctx);

  PASS();
}

static void test_event_cache_invalidation(void) {
  struct hash_verify_ctx ctx;
  struct lota_exec_event event;
  uint8_t hash1[LOTA_HASH_SIZE], hash2[LOTA_HASH_SIZE];
  uint64_t hits, misses, errors;
  char *path;
  int ret;

  TEST("hash_verify_event cache invalidation on fingerprint change");

  ret = hash_verify_init(&ctx, 64);
  ASSERT(ret == 0, "init failed");

  path = create_tmp_file("original content", 16);
  ASSERT(path != NULL, "failed to create temp file");

  memset(&event, 0, sizeof(event));
  event.event_type = LOTA_EVENT_MMAP_EXEC;
  strncpy(event.filename, path, sizeof(event.filename) - 1);
  memset(event.hash, 0xBB, LOTA_HASH_SIZE);

  /* first call */
  ret = hash_verify_event(&ctx, &event, hash1);
  ASSERT(ret == 0, "first call failed");

  /* change fingerprint (simulating file modification) */
  memset(event.hash, 0xCC, LOTA_HASH_SIZE);

  /* should be cache miss (fingerprint changed) */
  ret = hash_verify_event(&ctx, &event, hash2);
  ASSERT(ret == 0, "second call failed");

  hash_verify_stats(&ctx, &hits, &misses, &errors);
  ASSERT(misses == 2, "expected 2 misses (fingerprint changed)");
  ASSERT(hits == 0, "expected 0 hits");

  unlink(path);
  free(path);
  hash_verify_cleanup(&ctx);

  PASS();
}

static void test_event_relative_path(void) {
  struct hash_verify_ctx ctx;
  struct lota_exec_event event;
  uint8_t hash[LOTA_HASH_SIZE];
  int ret;

  TEST("hash_verify_event rejects relative path");

  ret = hash_verify_init(&ctx, 8);
  ASSERT(ret == 0, "init failed");

  memset(&event, 0, sizeof(event));
  event.event_type = LOTA_EVENT_EXEC;
  strncpy(event.filename, "not/absolute", sizeof(event.filename) - 1);

  ret = hash_verify_event(&ctx, &event, hash);
  ASSERT(ret == -ENOENT, "expected -ENOENT for relative path");

  hash_verify_cleanup(&ctx);

  PASS();
}

static void test_lru_eviction(void) {
  struct hash_verify_ctx ctx;
  struct lota_exec_event event;
  uint8_t hash[LOTA_HASH_SIZE];
  uint64_t hits, misses, errors;
  char *paths[4];
  int ret;

  TEST("LRU eviction with small cache (capacity=2)");

  ret = hash_verify_init(&ctx, 2);
  ASSERT(ret == 0, "init failed");

  /* 3 different files */
  for (int i = 0; i < 3; i++) {
    char data[32];
    snprintf(data, sizeof(data), "file content %d", i);
    paths[i] = create_tmp_file(data, strlen(data));
    ASSERT(paths[i] != NULL, "failed to create temp file");
  }

  /* insert file 0 -> miss */
  memset(&event, 0, sizeof(event));
  event.event_type = LOTA_EVENT_EXEC;
  strncpy(event.filename, paths[0], sizeof(event.filename) - 1);
  memset(event.hash, 0x01, LOTA_HASH_SIZE);
  ret = hash_verify_event(&ctx, &event, hash);
  ASSERT(ret == 0, "insert 0 failed");

  /* insert file 1 -> miss */
  memset(&event, 0, sizeof(event));
  event.event_type = LOTA_EVENT_EXEC;
  strncpy(event.filename, paths[1], sizeof(event.filename) - 1);
  memset(event.hash, 0x02, LOTA_HASH_SIZE);
  ret = hash_verify_event(&ctx, &event, hash);
  ASSERT(ret == 0, "insert 1 failed");

  /* insert file 2 -> miss, should evict file 0 (oldest) */
  memset(&event, 0, sizeof(event));
  event.event_type = LOTA_EVENT_EXEC;
  strncpy(event.filename, paths[2], sizeof(event.filename) - 1);
  memset(event.hash, 0x03, LOTA_HASH_SIZE);
  ret = hash_verify_event(&ctx, &event, hash);
  ASSERT(ret == 0, "insert 2 failed");

  hash_verify_stats(&ctx, &hits, &misses, &errors);
  ASSERT(misses == 3, "expected 3 misses");

  /* query file 0 again -> should be a miss (evicted) */
  memset(&event, 0, sizeof(event));
  event.event_type = LOTA_EVENT_EXEC;
  strncpy(event.filename, paths[0], sizeof(event.filename) - 1);
  memset(event.hash, 0x01, LOTA_HASH_SIZE);
  ret = hash_verify_event(&ctx, &event, hash);
  ASSERT(ret == 0, "re-query 0 failed");

  hash_verify_stats(&ctx, &hits, &misses, &errors);
  ASSERT(misses == 4, "expected 4 misses (file 0 was evicted)");

  for (int i = 0; i < 3; i++) {
    unlink(paths[i]);
    free(paths[i]);
  }
  hash_verify_cleanup(&ctx);

  PASS();
}

static void test_stats(void) {
  struct hash_verify_ctx ctx;
  uint64_t h, m, e;
  int ret;

  TEST("hash_verify_stats correctness");

  ret = hash_verify_init(&ctx, 8);
  ASSERT(ret == 0, "init failed");

  hash_verify_stats(&ctx, &h, &m, &e);
  ASSERT(h == 0 && m == 0 && e == 0, "stats not zero after init");

  /* trigger an error (nonexistent file) */
  {
    struct lota_exec_event event;
    uint8_t hash[LOTA_HASH_SIZE];
    memset(&event, 0, sizeof(event));
    event.event_type = LOTA_EVENT_EXEC;
    strncpy(event.filename, "/tmp/lota_test_nonexistent_99999999",
            sizeof(event.filename) - 1);
    memset(event.hash, 0xFF, LOTA_HASH_SIZE);
    hash_verify_event(&ctx, &event, hash);
  }

  hash_verify_stats(&ctx, &h, &m, &e);
  ASSERT(e == 1, "expected 1 error after bad path");

  hash_verify_cleanup(&ctx);

  PASS();
}

static void test_hash_large_file(void) {
  char *path;
  uint8_t hash[LOTA_HASH_SIZE];
  char our_hex[65];
  char expected_hex[65];
  int ret;

  TEST("hash_verify_file on 1 MB file (multi-chunk)");

  /* 1 MB file */
  path = strdup("/tmp/lota_test_hash_large_XXXXXX");
  {
    int fd = mkstemp(path);
    ASSERT(fd >= 0, "failed to create temp file");

    /* 1 MB of repeating pattern */
    uint8_t buf[4096];
    memset(buf, 0x42, sizeof(buf));
    for (int i = 0; i < 256; i++) { /* 256 * 4096 = 1 MB */
      ssize_t w = write(fd, buf, sizeof(buf));
      (void)w;
    }
    close(fd);
  }

  ret = hash_verify_file(path, hash);
  ASSERT(ret == 0, "hash_verify_file failed on large file");

  hex_str(hash, our_hex);

  ret = sha256sum_file(path, expected_hex);
  unlink(path);
  free(path);
  ASSERT(ret == 0, "sha256sum failed");
  ASSERT(strcmp(our_hex, expected_hex) == 0,
         "large file hash mismatch with sha256sum");

  PASS();
}

static void test_null_args(void) {
  struct hash_verify_ctx ctx;
  uint8_t hash[LOTA_HASH_SIZE];
  int ret;

  TEST("NULL argument handling");

  ret = hash_verify_file(NULL, hash);
  ASSERT(ret == -EINVAL, "expected -EINVAL for NULL path");

  ret = hash_verify_file("/tmp/whatever", NULL);
  ASSERT(ret == -EINVAL, "expected -EINVAL for NULL output");

  ret = hash_verify_init(NULL, 0);
  ASSERT(ret == -EINVAL, "expected -EINVAL for NULL ctx");

  {
    struct lota_exec_event event;
    memset(&event, 0, sizeof(event));
    ret = hash_verify_event(NULL, &event, hash);
    ASSERT(ret == -EINVAL, "expected -EINVAL for NULL ctx");
  }

  ret = hash_verify_init(&ctx, 8);
  ASSERT(ret == 0, "init failed");
  ret = hash_verify_event(&ctx, NULL, hash);
  ASSERT(ret == -EINVAL, "expected -EINVAL for NULL event");
  hash_verify_cleanup(&ctx);

  PASS();
}

int main(void) {
  printf("\n=== LOTA Hash Verification Tests ===\n\n");

  test_hash_known_content();
  test_hash_empty_file();
  test_hash_relative_path();
  test_hash_nonexistent();
  test_hash_directory();
  test_event_cache_miss_then_hit();
  test_event_cache_invalidation();
  test_event_relative_path();
  test_lru_eviction();
  test_stats();
  test_hash_large_file();
  test_null_args();

  printf("\n=== Results: %d/%d passed ===\n\n", tests_passed, tests_run);

  return (tests_passed == tests_run) ? 0 : 1;
}
