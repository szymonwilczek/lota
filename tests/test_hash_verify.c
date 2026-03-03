/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - hash_verify unit tests
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
#include <linux/fsverity.h>
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

static void test_hash_file_requires_verity(void) {
  const char *data = "Hello, LOTA hash verification!\n";
  char *path;
  uint8_t hash[LOTA_HASH_SIZE];
  int ret;

  TEST("hash_verify_file fail-closed without fs-verity");

  path = create_tmp_file(data, strlen(data));
  ASSERT(path != NULL, "failed to create temp file");

  ret = hash_verify_file(path, hash);
  unlink(path);
  free(path);

  ASSERT(ret < 0, "expected failure for non-verity file");
  ASSERT(ret == -ENODATA || ret == -EOPNOTSUPP || ret == -ENOTTY,
         "expected fs-verity unavailable/not-enabled error");

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

static void test_event_no_caching(void) {
  struct hash_verify_ctx ctx;
  struct lota_exec_event event;
  uint8_t hash1[LOTA_HASH_SIZE], hash2[LOTA_HASH_SIZE];
  uint64_t hits, misses, errors;
  char *path;
  int ret;

  TEST("hash_verify_event fail-closed without fs-verity");

  ret = hash_verify_init(&ctx, 64);
  ASSERT(ret == 0, "init failed");

  path = create_tmp_file("cache test content", 18);
  ASSERT(path != NULL, "failed to create temp file");

  memset(&event, 0, sizeof(event));
  event.event_type = LOTA_EVENT_EXEC;
  event.pid = getpid(); /* self PID to ensure /proc/PID/exe exists */

  strncpy(event.filename, "/tmp/ignored", sizeof(event.filename) - 1);

  /* first call */
  ret = hash_verify_event(&ctx, &event, hash1);
  ASSERT(ret < 0, "expected first hash_verify_event failure without verity");

  hash_verify_stats(&ctx, &hits, &misses, &errors);
  ASSERT(misses == 0, "expected 0 misses");
  ASSERT(hits == 0, "expected 0 hits");
  ASSERT(errors == 1, "expected 1 error");

  /* second call */
  ret = hash_verify_event(&ctx, &event, hash2);
  ASSERT(ret < 0, "expected second hash_verify_event failure without verity");

  hash_verify_stats(&ctx, &hits, &misses, &errors);
  ASSERT(hits == 0, "expected 0 hits (caching disabled)");
  ASSERT(misses == 0, "expected 0 misses");
  ASSERT(errors == 2, "expected 2 errors");

  hash_verify_cleanup(&ctx);
  unlink(path);
  free(path);

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
  int ret;

  TEST("hash_verify_file on 1 MB file fails without fs-verity");

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
  unlink(path);
  free(path);
  ASSERT(ret < 0, "expected failure for non-verity large file");

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

  test_hash_file_requires_verity();
  test_hash_relative_path();
  test_hash_nonexistent();
  test_hash_directory();
  test_event_no_caching();
  test_stats();
  test_hash_large_file();
  test_null_args();

  printf("\n=== Results: %d/%d passed ===\n\n", tests_passed, tests_run);

  return (tests_passed == tests_run) ? 0 : 1;
}
