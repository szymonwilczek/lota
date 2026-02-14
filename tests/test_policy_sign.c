/* SPDX-License-Identifier: MIT */
/*
 * LOTA - Policy Ed25519 Signing Tests
 *
 * Tests Ed25519 keypair generation, signing, and verification for
 * YAML policy files using the policy_sign module.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../src/agent/policy_sign.h"

#ifndef EAUTH
#define EAUTH 80
#endif

static int tests_run;
static int tests_passed;

#define TEST(name)                                                             \
  do {                                                                         \
    tests_run++;                                                               \
    printf("  [%d] %-50s ", tests_run, name);                                  \
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

/* temp directory for test artifacts */
static char tmpdir[64];

static void setup_tmpdir(void) {
  snprintf(tmpdir, sizeof(tmpdir), "/tmp/lota_test_sign_XXXXXX");
  if (!mkdtemp(tmpdir)) {
    fprintf(stderr, "Failed to create temp dir: %s\n", strerror(errno));
    exit(1);
  }
}

static void cleanup_tmpdir(void) {
  char cmd[128];
  snprintf(cmd, sizeof(cmd), "rm -rf %s", tmpdir);
  int ret = system(cmd); (void)ret;
}

static void make_paths(const char *base, char *priv, char *pub, size_t len) {
  snprintf(priv, len, "%s/%s.key", tmpdir, base);
  snprintf(pub, len, "%s/%s.pub", tmpdir, base);
}

static int write_file(const char *path, const void *data, size_t len) {
  FILE *f = fopen(path, "wb");
  if (!f)
    return -1;
  if (fwrite(data, 1, len, f) != len) {
    fclose(f);
    return -1;
  }
  fclose(f);
  return 0;
}

static void test_generate_keypair(void) {
  char priv[PATH_MAX], pub[PATH_MAX];
  int ret;

  TEST("generate keypair");
  make_paths("gen1", priv, pub, sizeof(priv));
  ret = policy_sign_generate_keypair(priv, pub);
  if (ret != 0) {
    FAIL("keygen returned error");
    return;
  }
  if (access(priv, F_OK) != 0) {
    FAIL("private key file missing");
    return;
  }
  if (access(pub, F_OK) != 0) {
    FAIL("public key file missing");
    return;
  }
  PASS();
}

static void test_generate_keypair_null_args(void) {
  char pub[PATH_MAX];
  int ret;

  TEST("generate keypair null privkey");
  snprintf(pub, sizeof(pub), "%s/null.pub", tmpdir);
  ret = policy_sign_generate_keypair(NULL, pub);
  if (ret != -EINVAL) {
    FAIL("expected -EINVAL");
    return;
  }
  PASS();

  TEST("generate keypair null pubkey");
  ret = policy_sign_generate_keypair(pub, NULL);
  if (ret != -EINVAL) {
    FAIL("expected -EINVAL");
    return;
  }
  PASS();
}

static void test_sign_verify_buffer(void) {
  char priv[PATH_MAX], pub[PATH_MAX];
  uint8_t sig[POLICY_SIG_SIZE];
  const uint8_t msg[] = "name: test-policy\npcrs:\n  0: abc123\n";
  int ret;

  TEST("sign and verify buffer");
  make_paths("buf1", priv, pub, sizeof(priv));

  ret = policy_sign_generate_keypair(priv, pub);
  if (ret != 0) {
    FAIL("keygen failed");
    return;
  }

  ret = policy_sign_buffer(msg, sizeof(msg) - 1, priv, sig);
  if (ret != 0) {
    FAIL("sign_buffer failed");
    return;
  }

  ret = policy_verify_buffer(msg, sizeof(msg) - 1, pub, sig);
  if (ret != 0) {
    FAIL("verify_buffer failed on valid sig");
    return;
  }
  PASS();
}

static void test_verify_buffer_tampered(void) {
  char priv[PATH_MAX], pub[PATH_MAX];
  uint8_t sig[POLICY_SIG_SIZE];
  uint8_t msg[] = "name: test-policy\npcrs:\n  0: abc123\n";
  int ret;

  TEST("verify buffer rejects tampered data");
  make_paths("tamp1", priv, pub, sizeof(priv));

  ret = policy_sign_generate_keypair(priv, pub);
  if (ret != 0) {
    FAIL("keygen failed");
    return;
  }

  ret = policy_sign_buffer(msg, sizeof(msg) - 1, priv, sig);
  if (ret != 0) {
    FAIL("sign_buffer failed");
    return;
  }

  /* tamper with message */
  msg[0] = 'X';

  ret = policy_verify_buffer(msg, sizeof(msg) - 1, pub, sig);
  if (ret != -EAUTH) {
    FAIL("expected -EAUTH for tampered data");
    return;
  }
  PASS();
}

static void test_verify_buffer_wrong_key(void) {
  char priv1[PATH_MAX], pub1[PATH_MAX];
  char priv2[PATH_MAX], pub2[PATH_MAX];
  uint8_t sig[POLICY_SIG_SIZE];
  const uint8_t msg[] = "hello policy";
  int ret;

  TEST("verify buffer rejects wrong key");
  make_paths("key1", priv1, pub1, sizeof(priv1));
  make_paths("key2", priv2, pub2, sizeof(priv2));

  ret = policy_sign_generate_keypair(priv1, pub1);
  if (ret != 0) {
    FAIL("keygen1 failed");
    return;
  }
  ret = policy_sign_generate_keypair(priv2, pub2);
  if (ret != 0) {
    FAIL("keygen2 failed");
    return;
  }

  /* sign with key1 */
  ret = policy_sign_buffer(msg, sizeof(msg) - 1, priv1, sig);
  if (ret != 0) {
    FAIL("sign_buffer failed");
    return;
  }

  /* verify with key2 -> should fail */
  ret = policy_verify_buffer(msg, sizeof(msg) - 1, pub2, sig);
  if (ret != -EAUTH) {
    FAIL("expected -EAUTH for wrong key");
    return;
  }
  PASS();
}

static void test_sign_verify_file(void) {
  char priv[PATH_MAX], pub[PATH_MAX];
  char yaml_path[PATH_MAX], sig_path[PATH_MAX];
  const char *content = "name: file-test\npcrs:\n  0: deadbeef\n";
  int ret;

  TEST("sign and verify file");
  make_paths("file1", priv, pub, sizeof(priv));
  snprintf(yaml_path, sizeof(yaml_path), "%s/policy.yaml", tmpdir);
  snprintf(sig_path, sizeof(sig_path), "%s/policy.yaml.sig", tmpdir);

  ret = policy_sign_generate_keypair(priv, pub);
  if (ret != 0) {
    FAIL("keygen failed");
    return;
  }

  ret = write_file(yaml_path, content, strlen(content));
  if (ret != 0) {
    FAIL("write yaml failed");
    return;
  }

  ret = policy_sign_file(yaml_path, priv, sig_path);
  if (ret != 0) {
    FAIL("sign_file failed");
    return;
  }

  if (access(sig_path, F_OK) != 0) {
    FAIL("sig file not created");
    return;
  }

  ret = policy_verify_file(yaml_path, pub, sig_path);
  if (ret != 0) {
    FAIL("verify_file failed on valid sig");
    return;
  }
  PASS();
}

static void test_verify_file_tampered(void) {
  char priv[PATH_MAX], pub[PATH_MAX];
  char yaml_path[PATH_MAX], sig_path[PATH_MAX];
  const char *content = "name: tamper-file\npcrs:\n  7: cafe0123\n";
  const char *tampered = "name: tamper-file\npcrs:\n  7: cafe9999\n";
  int ret;

  TEST("verify file rejects tampered content");
  make_paths("ftamp", priv, pub, sizeof(priv));
  snprintf(yaml_path, sizeof(yaml_path), "%s/tamper.yaml", tmpdir);
  snprintf(sig_path, sizeof(sig_path), "%s/tamper.yaml.sig", tmpdir);

  ret = policy_sign_generate_keypair(priv, pub);
  if (ret != 0) {
    FAIL("keygen failed");
    return;
  }

  write_file(yaml_path, content, strlen(content));
  ret = policy_sign_file(yaml_path, priv, sig_path);
  if (ret != 0) {
    FAIL("sign_file failed");
    return;
  }

  /* overwrite with tampered content */
  write_file(yaml_path, tampered, strlen(tampered));

  ret = policy_verify_file(yaml_path, pub, sig_path);
  if (ret != -EAUTH) {
    FAIL("expected -EAUTH for tampered file");
    return;
  }
  PASS();
}

static void test_verify_file_truncated_sig(void) {
  char priv[PATH_MAX], pub[PATH_MAX];
  char yaml_path[PATH_MAX], sig_path[PATH_MAX];
  const char *content = "name: trunc-test\n";
  uint8_t short_sig[32];
  int ret;

  TEST("verify file rejects truncated sig");
  make_paths("trunc", priv, pub, sizeof(priv));
  snprintf(yaml_path, sizeof(yaml_path), "%s/trunc.yaml", tmpdir);
  snprintf(sig_path, sizeof(sig_path), "%s/trunc.yaml.sig", tmpdir);

  ret = policy_sign_generate_keypair(priv, pub);
  if (ret != 0) {
    FAIL("keygen failed");
    return;
  }

  write_file(yaml_path, content, strlen(content));

  /* write a too-short signature */
  memset(short_sig, 0xAA, sizeof(short_sig));
  write_file(sig_path, short_sig, sizeof(short_sig));

  ret = policy_verify_file(yaml_path, pub, sig_path);
  if (ret != -EAUTH) {
    FAIL("expected -EAUTH for truncated sig");
    return;
  }
  PASS();
}

static void test_sign_buffer_null_args(void) {
  char priv[PATH_MAX], pub[PATH_MAX];
  uint8_t sig[POLICY_SIG_SIZE];
  const uint8_t msg[] = "data";
  int ret;

  make_paths("null1", priv, pub, sizeof(priv));
  policy_sign_generate_keypair(priv, pub);

  TEST("sign_buffer rejects null data");
  ret = policy_sign_buffer(NULL, 4, priv, sig);
  if (ret != -EINVAL) {
    FAIL("expected -EINVAL");
    return;
  }
  PASS();

  TEST("sign_buffer rejects null key path");
  ret = policy_sign_buffer(msg, sizeof(msg) - 1, NULL, sig);
  if (ret != -EINVAL) {
    FAIL("expected -EINVAL");
    return;
  }
  PASS();

  TEST("sign_buffer rejects null sig_out");
  ret = policy_sign_buffer(msg, sizeof(msg) - 1, priv, NULL);
  if (ret != -EINVAL) {
    FAIL("expected -EINVAL");
    return;
  }
  PASS();
}

static void test_verify_buffer_null_args(void) {
  char priv[PATH_MAX], pub[PATH_MAX];
  uint8_t sig[POLICY_SIG_SIZE];
  const uint8_t msg[] = "data";
  int ret;

  make_paths("null2", priv, pub, sizeof(priv));
  policy_sign_generate_keypair(priv, pub);
  policy_sign_buffer(msg, sizeof(msg) - 1, priv, sig);

  TEST("verify_buffer rejects null data");
  ret = policy_verify_buffer(NULL, 4, pub, sig);
  if (ret != -EINVAL) {
    FAIL("expected -EINVAL");
    return;
  }
  PASS();

  TEST("verify_buffer rejects null key path");
  ret = policy_verify_buffer(msg, sizeof(msg) - 1, NULL, sig);
  if (ret != -EINVAL) {
    FAIL("expected -EINVAL");
    return;
  }
  PASS();

  TEST("verify_buffer rejects null sig");
  ret = policy_verify_buffer(msg, sizeof(msg) - 1, pub, NULL);
  if (ret != -EINVAL) {
    FAIL("expected -EINVAL");
    return;
  }
  PASS();
}

static void test_sign_file_null_args(void) {
  TEST("sign_file rejects null file_path");
  int ret = policy_sign_file(NULL, "/tmp/k", "/tmp/s");
  if (ret != -EINVAL) {
    FAIL("expected -EINVAL");
    return;
  }
  PASS();

  TEST("sign_file rejects null key_path");
  ret = policy_sign_file("/tmp/f", NULL, "/tmp/s");
  if (ret != -EINVAL) {
    FAIL("expected -EINVAL");
    return;
  }
  PASS();

  TEST("sign_file rejects null sig_path");
  ret = policy_sign_file("/tmp/f", "/tmp/k", NULL);
  if (ret != -EINVAL) {
    FAIL("expected -EINVAL");
    return;
  }
  PASS();
}

static void test_verify_file_null_args(void) {
  TEST("verify_file rejects null file_path");
  int ret = policy_verify_file(NULL, "/tmp/k", "/tmp/s");
  if (ret != -EINVAL) {
    FAIL("expected -EINVAL");
    return;
  }
  PASS();

  TEST("verify_file rejects null key_path");
  ret = policy_verify_file("/tmp/f", NULL, "/tmp/s");
  if (ret != -EINVAL) {
    FAIL("expected -EINVAL");
    return;
  }
  PASS();

  TEST("verify_file rejects null sig_path");
  ret = policy_verify_file("/tmp/f", "/tmp/k", NULL);
  if (ret != -EINVAL) {
    FAIL("expected -EINVAL");
    return;
  }
  PASS();
}

static void test_sign_file_nonexistent(void) {
  char priv[PATH_MAX], pub[PATH_MAX];
  char sig_path[PATH_MAX];
  int ret;

  TEST("sign_file fails on nonexistent file");
  make_paths("nosrc", priv, pub, sizeof(priv));
  snprintf(sig_path, sizeof(sig_path), "%s/nosrc.sig", tmpdir);
  policy_sign_generate_keypair(priv, pub);

  ret = policy_sign_file("/tmp/lota_nonexistent_xyz.yaml", priv, sig_path);
  if (ret == 0) {
    FAIL("expected failure for nonexistent file");
    return;
  }
  PASS();
}

static void test_sign_nonexistent_key(void) {
  char yaml_path[PATH_MAX], sig_path[PATH_MAX];
  const char *content = "test: data\n";
  int ret;

  TEST("sign_buffer fails with nonexistent key");
  snprintf(yaml_path, sizeof(yaml_path), "%s/nokey.yaml", tmpdir);
  snprintf(sig_path, sizeof(sig_path), "%s/nokey.yaml.sig", tmpdir);
  write_file(yaml_path, content, strlen(content));

  ret = policy_sign_file(yaml_path, "/tmp/lota_nokey_xyz.key", sig_path);
  if (ret == 0) {
    FAIL("expected failure for nonexistent key");
    return;
  }
  PASS();
}

static void test_empty_message(void) {
  char priv[PATH_MAX], pub[PATH_MAX];
  uint8_t sig[POLICY_SIG_SIZE];
  const uint8_t empty[] = "";
  int ret;

  TEST("sign and verify empty message");
  make_paths("empty", priv, pub, sizeof(priv));
  policy_sign_generate_keypair(priv, pub);

  ret = policy_sign_buffer(empty, 0, priv, sig);
  if (ret != 0) {
    FAIL("sign_buffer failed on empty");
    return;
  }

  ret = policy_verify_buffer(empty, 0, pub, sig);
  if (ret != 0) {
    FAIL("verify_buffer failed on empty");
    return;
  }
  PASS();
}

static void test_sig_file_size(void) {
  char priv[PATH_MAX], pub[PATH_MAX];
  char yaml_path[PATH_MAX], sig_path[PATH_MAX];
  const char *content = "name: size-check\n";
  FILE *f;
  long fsize;
  int ret;

  TEST("sig file is exactly 64 bytes");
  make_paths("size", priv, pub, sizeof(priv));
  snprintf(yaml_path, sizeof(yaml_path), "%s/size.yaml", tmpdir);
  snprintf(sig_path, sizeof(sig_path), "%s/size.yaml.sig", tmpdir);

  policy_sign_generate_keypair(priv, pub);
  write_file(yaml_path, content, strlen(content));

  ret = policy_sign_file(yaml_path, priv, sig_path);
  if (ret != 0) {
    FAIL("sign_file failed");
    return;
  }

  f = fopen(sig_path, "rb");
  if (!f) {
    FAIL("cannot open sig file");
    return;
  }
  fseek(f, 0, SEEK_END);
  fsize = ftell(f);
  fclose(f);

  if (fsize != POLICY_SIG_SIZE) {
    char msg[64];
    snprintf(msg, sizeof(msg), "sig size is %ld, expected %d", fsize,
             POLICY_SIG_SIZE);
    FAIL(msg);
    return;
  }
  PASS();
}

static void test_verify_missing_sig_file(void) {
  char priv[PATH_MAX], pub[PATH_MAX];
  char yaml_path[PATH_MAX], sig_path[PATH_MAX];
  const char *content = "name: missing-sig\n";
  int ret;

  TEST("verify_file fails when sig file missing");
  make_paths("missig", priv, pub, sizeof(priv));
  snprintf(yaml_path, sizeof(yaml_path), "%s/missig.yaml", tmpdir);
  snprintf(sig_path, sizeof(sig_path), "%s/missig.yaml.sig", tmpdir);

  policy_sign_generate_keypair(priv, pub);
  write_file(yaml_path, content, strlen(content));

  /* do not create sig file */
  ret = policy_verify_file(yaml_path, pub, sig_path);
  if (ret == 0) {
    FAIL("expected failure for missing sig file");
    return;
  }
  PASS();
}

int main(void) {
  printf("=== LOTA Policy Signing Tests ===\n\n");

  setup_tmpdir();

  test_generate_keypair();
  test_generate_keypair_null_args();
  test_sign_verify_buffer();
  test_verify_buffer_tampered();
  test_verify_buffer_wrong_key();
  test_sign_verify_file();
  test_verify_file_tampered();
  test_verify_file_truncated_sig();
  test_sign_buffer_null_args();
  test_verify_buffer_null_args();
  test_sign_file_null_args();
  test_verify_file_null_args();
  test_sign_file_nonexistent();
  test_sign_nonexistent_key();
  test_empty_message();
  test_sig_file_size();
  test_verify_missing_sig_file();

  cleanup_tmpdir();

  printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
  return (tests_passed == tests_run) ? 0 : 1;
}
