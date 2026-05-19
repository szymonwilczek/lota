/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for AIK rotation (tpm.h / tpm.c metadata and lifecycle).
 *
 * These tests exercise the metadata persistence, age calculation,
 * rotation-needed checks, and grace period logic WITHOUT requiring
 * a real TPM. The heavy TPM call paths (EvictControl, CreatePrimary)
 * are not invoked here! -- those are integration-tested via
 * --test-tpm on a real machine.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "../src/agent/tpm.h"

static uint32_t tpm_ascii4(char a, char b, char c, char d) {
  return ((uint32_t)(uint8_t)a << 24) | ((uint32_t)(uint8_t)b << 16) |
         ((uint32_t)(uint8_t)c << 8) | (uint32_t)(uint8_t)d;
}

static int mock_prop_reader_swtpm(struct tpm_context *ctx, TPM2_PT prop,
                                  uint32_t *out_val) {
  (void)ctx;
  if (!out_val)
    return -EINVAL;

  switch (prop) {
  case TPM2_PT_MANUFACTURER:
    *out_val = tpm_ascii4('I', 'F', 'X', '\0');
    return 0;
  case TPM2_PT_FIRMWARE_VERSION_1:
    *out_val = 0x00010000;
    return 0;
  case TPM2_PT_FIRMWARE_VERSION_2:
    *out_val = 0x00000001;
    return 0;
  case TPM2_PT_VENDOR_STRING_1:
    *out_val = tpm_ascii4('S', 'W', 'T', 'P');
    return 0;
  case TPM2_PT_VENDOR_STRING_2:
    *out_val = tpm_ascii4('M', ' ', ' ', ' ');
    return 0;
  case TPM2_PT_VENDOR_STRING_3:
  case TPM2_PT_VENDOR_STRING_4:
    *out_val = 0;
    return 0;
  default:
    return -EINVAL;
  }
}

static int tests_run;
static int tests_passed;

#define TEST(name)                                                             \
  do {                                                                         \
    tests_run++;                                                               \
    printf("  [%2d] %-55s ", tests_run, name);                                 \
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

static char tmp_dir[128];

static void setup_tmp_dir(void) {
  snprintf(tmp_dir, sizeof(tmp_dir), "/tmp/lota_aik_%d", getpid());
  mkdir(tmp_dir, 0755);
}

static void cleanup_tmp_dir(void) {
  char cmd[256];
  snprintf(cmd, sizeof(cmd), "rm -rf %s", tmp_dir);
  int ret = system(cmd);
  (void)ret;
}

/*
 * Build a tpm_context with metadata path pointing to tmp_dir.
 * Does NOT call tpm_init()
 */
static void make_ctx(struct tpm_context *ctx) {
  memset(ctx, 0, sizeof(*ctx));
  /* pretend it is initialized so metadata functions proceed */
  ctx->initialized = true;
  snprintf(ctx->aik_meta_path, sizeof(ctx->aik_meta_path), "%s/aik_meta.dat",
           tmp_dir);
}

/*
 * save + load round-trip
 */
static void test_metadata_save_load(void) {
  struct tpm_context ctx;
  struct tpm_context ctx2;
  int ret;

  TEST("metadata save -> load round-trip");
  make_ctx(&ctx);
  make_ctx(&ctx2);

  ctx.aik_meta.magic = TPM_AIK_META_MAGIC;
  ctx.aik_meta.version = TPM_AIK_META_VERSION;
  ctx.aik_meta.generation = 42;
  ctx.aik_meta.provisioned_at = 1700000000;
  ctx.aik_meta.last_rotated_at = 1700000100;
  ctx.aik_meta_loaded = true;

  ret = tpm_aik_save_metadata(&ctx);
  if (ret != 0) {
    FAIL("save returned error");
    return;
  }

  ret = tpm_aik_load_metadata(&ctx2);
  if (ret != 0) {
    FAIL("load returned error");
    return;
  }

  if (ctx2.aik_meta.magic != TPM_AIK_META_MAGIC ||
      ctx2.aik_meta.version != TPM_AIK_META_VERSION ||
      ctx2.aik_meta.generation != 42 ||
      ctx2.aik_meta.provisioned_at != 1700000000 ||
      ctx2.aik_meta.last_rotated_at != 1700000100) {
    FAIL("metadata values mismatch after round-trip");
    return;
  }

  if (!ctx2.aik_meta_loaded) {
    FAIL("aik_meta_loaded not set");
    return;
  }

  PASS();
}

/*
 * load creates default metadata when file does not exist
 */
static void test_metadata_default_creation(void) {
  struct tpm_context ctx;
  int ret;
  time_t before, after;

  TEST("load creates default metadata if missing");
  make_ctx(&ctx);
  /* make sure file does not exist */
  unlink(ctx.aik_meta_path);

  before = time(NULL);
  ret = tpm_aik_load_metadata(&ctx);
  after = time(NULL);

  if (ret != 0) {
    FAIL("load returned error");
    return;
  }

  if (ctx.aik_meta.magic != TPM_AIK_META_MAGIC) {
    FAIL("wrong magic");
    return;
  }
  if (ctx.aik_meta.generation != 1) {
    FAIL("default generation should be 1");
    return;
  }
  if (ctx.aik_meta.provisioned_at < (int64_t)before ||
      ctx.aik_meta.provisioned_at > (int64_t)after) {
    FAIL("provisioned_at out of range");
    return;
  }
  if (ctx.aik_meta.last_rotated_at != 0) {
    FAIL("last_rotated_at should be 0 on first create");
    return;
  }

  /* verify file was persisted */
  if (access(ctx.aik_meta_path, F_OK) != 0) {
    FAIL("metadata file not created");
    return;
  }

  PASS();
}

/*
 * reject corrupted magic
 */
static void test_metadata_bad_magic(void) {
  struct tpm_context ctx;
  struct aik_metadata bad;
  int fd, ret;

  TEST("load rejects bad magic");
  make_ctx(&ctx);

  memset(&bad, 0, sizeof(bad));
  bad.magic = 0xDEADBEEF;
  bad.version = TPM_AIK_META_VERSION;

  fd = open(ctx.aik_meta_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) {
    FAIL("cannot create test file");
    return;
  }
  {
    ssize_t wr_ = write(fd, &bad, sizeof(bad));
    (void)wr_;
  }
  close(fd);

  ret = tpm_aik_load_metadata(&ctx);
  if (ret == 0) {
    FAIL("should reject bad magic");
    return;
  }
  if (ret != -EINVAL) {
    FAIL("expected -EINVAL for bad magic");
    return;
  }

  PASS();
}

/*
 * reject unsupported version
 */
static void test_metadata_bad_version(void) {
  struct tpm_context ctx;
  struct aik_metadata bad;
  int fd, ret;

  TEST("load rejects unsupported version");
  make_ctx(&ctx);

  memset(&bad, 0, sizeof(bad));
  bad.magic = TPM_AIK_META_MAGIC;
  bad.version = 99;

  fd = open(ctx.aik_meta_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) {
    FAIL("cannot create test file");
    return;
  }
  {
    ssize_t wr_ = write(fd, &bad, sizeof(bad));
    (void)wr_;
  }
  close(fd);

  ret = tpm_aik_load_metadata(&ctx);
  if (ret == 0) {
    FAIL("should reject version 99");
    return;
  }
  if (ret != -ENOTSUP) {
    FAIL("expected -ENOTSUP for bad version");
    return;
  }

  PASS();
}

/*
 * tpm_aik_age returns correct seconds
 */
static void test_aik_age(void) {
  struct tpm_context ctx;
  int64_t age;
  time_t now;

  TEST("tpm_aik_age returns correct age");
  make_ctx(&ctx);

  now = time(NULL);
  ctx.aik_meta.magic = TPM_AIK_META_MAGIC;
  ctx.aik_meta.version = TPM_AIK_META_VERSION;
  ctx.aik_meta.provisioned_at = (int64_t)(now - 7200); /* 2 hours ago */
  ctx.aik_meta_loaded = true;

  age = tpm_aik_age(&ctx);
  if (age < 7199 || age > 7201) {
    char buf[64];
    snprintf(buf, sizeof(buf), "expected ~7200, got %ld", (long)age);
    FAIL(buf);
    return;
  }

  PASS();
}

/*
 * tpm_aik_age fails without loaded metadata
 */
static void test_aik_age_no_metadata(void) {
  struct tpm_context ctx;
  int64_t age;

  TEST("tpm_aik_age fails if metadata not loaded");
  make_ctx(&ctx);
  ctx.aik_meta_loaded = false;

  age = tpm_aik_age(&ctx);
  if (age >= 0) {
    FAIL("should return negative error");
    return;
  }

  PASS();
}

/*
 * needs_rotation returns 0 when key is fresh
 */
static void test_needs_rotation_fresh(void) {
  struct tpm_context ctx;
  int ret;

  TEST("needs_rotation -> 0 for fresh key");
  make_ctx(&ctx);

  ctx.aik_meta.magic = TPM_AIK_META_MAGIC;
  ctx.aik_meta.version = TPM_AIK_META_VERSION;
  ctx.aik_meta.provisioned_at = (int64_t)time(NULL);
  ctx.aik_meta_loaded = true;

  ret = tpm_aik_needs_rotation(&ctx, 3600);
  if (ret != 0) {
    FAIL("should be 0 for just-provisioned key");
    return;
  }

  PASS();
}

/*
 * needs_rotation returns 1 when key expired
 */
static void test_needs_rotation_expired(void) {
  struct tpm_context ctx;
  int ret;

  TEST("needs_rotation -> 1 for expired key");
  make_ctx(&ctx);

  ctx.aik_meta.magic = TPM_AIK_META_MAGIC;
  ctx.aik_meta.version = TPM_AIK_META_VERSION;
  ctx.aik_meta.provisioned_at = (int64_t)(time(NULL) - 7200);
  ctx.aik_meta_loaded = true;

  ret = tpm_aik_needs_rotation(&ctx, 3600);
  if (ret != 1) {
    FAIL("should be 1 for 2h-old key with 1h TTL");
    return;
  }

  PASS();
}

/*
 * needs_rotation uses default TTL when max_age_sec == 0
 */
static void test_needs_rotation_default_ttl(void) {
  struct tpm_context ctx;
  int ret;

  TEST("needs_rotation uses default 30d TTL");
  make_ctx(&ctx);

  ctx.aik_meta.magic = TPM_AIK_META_MAGIC;
  ctx.aik_meta.version = TPM_AIK_META_VERSION;
  ctx.aik_meta.provisioned_at = (int64_t)time(NULL);
  ctx.aik_meta_loaded = true;

  /* 0 -> use TPM_AIK_DEFAULT_TTL_SEC (30 days) */
  ret = tpm_aik_needs_rotation(&ctx, 0);
  if (ret != 0) {
    FAIL("fresh key should not need rotation with 30d default");
    return;
  }

  /* simulate 31-day old key */
  ctx.aik_meta.provisioned_at = (int64_t)(time(NULL) - 31 * 24 * 3600);
  ret = tpm_aik_needs_rotation(&ctx, 0);
  if (ret != 1) {
    FAIL("31-day old key should need rotation with 30d default");
    return;
  }

  PASS();
}

/*
 * grace period inactive by default
 */
static void test_grace_period_inactive(void) {
  struct tpm_context ctx;

  TEST("grace period inactive by default");
  make_ctx(&ctx);

  if (tpm_aik_in_grace_period(&ctx) != 0) {
    FAIL("should be 0 with no rotation");
    return;
  }

  PASS();
}

/*
 * grace period active within deadline
 */
static void test_grace_period_active(void) {
  struct tpm_context ctx;

  TEST("grace period active within deadline");
  make_ctx(&ctx);

  ctx.grace_deadline = time(NULL) + 600; /* 10 minutes from now */
  ctx.prev_aik_public_size = 128;
  memset(ctx.prev_aik_public, 0xAA, 128);

  if (tpm_aik_in_grace_period(&ctx) != 1) {
    FAIL("should be 1 during grace window");
    return;
  }

  PASS();
}

/*
 * grace period expires and clears state
 */
static void test_grace_period_expired(void) {
  struct tpm_context ctx;

  TEST("grace period expires -> clears state");
  make_ctx(&ctx);

  ctx.grace_deadline = time(NULL) - 10; /* 10 seconds in the past */
  ctx.prev_aik_public_size = 128;

  if (tpm_aik_in_grace_period(&ctx) != 0) {
    FAIL("should be 0 after deadline");
    return;
  }

  if (ctx.prev_aik_public_size != 0) {
    FAIL("prev_aik_public_size not cleared");
    return;
  }

  if (ctx.grace_deadline != 0) {
    FAIL("grace_deadline not cleared");
    return;
  }

  PASS();
}

/*
 * get_prev_public returns key during grace period
 */
static void test_get_prev_public_grace(void) {
  struct tpm_context ctx;
  uint8_t buf[LOTA_MAX_AIK_PUB_SIZE];
  size_t out_size = 0;
  int ret;

  TEST("get_prev_public returns key in grace period");
  make_ctx(&ctx);

  ctx.grace_deadline = time(NULL) + 600;
  ctx.prev_aik_public_size = 64;
  memset(ctx.prev_aik_public, 0xBB, 64);

  ret = tpm_aik_get_prev_public(&ctx, buf, sizeof(buf), &out_size);
  if (ret != 0) {
    FAIL("should succeed during grace period");
    return;
  }
  if (out_size != 64) {
    FAIL("wrong output size");
    return;
  }
  if (buf[0] != 0xBB || buf[63] != 0xBB) {
    FAIL("data mismatch");
    return;
  }

  PASS();
}

/*
 * get_prev_public returns -ENOENT outside grace period
 */
static void test_get_prev_public_no_grace(void) {
  struct tpm_context ctx;
  uint8_t buf[LOTA_MAX_AIK_PUB_SIZE];
  size_t out_size = 0;
  int ret;

  TEST("get_prev_public -> -ENOENT without grace period");
  make_ctx(&ctx);

  ret = tpm_aik_get_prev_public(&ctx, buf, sizeof(buf), &out_size);
  if (ret != -ENOENT) {
    FAIL("expected -ENOENT");
    return;
  }

  PASS();
}

/*
 * save metadata creates parent directories
 */
static void test_save_creates_dirs(void) {
  struct tpm_context ctx;
  char nested[256];
  int ret;

  TEST("save creates parent directories");
  memset(&ctx, 0, sizeof(ctx));
  ctx.initialized = true;

  snprintf(nested, sizeof(nested), "%s/sub/dir/aik_meta.dat", tmp_dir);
  snprintf(ctx.aik_meta_path, sizeof(ctx.aik_meta_path), "%s", nested);

  ctx.aik_meta.magic = TPM_AIK_META_MAGIC;
  ctx.aik_meta.version = TPM_AIK_META_VERSION;
  ctx.aik_meta.generation = 7;
  ctx.aik_meta.provisioned_at = 1234567890;
  ctx.aik_meta_loaded = true;

  ret = tpm_aik_save_metadata(&ctx);
  if (ret != 0) {
    FAIL("save failed");
    return;
  }

  if (access(nested, F_OK) != 0) {
    FAIL("file not created at nested path");
    return;
  }

  PASS();
}

/*
 * truncated file rejected
 */
static void test_metadata_truncated(void) {
  struct tpm_context ctx;
  int fd, ret;

  TEST("load rejects truncated file");
  make_ctx(&ctx);

  fd = open(ctx.aik_meta_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0) {
    FAIL("cannot create test file");
    return;
  }
  /* write only 8 bytes, far less than sizeof(aik_metadata) */
  {
    ssize_t wr_ = write(fd, "AIKM\x01\x00\x00\x00", 8);
    (void)wr_;
  }
  close(fd);

  ret = tpm_aik_load_metadata(&ctx);
  if (ret == 0) {
    FAIL("should reject truncated file");
    return;
  }
  if (ret != -EIO) {
    char ebuf[32];
    snprintf(ebuf, sizeof(ebuf), "expected -EIO, got %d", ret);
    FAIL(ebuf);
    return;
  }

  PASS();
}

/*
 * needs_rotation boundary (age == max_age_sec)
 */
static void test_needs_rotation_boundary(void) {
  struct tpm_context ctx;
  int ret;

  TEST("needs_rotation boundary: age == TTL -> 1");
  make_ctx(&ctx);

  ctx.aik_meta.magic = TPM_AIK_META_MAGIC;
  ctx.aik_meta.version = TPM_AIK_META_VERSION;
  ctx.aik_meta.provisioned_at = (int64_t)(time(NULL) - 3600);
  ctx.aik_meta_loaded = true;

  /* exactly at boundary */
  ret = tpm_aik_needs_rotation(&ctx, 3600);
  if (ret != 1) {
    FAIL("age == TTL should trigger rotation");
    return;
  }

  PASS();
}

/*
 * get_prev_public -> -ENOSPC when buffer too small
 */
static void test_get_prev_public_small_buf(void) {
  struct tpm_context ctx;
  uint8_t buf[8];
  size_t out_size = 0;
  int ret;

  TEST("get_prev_public -> -ENOSPC if buffer too small");
  make_ctx(&ctx);

  ctx.grace_deadline = time(NULL) + 600;
  ctx.prev_aik_public_size = 64;
  memset(ctx.prev_aik_public, 0xCC, 64);

  ret = tpm_aik_get_prev_public(&ctx, buf, sizeof(buf), &out_size);
  if (ret != -ENOSPC) {
    char ebuf[32];
    snprintf(ebuf, sizeof(ebuf), "expected -ENOSPC, got %d", ret);
    FAIL(ebuf);
    return;
  }

  PASS();
}

static void test_provision_rejects_swtpm_vendor(void) {
  struct tpm_context ctx;
  int ret;

  TEST("provision rejects software TPM vendor strings");
  make_ctx(&ctx);

  tpm_test_set_prop_reader(mock_prop_reader_swtpm);
  ret = tpm_provision_aik(&ctx);
  tpm_test_reset_prop_reader();

  if (ret != -EACCES) {
    char ebuf[64];
    snprintf(ebuf, sizeof(ebuf), "expected -EACCES, got %d", ret);
    FAIL(ebuf);
    return;
  }

  PASS();
}

static void test_rc_success_is_zero(void) {
  TEST("tpm_test_rc_to_errno: TSS2_RC_SUCCESS -> 0");

  if (tpm_test_rc_to_errno(TSS2_RC_SUCCESS) != 0) {
    FAIL("expected 0");
    return;
  }

  PASS();
}

static void test_rc_lockout_raw(void) {
  TEST("tpm_test_rc_is_lockout: raw TPM2_RC_LOCKOUT");

  if (!tpm_test_rc_is_lockout(TPM2_RC_LOCKOUT)) {
    FAIL("LOCKOUT not detected");
    return;
  }
  if (tpm_test_rc_is_transient(TPM2_RC_LOCKOUT)) {
    FAIL("LOCKOUT must not be transient");
    return;
  }
  if (tpm_test_rc_to_errno(TPM2_RC_LOCKOUT) != -EOWNERDEAD) {
    FAIL("expected -EOWNERDEAD for LOCKOUT");
    return;
  }

  PASS();
}

static void test_rc_lockout_resmgr_layer(void) {
  TPM2_RC wrapped = (TPM2_RC)(TSS2_RESMGR_TPM_RC_LAYER | TPM2_RC_LOCKOUT);

  TEST("tpm_test_rc_is_lockout: resmgr-wrapped LOCKOUT");

  if (!tpm_test_rc_is_lockout(wrapped)) {
    FAIL("layered LOCKOUT not detected");
    return;
  }
  if (tpm_test_rc_to_errno(wrapped) != -EOWNERDEAD) {
    FAIL("expected -EOWNERDEAD for layered LOCKOUT");
    return;
  }

  PASS();
}

static void test_rc_transient_codes(void) {
  TPM2_RC transient[] = {
      TPM2_RC_RETRY,         TPM2_RC_YIELDED,        TPM2_RC_TESTING,
      TPM2_RC_NV_RATE,       TPM2_RC_NV_UNAVAILABLE, TPM2_RC_SESSION_MEMORY,
      TPM2_RC_OBJECT_MEMORY, TPM2_RC_MEMORY,
  };

  TEST("tpm_test_rc_is_transient: WARN codes -> EAGAIN");

  for (size_t i = 0; i < sizeof(transient) / sizeof(transient[0]); i++) {
    if (!tpm_test_rc_is_transient(transient[i])) {
      char ebuf[64];
      snprintf(ebuf, sizeof(ebuf), "code 0x%X not transient",
               (unsigned)transient[i]);
      FAIL(ebuf);
      return;
    }
    if (tpm_test_rc_to_errno(transient[i]) != -EAGAIN) {
      char ebuf[64];
      snprintf(ebuf, sizeof(ebuf), "code 0x%X != -EAGAIN",
               (unsigned)transient[i]);
      FAIL(ebuf);
      return;
    }
    if (tpm_test_rc_is_lockout(transient[i])) {
      FAIL("transient must not be classified as lockout");
      return;
    }
  }

  PASS();
}

static void test_rc_auth_fail_with_session_bits(void) {
  /* TPM2_RC_AUTH_FAIL is a format-1 code; the actual returned RC carries
   * session/handle indices in bits 8-11. tpm_test_rc_to_errno must strip
   * those scratch bits before mapping. */
  TPM2_RC auth_fail_with_session = (TPM2_RC)(TPM2_RC_AUTH_FAIL | 0x300);

  TEST("tpm_test_rc_to_errno: AUTH_FAIL with session offset -> EACCES");

  if (tpm_test_rc_to_errno(auth_fail_with_session) != -EACCES) {
    FAIL("expected -EACCES");
    return;
  }
  if (tpm_test_rc_is_lockout(auth_fail_with_session)) {
    FAIL("AUTH_FAIL must not be lockout");
    return;
  }
  if (tpm_test_rc_is_transient(auth_fail_with_session)) {
    FAIL("AUTH_FAIL must not be transient");
    return;
  }

  PASS();
}

static void test_rc_value_and_handle(void) {
  TEST("tpm_test_rc_to_errno: VALUE/HANDLE map cleanly");

  if (tpm_test_rc_to_errno(TPM2_RC_VALUE) != -EINVAL) {
    FAIL("VALUE != -EINVAL");
    return;
  }
  if (tpm_test_rc_to_errno(TPM2_RC_HANDLE) != -ENOENT) {
    FAIL("HANDLE != -ENOENT");
    return;
  }

  PASS();
}

static void test_rc_tcti_layer(void) {
  TEST("tpm_test_rc_to_errno: TCTI layer codes");

  if (tpm_test_rc_to_errno(TSS2_TCTI_RC_NO_CONNECTION) != -ENODEV) {
    FAIL("NO_CONNECTION != -ENODEV");
    return;
  }
  if (tpm_test_rc_to_errno(TSS2_TCTI_RC_TRY_AGAIN) != -EAGAIN) {
    FAIL("TRY_AGAIN != -EAGAIN");
    return;
  }
  if (!tpm_test_rc_is_transient(TSS2_TCTI_RC_TRY_AGAIN)) {
    FAIL("TRY_AGAIN must be transient");
    return;
  }

  PASS();
}

static void test_lockout_flag_lifecycle(void) {
  struct tpm_context ctx;

  TEST("tpm_is_locked_out reflects sticky state and resets cleanly");
  make_ctx(&ctx);

  if (tpm_is_locked_out(&ctx)) {
    FAIL("fresh context must not be in lockout");
    return;
  }

  /* lockout-record helper is internal; tests drive the public
   * surface by toggling the latched flag manually. */
  ctx.lockout_active = true;
  ctx.lockout_first_seen = time(NULL);
  ctx.lockout_event_count = 3;

  if (!tpm_is_locked_out(&ctx)) {
    FAIL("lockout_active was ignored");
    return;
  }

  tpm_reset_lockout_state(&ctx);

  if (tpm_is_locked_out(&ctx)) {
    FAIL("reset did not clear lockout state");
    return;
  }
  if (ctx.lockout_first_seen != 0) {
    FAIL("first_seen not cleared by reset");
    return;
  }

  PASS();
}

int main(void) {
  printf("\n=== AIK Rotation Tests ===\n\n");

  setup_tmp_dir();

  test_metadata_save_load();
  test_metadata_default_creation();
  test_metadata_bad_magic();
  test_metadata_bad_version();
  test_aik_age();
  test_aik_age_no_metadata();
  test_needs_rotation_fresh();
  test_needs_rotation_expired();
  test_needs_rotation_default_ttl();
  test_grace_period_inactive();
  test_grace_period_active();
  test_grace_period_expired();
  test_get_prev_public_grace();
  test_get_prev_public_no_grace();
  test_save_creates_dirs();
  test_metadata_truncated();
  test_needs_rotation_boundary();
  test_get_prev_public_small_buf();
  test_provision_rejects_swtpm_vendor();
  test_rc_success_is_zero();
  test_rc_lockout_raw();
  test_rc_lockout_resmgr_layer();
  test_rc_transient_codes();
  test_rc_auth_fail_with_session_bits();
  test_rc_value_and_handle();
  test_rc_tcti_layer();
  test_lockout_flag_lifecycle();

  cleanup_tmp_dir();

  printf("\n  Result: %d/%d passed\n\n", tests_passed, tests_run);
  return (tests_passed == tests_run) ? 0 : 1;
}
