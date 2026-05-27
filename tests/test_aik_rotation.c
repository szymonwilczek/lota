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
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "../src/agent/agent_internal.h"

static uint32_t tpm_ascii4(char a, char b, char c, char d)
{
	return ((uint32_t)(uint8_t)a << 24) | ((uint32_t)(uint8_t)b << 16) |
	       ((uint32_t)(uint8_t)c << 8) | (uint32_t)(uint8_t)d;
}

static int mock_prop_reader_swtpm(struct tpm_context *ctx, TPM2_PT prop,
				  uint32_t *out_val)
{
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
	do {                                                                   \
		tests_run++;                                                   \
		printf("  [%2d] %-55s ", tests_run, name);                     \
	} while (0)

#define PASS()                                                                 \
	do {                                                                   \
		tests_passed++;                                                \
		printf("PASS\n");                                              \
	} while (0)

#define FAIL(msg)                                                              \
	do {                                                                   \
		printf("FAIL: %s\n", msg);                                     \
	} while (0)

static char tmp_dir[128];

static void setup_tmp_dir(void)
{
	snprintf(tmp_dir, sizeof(tmp_dir), "/tmp/lota_aik_%d", getpid());
	mkdir(tmp_dir, 0755);
}

static void cleanup_tmp_dir(void)
{
	char cmd[256];
	snprintf(cmd, sizeof(cmd), "rm -rf %s", tmp_dir);
	int ret = system(cmd);
	(void)ret;
}

/*
 * Build a tpm_context with metadata path pointing to tmp_dir.
 * Does NOT call tpm_init()
 */
static void make_ctx(struct tpm_context *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	/* pretend it is initialized so metadata functions proceed */
	ctx->initialized = true;
	snprintf(ctx->aik_meta_path, sizeof(ctx->aik_meta_path),
		 "%s/aik_meta.dat", tmp_dir);
}

static void test_metadata_save_load(void)
{
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

static void test_metadata_default_creation(void)
{
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

static void test_metadata_bad_magic(void)
{
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

static void test_metadata_bad_version(void)
{
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

static void test_aik_age(void)
{
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
		snprintf(buf, sizeof(buf), "expected ~7200, got %ld",
			 (long)age);
		FAIL(buf);
		return;
	}

	PASS();
}

static void test_aik_age_no_metadata(void)
{
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

static void test_needs_rotation_fresh(void)
{
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

static void test_needs_rotation_expired(void)
{
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

static void test_needs_rotation_default_ttl(void)
{
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

static void test_grace_period_inactive(void)
{
	struct tpm_context ctx;

	TEST("grace period inactive by default");
	make_ctx(&ctx);

	if (tpm_aik_in_grace_period(&ctx) != 0) {
		FAIL("should be 0 with no rotation");
		return;
	}

	PASS();
}

static void test_grace_period_active(void)
{
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

static void test_grace_period_expired(void)
{
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

static void test_get_prev_public_grace(void)
{
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

static void test_get_prev_public_no_grace(void)
{
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

static void test_save_creates_dirs(void)
{
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

static void test_metadata_truncated(void)
{
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

static void test_needs_rotation_boundary(void)
{
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

static void test_get_prev_public_small_buf(void)
{
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

static void test_provision_rejects_swtpm_vendor(void)
{
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

static void test_rc_success_is_zero(void)
{
	TEST("tpm_test_rc_to_errno: TSS2_RC_SUCCESS -> 0");

	if (tpm_test_rc_to_errno(TSS2_RC_SUCCESS) != 0) {
		FAIL("expected 0");
		return;
	}

	PASS();
}

static void test_rc_lockout_raw(void)
{
	TEST("tpm_test_rc_is_lockout: raw TPM2_RC_LOCKOUT");

	if (!tpm_test_rc_is_lockout(TPM2_RC_LOCKOUT)) {
		FAIL("LOCKOUT not detected");
		return;
	}
	if (tpm_test_rc_is_transient(TPM2_RC_LOCKOUT)) {
		FAIL("LOCKOUT must not be transient");
		return;
	}
	if (tpm_test_rc_to_errno(TPM2_RC_LOCKOUT) != -LOTA_ERR_TPM_LOCKED) {
		FAIL("expected -LOTA_ERR_TPM_LOCKED for LOCKOUT");
		return;
	}

	PASS();
}

static void test_rc_lockout_resmgr_layer(void)
{
	TPM2_RC wrapped = (TPM2_RC)(TSS2_RESMGR_TPM_RC_LAYER | TPM2_RC_LOCKOUT);

	TEST("tpm_test_rc_is_lockout: resmgr-wrapped LOCKOUT");

	if (!tpm_test_rc_is_lockout(wrapped)) {
		FAIL("layered LOCKOUT not detected");
		return;
	}
	if (tpm_test_rc_to_errno(wrapped) != -LOTA_ERR_TPM_LOCKED) {
		FAIL("expected -LOTA_ERR_TPM_LOCKED for layered LOCKOUT");
		return;
	}

	PASS();
}

static void test_rc_transient_codes(void)
{
	TPM2_RC transient[] = {
	    TPM2_RC_RETRY,	    TPM2_RC_YIELDED,
	    TPM2_RC_TESTING,	    TPM2_RC_NV_RATE,
	    TPM2_RC_NV_UNAVAILABLE, TPM2_RC_SESSION_MEMORY,
	    TPM2_RC_OBJECT_MEMORY,  TPM2_RC_MEMORY,
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

static void test_rc_auth_fail_with_session_bits(void)
{
	/* TPM2_RC_AUTH_FAIL is a format-1 code; the actual returned RC carries
	 * session/handle indices in bits 8-11. tpm_test_rc_to_errno must strip
	 * those scratch bits before mapping. */
	TPM2_RC auth_fail_with_session = (TPM2_RC)(TPM2_RC_AUTH_FAIL | 0x300);

	TEST("tpm_test_rc_to_errno: AUTH_FAIL -> LOTA_ERR_TPM_AUTH_FAIL");

	if (tpm_test_rc_to_errno(auth_fail_with_session) !=
	    -LOTA_ERR_TPM_AUTH_FAIL) {
		FAIL("expected -LOTA_ERR_TPM_AUTH_FAIL");
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

static void test_rc_value_and_handle(void)
{
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

static void test_rc_tcti_layer(void)
{
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

static void test_lockout_flag_lifecycle(void)
{
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

/*
 * Boot-time self_hash buffer round-trip.
 *
 * The agent must pin /proc/self/exe SHA-256 once at startup (in
 * self_measure) and re-use the cached value for every outgoing
 * attestation report. tpm_get_self_hash is the read accessor; this
 * test exercises its contract directly so the build catches any
 * regression in self_hash_ready gating or buffer width.
 */
/*
 * tpm_strerror must produce a LOTA-specific string for our private
 * code and fall back to strerror() for any POSIX value. Both the
 * negative and absolute encoding of the value must yield the same
 * output because callers pass the raw return without normalising
 * the sign.
 */
static void test_tpm_strerror_maps_lota_private(void)
{
	TEST("tpm_strerror covers LOTA_ERR_TPM_LOCKED + POSIX fallback");

	const char *neg = tpm_strerror(-LOTA_ERR_TPM_LOCKED);
	const char *pos = tpm_strerror(LOTA_ERR_TPM_LOCKED);
	if (!neg || !pos) {
		FAIL("tpm_strerror returned NULL");
		return;
	}
	if (strstr(neg, "lockout") == NULL || strstr(pos, "lockout") == NULL) {
		FAIL("expected the description to mention the lockout");
		return;
	}

	const char *auth = tpm_strerror(-LOTA_ERR_TPM_AUTH_FAIL);
	if (!auth || strstr(auth, "DA") == NULL) {
		FAIL("AUTH_FAIL description must call out the DA-counter "
		     "implication");
		return;
	}

	/* POSIX value still routes through strerror */
	const char *einval = tpm_strerror(-EINVAL);
	const char *strerror_einval = strerror(EINVAL);
	if (!einval || !strerror_einval ||
	    strcmp(einval, strerror_einval) != 0) {
		FAIL("tpm_strerror should fall back to strerror for POSIX "
		     "values");
		return;
	}

	/* Zero must not return NULL nor confuse the caller */
	if (!tpm_strerror(0)) {
		FAIL("tpm_strerror(0) must not be NULL");
		return;
	}

	PASS();
}

static void fill_pattern(uint8_t *buf, size_t n, uint8_t seed)
{
	for (size_t i = 0; i < n; i++)
		buf[i] = (uint8_t)(seed ^ i);
}

/*
 * Clock-state save/load round-trip: every field that survives the
 * persistence layer must come back bit-identical so the tamper-
 * attribution logic in tpm_extend_boot_commitment compares against
 * the exact snapshot it wrote.
 */
static void test_clock_state_save_load_round_trip(void)
{
	struct tpm_context ctx;
	struct lota_clock_state in;
	struct lota_clock_state out;

	TEST("tpm_clock_state save -> load round-trips every field");
	make_ctx(&ctx);
	snprintf(ctx.clock_state_path, sizeof(ctx.clock_state_path),
		 "%s/clock_state.dat", tmp_dir);
	unlink(ctx.clock_state_path);

	memset(&in, 0, sizeof(in));
	in.reset_count = 0xCAFEBABEU;
	in.restart_count = 7;
	fill_pattern(in.pcr14, LOTA_HASH_SIZE, 0x42);
	fill_pattern(in.self_hash, LOTA_HASH_SIZE, 0xA5);
	in.saved_at = 1715000000;
	in.flags = LOTA_CLOCK_STATE_FLAG_INITRAMFS_LOCK;

	if (tpm_clock_state_save(&ctx, &in) != 0) {
		FAIL("save failed");
		return;
	}

	if (tpm_clock_state_load(&ctx, &out) != 0) {
		FAIL("load failed");
		return;
	}

	if (out.reset_count != in.reset_count ||
	    out.restart_count != in.restart_count ||
	    out.saved_at != in.saved_at || out.flags != in.flags) {
		FAIL("scalar field mismatch after round-trip");
		return;
	}
	if (memcmp(out.pcr14, in.pcr14, LOTA_HASH_SIZE) != 0) {
		FAIL("pcr14 bytes mismatch after round-trip");
		return;
	}
	if (memcmp(out.self_hash, in.self_hash, LOTA_HASH_SIZE) != 0) {
		FAIL("self_hash bytes mismatch after round-trip");
		return;
	}

	PASS();
}

/*
 * Older clock-state snapshots zero-filled the reserved tail. The
 * initramfs-lock flag now lives in the first byte of that tail, so
 * loading a zero-filled v1 record must preserve the legacy meaning:
 * no initramfs lock was observed on that boot.
 */
static void test_clock_state_legacy_reserved_maps_to_no_lock(void)
{
	struct tpm_context ctx;
	struct lota_clock_state legacy;
	struct lota_clock_state out;

	TEST("tpm_clock_state_load treats legacy reserved byte as no lock");
	make_ctx(&ctx);
	snprintf(ctx.clock_state_path, sizeof(ctx.clock_state_path),
		 "%s/legacy_clock_state.dat", tmp_dir);

	memset(&legacy, 0, sizeof(legacy));
	legacy.magic = TPM_CLOCK_STATE_MAGIC;
	legacy.version = TPM_CLOCK_STATE_VERSION;
	legacy.reset_count = 3;
	legacy.restart_count = 4;
	legacy.saved_at = 1715000001;

	int fd = open(ctx.clock_state_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0) {
		FAIL("cannot create legacy clock-state file");
		return;
	}
	{
		ssize_t w = write(fd, &legacy, sizeof(legacy));
		(void)w;
	}
	close(fd);

	if (tpm_clock_state_load(&ctx, &out) != 0) {
		FAIL("legacy-shaped clock-state load failed");
		return;
	}
	if (out.flags != 0) {
		FAIL("legacy reserved byte must load as flags=0");
		return;
	}

	PASS();
}

static void reference_initramfs_lock_digest(uint32_t reset_count,
					    uint32_t restart_count,
					    uint8_t out[LOTA_HASH_SIZE])
{
	static const char tag[] = "LOTA-PCR14-INITRAMFS-LOCK-v1";
	uint8_t counters[8];
	EVP_MD_CTX *md = EVP_MD_CTX_new();

	counters[0] = (uint8_t)(reset_count >> 24);
	counters[1] = (uint8_t)(reset_count >> 16);
	counters[2] = (uint8_t)(reset_count >> 8);
	counters[3] = (uint8_t)reset_count;
	counters[4] = (uint8_t)(restart_count >> 24);
	counters[5] = (uint8_t)(restart_count >> 16);
	counters[6] = (uint8_t)(restart_count >> 8);
	counters[7] = (uint8_t)restart_count;

	if (!md) {
		memset(out, 0, LOTA_HASH_SIZE);
		return;
	}
	if (EVP_DigestInit_ex(md, EVP_sha256(), NULL) != 1 ||
	    EVP_DigestUpdate(md, tag, sizeof(tag) - 1) != 1 ||
	    EVP_DigestUpdate(md, counters, sizeof(counters)) != 1 ||
	    EVP_DigestFinal_ex(md, out, NULL) != 1)
		memset(out, 0, LOTA_HASH_SIZE);
	EVP_MD_CTX_free(md);
}

/*
 * The agent's lock-digest helper mirrors the standalone initramfs
 * binary. Pin it against an independent OpenSSL construction so a
 * tag or endian drift is caught without needing a hardware TPM.
 */
static void test_initramfs_lock_digest_matches_reference(void)
{
	uint8_t got[LOTA_HASH_SIZE];
	uint8_t want[LOTA_HASH_SIZE];

	TEST("tpm_initramfs_lock_digest matches reference derivation");
	memset(got, 0, sizeof(got));
	memset(want, 0, sizeof(want));

	if (tpm_initramfs_lock_digest(0x01020304U, 0xA0B0C0D0U, got) != 0) {
		FAIL("digest helper failed");
		return;
	}
	reference_initramfs_lock_digest(0x01020304U, 0xA0B0C0D0U, want);
	if (memcmp(got, want, LOTA_HASH_SIZE) != 0) {
		FAIL("digest mismatch");
		return;
	}
	if (tpm_initramfs_lock_digest(1, 2, NULL) != -EINVAL) {
		FAIL("NULL output must be rejected");
		return;
	}

	PASS();
}

/*
 * Missing snapshot must surface as -ENOENT (non-fatal "first run"
 * signal) so the agent's attribution layer can degrade gracefully
 * instead of treating a fresh host as a tamper.
 */
static void test_clock_state_load_missing_is_enoent(void)
{
	struct tpm_context ctx;
	struct lota_clock_state out;

	TEST("tpm_clock_state_load reports -ENOENT on missing file");
	make_ctx(&ctx);
	snprintf(ctx.clock_state_path, sizeof(ctx.clock_state_path),
		 "%s/no_state.dat", tmp_dir);
	unlink(ctx.clock_state_path);

	int ret = tpm_clock_state_load(&ctx, &out);
	if (ret != -ENOENT) {
		FAIL("expected -ENOENT, got different errno");
		return;
	}
	PASS();
}

/*
 * Corrupted file (wrong magic / truncated) must be rejected with
 * -EINVAL so a tampered or partial state cannot pose as a valid
 * snapshot.
 */
static void test_clock_state_load_rejects_corrupt(void)
{
	struct tpm_context ctx;
	struct lota_clock_state out;

	TEST("tpm_clock_state_load rejects bad magic + truncated record");
	make_ctx(&ctx);
	snprintf(ctx.clock_state_path, sizeof(ctx.clock_state_path),
		 "%s/bad_state.dat", tmp_dir);

	/* truncated: zero-byte file */
	int fd = open(ctx.clock_state_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0) {
		FAIL("cannot create truncated test file");
		return;
	}
	close(fd);
	if (tpm_clock_state_load(&ctx, &out) != -EINVAL) {
		FAIL("zero-byte file should produce -EINVAL");
		return;
	}

	/* bad magic */
	struct lota_clock_state bad;
	memset(&bad, 0, sizeof(bad));
	bad.magic = 0xDEADBEEFU;
	bad.version = TPM_CLOCK_STATE_VERSION;
	fd = open(ctx.clock_state_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0) {
		FAIL("cannot create bad-magic test file");
		return;
	}
	{
		ssize_t w = write(fd, &bad, sizeof(bad));
		(void)w;
	}
	close(fd);
	if (tpm_clock_state_load(&ctx, &out) != -EINVAL) {
		FAIL("bad magic should produce -EINVAL");
		return;
	}

	/* bad version */
	bad.magic = TPM_CLOCK_STATE_MAGIC;
	bad.version = 99;
	fd = open(ctx.clock_state_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0) {
		FAIL("cannot create bad-version test file");
		return;
	}
	{
		ssize_t w = write(fd, &bad, sizeof(bad));
		(void)w;
	}
	close(fd);
	if (tpm_clock_state_load(&ctx, &out) != -EINVAL) {
		FAIL("bad version should produce -EINVAL");
		return;
	}

	PASS();
}

static void test_self_hash_pin_round_trip(void)
{
	struct tpm_context ctx;
	uint8_t out[LOTA_HASH_SIZE];
	int ret;

	TEST(
	    "tpm_get_self_hash gates on self_hash_ready and round-trips bytes");
	make_ctx(&ctx);

	ret = tpm_get_self_hash(&ctx, out);
	if (ret != -ENODATA) {
		FAIL("expected -ENODATA before self_measure() captured a hash");
		return;
	}

	for (size_t i = 0; i < LOTA_HASH_SIZE; i++)
		ctx.self_hash[i] = (uint8_t)(0xA0 ^ i);
	ctx.self_hash_ready = true;

	memset(out, 0, sizeof(out));
	ret = tpm_get_self_hash(&ctx, out);
	if (ret != 0) {
		FAIL("expected success after self_hash_ready was set");
		return;
	}
	if (memcmp(out, ctx.self_hash, LOTA_HASH_SIZE) != 0) {
		FAIL("returned bytes diverged from cached self_hash");
		return;
	}

	ret = tpm_get_self_hash(NULL, out);
	if (ret != -EINVAL) {
		FAIL("NULL ctx must produce -EINVAL");
		return;
	}
	ret = tpm_get_self_hash(&ctx, NULL);
	if (ret != -EINVAL) {
		FAIL("NULL out must produce -EINVAL");
		return;
	}

	PASS();
}

/*
 * Thunk state for the tpm_call_with_backoff regression test. The thunk
 * mimics libtss2: it overwrites *slot with a heap allocation that
 * Esys_Free() (== free()) can release, returns TPM2_RC_RETRY for the
 * configured number of attempts, and then succeeds. Between calls the
 * helper MUST have zeroed *slot - any non-NULL observation indicates
 * the leak the patch is meant to prevent.
 */
struct backoff_thunk_state {
	int calls;
	int fail_attempts;
	int saw_dirty_slot;
	void **slot;
};

static TSS2_RC backoff_test_thunk(void *u)
{
	struct backoff_thunk_state *s = u;
	if (*s->slot != NULL)
		s->saw_dirty_slot = 1;
	*s->slot = malloc(64);
	if (!*s->slot)
		return TSS2_BASE_RC_GENERAL_FAILURE;
	s->calls++;
	if (s->calls <= s->fail_attempts)
		return TPM2_RC_RETRY;
	return TSS2_RC_SUCCESS;
}

/*
 * Verify that tpm_call_with_backoff:
 *   - frees the previous allocation before retry (slot observed NULL
 *     on every thunk entry);
 *   - performs at most TPM_RETRY_MAX_ATTEMPTS+1 thunk calls before
 *     bailing;
 *   - returns 0 and the last successful TSS2_RC when the thunk
 *     eventually succeeds.
 */
static void test_call_with_backoff_no_leak_on_retry(void)
{
	TEST("tpm_call_with_backoff frees output between transient retries");
	void *slot = NULL;
	struct backoff_thunk_state state = {
	    .calls = 0,
	    .fail_attempts = 3, /* succeed on call #4 */
	    .saw_dirty_slot = 0,
	    .slot = &slot,
	};
	void **slots[1] = {&slot};
	uint32_t rc = 0;
	int ret = tpm_test_call_with_backoff_array(NULL, backoff_test_thunk,
						   &state, &rc, slots, 1);

	if (ret != 0) {
		FAIL("expected 0 on eventual success");
		free(slot);
		return;
	}
	if (rc != TSS2_RC_SUCCESS) {
		FAIL("expected last rc == TSS2_RC_SUCCESS");
		free(slot);
		return;
	}
	if (state.saw_dirty_slot != 0) {
		FAIL("helper failed to zero slot between attempts (leak)");
		free(slot);
		return;
	}
	if (state.calls != state.fail_attempts + 1) {
		FAIL("thunk call count diverged from fail_attempts+1");
		free(slot);
		return;
	}
	if (slot == NULL) {
		FAIL("successful attempt must leave the slot populated");
		return;
	}

	/* successful allocation owns one heap block; release it before exit */
	free(slot);
	PASS();
}

/*
 * Total wall-time spent inside tpm_call_with_backoff() must stay
 * under TPM_RETRY_BUDGET_MS (2000 ms) so a single TPM call cannot
 * monopolise the systemd watchdog window. The test forces the
 * helper to take the maximum number of geometric backoff steps and
 * checks the wall-clock duration against a hard ceiling that is
 * comfortably below the configured WatchdogSec=60s in
 * systemd/lota-agent.service.
 */
static void test_call_with_backoff_respects_wallclock_budget(void)
{
	TEST("tpm_call_with_backoff cumulative sleep stays under watchdog "
	     "budget");
	void *slot = NULL;
	struct backoff_thunk_state state = {
	    .calls = 0,
	    .fail_attempts = 100,
	    .saw_dirty_slot = 0,
	    .slot = &slot,
	};
	void **slots[1] = {&slot};
	uint32_t rc = 0;

	struct timespec t0, t1;
	clock_gettime(CLOCK_MONOTONIC, &t0);
	int ret = tpm_test_call_with_backoff_array(NULL, backoff_test_thunk,
						   &state, &rc, slots, 1);
	clock_gettime(CLOCK_MONOTONIC, &t1);

	if (ret == 0) {
		FAIL("expected non-zero return on retry exhaustion");
		free(slot);
		return;
	}

	int64_t elapsed_ns = (int64_t)(t1.tv_sec - t0.tv_sec) * 1000000000LL +
			     ((int64_t)t1.tv_nsec - (int64_t)t0.tv_nsec);
	uint64_t elapsed_ms =
	    elapsed_ns < 0 ? 0 : (uint64_t)(elapsed_ns / 1000000);

	/*
	 * Budget is 2000 ms inside tpm.c. Allow a generous 500 ms slack
	 * for the final RETRY observation that bails (next_ms would have
	 * exceeded the budget) plus scheduling jitter on busy CI hosts.
	 * Crossing 2500 ms means the budget guard is broken.
	 */
	if (elapsed_ms >= 2500) {
		char buf[96];
		snprintf(buf, sizeof(buf),
			 "wall time %llu ms exceeded budget+slack",
			 (unsigned long long)elapsed_ms);
		FAIL(buf);
		free(slot);
		return;
	}
	free(slot);
	PASS();
}

/*
 * Verify that the helper gives up after TPM_RETRY_MAX_ATTEMPTS
 * transient observations without leaking. We set fail_attempts well
 * above the retry budget so the loop exhausts itself, then assert
 * that:
 *   - the helper returns a non-zero errno (mapped from TPM2_RC_RETRY,
 *     which decodes to -EAGAIN through tss2_rc_to_errno);
 *   - the slot was zeroed before every thunk call, including the
 *     final one (no dirty observations);
 *   - the slot holds the allocation from the final failing attempt
 *     and is therefore caller-owned; the test frees it.
 */
static void test_call_with_backoff_gives_up_without_leak(void)
{
	TEST("tpm_call_with_backoff exhausts retry budget without leaking");
	void *slot = NULL;
	struct backoff_thunk_state state = {
	    .calls = 0,
	    .fail_attempts = 100, /* much larger than TPM_RETRY_MAX_ATTEMPTS */
	    .saw_dirty_slot = 0,
	    .slot = &slot,
	};
	void **slots[1] = {&slot};
	uint32_t rc = 0;
	int ret = tpm_test_call_with_backoff_array(NULL, backoff_test_thunk,
						   &state, &rc, slots, 1);

	if (ret == 0) {
		FAIL("expected error after retry exhaustion");
		free(slot);
		return;
	}
	if (state.saw_dirty_slot != 0) {
		FAIL("helper failed to zero slot between attempts (leak)");
		free(slot);
		return;
	}
	if (state.calls < 2) {
		FAIL("helper bailed before exercising the retry path");
		free(slot);
		return;
	}
	if (slot == NULL) {
		FAIL("last failing attempt must leave the slot populated");
		return;
	}
	free(slot);
	PASS();
}

int main(void)
{
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
	test_self_hash_pin_round_trip();
	test_tpm_strerror_maps_lota_private();
	test_clock_state_save_load_round_trip();
	test_clock_state_legacy_reserved_maps_to_no_lock();
	test_initramfs_lock_digest_matches_reference();
	test_clock_state_load_missing_is_enoent();
	test_clock_state_load_rejects_corrupt();
	test_call_with_backoff_no_leak_on_retry();
	test_call_with_backoff_gives_up_without_leak();
	test_call_with_backoff_respects_wallclock_budget();

	cleanup_tmp_dir();

	printf("\n  Result: %d/%d passed\n\n", tests_passed, tests_run);
	return (tests_passed == tests_run) ? 0 : 1;
}
