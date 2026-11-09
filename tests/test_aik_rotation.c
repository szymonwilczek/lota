/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for the AIK record and lifecycle (tpm.h / tpm.c).
 *
 * These tests exercise the metadata persistence WITHOUT requiring
 * a real TPM. The heavy TPM call paths (EvictControl, CreatePrimary)
 * are not invoked here! -- those are integration-tested via
 * --test-tpm on a real machine.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <openssl/types.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <tss2/tss2_common.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tpm2_types.h>

#include "test.h"
#include "../src/agent/agent_internal.h" // IWYU pragma: keep (defines LOTA_TPM_TESTING)
#include "../src/agent/quote.h"
#include "lota.h"

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

/*
 * The record says how the key it describes was derived, and that answer
 * decides whether the daemon will attest with the key at all.
 * A field the writer forgets is not a missing feature here: every byte
 * of the struct reaches the disk, so an unassigned one reads back as
 * a derivation nobody chose.
 */
static void test_metadata_key_derivation_round_trip(void)
{
	struct tpm_context ctx;
	struct tpm_context ctx2;

	TEST("the key-derivation marker survives save -> load");
	make_ctx(&ctx);
	make_ctx(&ctx2);

	ctx.aik_meta.magic = TPM_AIK_META_MAGIC;
	ctx.aik_meta.version = TPM_AIK_META_VERSION;
	ctx.aik_meta.key_derivation = TPM_AIK_KEY_DERIVATION_PER_PUBLISHER;
	ctx.aik_meta_loaded = true;

	if (tpm_aik_save_metadata(&ctx) != 0) {
		FAIL("save returned error");
		return;
	}
	if (tpm_aik_load_metadata(&ctx2) != 0) {
		FAIL("load returned error");
		return;
	}
	if (ctx2.aik_meta.key_derivation !=
	    TPM_AIK_KEY_DERIVATION_PER_PUBLISHER) {
		FAIL("the marker did not survive the round-trip");
		return;
	}

	/* and a key with no publisher stays marked as such */
	snprintf(ctx2.aik_profile_id, sizeof(ctx2.aik_profile_id), "%s", "");
	if (tpm_aik_key_is_shared(&ctx2)) {
		FAIL("a host with no publisher was called shared");
		return;
	}
	PASS();
}

/*
 * A publisher enrolling for the first time has no record, and reading one
 * that is not there must not invent an answer about a key that does not exist.
 * The shared derivation belongs to keys created before publishers had keys of
 * their own; a zeroed struct is not evidence of one, and the enrollment path
 * prints "replacing the key this publisher shares" when it believes it.
 */
static void test_absent_metadata_claims_nothing(void)
{
	char path[512];
	struct tpm_context ctx;
	struct stat st;

	TEST("a key that does not exist yet is not called shared");
	make_ctx(&ctx);
	snprintf(path, sizeof(path), "%s", ctx.aik_meta_path);
	unlink(path);
	snprintf(
		ctx.aik_profile_id, sizeof(ctx.aik_profile_id), "%s",
		"0d96137b233ee2743da7d4a676b8734b51035598a0bf2a429c805b730ee22a43");

	if (tpm_aik_load_metadata(&ctx) != 0) {
		FAIL("load of an absent record returned error");
		return;
	}

	if (tpm_aik_key_is_shared(&ctx)) {
		FAIL("a publisher with no key was called shared");
		return;
	}

	if (stat(path, &st) == 0) {
		FAIL("reading an absent record wrote one");
		return;
	}

	PASS();
}

/*
 * The other half: a host upgraded from a build where every publisher used
 * one key still has that record, and it still has to mean what it says,
 * or the enrollment path stops replacing a key it must replace.
 */
static void test_recorded_shared_key_still_reads_shared(void)
{
	struct tpm_context ctx;
	struct tpm_context ctx2;

	TEST("a recorded shared key still reads as shared");
	make_ctx(&ctx);
	make_ctx(&ctx2);

	ctx.aik_meta.magic = TPM_AIK_META_MAGIC;
	ctx.aik_meta.version = TPM_AIK_META_VERSION;
	ctx.aik_meta.key_derivation = TPM_AIK_KEY_DERIVATION_SHARED;
	ctx.aik_meta_loaded = true;

	if (tpm_aik_save_metadata(&ctx) != 0) {
		FAIL("save returned error");
		return;
	}

	snprintf(
		ctx2.aik_profile_id, sizeof(ctx2.aik_profile_id), "%s",
		"0d96137b233ee2743da7d4a676b8734b51035598a0bf2a429c805b730ee22a43");
	if (tpm_aik_load_metadata(&ctx2) != 0) {
		FAIL("load returned error");
		return;
	}

	if (!tpm_aik_key_is_shared(&ctx2)) {
		FAIL("a recorded shared key stopped reading as shared");
		return;
	}

	PASS();
}

/*
 * A cleared TPM keeps none of the keys and the profile directory keeps all of
 * the files, so the handle, the consent and the certificate outlive the key
 * the certificate names.
 * Provisioning then mints a replacement at the recorded handle, the certificate
 * binds a key the TPM no longer holds, and every round is refused until
 * the publisher re-enrolls.
 *
 * After a TPM2_Clear through the firmware's PPI, all four publishers came back
 * with certificates whose SPKI did not match the key at their handle,
 * four out of four, while the agent logged "AIK ready, signed tokens enabled".
 *
 * A first enrollment has no key and no certificate, and must not be confused
 * with this.
 */
static void test_provisioning_names_an_orphaned_cert(void)
{
	TEST("a replacement key that orphans a stored certificate is named");

	if (tpm_aik_provisioning_orphans_cert(0, true, -EKEYREJECTED) != true) {
		FAIL("a certificate naming another key was not named");
		return;
	}

	if (tpm_aik_provisioning_orphans_cert(0, true, 0) != false) {
		FAIL("a key that came back matching was called orphaned");
		return;
	}

	if (tpm_aik_provisioning_orphans_cert(0, true, -ENOENT) != false) {
		FAIL("an unreadable certificate was called orphaned");
		return;
	}

	if (tpm_aik_provisioning_orphans_cert(0, false, 0) != false) {
		FAIL("a first enrollment was called an orphaned certificate");
		return;
	}

	if (tpm_aik_provisioning_orphans_cert(1, true, -EKEYREJECTED) !=
	    false) {
		FAIL("a key that is there was called missing");
		return;
	}

	PASS();
}

/*
 * A record is not a key.
 * An upgraded host carries a record saying shared in every profile an older
 * build ever read, including profiles that never enrolled, so the question
 * the enrollment path asks -- am I about to replace the key this publisher
 * shares -- has to be answered by the key, not by the file describing one.
 */
static void test_shared_replacement_needs_a_key(void)
{
	struct tpm_context ctx;

	TEST("replacing a shared key takes a key, not just a record");
	make_ctx(&ctx);
	snprintf(
		ctx.aik_profile_id, sizeof(ctx.aik_profile_id), "%s",
		"0d96137b233ee2743da7d4a676b8734b51035598a0bf2a429c805b730ee22a43");
	ctx.aik_meta.magic = TPM_AIK_META_MAGIC;
	ctx.aik_meta.version = TPM_AIK_META_VERSION;
	ctx.aik_meta.key_derivation = TPM_AIK_KEY_DERIVATION_SHARED;
	ctx.aik_meta_loaded = true;

	if (tpm_aik_replacing_shared_key(&ctx, 0)) {
		FAIL("a record with no key behind it was called a replacement");
		return;
	}

	if (!tpm_aik_replacing_shared_key(&ctx, 1)) {
		FAIL("a shared key that is there was not called a replacement");
		return;
	}

	ctx.aik_meta.key_derivation = TPM_AIK_KEY_DERIVATION_PER_PUBLISHER;
	if (tpm_aik_replacing_shared_key(&ctx, 1)) {
		FAIL("a per-publisher key was called a shared one");
		return;
	}

	PASS();
}

/* Bytes 8-31 are written zero and read past: key_derivation sits at 32 */
static void test_metadata_unused_bytes_are_ignored(void)
{
	struct tpm_context ctx;
	uint8_t raw[sizeof(struct aik_metadata)];
	uint32_t word;
	int fd, ret;

	TEST("load reads key_derivation past the unused bytes");
	make_ctx(&ctx);

	memset(raw, 0, sizeof(raw));
	word = htole32(TPM_AIK_META_MAGIC);
	memcpy(raw, &word, sizeof(word));
	word = htole32(TPM_AIK_META_VERSION);
	memcpy(raw + 4, &word, sizeof(word));
	memset(raw + 8, 0x5A, 24);
	raw[32] = TPM_AIK_KEY_DERIVATION_SHARED;

	fd = open(ctx.aik_meta_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0) {
		FAIL("cannot create test file");
		return;
	}
	{
		ssize_t wr_ = write(fd, raw, sizeof(raw));
		(void)wr_;
	}
	close(fd);

	ret = tpm_aik_load_metadata(&ctx);
	if (ret != 0) {
		FAIL("load returned error");
		return;
	}
	if (ctx.aik_meta.key_derivation != TPM_AIK_KEY_DERIVATION_SHARED) {
		FAIL("key_derivation read from the wrong offset");
		return;
	}

	ctx.aik_meta.key_derivation = TPM_AIK_KEY_DERIVATION_PER_PUBLISHER;
	if (tpm_aik_save_metadata(&ctx) != 0) {
		FAIL("save returned error");
		return;
	}
	fd = open(ctx.aik_meta_path, O_RDONLY);
	if (fd < 0 || read(fd, raw, sizeof(raw)) != (ssize_t)sizeof(raw)) {
		if (fd >= 0)
			close(fd);
		FAIL("cannot read the record back");
		return;
	}
	close(fd);
	for (size_t i = 8; i < 32; i++) {
		if (raw[i] != 0) {
			FAIL("save wrote a nonzero unused byte");
			return;
		}
	}
	if (raw[32] != TPM_AIK_KEY_DERIVATION_PER_PUBLISHER) {
		FAIL("save moved key_derivation");
		return;
	}

	PASS();
}

static void test_metadata_default_creation(void)
{
	struct tpm_context ctx;
	int ret;

	TEST("load fills defaults without writing a record");
	make_ctx(&ctx);
	/* make sure file does not exist */
	unlink(ctx.aik_meta_path);

	ret = tpm_aik_load_metadata(&ctx);

	if (ret != 0) {
		FAIL("load returned error");
		return;
	}

	if (ctx.aik_meta.magic != TPM_AIK_META_MAGIC) {
		FAIL("wrong magic");
		return;
	}
	if (ctx.aik_meta.key_derivation !=
	    TPM_AIK_KEY_DERIVATION_PER_PUBLISHER) {
		FAIL("default key_derivation should be per publisher");
		return;
	}

	/*
	 * Nothing is written.
	 * The defaults describe a key that does not exist;
	 * the record is written when the key is created.
	 */
	if (access(ctx.aik_meta_path, F_OK) == 0) {
		FAIL("metadata file created for a key that does not exist");
		return;
	}

	PASS();
}

static void test_new_key_metadata_persisted(void)
{
	struct tpm_context ctx;
	struct tpm_context ctx2;
	int ret;

	TEST("new AIK metadata is persisted");
	make_ctx(&ctx);
	make_ctx(&ctx2);
	unlink(ctx.aik_meta_path);

	ret = tpm_test_save_new_key_metadata(&ctx);

	if (ret != 0) {
		FAIL("save new-key metadata returned error");
		return;
	}

	if (access(ctx.aik_meta_path, F_OK) != 0) {
		FAIL("metadata file not created");
		return;
	}

	ret = tpm_aik_load_metadata(&ctx2);
	if (ret != 0) {
		FAIL("reload returned error");
		return;
	}

	if (ctx2.aik_meta.magic != TPM_AIK_META_MAGIC ||
	    ctx2.aik_meta.version != TPM_AIK_META_VERSION ||
	    ctx2.aik_meta.key_derivation != TPM_AIK_KEY_DERIVATION_SHARED) {
		FAIL("metadata defaults mismatch");
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
		TPM2_RC_RETRY,		TPM2_RC_YIELDED,
		TPM2_RC_TESTING,	TPM2_RC_NV_RATE,
		TPM2_RC_NV_UNAVAILABLE, TPM2_RC_SESSION_MEMORY,
		TPM2_RC_OBJECT_MEMORY,	TPM2_RC_MEMORY,
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

/*
 * A TPM with no room for another persistent object is a full machine,
 * not a broken one.
 * Reported as -EIO it printed "Input/output error" to a player adding
 * a publisher, which names failing hardware and nothing they can act on.
 */
static void test_rc_nv_space(void)
{
	TEST("tpm_test_rc_to_errno: NV_SPACE -> ENOSPC");

	if (tpm_test_rc_to_errno(TPM2_RC_NV_SPACE) != -ENOSPC) {
		FAIL("NV_SPACE != -ENOSPC");
		return;
	}
	if (tpm_test_rc_is_transient(TPM2_RC_NV_SPACE)) {
		FAIL("a full TPM must not be retried as transient");
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

static uint32_t g_mock_permanent;

static int mock_prop_reader_permanent(struct tpm_context *ctx, TPM2_PT prop,
				      uint32_t *out_val)
{
	(void)ctx;
	if (prop != TPM2_PT_PERMANENT || !out_val)
		return -EINVAL;
	*out_val = g_mock_permanent;
	return 0;
}

static TSS2_RC success_thunk(void *u)
{
	(void)u;
	return TSS2_RC_SUCCESS;
}

static void test_lockout_survives_auth_free_success(void)
{
	struct tpm_context ctx;
	int ret;

	TEST("success keeps the lockout flag while inLockout is set");
	make_ctx(&ctx);
	ctx.lockout_active = true;
	ctx.lockout_first_seen = 1000;

	tpm_test_set_prop_reader(mock_prop_reader_permanent);
	g_mock_permanent = TPMA_PERMANENT_INLOCKOUT;
	ret = tpm_test_call_with_backoff_array(&ctx, success_thunk, NULL, NULL,
					       NULL, 0);
	if (ret != 0 || !tpm_is_locked_out(&ctx) ||
	    ctx.lockout_first_seen != 1000) {
		tpm_test_reset_prop_reader();
		FAIL("flag cleared while the TPM reports inLockout");
		return;
	}

	g_mock_permanent = 0;
	ret = tpm_test_call_with_backoff_array(&ctx, success_thunk, NULL, NULL,
					       NULL, 0);
	tpm_test_reset_prop_reader();
	if (ret != 0 || tpm_is_locked_out(&ctx) ||
	    ctx.lockout_first_seen != 0) {
		FAIL("flag kept after the TPM left lockout");
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
	TEST("tpm_strerror names every LOTA code, POSIX falls through");

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
	if (!auth || strstr(auth, "authorization") == NULL ||
	    strstr(auth, "DA") != NULL) {
		FAIL("AUTH_FAIL covers codes the DA counter ignores");
		return;
	}

	/* an EK policy session fails with the same code as a PCR unseal */
	const char *policy = tpm_strerror(-LOTA_ERR_TPM_POLICY_FAIL);
	if (!policy || strstr(policy, "policy") == NULL ||
	    strstr(policy, "boot") != NULL) {
		FAIL("POLICY_FAIL description names a boot state");
		return;
	}
	if (strcmp(policy, strerror(LOTA_ERR_TPM_POLICY_FAIL)) == 0) {
		FAIL("POLICY_FAIL is left to strerror");
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

static void reference_initramfs_lock_digest(uint8_t out[LOTA_HASH_SIZE])
{
	static const char tag[] = "LOTA-PCR14-INITRAMFS-LOCK-v1";
	EVP_MD_CTX *md = EVP_MD_CTX_new();

	if (!md) {
		memset(out, 0, LOTA_HASH_SIZE);
		return;
	}
	if (EVP_DigestInit_ex(md, EVP_sha256(), NULL) != 1 ||
	    EVP_DigestUpdate(md, tag, sizeof(tag) - 1) != 1 ||
	    EVP_DigestFinal_ex(md, out, NULL) != 1)
		memset(out, 0, LOTA_HASH_SIZE);
	EVP_MD_CTX_free(md);
}

/*
 * The agent's lock-digest helper mirrors the standalone initramfs
 * binary. Pin it against an independent OpenSSL construction so a
 * tag drift is caught without needing a hardware TPM.
 */
static void test_initramfs_lock_digest_matches_reference(void)
{
	uint8_t got[LOTA_HASH_SIZE];
	uint8_t want[LOTA_HASH_SIZE];

	TEST("tpm_initramfs_lock_digest matches reference derivation");
	memset(got, 0, sizeof(got));
	memset(want, 0, sizeof(want));

	if (tpm_initramfs_lock_digest(got) != 0) {
		FAIL("digest helper failed");
		return;
	}
	reference_initramfs_lock_digest(want);
	if (memcmp(got, want, LOTA_HASH_SIZE) != 0) {
		FAIL("digest mismatch");
		return;
	}
	if (tpm_initramfs_lock_digest(NULL) != -EINVAL) {
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

	TEST("tpm_get_self_hash gates on self_hash_ready and round-trips bytes");
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
	void **slots[1] = { &slot };
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
	void **slots[1] = { &slot };
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
	uint64_t elapsed_ms = elapsed_ns < 0 ? 0 :
					       (uint64_t)(elapsed_ns / 1000000);

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
		.fail_attempts =
			100, /* much larger than TPM_RETRY_MAX_ATTEMPTS */
		.saw_dirty_slot = 0,
		.slot = &slot,
	};
	void **slots[1] = { &slot };
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

/*
 * Each publisher is promised its own attestation key.
 * A TPM primary is derived from the hierarchy seed and the creation template,
 * so the template is the only place that promise can be kept:
 * two profiles whose template is identical get one key at two handles,
 * which is what a publisher can see by comparing the certificate it already holds.
 */
static void test_aik_unique_separates_publishers(void)
{
	const char *id_a =
		"ea34ead0000000000000000000000000000000000000000000000000"
		"3ceacdd1";
	const char *id_b =
		"1feba674000000000000000000000000000000000000000000000000"
		"3ceacdd1";
	uint8_t a[LOTA_HASH_SIZE];
	uint8_t b[LOTA_HASH_SIZE];
	uint8_t again[LOTA_HASH_SIZE];
	uint16_t len_a = 0, len_b = 0, len_again = 0;

	TEST("the AIK creation input differs per publisher profile");

	if (tpm_aik_profile_unique(id_a, a, &len_a) != 0 ||
	    tpm_aik_profile_unique(id_b, b, &len_b) != 0) {
		FAIL("the helper refused a well-formed profile identity");
		return;
	}

	if (len_a == 0 || len_b == 0) {
		FAIL("a bound publisher contributes nothing to the key");
		return;
	}
	if (len_a == len_b && memcmp(a, b, len_a) == 0) {
		FAIL("two publishers share one creation input, so one key");
		return;
	}

	/* re-enrolment has to reproduce the same key, not a new one */
	if (tpm_aik_profile_unique(id_a, again, &len_again) != 0 ||
	    len_again != len_a || memcmp(a, again, len_a) != 0) {
		FAIL("the same publisher did not reproduce its own input");
		return;
	}

	/* a host with no publisher keeps the profile-less derivation */
	uint8_t none[LOTA_HASH_SIZE];
	uint16_t len_none = 1;

	if (tpm_aik_profile_unique("", none, &len_none) != 0 || len_none != 0) {
		FAIL("a host with no publisher must contribute nothing");
		return;
	}

	static const char *const bad[] = { "1g", " 1", "+1", "-1" };
	for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		char id[LOTA_PROFILE_ID_LEN];

		snprintf(id, sizeof(id), "%s", id_a);
		memcpy(id + 6, bad[i], 2);
		if (tpm_aik_profile_unique(id, again, &len_again) != -EINVAL) {
			FAIL("a profile id with a non-hex byte was read");
			return;
		}
	}
	PASS();
}

static void test_stale_object_record_is_told_from_a_tpm_refusal(void)
{
	TEST("a poisoned session is told from a TPM refusal");

	if (!tpm_test_rc_is_stale_object_record(TSS2_ESYS_RC_GENERAL_FAILURE)) {
		FAIL("the session ESYS refuses to reuse was not recognised");
		return;
	}

	if (tpm_test_rc_is_stale_object_record(TPM2_RC_HANDLE)) {
		FAIL("an empty handle would have reopened the session");
		return;
	}

	if (tpm_test_rc_is_stale_object_record(TSS2_RC_SUCCESS) ||
	    tpm_test_rc_is_stale_object_record(TPM2_RC_LOCKOUT) ||
	    tpm_test_rc_is_stale_object_record(TSS2_TCTI_RC_TRY_AGAIN)) {
		FAIL("success, lockout or a retry would have reopened it");
		return;
	}
	PASS();
}

static void test_binding_does_not_survive_a_reused_handle(void)
{
	const char *forgotten =
		"01f58f72000000000000000000000000000000000000000000000000"
		"3ceacdd1";
	const char *next =
		"eb69693e000000000000000000000000000000000000000000000000"
		"3ceacdd1";

	TEST("a reused handle number does not carry the old key's cache");

	/* Same publisher, same handle: the cached key is still that key */
	if (!tpm_test_aik_binding_survives(forgotten, 0x81010017, forgotten,
					   0x81010017)) {
		FAIL("re-binding one publisher dropped its own key");
		return;
	}

	/*
	 * The shape this was driven on: a publisher is forgotten, the next one
	 * provisioned takes the number it freed, and the numbers match while
	 * the keys do not.
	 */
	if (tpm_test_aik_binding_survives(forgotten, 0x81010017, next,
					  0x81010017)) {
		FAIL("two publishers at one number were read as one key");
		return;
	}

	if (tpm_test_aik_binding_survives(forgotten, 0x81010017, forgotten,
					  0x81010010)) {
		FAIL("a moved handle kept the cache of the old one");
		return;
	}

	/* Nothing bound yet is nothing to carry across */
	if (tpm_test_aik_binding_survives("", 0, next, 0x81010010)) {
		FAIL("an unbound context claimed to hold this key");
		return;
	}
	PASS();
}

static void test_object_change_is_read_from_the_name(void)
{
	const uint8_t name_a[] = { 0x00, 0x0b, 0x11, 0x22, 0x33 };
	const uint8_t name_b[] = { 0x00, 0x0b, 0x11, 0x22, 0x34 };

	TEST("the AIK object is compared by Name, not by handle number");

	if (tpm_test_aik_object_changed(name_a, sizeof(name_a), name_a,
					sizeof(name_a))) {
		FAIL("the same object read as a different one");
		return;
	}

	if (!tpm_test_aik_object_changed(name_a, sizeof(name_a), name_b,
					 sizeof(name_b))) {
		FAIL("a different key at the same handle read as the same key");
		return;
	}

	if (!tpm_test_aik_object_changed(name_a, sizeof(name_a), name_a,
					 sizeof(name_a) - 1)) {
		FAIL("a shorter Name read as the same key");
		return;
	}

	/*
	 * The first look is what records the Name the rest are compared
	 * against, so nothing seen yet is not a change
	 */
	if (tpm_test_aik_object_changed(NULL, 0, name_a, sizeof(name_a))) {
		FAIL("the first look reported the key as replaced");
		return;
	}
	PASS();
}

/* A 24-PCR SHA-256 bank: PCR n reads n + 1 in every byte. */
static int g_pcr_read_calls;

TSS2_RC __wrap_Esys_PCR_Read(ESYS_CONTEXT *esys_ctx, ESYS_TR shandle1,
			     ESYS_TR shandle2, ESYS_TR shandle3,
			     const TPML_PCR_SELECTION *in, UINT32 *counter,
			     TPML_PCR_SELECTION **sel_out,
			     TPML_DIGEST **values_out);

TSS2_RC __wrap_Esys_PCR_Read(ESYS_CONTEXT *esys_ctx, ESYS_TR shandle1,
			     ESYS_TR shandle2, ESYS_TR shandle3,
			     const TPML_PCR_SELECTION *in, UINT32 *counter,
			     TPML_PCR_SELECTION **sel_out,
			     TPML_DIGEST **values_out)
{
	TPML_PCR_SELECTION *sel = calloc(1, sizeof(*sel));
	TPML_DIGEST *values = calloc(1, sizeof(*values));

	(void)esys_ctx;
	(void)shandle1;
	(void)shandle2;
	(void)shandle3;
	g_pcr_read_calls++;
	if (!sel || !values) {
		free(sel);
		free(values);
		return TSS2_ESYS_RC_MEMORY;
	}
	*counter = 1;
	sel->count = 1;
	sel->pcrSelections[0].hash = TPM2_ALG_SHA256;
	sel->pcrSelections[0].sizeofSelect = 3;
	for (uint32_t i = 0; i < 24 && values->count < 8; i++) {
		if (!(in->pcrSelections[0].pcrSelect[i / 8] & (1U << (i % 8))))
			continue;
		sel->pcrSelections[0].pcrSelect[i / 8] |= 1U << (i % 8);
		values->digests[values->count].size = LOTA_HASH_SIZE;
		memset(values->digests[values->count].buffer, (int)(i + 1),
		       LOTA_HASH_SIZE);
		values->count++;
	}
	*sel_out = sel;
	*values_out = values;
	return TSS2_RC_SUCCESS;
}

static void test_pcr_batch_reads_past_eight(void)
{
	static uint8_t values[LOTA_PCR_COUNT][LOTA_HASH_SIZE];
	struct tpm_context ctx;
	int ret;

	TEST("tpm_read_pcrs_batch reads every PCR of a 24-bit mask");
	make_ctx(&ctx);
	g_pcr_read_calls = 0;

	ret = tpm_read_pcrs_batch(&ctx, 0xFFFFFF, values);
	if (ret != 0) {
		FAIL("batch read failed");
		return;
	}
	for (uint32_t i = 0; i < LOTA_PCR_COUNT; i++) {
		if (values[i][0] != i + 1 ||
		    values[i][LOTA_HASH_SIZE - 1] != i + 1) {
			FAIL("a PCR past the first eight read zero");
			return;
		}
	}
	if (g_pcr_read_calls != 3) {
		FAIL("expected three TPM2_PCR_Read calls");
		return;
	}

	PASS();
}

static void test_refused_unseal_with_unmoved_pcrs_is_the_blob(void)
{
	uint8_t same[LOTA_HASH_SIZE];
	uint8_t moved[LOTA_HASH_SIZE];
	uint8_t value[LOTA_HASH_SIZE];
	struct tpm_context ctx;
	unsigned int len = 0;
	EVP_MD_CTX *md;
	int ok;

	TEST("a refused unseal with the seal-time PCRs is a rejected blob");
	make_ctx(&ctx);

	/* PCRs 0, 1 and 7 of the mocked bank */
	md = EVP_MD_CTX_new();
	ok = md && EVP_DigestInit_ex(md, EVP_sha256(), NULL) == 1;
	for (int i = 0; ok && i < 3; i++) {
		memset(value, i == 2 ? 8 : i + 1, sizeof(value));
		ok = EVP_DigestUpdate(md, value, sizeof(value)) == 1;
	}
	ok = ok && EVP_DigestFinal_ex(md, same, &len) == 1;
	EVP_MD_CTX_free(md);
	if (!ok || len != sizeof(same)) {
		FAIL("digest");
		return;
	}
	memcpy(moved, same, sizeof(moved));
	moved[0] ^= 1;

	if (tpm_test_seal_refusal_errno(&ctx, 0x83, same, TPM2_RC_INTEGRITY,
					-EIO) != -EBADMSG) {
		FAIL("an integrity refusal with unmoved PCRs");
		return;
	}
	if (tpm_test_seal_refusal_errno(&ctx, 0x83, same, TPM2_RC_POLICY_FAIL,
					-LOTA_ERR_TPM_POLICY_FAIL) !=
	    -EBADMSG) {
		FAIL("a policy refusal with unmoved PCRs");
		return;
	}
	if (tpm_test_seal_refusal_errno(&ctx, 0x83, moved, TPM2_RC_POLICY_FAIL,
					-LOTA_ERR_TPM_POLICY_FAIL) !=
	    -LOTA_ERR_TPM_POLICY_FAIL) {
		FAIL("moved PCRs read as a rejected blob");
		return;
	}
	if (tpm_test_seal_refusal_errno(&ctx, 0x83, same,
					TSS2_ESYS_RC_GENERAL_FAILURE,
					-EIO) != -EIO) {
		FAIL("a stack error read as a TPM refusal");
		return;
	}
	if (tpm_test_seal_refusal_errno(&ctx, 0x83, same, TPM2_RC_LOCKOUT,
					-LOTA_ERR_TPM_LOCKED) !=
	    -LOTA_ERR_TPM_LOCKED) {
		FAIL("a lockout read as a rejected blob");
		return;
	}
	PASS();
}

static void test_failed_bind_keeps_the_bound_publisher(void)
{
	static const char bound[] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
				    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
	static struct profile_paths paths;
	struct tpm_context ctx;
	int ret;

	TEST("a failed bind leaves the bound publisher's id in place");
	make_ctx(&ctx);
	snprintf(ctx.aik_profile_id, sizeof(ctx.aik_profile_id), "%s", bound);
	ctx.aik_handle = 0x81010016;

	memset(&paths, 0, sizeof(paths));
	memset(paths.id, 'b', LOTA_PROFILE_ID_LEN - 1);
	memset(paths.aik_meta, 'm', sizeof(ctx.aik_meta_path));

	ret = tpm_bind_profile(&ctx, &paths);
	if (ret != -ENAMETOOLONG) {
		FAIL("expected -ENAMETOOLONG");
		return;
	}
	if (strcmp(ctx.aik_profile_id, bound) != 0) {
		FAIL("the refused publisher's id stayed bound");
		return;
	}
	if (ctx.aik_handle != 0x81010016) {
		FAIL("the handle moved");
		return;
	}
	PASS();
}

static void test_reprovision_reads_the_record_first(void)
{
	struct tpm_context ctx;
	int ret;

	TEST("reprovision loads the record and refuses a shared key");
	make_ctx(&ctx);
	ctx.aik_meta.magic = TPM_AIK_META_MAGIC;
	ctx.aik_meta.version = TPM_AIK_META_VERSION;
	ctx.aik_meta.key_derivation = TPM_AIK_KEY_DERIVATION_SHARED;
	ctx.aik_meta_loaded = true;
	if (tpm_aik_save_metadata(&ctx) != 0) {
		FAIL("save returned error");
		return;
	}

	/* a bind leaves the record unloaded */
	memset(&ctx.aik_meta, 0, sizeof(ctx.aik_meta));
	ctx.aik_meta_loaded = false;
	memset(ctx.aik_profile_id, 'c', LOTA_PROFILE_ID_LEN - 1);

	ret = tpm_test_aik_check_shared_replace(&ctx);
	if (ret != -ENOTSUP) {
		FAIL("a shared key was let through");
		return;
	}
	if (!ctx.aik_meta_loaded ||
	    ctx.aik_meta.key_derivation != TPM_AIK_KEY_DERIVATION_SHARED) {
		FAIL("the record was not loaded");
		return;
	}

	tpm_aik_allow_shared_key_replace(&ctx, true);
	ret = tpm_test_aik_check_shared_replace(&ctx);
	tpm_aik_allow_shared_key_replace(&ctx, false);
	if (ret != 0) {
		FAIL("enrollment could not replace a shared key");
		return;
	}

	ctx.aik_meta.key_derivation = TPM_AIK_KEY_DERIVATION_PER_PUBLISHER;
	if (tpm_test_aik_check_shared_replace(&ctx) != 0) {
		FAIL("the publisher's own key was refused");
		return;
	}
	PASS();
}

/* The TPM lists the bound handle; opening it needs g_key_object */
static uint32_t g_listed_handle;
static int g_key_opens;
static ESYS_TR g_key_object;

TSS2_RC __wrap_Esys_GetCapability(ESYS_CONTEXT *esys_ctx, ESYS_TR shandle1,
				  ESYS_TR shandle2, ESYS_TR shandle3,
				  TPM2_CAP capability, UINT32 property,
				  UINT32 property_count, TPMI_YES_NO *more_data,
				  TPMS_CAPABILITY_DATA **capability_data);
TSS2_RC __wrap_Esys_TR_FromTPMPublic(ESYS_CONTEXT *esys_ctx, TPM2_HANDLE handle,
				     ESYS_TR shandle1, ESYS_TR shandle2,
				     ESYS_TR shandle3, ESYS_TR *object);

TSS2_RC __wrap_Esys_GetCapability(ESYS_CONTEXT *esys_ctx, ESYS_TR shandle1,
				  ESYS_TR shandle2, ESYS_TR shandle3,
				  TPM2_CAP capability, UINT32 property,
				  UINT32 property_count, TPMI_YES_NO *more_data,
				  TPMS_CAPABILITY_DATA **capability_data)
{
	TPMS_CAPABILITY_DATA *data = calloc(1, sizeof(*data));

	(void)esys_ctx;
	(void)shandle1;
	(void)shandle2;
	(void)shandle3;
	(void)property;
	(void)property_count;
	if (!data)
		return TSS2_ESYS_RC_MEMORY;
	data->capability = capability;
	data->data.handles.count = 1;
	data->data.handles.handle[0] = g_listed_handle;
	if (more_data)
		*more_data = TPM2_NO;
	*capability_data = data;
	return TSS2_RC_SUCCESS;
}

TSS2_RC __wrap_Esys_TR_FromTPMPublic(ESYS_CONTEXT *esys_ctx, TPM2_HANDLE handle,
				     ESYS_TR shandle1, ESYS_TR shandle2,
				     ESYS_TR shandle3, ESYS_TR *object)
{
	(void)esys_ctx;
	(void)handle;
	(void)shandle1;
	(void)shandle2;
	(void)shandle3;
	g_key_opens++;
	if (!g_key_object)
		return TSS2_ESYS_RC_GENERAL_FAILURE;
	*object = g_key_object;
	return TSS2_RC_SUCCESS;
}

static void test_lost_auth_keeps_a_shared_key(void)
{
	static int session;
	char dir[192];
	struct tpm_context ctx;
	int ret;

	TEST("a lost auth record does not replace a shared key");
	snprintf(dir, sizeof(dir), "%s/lost_auth", tmp_dir);
	mkdir(dir, 0700);
	make_ctx(&ctx);
	snprintf(ctx.aik_meta_path, sizeof(ctx.aik_meta_path),
		 "%s/aik_meta.dat", dir);
	ctx.esys_ctx = (ESYS_CONTEXT *)&session;
	ctx.aik_handle = 0x81010016;
	g_listed_handle = ctx.aik_handle;
	g_key_opens = 0;
	memset(ctx.aik_profile_id, 'd', LOTA_PROFILE_ID_LEN - 1);
	ctx.aik_meta.magic = TPM_AIK_META_MAGIC;
	ctx.aik_meta.version = TPM_AIK_META_VERSION;
	ctx.aik_meta.key_derivation = TPM_AIK_KEY_DERIVATION_SHARED;
	ctx.aik_meta_loaded = true;

	ret = tpm_provision_aik(&ctx);

	if (ret != -ENOTSUP) {
		FAIL("expected -ENOTSUP");
		return;
	}
	if (g_key_opens != 0) {
		FAIL("provisioning went on to replace the key");
		return;
	}
	PASS();
}

static void test_reprovision_rewrites_a_missing_record(void)
{
	static int session;
	char dir[192];
	struct tpm_context ctx;
	int ret;

	TEST("a missing record does not block reprovision");
	snprintf(dir, sizeof(dir), "%s/missing_meta", tmp_dir);
	mkdir(dir, 0700);
	make_ctx(&ctx);
	snprintf(ctx.aik_meta_path, sizeof(ctx.aik_meta_path),
		 "%s/aik_meta.dat", dir);
	ctx.esys_ctx = (ESYS_CONTEXT *)&session;
	ctx.aik_handle = 0x81010016;
	g_listed_handle = ctx.aik_handle;
	g_key_opens = 0;
	memset(ctx.aik_profile_id, 'e', LOTA_PROFILE_ID_LEN - 1);

	ret = tpm_test_aik_check_shared_replace(&ctx);
	if (ret != 0) {
		char ebuf[64];
		snprintf(ebuf, sizeof(ebuf), "expected 0, got %d", ret);
		FAIL(ebuf);
		return;
	}
	if (ctx.aik_meta_loaded) {
		FAIL("a record was assumed");
		return;
	}
	PASS();
}

static void test_provision_ignores_the_vendor_string(void)
{
	static int session;
	struct tpm_context ctx;
	int ret;

	TEST("provisioning does not judge the vendor string");
	make_ctx(&ctx);
	ctx.esys_ctx = (ESYS_CONTEXT *)&session;
	ctx.aik_handle = 0x81010016;
	g_listed_handle = ctx.aik_handle;
	g_key_opens = 0;
	memset(ctx.aik_profile_id, 'd', LOTA_PROFILE_ID_LEN - 1);
	ctx.aik_meta.magic = TPM_AIK_META_MAGIC;
	ctx.aik_meta.version = TPM_AIK_META_VERSION;
	ctx.aik_meta.key_derivation = TPM_AIK_KEY_DERIVATION_SHARED;
	ctx.aik_meta_loaded = true;

	tpm_test_set_prop_reader(mock_prop_reader_swtpm);
	ret = tpm_provision_aik(&ctx);
	tpm_test_reset_prop_reader();

	if (ret != -ENOTSUP) {
		char ebuf[64];
		snprintf(ebuf, sizeof(ebuf), "expected -ENOTSUP, got %d", ret);
		FAIL(ebuf);
		return;
	}
	PASS();
}

static int g_esys_session;

void __wrap_Esys_Finalize(ESYS_CONTEXT **esys_ctx);
TSS2_RC __wrap_Esys_Initialize(ESYS_CONTEXT **esys_ctx, TSS2_TCTI_CONTEXT *tcti,
			       TSS2_ABI_VERSION *abi);

void __wrap_Esys_Finalize(ESYS_CONTEXT **esys_ctx)
{
	*esys_ctx = NULL;
}

TSS2_RC __wrap_Esys_Initialize(ESYS_CONTEXT **esys_ctx, TSS2_TCTI_CONTEXT *tcti,
			       TSS2_ABI_VERSION *abi)
{
	(void)tcti;
	(void)abi;
	*esys_ctx = (ESYS_CONTEXT *)&g_esys_session;
	return TSS2_RC_SUCCESS;
}

static void test_reconnect_keeps_the_aik_name(void)
{
	static int tcti;
	struct tpm_context ctx;

	TEST("a session reconnect keeps the AIK's Name");
	make_ctx(&ctx);
	ctx.esys_ctx = (ESYS_CONTEXT *)&tcti;
	ctx.tcti_ctx = (TSS2_TCTI_CONTEXT *)&tcti;
	memset(ctx.aik_object_name, 0x5a, 34);
	ctx.aik_object_name_size = 34;
	ctx.aik_auth_loaded = true;
	ctx.aik_meta_loaded = true;

	if (tpm_test_esys_reconnect(&ctx) != 0) {
		FAIL("reconnect failed");
		return;
	}
	if (ctx.esys_ctx != (ESYS_CONTEXT *)&g_esys_session) {
		FAIL("the session was not replaced");
		return;
	}
	if (ctx.aik_object_name_size != 34 || ctx.aik_object_name[0] != 0x5a ||
	    ctx.aik_object_name[33] != 0x5a) {
		FAIL("the AIK's Name was forgotten");
		return;
	}
	if (ctx.aik_auth_loaded || ctx.aik_meta_loaded) {
		FAIL("the cached auth or record survived");
		return;
	}
	PASS();
}

static int g_quotes;

TSS2_RC __wrap_Esys_TR_GetName(ESYS_CONTEXT *esys_ctx, ESYS_TR handle,
			       TPM2B_NAME **name);
TSS2_RC __wrap_Esys_TR_SetAuth(ESYS_CONTEXT *esys_ctx, ESYS_TR handle,
			       const TPM2B_AUTH *auth);
TSS2_RC __wrap_Esys_TR_Close(ESYS_CONTEXT *esys_ctx, ESYS_TR *object);
TSS2_RC __wrap_Esys_Quote(ESYS_CONTEXT *esys_ctx, ESYS_TR sign_handle,
			  ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3,
			  const TPM2B_DATA *qualifying_data,
			  const TPMT_SIG_SCHEME *in_scheme,
			  const TPML_PCR_SELECTION *pcr_select,
			  TPM2B_ATTEST **quoted, TPMT_SIGNATURE **signature);

TSS2_RC __wrap_Esys_TR_GetName(ESYS_CONTEXT *esys_ctx, ESYS_TR handle,
			       TPM2B_NAME **name)
{
	(void)esys_ctx;
	(void)handle;
	*name = calloc(1, sizeof(**name));
	if (!*name)
		return TSS2_ESYS_RC_MEMORY;
	(*name)->size = 34;
	memset((*name)->name, 0x5a, 34);
	return TSS2_RC_SUCCESS;
}

TSS2_RC __wrap_Esys_TR_SetAuth(ESYS_CONTEXT *esys_ctx, ESYS_TR handle,
			       const TPM2B_AUTH *auth)
{
	(void)esys_ctx;
	(void)handle;
	(void)auth;
	return TSS2_RC_SUCCESS;
}

TSS2_RC __wrap_Esys_TR_Close(ESYS_CONTEXT *esys_ctx, ESYS_TR *object)
{
	(void)esys_ctx;
	*object = ESYS_TR_NONE;
	return TSS2_RC_SUCCESS;
}

/* Every quote is refused: the stored authorization is not the key's. */
TSS2_RC __wrap_Esys_Quote(ESYS_CONTEXT *esys_ctx, ESYS_TR sign_handle,
			  ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3,
			  const TPM2B_DATA *qualifying_data,
			  const TPMT_SIG_SCHEME *in_scheme,
			  const TPML_PCR_SELECTION *pcr_select,
			  TPM2B_ATTEST **quoted, TPMT_SIGNATURE **signature)
{
	(void)esys_ctx;
	(void)sign_handle;
	(void)shandle1;
	(void)shandle2;
	(void)shandle3;
	(void)qualifying_data;
	(void)in_scheme;
	(void)pcr_select;
	*quoted = NULL;
	*signature = NULL;
	g_quotes++;
	return (TSS2_RC)(TPM2_RC_AUTH_FAIL | 0x300);
}

static void test_refused_auth_is_not_offered_again(void)
{
	static struct tpm_quote_response resp;
	static int session;
	uint8_t nonce[LOTA_NONCE_SIZE] = { 0 };
	uint8_t auth[TPM_AIK_AUTH_SIZE];
	char dir[192];
	struct tpm_context ctx;
	int first;
	int again;
	int changed;

	TEST("a refused AIK authorization is not offered to the TPM again");
	snprintf(dir, sizeof(dir), "%s/refused_auth", tmp_dir);
	mkdir(dir, 0700);
	make_ctx(&ctx);
	snprintf(ctx.aik_meta_path, sizeof(ctx.aik_meta_path),
		 "%s/aik_meta.dat", dir);
	ctx.esys_ctx = (ESYS_CONTEXT *)&session;
	ctx.aik_handle = 0x81010017;
	g_listed_handle = ctx.aik_handle;
	g_key_object = 0x4000ff;
	g_quotes = 0;
	memset(auth, 0x11, sizeof(auth));
	if (tpm_test_aik_save_auth(&ctx, auth) != 0) {
		g_key_object = 0;
		FAIL("could not store the authorization");
		return;
	}

	first = tpm_quote(&ctx, nonce, 1, &resp);
	again = tpm_quote(&ctx, nonce, 1, &resp);
	if (first != -LOTA_ERR_TPM_AUTH_FAIL || again != first ||
	    g_quotes != 1) {
		g_key_object = 0;
		FAIL("the refused authorization reached the TPM again");
		return;
	}

	/* what --reprovision-aik leaves behind */
	memset(auth, 0x22, sizeof(auth));
	tpm_test_aik_save_auth(&ctx, auth);
	changed = tpm_quote(&ctx, nonce, 1, &resp);
	g_key_object = 0;
	if (changed != -LOTA_ERR_TPM_AUTH_FAIL || g_quotes != 2) {
		FAIL("a changed authorization was not offered");
		return;
	}
	PASS();
}

static void publisher_paths(struct profile_paths *paths, const char *name,
			    char id, uint32_t handle)
{
	char dir[192];
	int fd;

	memset(paths, 0, sizeof(*paths));
	memset(paths->id, id, LOTA_PROFILE_ID_LEN - 1);
	snprintf(dir, sizeof(dir), "%s/%s", tmp_dir, name);
	mkdir(dir, 0700);
	snprintf(paths->dir, sizeof(paths->dir), "%s", dir);
	snprintf(paths->aik_meta, sizeof(paths->aik_meta), "%s/aik_meta.dat",
		 dir);
	snprintf(paths->aik_handle, sizeof(paths->aik_handle), "%s/aik_handle",
		 dir);
	fd = open(paths->aik_handle, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd >= 0) {
		dprintf(fd, "0x%08X\n", handle);
		close(fd);
	}
}

static void test_refusal_outlives_a_publisher_switch(void)
{
	static struct profile_paths a;
	static struct profile_paths b;
	static struct tpm_quote_response resp;
	static int session;
	uint8_t nonce[LOTA_NONCE_SIZE] = { 0 };
	uint8_t auth[TPM_AIK_AUTH_SIZE];
	struct tpm_context ctx;
	int ret;

	TEST("a refused AIK authorization stays refused across publishers");
	publisher_paths(&a, "refused_pub_a", 'a', 0x81010017);
	publisher_paths(&b, "refused_pub_b", 'b', 0x81010018);
	make_ctx(&ctx);
	ctx.esys_ctx = (ESYS_CONTEXT *)&session;
	g_listed_handle = 0x81010017;
	g_key_object = 0x4000ff;
	g_quotes = 0;
	memset(auth, 0x33, sizeof(auth));
	if (tpm_bind_profile(&ctx, &a) != 0 ||
	    tpm_test_aik_save_auth(&ctx, auth) != 0) {
		g_key_object = 0;
		FAIL("could not bind the first publisher");
		return;
	}

	tpm_quote(&ctx, nonce, 1, &resp);
	if (tpm_bind_profile(&ctx, &b) != 0 ||
	    tpm_bind_profile(&ctx, &a) != 0) {
		g_key_object = 0;
		FAIL("could not switch publishers");
		return;
	}
	ret = tpm_quote(&ctx, nonce, 1, &resp);
	g_key_object = 0;
	if (ret != -LOTA_ERR_TPM_AUTH_FAIL || g_quotes != 1) {
		FAIL("the refused authorization reached the TPM again");
		return;
	}
	PASS();
}

int main(void)
{
	printf("\n=== AIK Tests ===\n\n");

	setup_tmp_dir();

	test_metadata_unused_bytes_are_ignored();
	test_metadata_key_derivation_round_trip();
	test_absent_metadata_claims_nothing();
	test_recorded_shared_key_still_reads_shared();
	test_shared_replacement_needs_a_key();
	test_provisioning_names_an_orphaned_cert();
	test_metadata_default_creation();
	test_new_key_metadata_persisted();
	test_metadata_bad_magic();
	test_metadata_bad_version();
	test_save_creates_dirs();
	test_metadata_truncated();
	test_rc_success_is_zero();
	test_rc_lockout_raw();
	test_rc_lockout_resmgr_layer();
	test_rc_transient_codes();
	test_rc_auth_fail_with_session_bits();
	test_rc_value_and_handle();
	test_rc_nv_space();
	test_rc_tcti_layer();
	test_lockout_flag_lifecycle();
	test_lockout_survives_auth_free_success();
	test_pcr_batch_reads_past_eight();
	test_refused_unseal_with_unmoved_pcrs_is_the_blob();
	test_failed_bind_keeps_the_bound_publisher();
	test_reconnect_keeps_the_aik_name();
	test_reprovision_reads_the_record_first();
	test_lost_auth_keeps_a_shared_key();
	test_refused_auth_is_not_offered_again();
	test_refusal_outlives_a_publisher_switch();
	test_reprovision_rewrites_a_missing_record();
	test_provision_ignores_the_vendor_string();
	test_self_hash_pin_round_trip();
	test_tpm_strerror_maps_lota_private();
	test_clock_state_save_load_round_trip();
	test_initramfs_lock_digest_matches_reference();
	test_aik_unique_separates_publishers();
	test_clock_state_load_missing_is_enoent();
	test_clock_state_load_rejects_corrupt();
	test_call_with_backoff_no_leak_on_retry();
	test_call_with_backoff_gives_up_without_leak();
	test_call_with_backoff_respects_wallclock_budget();
	test_binding_does_not_survive_a_reused_handle();
	test_stale_object_record_is_told_from_a_tpm_refusal();
	test_object_change_is_read_from_the_name();

	cleanup_tmp_dir();

	printf("\n  Result: %d/%d passed\n\n", tests_passed, tests_run);
	return (tests_passed == tests_run) ? 0 : 1;
}
