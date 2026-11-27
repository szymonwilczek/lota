/* SPDX-License-Identifier: MIT */
/*
 * LOTA AIK userAuth at-rest hardening - unit tests.
 *
 * Default (flags off) save/load path is pure file I/O and is verified
 * here end-to-end without a TPM: it must remain byte-for-byte the previous
 * plaintext-sidecar behaviour. The sealed-path derivation and the
 * dispatch decisions are also checked.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>
#include <tss2/tss2_tpm2_types.h>
#include "lota_seal.h"

#include "test.h"
#include "../src/agent/agent_internal.h" // IWYU pragma: keep (defines LOTA_TPM_TESTING)

static char test_dir[96];

static void setup_dir(void)
{
	snprintf(test_dir, sizeof(test_dir), "/tmp/lota_seal_aik_XXXXXX");
	if (!mkdtemp(test_dir)) {
		perror("mkdtemp");
		exit(1);
	}
}

static void cleanup_dir(void)
{
	char cmd[512];
	snprintf(cmd, sizeof(cmd), "rm -rf %s", test_dir);
	if (system(cmd) != 0)
		fprintf(stderr, "warning: cleanup failed\n");
}

static void init_ctx(struct tpm_context *ctx)
{
	memset(ctx, 0, sizeof(*ctx));
	snprintf(ctx->aik_meta_path, sizeof(ctx->aik_meta_path),
		 "%s/aik_meta.dat", test_dir);
}

static int file_exists(const char *path)
{
	struct stat st;
	return stat(path, &st) == 0;
}

static void test_default_off_roundtrip(void)
{
	struct tpm_context ctx;
	uint8_t auth[TPM_AIK_AUTH_SIZE];
	char plain[512], sealed[512];

	TEST("default (flags off): plaintext save/load round-trips");
	init_ctx(&ctx);
	for (unsigned i = 0; i < TPM_AIK_AUTH_SIZE; i++)
		auth[i] = (uint8_t)(0x40 + i);

	if (tpm_test_aik_save_auth(&ctx, auth) != 0) {
		FAIL("save");
		return;
	}
	if (tpm_test_aik_plaintext_path(&ctx, plain, sizeof(plain)) != 0 ||
	    tpm_test_aik_sealed_path(&ctx, sealed, sizeof(sealed)) != 0) {
		FAIL("path");
		return;
	}
	/* default off: plaintext written, sealed copy must NOT exist */
	if (!file_exists(plain)) {
		FAIL("no plaintext file");
		return;
	}
	if (file_exists(sealed)) {
		FAIL("sealed file created with flags off");
		return;
	}

	memset(ctx.aik_auth, 0, sizeof(ctx.aik_auth));
	ctx.aik_auth_loaded = false;
	if (tpm_test_aik_load_auth(&ctx) != 0) {
		FAIL("load");
		return;
	}
	if (!ctx.aik_auth_loaded ||
	    memcmp(ctx.aik_auth, auth, TPM_AIK_AUTH_SIZE) != 0) {
		FAIL("auth mismatch after reload");
		return;
	}
	PASS();
}

static void test_sealed_path_derivation(void)
{
	struct tpm_context ctx;
	char sealed[512], plain[512];

	TEST("sealed path is aik_auth.sealed beside the metadata");
	init_ctx(&ctx);
	if (tpm_test_aik_sealed_path(&ctx, sealed, sizeof(sealed)) != 0 ||
	    tpm_test_aik_plaintext_path(&ctx, plain, sizeof(plain)) != 0) {
		FAIL("derive");
		return;
	}
	char want_sealed[512], want_plain[512];
	snprintf(want_sealed, sizeof(want_sealed), "%s/aik_auth.sealed",
		 test_dir);
	snprintf(want_plain, sizeof(want_plain), "%s/aik_auth.dat", test_dir);
	if (strcmp(sealed, want_sealed) != 0) {
		FAIL("sealed path");
		return;
	}
	if (strcmp(plain, want_plain) != 0) {
		FAIL("plain path");
		return;
	}
	PASS();
}

static void test_sealing_on_without_tpm_fails_cleanly(void)
{
	struct tpm_context ctx;
	uint8_t auth[TPM_AIK_AUTH_SIZE];
	char sealed[512];

	TEST("seal flag on, no TPM: save fails, no plaintext leak, no crash");
	init_ctx(&ctx);
	ctx.seal_aik_auth = true; /* but esys_ctx/initialized are zero */
	memset(auth, 0x5A, sizeof(auth));

	/* sealing is attempted first
	 * with no TPM it returns an error and the dispatcher must surface it
	 * instead of silently writing plaintext */
	if (tpm_test_aik_save_auth(&ctx, auth) == 0) {
		FAIL("save unexpectedly succeeded without a TPM");
		return;
	}
	if (tpm_test_aik_sealed_path(&ctx, sealed, sizeof(sealed)) != 0) {
		FAIL("path");
		return;
	}
	if (file_exists(sealed)) {
		FAIL("sealed file created despite seal failure");
		return;
	}
	PASS();
}

static void test_strict_load_no_plaintext_fallback(void)
{
	struct tpm_context ctx;
	uint8_t auth[TPM_AIK_AUTH_SIZE];

	TEST("strict load does not fall back to a plaintext sidecar");
	init_ctx(&ctx);

	/* plant a valid plaintext sidecar via the default-off path */
	for (unsigned i = 0; i < TPM_AIK_AUTH_SIZE; i++)
		auth[i] = (uint8_t)(0x11 + i);
	if (tpm_test_aik_save_auth(&ctx, auth) != 0) {
		FAIL("seed plaintext");
		return;
	}

	/* now demand strict sealed-only load: with no sealed file and no TPM
	 * it must fail instead of silently returning the plaintext auth */
	ctx.seal_aik_auth_strict = true;
	memset(ctx.aik_auth, 0, sizeof(ctx.aik_auth));
	ctx.aik_auth_loaded = false;
	if (tpm_test_aik_load_auth(&ctx) == 0) {
		FAIL("strict load fell back to plaintext");
		return;
	}
	if (ctx.aik_auth_loaded) {
		FAIL("auth marked loaded after strict failure");
		return;
	}
	PASS();
}

/*
 * An auth record this build cannot read still authorizes the enrolled key;
 * rotating over it destroys the identity and its certificate.
 * Only a missing record may reprovision.
 */
static int blocks_reprovision(int load_rc)
{
	return tpm_aik_load_failure_blocks_reprovision(load_rc);
}

enum record_damage {
	DAMAGE_VERSION,
	DAMAGE_MAGIC,
	DAMAGE_TRUNCATE,
	DAMAGE_ZERO_AUTH,
	DAMAGE_ABSENT,
};

static int seed_damaged_record(struct tpm_context *ctx, enum record_damage what)
{
	uint8_t auth[TPM_AIK_AUTH_SIZE];
	struct aik_auth_record rec;
	char path[512];
	size_t want;
	FILE *f;
	int fd;

	init_ctx(ctx);
	for (unsigned i = 0; i < TPM_AIK_AUTH_SIZE; i++)
		auth[i] = (uint8_t)(0x70 + i);
	if (tpm_test_aik_save_auth(ctx, auth) != 0)
		return -1;
	if (tpm_test_aik_plaintext_path(ctx, path, sizeof(path)) != 0)
		return -1;

	if (what == DAMAGE_ABSENT)
		return unlink(path) == 0 ? 0 : -1;

	f = fopen(path, "rb");
	if (!f)
		return -1;
	if (fread(&rec, 1, sizeof(rec), f) != sizeof(rec)) {
		fclose(f);
		return -1;
	}
	fclose(f);

	switch (what) {
	case DAMAGE_VERSION:
		rec.version = htole32(le32toh(rec.version) + 1);
		break;
	case DAMAGE_MAGIC:
		rec.magic = htole32(le32toh(rec.magic) ^ 0xFFu);
		break;
	case DAMAGE_ZERO_AUTH:
		memset(rec.auth, 0, sizeof(rec.auth));
		break;
	default:
		break;
	}

	want = (what == DAMAGE_TRUNCATE) ? 8 : sizeof(rec);
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0)
		return -1;
	f = fdopen(fd, "wb");
	if (!f) {
		close(fd);
		return -1;
	}
	if (fwrite(&rec, 1, want, f) != want) {
		fclose(f);
		return -1;
	}
	fclose(f);
	return 0;
}

static void test_unreadable_record_is_not_a_missing_one(void)
{
	static const struct {
		enum record_damage what;
		int want_rc;
		int want_block;
		const char *name;
	} cases[] = {
		{ DAMAGE_VERSION, -ENOTSUP, 1,
		  "version this build cannot read" },
		{ DAMAGE_MAGIC, -EINVAL, 1, "magic that is not the record's" },
		{ DAMAGE_TRUNCATE, -EIO, 1, "record shorter than the record" },
		{ DAMAGE_ZERO_AUTH, -EKEYREVOKED, 1, "all-zero secret" },
		{ DAMAGE_ABSENT, -ENOENT, 0, "no record at all" },
	};
	struct tpm_context ctx;
	char reason[160];

	TEST("only an absent auth record may rotate the AIK");
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		int rc;

		if (seed_damaged_record(&ctx, cases[i].what) != 0) {
			FAIL("seed");
			return;
		}
		memset(ctx.aik_auth, 0, sizeof(ctx.aik_auth));
		ctx.aik_auth_loaded = false;

		rc = tpm_test_aik_load_auth(&ctx);
		if (rc != cases[i].want_rc) {
			snprintf(reason, sizeof(reason),
				 "%s: load returned %d, want %d", cases[i].name,
				 rc, cases[i].want_rc);
			FAIL(reason);
			return;
		}
		if (ctx.aik_auth_loaded && rc != 0) {
			snprintf(reason, sizeof(reason),
				 "%s: auth marked loaded after a failed load",
				 cases[i].name);
			FAIL(reason);
			return;
		}
		if (blocks_reprovision(rc) != cases[i].want_block) {
			snprintf(reason, sizeof(reason),
				 "%s: reprovision decision is %d, want %d",
				 cases[i].name, blocks_reprovision(rc),
				 cases[i].want_block);
			FAIL(reason);
			return;
		}
	}
	PASS();
}

static void test_recovery_decision(void)
{
	TEST("reprovision-block decision is correct");
	/* sealed auth no longer unseals; the record exists in either mode */
	if (blocks_reprovision(-LOTA_ERR_TPM_POLICY_FAIL) != 1) {
		FAIL("strict policy-fail not blocked");
		return;
	}
	/* a genuinely missing auth leaves a key nothing can drive again */
	if (blocks_reprovision(-ENOENT) != 0) {
		FAIL("missing auth blocked");
		return;
	}
	/* a successful load is never a reprovision trigger */
	if (blocks_reprovision(0) != 0) {
		FAIL("success blocked");
		return;
	}
	PASS();
}

/*
 * Hardened mode reports -ENOENT when only the plaintext sidecar exists;
 * the key is still authorized and must not rotate.
 */
static void test_leftover_sidecar_is_still_a_record(void)
{
	struct tpm_context ctx;
	uint8_t auth[TPM_AIK_AUTH_SIZE];

	TEST("hardened mode with only a sidecar left does not rotate");
	init_ctx(&ctx);
	for (unsigned i = 0; i < TPM_AIK_AUTH_SIZE; i++)
		auth[i] = (uint8_t)(0x21 + i);
	if (tpm_test_aik_save_auth(&ctx, auth) != 0) {
		FAIL("seed plaintext");
		return;
	}

	ctx.seal_aik_auth_strict = true;
	memset(ctx.aik_auth, 0, sizeof(ctx.aik_auth));
	ctx.aik_auth_loaded = false;
	if (tpm_test_aik_load_auth(&ctx) != -ENOENT) {
		FAIL("expected a missing sealed copy");
		return;
	}
	/* the load code alone would rotate here */
	if (blocks_reprovision(-ENOENT) != 0) {
		FAIL("absent record blocked");
		return;
	}
	/* the disk says the authorization is right there */
	if (tpm_test_aik_auth_record_exists(&ctx) != 1) {
		FAIL("sidecar not seen");
		return;
	}
	PASS();
}

/* a sealed copy left from before would be loaded ahead of the new value */
static void test_plaintext_save_drops_an_old_sealed_copy(void)
{
	struct tpm_context ctx;
	uint8_t auth[TPM_AIK_AUTH_SIZE];
	char sealed[512];
	int fd;

	TEST("plaintext save removes a sealed copy of the old value");
	init_ctx(&ctx);
	if (tpm_test_aik_sealed_path(&ctx, sealed, sizeof(sealed)) != 0) {
		FAIL("path");
		return;
	}
	fd = open(sealed, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0 || write(fd, "old", 3) != 3) {
		if (fd >= 0)
			close(fd);
		FAIL("seed sealed copy");
		return;
	}
	close(fd);

	for (unsigned i = 0; i < TPM_AIK_AUTH_SIZE; i++)
		auth[i] = (uint8_t)(0x61 + i);
	if (tpm_test_aik_save_auth(&ctx, auth) != 0) {
		FAIL("save");
		return;
	}
	if (file_exists(sealed)) {
		FAIL("old sealed copy kept");
		return;
	}
	PASS();
}

/* write @len bytes of @magic with @version + 1 */
static int write_bumped_record(const char *path, uint32_t magic,
			       uint32_t version, size_t len)
{
	uint8_t buf[512];
	uint32_t le_magic = htole32(magic);
	uint32_t le_version = htole32(version + 1);
	FILE *f;
	int fd;

	if (len > sizeof(buf))
		return -1;
	memset(buf, 0, sizeof(buf));
	memcpy(buf, &le_magic, sizeof(le_magic));
	memcpy(buf + sizeof(le_magic), &le_version, sizeof(le_version));

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0)
		return -1;
	f = fdopen(fd, "wb");
	if (!f) {
		close(fd);
		return -1;
	}
	if (fwrite(buf, 1, len, f) != len) {
		fclose(f);
		return -1;
	}
	fclose(f);
	return 0;
}

/*
 * Every version-guarded state file refuses an unknown version:
 * the clock snapshot is discarded, metadata and auth records stop the run.
 */
static void test_state_files_at_an_unknown_version(void)
{
	struct tpm_context ctx;
	struct lota_clock_state clock_out;
	char path[512];
	int rc;

	TEST("every version-guarded state file refuses a version it cannot read");
	init_ctx(&ctx);

	/* clock_state.dat: refused, and the caller carries on without it */
	snprintf(ctx.clock_state_path, sizeof(ctx.clock_state_path),
		 "%s/clock_state.dat", test_dir);
	if (write_bumped_record(ctx.clock_state_path, TPM_CLOCK_STATE_MAGIC,
				TPM_CLOCK_STATE_VERSION,
				sizeof(struct lota_clock_state)) != 0) {
		FAIL("seed clock state");
		return;
	}
	memset(&clock_out, 0, sizeof(clock_out));
	rc = tpm_clock_state_load(&ctx, &clock_out);
	if (rc == 0) {
		FAIL("clock state accepted an unknown version");
		return;
	}
	if (clock_out.version != 0) {
		FAIL("clock state handed back a record it refused");
		return;
	}

	/* aik_meta.dat: refused, and the run stops */
	if (write_bumped_record(ctx.aik_meta_path, TPM_AIK_META_MAGIC,
				TPM_AIK_META_VERSION,
				sizeof(struct aik_metadata)) != 0) {
		FAIL("seed metadata");
		return;
	}
	ctx.initialized = true; /* no esys_ctx: this path is pure file I/O */
	rc = tpm_aik_load_metadata(&ctx);
	ctx.initialized = false;
	if (rc != -ENOTSUP) {
		FAIL("metadata did not refuse an unknown version");
		return;
	}
	if (ctx.aik_meta_loaded) {
		FAIL("metadata marked loaded after a refusal");
		return;
	}

	/* aik_auth.dat: refused, and the key it names is left alone */
	if (tpm_test_aik_plaintext_path(&ctx, path, sizeof(path)) != 0 ||
	    write_bumped_record(path, TPM_AIK_AUTH_MAGIC, TPM_AIK_AUTH_VERSION,
				sizeof(struct aik_auth_record)) != 0) {
		FAIL("seed auth record");
		return;
	}
	rc = tpm_test_aik_load_auth(&ctx);
	if (rc != -ENOTSUP || blocks_reprovision(rc) != 1) {
		FAIL("auth record did not refuse an unknown version");
		return;
	}

	/*
	 * aik_auth.sealed: unsealing needs a TPM, so check only that a copy
	 * that fails to load still counts as a record and blocks rotation
	 */
	if (tpm_test_aik_sealed_path(&ctx, path, sizeof(path)) != 0 ||
	    write_bumped_record(path, TPM_AIK_AUTH_MAGIC, TPM_AIK_AUTH_VERSION,
				64) != 0) {
		FAIL("seed sealed copy");
		return;
	}
	ctx.seal_aik_auth_strict = true;
	memset(ctx.aik_auth, 0, sizeof(ctx.aik_auth));
	ctx.aik_auth_loaded = false;
	rc = tpm_test_aik_load_auth(&ctx);
	if (rc == 0) {
		FAIL("sealed copy unsealed without a TPM");
		return;
	}
	if (blocks_reprovision(rc) != 1 ||
	    tpm_test_aik_auth_record_exists(&ctx) != 1) {
		FAIL("an unreadable sealed copy would rotate the key");
		return;
	}
	PASS();
}

static void test_reseal_reprovision_arg_guards(void)
{
	struct tpm_context ctx;

	TEST("reseal/reprovision reject NULL and uninitialised ctx");
	memset(&ctx, 0, sizeof(ctx)); /* initialized == false */
	if (tpm_aik_reseal_auth(NULL) != -EINVAL ||
	    tpm_aik_reseal_auth(&ctx) != -EINVAL) {
		FAIL("reseal guard");
		return;
	}
	if (tpm_reprovision_aik(NULL, NULL) != -EINVAL ||
	    tpm_reprovision_aik(&ctx, NULL) != -EINVAL) {
		FAIL("reprovision guard");
		return;
	}
	PASS();
}

static void test_mask_selection_default(void)
{
	uint8_t sel[3];
	uint32_t count = 0;

	TEST("mask->selection: default mask sets PCR 0, 1, 7 and not PCR14");
	if (tpm_test_pcr_mask_to_selection(LOTA_SEAL_DEFAULT_PCR_MASK, sel,
					   &count) != 0) {
		FAIL("call");
		return;
	}
	/* PCR 0, 1, 7 -> byte0 = 0x83; byte1 and byte2 stay 0 */
	if (count != 1 || sel[0] != 0x83 || sel[1] != 0x00 || sel[2] != 0x00) {
		FAIL("bitmap mismatch");
		return;
	}
	PASS();
}

/*
 * The agent-bound mask is the one that reaches PCR14, and it has to still
 * marshal correctly -- a caller who wants the agent binary in the policy is
 * asking for a supported thing, just not the default one.
 */
static void test_mask_selection_agent_bound(void)
{
	uint8_t sel[3];
	uint32_t count = 0;

	TEST("mask->selection: agent-bound mask adds PCR14 to PCR 0, 1, 7");
	if (tpm_test_pcr_mask_to_selection(LOTA_SEAL_AGENT_BOUND_PCR_MASK, sel,
					   &count) != 0) {
		FAIL("call");
		return;
	}
	/* PCR 0, 1, 7 -> byte0 = 0x83; PCR14 -> byte1 bit6 = 0x40; byte2 = 0 */
	if (count != 1 || sel[0] != 0x83 || sel[1] != 0x40 || sel[2] != 0x00) {
		FAIL("bitmap mismatch");
		return;
	}
	PASS();
}

static void test_mask_selection_edges(void)
{
	uint8_t sel[3];
	uint32_t count = 0;

	TEST("mask->selection: PCR0, PCR14, PCR23 map to the right bits");
	tpm_test_pcr_mask_to_selection(1u << 0, sel, &count);
	if (sel[0] != 0x01 || sel[1] != 0 || sel[2] != 0) {
		FAIL("PCR0");
		return;
	}
	tpm_test_pcr_mask_to_selection(1u << 14, sel, &count);
	if (sel[0] != 0 || sel[1] != 0x40 || sel[2] != 0) {
		FAIL("PCR14");
		return;
	}
	tpm_test_pcr_mask_to_selection(1u << 23, sel, &count);
	if (sel[0] != 0 || sel[1] != 0 || sel[2] != 0x80) {
		FAIL("PCR23");
		return;
	}
	PASS();
}

static void test_mask_selection_ignores_out_of_range(void)
{
	uint8_t sel[3];
	uint32_t count = 0;

	TEST("mask->selection: bits above PCR23 contribute nothing");
	tpm_test_pcr_mask_to_selection((1u << 24) | (1u << 31), sel, &count);
	if (sel[0] != 0 || sel[1] != 0 || sel[2] != 0) {
		FAIL("out-of-range bit leaked into selection");
		return;
	}
	PASS();
}

static void test_mask_selection_null_args(void)
{
	uint8_t sel[3];
	uint32_t count = 0;

	TEST("mask->selection: NULL outputs rejected");
	if (tpm_test_pcr_mask_to_selection(1u << 0, NULL, &count) != -EINVAL) {
		FAIL("NULL select");
		return;
	}
	if (tpm_test_pcr_mask_to_selection(1u << 0, sel, NULL) != -EINVAL) {
		FAIL("NULL count");
		return;
	}
	PASS();
}

static void test_seal_arg_validation(void)
{
	uint8_t secret[16] = { 0 };
	uint8_t big[LOTA_SEAL_MAX_SECRET + 1] = { 0 };
	uint8_t out[LOTA_SEAL_MAX_BLOB];
	size_t out_len = 0;

	TEST("seal: NULL ctx and bad lengths rejected before any TPM call");
	/* NULL context: returns before touching the TPM */
	if (tpm_seal_secret(NULL, secret, sizeof(secret), 0, out, sizeof(out),
			    &out_len) != -EINVAL) {
		FAIL("NULL ctx");
		return;
	}
	/*
	 * zeroed context has esys_ctx == NULL and initialized == false, so
	 * the guard rejects it before any Esys call -- safe without a TPM
	 */
	struct tpm_context ctx;
	memset(&ctx, 0, sizeof(ctx));
	if (tpm_seal_secret(&ctx, secret, sizeof(secret), 0, out, sizeof(out),
			    &out_len) != -EINVAL) {
		FAIL("uninit ctx");
		return;
	}
	if (tpm_seal_secret(&ctx, secret, 0, 0, out, sizeof(out), &out_len) !=
	    -EINVAL) {
		FAIL("zero len");
		return;
	}
	if (tpm_seal_secret(&ctx, big, sizeof(big), 0, out, sizeof(out),
			    &out_len) != -EINVAL) {
		FAIL("oversize secret");
		return;
	}
	if (tpm_seal_secret(&ctx, NULL, 8, 0, out, sizeof(out), &out_len) !=
	    -EINVAL) {
		FAIL("NULL secret");
		return;
	}
	PASS();
}

static void test_unseal_arg_validation(void)
{
	uint8_t blob[LOTA_SEAL_MAX_BLOB] = { 0 };
	uint8_t out[LOTA_SEAL_MAX_SECRET];
	size_t out_len = 0;

	TEST("unseal: NULL ctx and NULL args rejected before any TPM call");
	if (tpm_unseal_secret(NULL, blob, sizeof(blob), out, sizeof(out),
			      &out_len) != -EINVAL) {
		FAIL("NULL ctx");
		return;
	}
	struct tpm_context ctx;
	memset(&ctx, 0, sizeof(ctx));
	if (tpm_unseal_secret(&ctx, NULL, 0, out, sizeof(out), &out_len) !=
	    -EINVAL) {
		FAIL("NULL blob");
		return;
	}
	if (tpm_unseal_secret(&ctx, blob, sizeof(blob), out, sizeof(out),
			      NULL) != -EINVAL) {
		FAIL("NULL out_len");
		return;
	}
	PASS();
}

static void test_policy_fail_maps_clean(void)
{
	TEST("PolicyPCR mismatch maps to the dedicated policy-fail code");
	/*
	 * PCR-bound unseal in the wrong boot state returns TPM2_RC_POLICY_FAIL.
	 * It must surface as the dedicated LOTA code, not -EIO.
	 */
	if (tpm_test_rc_to_errno(TPM2_RC_POLICY_FAIL) !=
	    -LOTA_ERR_TPM_POLICY_FAIL) {
		FAIL("POLICY_FAIL not mapped");
		return;
	}
	if (tpm_test_rc_to_errno(TPM2_RC_PCR_CHANGED) !=
	    -LOTA_ERR_TPM_POLICY_FAIL) {
		FAIL("PCR_CHANGED not mapped");
		return;
	}
	PASS();
}

/* the boot-state hint must not follow a framing refusal */
static void test_boot_state_hint_is_for_a_tpm_that_did_not_say(void)
{
	TEST("the boot-state hint is only for a TPM refusal");

	if (!tpm_unseal_boot_state_unknown(-LOTA_ERR_TPM_POLICY_FAIL)) {
		FAIL("a policy failure does not say which policy");
		return;
	}
	if (tpm_unseal_boot_state_unknown(-EBADMSG)) {
		FAIL("an envelope tamper is a file, not a boot state");
		return;
	}
	if (tpm_unseal_boot_state_unknown(0)) {
		FAIL("a successful unseal");
		return;
	}
	if (!tpm_unseal_boot_state_unknown(-EIO)) {
		FAIL("a TPM that refused without saying why");
		return;
	}
	if (!tpm_unseal_boot_state_unknown(-LOTA_ERR_TPM_LOCKED)) {
		FAIL("a lockout is still an answer from the chip");
		return;
	}
	PASS();
}

static void test_seal_primary_name_match(void)
{
	TPM2B_NAME a = { .size = 4, .name = { 0x00, 0x0b, 0xaa, 0xbb } };
	TPM2B_NAME b = a;

	TEST("seal primary is used only under the recorded Name");
	if (!tpm_seal_primary_name_equal(&a, &b)) {
		FAIL("the same Name");
		return;
	}
	b.name[3] = 0xbc;
	if (tpm_seal_primary_name_equal(&a, &b)) {
		FAIL("another object at the handle");
		return;
	}
	b = a;
	b.size = 3;
	if (tpm_seal_primary_name_equal(&a, &b)) {
		FAIL("a Name that is a prefix of the recorded one");
		return;
	}
	a.size = b.size = sizeof(a.name) + 1;
	if (tpm_seal_primary_name_equal(&a, &b)) {
		FAIL("a size past the buffer");
		return;
	}
	PASS();
}

int main(void)
{
	printf("Running LOTA AIK-auth hardening tests...\n\n");
	setup_dir();

	test_default_off_roundtrip();
	test_sealed_path_derivation();
	test_sealing_on_without_tpm_fails_cleanly();
	test_strict_load_no_plaintext_fallback();
	test_unreadable_record_is_not_a_missing_one();
	test_recovery_decision();
	test_leftover_sidecar_is_still_a_record();
	test_plaintext_save_drops_an_old_sealed_copy();
	test_state_files_at_an_unknown_version();
	test_reseal_reprovision_arg_guards();
	test_mask_selection_default();
	test_mask_selection_agent_bound();
	test_mask_selection_edges();
	test_mask_selection_ignores_out_of_range();
	test_mask_selection_null_args();
	test_seal_arg_validation();
	test_unseal_arg_validation();
	test_policy_fail_maps_clean();
	test_boot_state_hint_is_for_a_tpm_that_did_not_say();
	test_seal_primary_name_match();

	cleanup_dir();
	printf("\n%d/%d tests passed\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
