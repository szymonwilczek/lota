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

#include "../src/agent/agent_internal.h" // IWYU pragma: keep (defines LOTA_TPM_TESTING)

static int tests_run;
static int tests_passed;

#define TEST(name)                                        \
	do {                                              \
		tests_run++;                              \
		printf("  [%2d] %-58s", tests_run, name); \
	} while (0)

#define PASS()                    \
	do {                      \
		tests_passed++;   \
		printf("PASS\n"); \
	} while (0)

#define FAIL(reason)                           \
	do {                                   \
		printf("FAIL (%s)\n", reason); \
	} while (0)

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
static int blocks_reprovision(int strict, int load_rc)
{
	return tpm_aik_strict_blocks_reprovision(strict, load_rc);
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
		if (blocks_reprovision(0, rc) != cases[i].want_block) {
			snprintf(reason, sizeof(reason),
				 "%s: reprovision decision is %d, want %d",
				 cases[i].name, blocks_reprovision(0, rc),
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
	/* the sealed auth no longer unseals in the current boot state */
	if (blocks_reprovision(1, -LOTA_ERR_TPM_POLICY_FAIL) != 1) {
		FAIL("strict policy-fail not blocked");
		return;
	}
	/* the record exists in either mode */
	if (blocks_reprovision(0, -LOTA_ERR_TPM_POLICY_FAIL) != 1) {
		FAIL("non-strict policy-fail not blocked");
		return;
	}
	/* a genuinely missing auth leaves a key nothing can drive again */
	if (blocks_reprovision(1, -ENOENT) != 0 ||
	    blocks_reprovision(0, -ENOENT) != 0) {
		FAIL("missing auth blocked");
		return;
	}
	/* a successful load is never a reprovision trigger */
	if (blocks_reprovision(1, 0) != 0 || blocks_reprovision(0, 0) != 0) {
		FAIL("success blocked");
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
	if (tpm_reprovision_aik(NULL) != -EINVAL ||
	    tpm_reprovision_aik(&ctx) != -EINVAL) {
		FAIL("reprovision guard");
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
	test_reseal_reprovision_arg_guards();

	cleanup_dir();
	printf("\n%d/%d tests passed\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
