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

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <stdbool.h>
#include <stdint.h>

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

static void test_recovery_decision(void)
{
	TEST("strict-mode reprovision-block decision is correct");
	/* non-strict: a load failure always allows reprovision */
	if (tpm_aik_strict_blocks_reprovision(0, -LOTA_ERR_TPM_POLICY_FAIL) !=
	    0) {
		FAIL("non-strict blocked");
		return;
	}
	/* strict + boot-state mismatch: must block silent AIK rotation */
	if (tpm_aik_strict_blocks_reprovision(1, -LOTA_ERR_TPM_POLICY_FAIL) !=
	    1) {
		FAIL("strict policy-fail not blocked");
		return;
	}
	/* strict but a genuinely missing/corrupt auth: reprovision is fine */
	if (tpm_aik_strict_blocks_reprovision(1, -ENOENT) != 0) {
		FAIL("strict missing-auth blocked");
		return;
	}
	if (tpm_aik_strict_blocks_reprovision(1, -EIO) != 0) {
		FAIL("strict io-error blocked");
		return;
	}
	/* a successful load is never a reprovision trigger */
	if (tpm_aik_strict_blocks_reprovision(1, 0) != 0) {
		FAIL("strict success blocked");
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
	test_recovery_decision();
	test_reseal_reprovision_arg_guards();

	cleanup_dir();
	printf("\n%d/%d tests passed\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
