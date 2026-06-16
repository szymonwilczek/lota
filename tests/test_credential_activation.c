/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for the TPM credential-activation entry points.
 *
 * These cover argument validation and the wire-blob unmarshal guards,
 * which run before any Esys call and therefore need no TPM. The Esys
 * activation path itself (StartAuthSession, PolicySecret,
 * ActivateCredential against a real EK) is integration-tested against
 * swTPM in the VM; it cannot run here.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../src/agent/agent_internal.h" // IWYU pragma: keep (defines LOTA_TPM_TESTING)

static int g_failures;

#define CHECK(cond, msg)                                    \
	do {                                                \
		if (!(cond)) {                              \
			fprintf(stderr, "FAIL: %s\n", msg); \
			g_failures++;                       \
		} else {                                    \
			printf("PASS: %s\n", msg);          \
		}                                           \
	} while (0)

static void test_aik_tpmt_public_validation(void)
{
	struct tpm_context ctx;
	uint8_t buf[512];
	size_t out = 0;

	memset(&ctx, 0, sizeof(ctx));

	CHECK(tpm_get_aik_tpmt_public(NULL, buf, sizeof(buf), &out) == -EINVAL,
	      "aik_tpmt_public rejects nil ctx");

	/* ctx.initialized == false */
	CHECK(tpm_get_aik_tpmt_public(&ctx, buf, sizeof(buf), &out) == -EINVAL,
	      "aik_tpmt_public rejects uninitialized ctx");

	ctx.initialized = true;
	CHECK(tpm_get_aik_tpmt_public(&ctx, NULL, sizeof(buf), &out) == -EINVAL,
	      "aik_tpmt_public rejects nil buffer");
	CHECK(tpm_get_aik_tpmt_public(&ctx, buf, sizeof(buf), NULL) == -EINVAL,
	      "aik_tpmt_public rejects nil out_size");
}

static void test_activate_credential_validation(void)
{
	struct tpm_context ctx;
	uint8_t out_secret[64];
	size_t out_len = 0;
	const uint8_t cred[] = { 0x00, 0x10 };
	const uint8_t secret[] = { 0x00, 0x10 };

	memset(&ctx, 0, sizeof(ctx));

	CHECK(tpm_activate_credential(NULL, cred, sizeof(cred), secret,
				      sizeof(secret), out_secret,
				      sizeof(out_secret), &out_len) == -EINVAL,
	      "activate_credential rejects nil ctx");

	ctx.initialized = true;
	CHECK(tpm_activate_credential(&ctx, NULL, 0, secret, sizeof(secret),
				      out_secret, sizeof(out_secret),
				      &out_len) == -EINVAL,
	      "activate_credential rejects nil cred_blob");
	CHECK(tpm_activate_credential(&ctx, cred, sizeof(cred), NULL, 0,
				      out_secret, sizeof(out_secret),
				      &out_len) == -EINVAL,
	      "activate_credential rejects nil enc_secret");
	CHECK(tpm_activate_credential(&ctx, cred, sizeof(cred), secret,
				      sizeof(secret), NULL, sizeof(out_secret),
				      &out_len) == -EINVAL,
	      "activate_credential rejects nil out_secret");
}

static void test_activate_credential_malformed_blobs(void)
{
	struct tpm_context ctx;
	uint8_t out_secret[64];
	size_t out_len = 0;

	/*
	 * TPM2B length prefix that claims more bytes than are present must be
	 * rejected by the unmarshal guard before any Esys call, so this is safe
	 * to run with a NULL esys context
	 */
	const uint8_t bad_cred[] = { 0xFF, 0xFF };
	const uint8_t ok_cred[] = { 0x00, 0x00 };
	const uint8_t bad_secret[] = { 0xFF, 0xFF };
	const uint8_t ok_secret[] = { 0x00, 0x00 };

	memset(&ctx, 0, sizeof(ctx));
	ctx.initialized = true;

	CHECK(tpm_activate_credential(&ctx, bad_cred, sizeof(bad_cred),
				      ok_secret, sizeof(ok_secret), out_secret,
				      sizeof(out_secret), &out_len) == -EINVAL,
	      "activate_credential rejects malformed credential blob");

	CHECK(tpm_activate_credential(&ctx, ok_cred, sizeof(ok_cred),
				      bad_secret, sizeof(bad_secret),
				      out_secret, sizeof(out_secret),
				      &out_len) == -EINVAL,
	      "activate_credential rejects malformed encrypted secret");
}

int main(void)
{
	printf("=== credential activation unit tests ===\n");
	test_aik_tpmt_public_validation();
	test_activate_credential_validation();
	test_activate_credential_malformed_blobs();

	if (g_failures) {
		fprintf(stderr, "\n%d test(s) failed\n", g_failures);
		return 1;
	}
	printf("\nAll credential activation tests passed\n");
	return 0;
}
