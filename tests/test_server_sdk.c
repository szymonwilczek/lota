/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * LOTA Server SDK - Integration Test
 *
 * Tests the full pipeline:
 *  - Serialize a token (gaming SDK)
 *  - Parse without verification (server SDK)
 *  - Full RSA signature verification (server SDK)
 *  - Bad signature rejection
 *  - Tampered token rejection
 *  - Expired token detection
 *  - Nonce mismatch rejection
 *  - Malformed input handling
 */

#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/types.h>
#include <stdint.h>

#include "lota_gaming.h"
#include "lota_runtime_protect_digest.h"
#include "lota_server.h"
#include "lota_token.h"
#include "token_forge.h"

#define GREEN "\033[32m"
#define RED "\033[31m"
#define YELLOW "\033[33m"
#define RESET "\033[0m"
#define BOLD "\033[1m"

static int tests_run = 0;
static int tests_pass = 0;
static int tests_fail = 0;

#define TEST(name)                                         \
	do {                                               \
		tests_run++;                               \
		printf("  [%2d] %-50s ", tests_run, name); \
	} while (0)

#define PASS()                                   \
	do {                                     \
		tests_pass++;                    \
		printf(GREEN "PASS" RESET "\n"); \
	} while (0)

#define FAIL(reason)                                        \
	do {                                                \
		tests_fail++;                               \
		printf(RED "FAIL" RESET " — %s\n", reason); \
	} while (0)

/*
 * A tampered image digest is the one signal a relying party has that the
 * runtime image measurement did not reconcile, so it may not arrive wearing
 * the name of a nonce failure.
 */
static void test_verify_tampered_image_digest_is_named(EVP_PKEY *key,
						       const uint8_t *aik_der,
						       size_t aik_len)
{
	TEST("lota_server_verify_token - tampered image digest is not a nonce failure");

	uint64_t now = (uint64_t)time(NULL);
	uint8_t nonce[32] = { 0 };
	uint8_t tokbuf[2048];
	size_t tok_written = 0;
	struct lota_server_claims claims;
	size_t image_off;
	const char *msg_image;
	const char *msg_nonce;
	int ret;

	if (forge_token_protected(key, now + LOTA_SERVER_MAX_TOKEN_AGE_SEC,
				  0x07, nonce, tokbuf, sizeof(tokbuf),
				  &tok_written) != LOTA_OK) {
		FAIL("forge_token_protected failed");
		return;
	}

	if (lota_server_verify_token(tokbuf, tok_written, aik_der, aik_len,
				     nonce, &claims) != LOTA_SERVER_OK) {
		FAIL("the untampered token did not verify");
		return;
	}

	/* header, then the four-byte pid list, then the image digest */
	image_off = LOTA_TOKEN_HEADER_SIZE + sizeof(uint32_t);
	tokbuf[image_off] ^= 0x01;

	ret = lota_server_verify_token(tokbuf, tok_written, aik_der, aik_len,
				       nonce, &claims);
	if (ret == LOTA_SERVER_OK) {
		FAIL("a tampered image digest was accepted");
		return;
	}
	if (ret == LOTA_SERVER_ERR_NONCE_FAIL) {
		FAIL("reported as a nonce failure, which is a different fault");
		return;
	}

	msg_image = lota_server_strerror(ret);
	msg_nonce = lota_server_strerror(LOTA_SERVER_ERR_NONCE_FAIL);
	if (!msg_image || strlen(msg_image) == 0 ||
	    strcmp(msg_image, msg_nonce) == 0 ||
	    strcmp(msg_image, "Unknown error") == 0) {
		FAIL("the runtime-image refusal has no message of its own");
		return;
	}

	PASS();
}

static void test_serialize_basic(void)
{
	TEST("lota_token_serialize - basic roundtrip");

	struct lota_token token;
	memset(&token, 0, sizeof(token));
	token.runtime_protect_version = LOTA_RUNTIME_PROTECT_V1;
	token.valid_until = 1700003600;
	token.flags = 0x07;
	token.sig_alg = 0x0014;
	token.hash_alg = 0x000B;
	token.pcr_mask = 0x4001;

	uint8_t fake_attest[64] = { 0xAA };
	uint8_t fake_sig[32] = { 0xBB };
	token.attest_data = fake_attest;
	token.attest_size = sizeof(fake_attest);
	token.signature = fake_sig;
	token.signature_len = sizeof(fake_sig);

	size_t expected = lota_token_serialized_size(&token);
	if (expected != LOTA_TOKEN_HEADER_SIZE + 64 + 32) {
		char msg[64];
		snprintf(msg, sizeof(msg), "size=%zu, expected=%zu", expected,
			 (size_t)LOTA_TOKEN_HEADER_SIZE + 64 + 32);
		FAIL(msg);
		return;
	}

	uint8_t buf[256];
	size_t written = 0;
	int ret = lota_token_serialize(&token, buf, sizeof(buf), &written);
	if (ret != LOTA_OK || written != expected) {
		FAIL("serialize failed or wrong size");
		return;
	}

	uint32_t magic;
	memcpy(&magic, buf, 4);
	if (magic != 0x4B544F4C) {
		FAIL("bad magic");
		return;
	}

	PASS();
}

static void test_serialize_buffer_too_small(void)
{
	TEST("lota_token_serialize - buffer too small");

	struct lota_token token;
	memset(&token, 0, sizeof(token));
	token.runtime_protect_version = LOTA_RUNTIME_PROTECT_V1;
	uint8_t fake[16] = { 0 };
	token.attest_data = fake;
	token.attest_size = 16;
	token.signature = fake;
	token.signature_len = 16;

	uint8_t tiny[10];
	int ret = lota_token_serialize(&token, tiny, sizeof(tiny), NULL);
	if (ret == LOTA_ERR_BUFFER_TOO_SMALL) {
		PASS();
	} else {
		FAIL("expected LOTA_ERR_BUFFER_TOO_SMALL");
	}
}

/*
 * Caller that zeroes its struct and forgets runtime_protect_version would otherwise
 * get a token every parser refuses, and would only find out at the far end.
 * Serializer names the fault at the point it is made.
 */
static void test_serialize_requires_protect_version(void)
{
	TEST("lota_token_serialize - unset runtime_protect_version rejected");

	struct lota_token token;
	memset(&token, 0, sizeof(token));
	uint8_t fake[16] = { 0 };
	token.attest_data = fake;
	token.attest_size = 16;
	token.signature = fake;
	token.signature_len = 16;

	uint8_t buf[512];
	size_t written = 0;

	/* left at 0 by the memset: refused */
	if (lota_token_serialize(&token, buf, sizeof(buf), &written) !=
	    LOTA_ERR_INVALID_ARG) {
		FAIL("expected LOTA_ERR_INVALID_ARG for an unset version");
		return;
	}

	/* out of range: refused too */
	token.runtime_protect_version = LOTA_RUNTIME_PROTECT_V1 + 1;
	if (lota_token_serialize(&token, buf, sizeof(buf), &written) !=
	    LOTA_ERR_INVALID_ARG) {
		FAIL("expected LOTA_ERR_INVALID_ARG for an unknown version");
		return;
	}

	/* named version serializes */
	token.runtime_protect_version = LOTA_RUNTIME_PROTECT_V1;
	if (lota_token_serialize(&token, buf, sizeof(buf), &written) !=
	    LOTA_OK) {
		FAIL("token failed to serialize");
		return;
	}
	PASS();
}

static void test_serialize_total_size_within_u16(void)
{
	TEST("lota_token_serialize - total_size stays within uint16 wire field");

	struct lota_token token;
	memset(&token, 0, sizeof(token));
	token.runtime_protect_version = LOTA_RUNTIME_PROTECT_V1;
	token.valid_until = 1700003600;
	token.flags = 0x07;
	token.sig_alg = 0x0014;
	token.hash_alg = 0x000B;
	token.pcr_mask = 0x4001;

	uint8_t max_attest[1024] = { 0 };
	uint8_t max_sig[512] = { 0 };
	token.attest_data = max_attest;
	token.attest_size = sizeof(max_attest);
	token.signature = max_sig;
	token.signature_len = sizeof(max_sig);

	size_t expected = lota_token_serialized_size(&token);
	if (expected == 0 || expected > 0xFFFFu) {
		FAIL("serialized size exceeds uint16 wire capacity");
		return;
	}

	uint8_t buf[2048];
	size_t written = 0;
	int ret = lota_token_serialize(&token, buf, sizeof(buf), &written);
	if (ret != LOTA_OK || written != expected) {
		FAIL("serialize failed at max supported sizes");
		return;
	}

	{
		uint16_t wire_total = (uint16_t)buf[6] |
				      ((uint16_t)buf[7] << 8);
		if ((size_t)wire_total != expected) {
			FAIL("wire total_size mismatch");
			return;
		}
	}

	PASS();
}

static void test_parse_untrusted(void)
{
	TEST("lota_server_parse_token - untrusted parse");

	struct lota_token token;
	memset(&token, 0, sizeof(token));
	token.runtime_protect_version = LOTA_RUNTIME_PROTECT_V1;
	token.valid_until = 1700003600;
	token.flags = 0x1F;
	memset(token.nonce, 0x42, 32);
	token.sig_alg = 0x0014;
	token.hash_alg = 0x000B;
	token.pcr_mask = 0x4001;

	uint8_t fake_attest[32] = { 0 };
	token.attest_data = fake_attest;
	token.attest_size = sizeof(fake_attest);
	uint8_t fake_sig[32] = { 0 };
	token.signature = fake_sig;
	token.signature_len = sizeof(fake_sig);

	uint8_t buf[256];
	size_t written;
	lota_token_serialize(&token, buf, sizeof(buf), &written);

	struct lota_server_claims claims;
	int ret = lota_server_parse_token(buf, written, &claims);
	if (ret != LOTA_SERVER_OK) {
		char msg[64];
		snprintf(msg, sizeof(msg), "parse returned %d: %s", ret,
			 lota_server_strerror(ret));
		FAIL(msg);
		return;
	}

	if (claims.valid_until != 1700003600 || claims.flags != 0x1F ||
	    claims.pcr_mask != 0x4001) {
		FAIL("claims mismatch");
		return;
	}

	if (claims.nonce[0] != 0x42) {
		FAIL("nonce not echoed");
		return;
	}

	PASS();
}

static void test_verify_full_success(EVP_PKEY *key, const uint8_t *aik_der,
				     size_t aik_len)
{
	TEST("lota_server_verify_token - full success");

	uint64_t now = (uint64_t)time(NULL);
	uint8_t nonce[32] = { 0xDE, 0xAD, 0xBE, 0xEF };

	uint8_t tokbuf[2048];
	size_t tok_written;
	int ret = forge_token_sha256(key, now + LOTA_SERVER_MAX_TOKEN_AGE_SEC,
				     0x07, nonce, tokbuf, sizeof(tokbuf),
				     &tok_written);
	if (ret != LOTA_OK) {
		FAIL("build_full_token failed");
		return;
	}

	struct lota_server_claims claims;
	ret = lota_server_verify_token(tokbuf, tok_written, aik_der, aik_len,
				       nonce, &claims);
	if (ret != LOTA_SERVER_OK) {
		char msg[128];
		snprintf(msg, sizeof(msg), "verify returned %d: %s", ret,
			 lota_server_strerror(ret));
		FAIL(msg);
		return;
	}

	if (claims.expired) {
		FAIL("should not be expired");
		return;
	}
	if (claims.flags != 0x07) {
		FAIL("flags mismatch");
		return;
	}
	if (claims.pcr_digest_len != 32) {
		char msg[64];
		snprintf(msg, sizeof(msg), "pcr_digest_len=%zu, want 32",
			 claims.pcr_digest_len);
		FAIL(msg);
		return;
	}

	PASS();
}

static void test_verify_full_success_sha384(EVP_PKEY *key,
					    const uint8_t *aik_der,
					    size_t aik_len)
{
	TEST("lota_server_verify_token - SHA-384 hash_alg");

	uint64_t now = (uint64_t)time(NULL);
	uint8_t nonce[32] = { 0xDE, 0xAD, 0xBE, 0xEF };

	uint8_t tokbuf[2048];
	size_t tok_written;
	int ret = forge_token(key, 0x000C, EVP_sha384(),
			      now + LOTA_SERVER_MAX_TOKEN_AGE_SEC, 0x07, nonce,
			      tokbuf, sizeof(tokbuf), &tok_written);
	if (ret != LOTA_OK) {
		FAIL("forge_token(SHA-384) failed");
		return;
	}

	struct lota_server_claims claims;
	ret = lota_server_verify_token(tokbuf, tok_written, aik_der, aik_len,
				       nonce, &claims);
	if (ret != LOTA_SERVER_OK) {
		char msg[128];
		snprintf(msg, sizeof(msg), "verify returned %d: %s", ret,
			 lota_server_strerror(ret));
		FAIL(msg);
		return;
	}

	if (claims.pcr_digest_len != 48) {
		char msg[64];
		snprintf(msg, sizeof(msg), "pcr_digest_len=%zu, want 48",
			 claims.pcr_digest_len);
		FAIL(msg);
		return;
	}

	PASS();
}

static void test_verify_full_success_sha512(EVP_PKEY *key,
					    const uint8_t *aik_der,
					    size_t aik_len)
{
	TEST("lota_server_verify_token - SHA-512 hash_alg");

	uint64_t now = (uint64_t)time(NULL);
	uint8_t nonce[32] = { 0xDE, 0xAD, 0xBE, 0xEF };

	uint8_t tokbuf[2048];
	size_t tok_written;
	int ret = forge_token(key, 0x000D, EVP_sha512(),
			      now + LOTA_SERVER_MAX_TOKEN_AGE_SEC, 0x07, nonce,
			      tokbuf, sizeof(tokbuf), &tok_written);
	if (ret != LOTA_OK) {
		FAIL("forge_token(SHA-512) failed");
		return;
	}

	struct lota_server_claims claims;
	ret = lota_server_verify_token(tokbuf, tok_written, aik_der, aik_len,
				       nonce, &claims);
	if (ret != LOTA_SERVER_OK) {
		char msg[128];
		snprintf(msg, sizeof(msg), "verify returned %d: %s", ret,
			 lota_server_strerror(ret));
		FAIL(msg);
		return;
	}

	if (claims.pcr_digest_len != 64) {
		char msg[64];
		snprintf(msg, sizeof(msg), "pcr_digest_len=%zu, want 64",
			 claims.pcr_digest_len);
		FAIL(msg);
		return;
	}

	PASS();
}

static void test_verify_with_expected_nonce(EVP_PKEY *key,
					    const uint8_t *aik_der,
					    size_t aik_len)
{
	TEST("lota_server_verify_token — correct expected_nonce");

	uint64_t now = (uint64_t)time(NULL);
	uint8_t nonce[32] = { 0x01, 0x02, 0x03 };

	uint8_t tokbuf[2048];
	size_t tok_written = 0;
	int ret = forge_token_sha256(key, now + LOTA_SERVER_MAX_TOKEN_AGE_SEC,
				     0, nonce, tokbuf, sizeof(tokbuf),
				     &tok_written);
	if (ret != LOTA_OK) {
		FAIL("build_full_token failed");
		return;
	}

	struct lota_server_claims claims;
	ret = lota_server_verify_token(tokbuf, tok_written, aik_der, aik_len,
				       nonce, &claims);
	if (ret != LOTA_SERVER_OK) {
		FAIL("should pass with correct nonce");
		return;
	}

	PASS();
}

static void test_verify_wrong_nonce(EVP_PKEY *key, const uint8_t *aik_der,
				    size_t aik_len)
{
	TEST("lota_server_verify_token — wrong expected_nonce → NONCE_FAIL");

	uint64_t now = (uint64_t)time(NULL);
	uint8_t nonce[32] = { 0x01, 0x02, 0x03 };

	uint8_t tokbuf[2048];
	size_t tok_written = 0;
	int ret = forge_token_sha256(key, now + LOTA_SERVER_MAX_TOKEN_AGE_SEC,
				     0, nonce, tokbuf, sizeof(tokbuf),
				     &tok_written);
	if (ret != LOTA_OK) {
		FAIL("build_full_token failed");
		return;
	}

	uint8_t wrong_nonce[32] = { 0xFF, 0xFF, 0xFF };
	struct lota_server_claims claims;
	ret = lota_server_verify_token(tokbuf, tok_written, aik_der, aik_len,
				       wrong_nonce, &claims);
	if (ret == LOTA_SERVER_ERR_NONCE_FAIL) {
		PASS();
	} else {
		char msg[64];
		snprintf(msg, sizeof(msg), "expected NONCE_FAIL, got %d", ret);
		FAIL(msg);
	}
}

static void test_verify_bad_signature(EVP_PKEY *key, const uint8_t *aik_der,
				      size_t aik_len)
{
	TEST("lota_server_verify_token — wrong AIK key → SIG_FAIL");
	(void)key; /* original key, not used directly */

	/* DIFFERENT key to sign with */
	EVP_PKEY *wrong_key = forge_rsa_key();

	uint64_t now = (uint64_t)time(NULL);
	uint8_t nonce[32] = { 0 };

	uint8_t tokbuf[2048];
	size_t tok_written = 0;
	/* sign with wrong_key, but verify with original aik_der */
	int ret = forge_token_sha256(wrong_key,
				     now + LOTA_SERVER_MAX_TOKEN_AGE_SEC, 0,
				     nonce, tokbuf, sizeof(tokbuf),
				     &tok_written);
	if (ret != LOTA_OK) {
		EVP_PKEY_free(wrong_key);
		FAIL("build_full_token failed");
		return;
	}

	struct lota_server_claims claims;
	ret = lota_server_verify_token(tokbuf, tok_written, aik_der, aik_len,
				       nonce, &claims);
	EVP_PKEY_free(wrong_key);

	if (ret == LOTA_SERVER_ERR_SIG_FAIL) {
		PASS();
	} else {
		char msg[64];
		snprintf(msg, sizeof(msg), "expected SIG_FAIL, got %d", ret);
		FAIL(msg);
	}
}

static void test_verify_tampered_flags(EVP_PKEY *key, const uint8_t *aik_der,
				       size_t aik_len)
{
	TEST("lota_server_verify_token - tampered flags → NONCE_FAIL");

	uint64_t now = (uint64_t)time(NULL);
	uint8_t nonce[32] = { 0 };

	uint8_t tokbuf[2048];
	size_t tok_written = 0;
	int ret = forge_token_sha256(key, now + LOTA_SERVER_MAX_TOKEN_AGE_SEC,
				     0x07, nonce, tokbuf, sizeof(tokbuf),
				     &tok_written);
	if (ret != LOTA_OK) {
		FAIL("build_full_token failed");
		return;
	}

	/* tamper: change flags from 0x07 to 0xFF in wire (offset 16) */
	tokbuf[16] = 0xFF;

	struct lota_server_claims claims;
	ret = lota_server_verify_token(tokbuf, tok_written, aik_der, aik_len,
				       nonce, &claims);
	if (ret == LOTA_SERVER_ERR_NONCE_FAIL) {
		PASS();
	} else {
		char msg[64];
		snprintf(msg, sizeof(msg), "expected NONCE_FAIL, got %d", ret);
		FAIL(msg);
	}
}

static void test_verify_tampered_pcr_mask(EVP_PKEY *key, const uint8_t *aik_der,
					  size_t aik_len)
{
	TEST("lota_server_verify_token - tampered pcr_mask → NONCE_FAIL");

	uint64_t now = (uint64_t)time(NULL);
	uint8_t nonce[32] = { 0 };

	uint8_t tokbuf[2048];
	size_t tok_written = 0;
	int ret = forge_token_sha256(key, now + LOTA_SERVER_MAX_TOKEN_AGE_SEC,
				     0x07, nonce, tokbuf, sizeof(tokbuf),
				     &tok_written);
	if (ret != LOTA_OK) {
		FAIL("build_full_token failed");
		return;
	}

	/* tamper: change pcr_mask from 0x4001 to 0x0001 in wire (offset 56 LE)
	 */
	tokbuf[56] = 0x01;
	tokbuf[57] = 0x00;
	tokbuf[58] = 0x00;
	tokbuf[59] = 0x00;

	struct lota_server_claims claims;
	ret = lota_server_verify_token(tokbuf, tok_written, aik_der, aik_len,
				       nonce, &claims);
	if (ret == LOTA_SERVER_ERR_NONCE_FAIL) {
		PASS();
	} else {
		char msg[64];
		snprintf(msg, sizeof(msg), "expected NONCE_FAIL, got %d", ret);
		FAIL(msg);
	}
}

static void test_verify_mixed_pcr_banks_rejected(EVP_PKEY *key,
						 const uint8_t *aik_der,
						 size_t aik_len)
{
	TEST("lota_server_verify_token - mixed PCR banks -> ERR_ATTEST_PARSE");

	uint64_t now = (uint64_t)time(NULL);
	uint64_t valid_until = now + LOTA_SERVER_MAX_TOKEN_AGE_SEC;
	uint32_t flags = 0x07;
	uint32_t pcr_mask_union = 0x0007; /* SHA-1: PCR0, SHA-256: PCR1|PCR2 */
	uint8_t nonce[32] = { 0 };
	uint8_t policy_digest[32] = { 0x11, 0x22, 0x33 };
	uint8_t runtime_digest[32];
	uint8_t expected_nonce[32];
	uint8_t pcr_digest[32];
	uint8_t tokbuf[2048];
	size_t tok_written = 0;
	size_t attest_len = 0;
	size_t sig_len = 0;
	uint8_t *attest = NULL;
	uint8_t *sig = NULL;
	struct lota_server_claims claims;

	memset(pcr_digest, 0xDD, sizeof(pcr_digest));

	if (lota_compute_runtime_protect_digest(NULL, NULL, 0,
						runtime_digest) != 0) {
		FAIL("runtime digest compute failed");
		return;
	}

	if (forge_quote_nonce(valid_until, flags, pcr_mask_union, nonce,
			      policy_digest, runtime_digest, 0,
			      expected_nonce) != 0) {
		FAIL("expected nonce compute failed");
		return;
	}

	attest = forge_tpms_attest_mixed_banks(expected_nonce, 32, 0x0001,
					       0x0006, pcr_digest,
					       sizeof(pcr_digest), &attest_len);
	if (!attest) {
		FAIL("attest build failed");
		return;
	}

	sig = forge_sign(key, EVP_sha256(), attest, attest_len, &sig_len);
	if (!sig) {
		free(attest);
		FAIL("attest sign failed");
		return;
	}

	struct lota_token token;
	memset(&token, 0, sizeof(token));
	token.runtime_protect_version = LOTA_RUNTIME_PROTECT_V1;
	token.valid_until = valid_until;
	token.flags = flags;
	memcpy(token.nonce, nonce, sizeof(token.nonce));
	token.sig_alg = 0x0014; /* RSASSA */
	token.hash_alg = 0x000B; /* SHA-256 */
	token.pcr_mask = pcr_mask_union;
	memcpy(token.policy_digest, policy_digest, sizeof(token.policy_digest));
	memcpy(token.runtime_protect_digest, runtime_digest,
	       sizeof(token.runtime_protect_digest));
	token.runtime_protect_epoch = 0;
	token.protect_pid_count = 0;
	token.protected_pids = NULL;
	token.attest_data = attest;
	token.attest_size = attest_len;
	token.signature = sig;
	token.signature_len = sig_len;

	if (lota_token_serialize(&token, tokbuf, sizeof(tokbuf),
				 &tok_written) != LOTA_OK) {
		free(attest);
		free(sig);
		FAIL("token serialize failed");
		return;
	}

	int ret = lota_server_verify_token(tokbuf, tok_written, aik_der,
					   aik_len, nonce, &claims);
	free(attest);
	free(sig);

	if (ret == LOTA_SERVER_ERR_ATTEST_PARSE) {
		PASS();
	} else {
		char msg[80];
		snprintf(msg, sizeof(msg), "expected ERR_ATTEST_PARSE, got %d",
			 ret);
		FAIL(msg);
	}
}

static void test_verify_expired(EVP_PKEY *key, const uint8_t *aik_der,
				size_t aik_len)
{
	TEST("lota_server_verify_token - expired token -> ERR_EXPIRED");

	uint64_t now = (uint64_t)time(NULL);
	uint8_t nonce[32] = { 0 };

	uint8_t tokbuf[2048];
	size_t tok_written = 0;
	/* valid_until 1 hour AGO */
	int ret = forge_token_sha256(key, now - 3600, 0, nonce, tokbuf,
				     sizeof(tokbuf), &tok_written);
	if (ret != LOTA_OK) {
		FAIL("build_full_token failed");
		return;
	}

	struct lota_server_claims claims;
	ret = lota_server_verify_token(tokbuf, tok_written, aik_der, aik_len,
				       nonce, &claims);
	if (ret != LOTA_SERVER_ERR_EXPIRED) {
		char msg[64];
		snprintf(msg, sizeof(msg), "expected ERR_EXPIRED, got %d", ret);
		FAIL(msg);
		return;
	}
	if (!claims.expired) {
		FAIL("claims.expired should be 1");
		return;
	}
	PASS();
}

/*
 * The freshness window is the SDK's, not the caller's, and both implementations
 * of it have to accept the same set: token whose expiry is beyond one attestation
 * interval plus clock skew is refused here exactly as sdk/server refuses it in Go.
 * Sized just past the window so token that legitimate agent would mint still passes.
 */
static void test_verify_beyond_freshness_window(EVP_PKEY *key,
						const uint8_t *aik_der,
						size_t aik_len)
{
	TEST("lota_server_verify_token - beyond freshness window -> ERR_FUTURE");

	uint64_t now = (uint64_t)time(NULL);
	uint8_t nonce[32] = { 0 };

	uint8_t tokbuf[2048];
	size_t tok_written = 0;
	int ret = forge_token_sha256(
		key,
		now + (uint64_t)LOTA_SERVER_MAX_TOKEN_AGE_SEC +
			(uint64_t)LOTA_SERVER_MAX_CLOCK_SKEW_SEC + 60ULL,
		0, nonce, tokbuf, sizeof(tokbuf), &tok_written);
	if (ret != LOTA_OK) {
		FAIL("build_full_token failed");
		return;
	}

	struct lota_server_claims claims;
	ret = lota_server_verify_token(tokbuf, tok_written, aik_der, aik_len,
				       nonce, &claims);
	if (ret != LOTA_SERVER_ERR_FUTURE) {
		char msg[64];
		snprintf(msg, sizeof(msg), "expected ERR_FUTURE, got %d", ret);
		FAIL(msg);
		return;
	}
	PASS();
}

/* Token an agent on the default interval mints must stay acceptable */
static void test_verify_at_freshness_window(EVP_PKEY *key,
					    const uint8_t *aik_der,
					    size_t aik_len)
{
	TEST("lota_server_verify_token - default agent interval -> OK");

	uint64_t now = (uint64_t)time(NULL);
	uint8_t nonce[32] = { 0 };

	uint8_t tokbuf[2048];
	size_t tok_written = 0;
	int ret = forge_token_sha256(
		key, now + (uint64_t)LOTA_SERVER_MAX_TOKEN_AGE_SEC + 60ULL, 0,
		nonce, tokbuf, sizeof(tokbuf), &tok_written);
	if (ret != LOTA_OK) {
		FAIL("build_full_token failed");
		return;
	}

	struct lota_server_claims claims;
	ret = lota_server_verify_token(tokbuf, tok_written, aik_der, aik_len,
				       nonce, &claims);
	if (ret != LOTA_SERVER_OK) {
		char msg[64];
		snprintf(msg, sizeof(msg), "expected OK, got %d", ret);
		FAIL(msg);
		return;
	}
	PASS();
}

static void test_strerror_new_codes(void)
{
	TEST("lota_server_strerror - TOO_OLD and FUTURE codes");

	const char *s;
	int all_ok = 1;

	s = lota_server_strerror(LOTA_SERVER_ERR_EXPIRED);
	if (!s || strlen(s) == 0)
		all_ok = 0;

	s = lota_server_strerror(LOTA_SERVER_ERR_FUTURE);
	if (!s || strlen(s) == 0)
		all_ok = 0;

	if (all_ok) {
		PASS();
	} else {
		FAIL("some strerror returned NULL or empty for new codes");
	}
}

static void test_malformed_inputs(void)
{
	TEST("lota_server_verify_token - NULL inputs");
	struct lota_server_claims claims;
	int ret = lota_server_verify_token(NULL, 0, NULL, 0, NULL, &claims);
	if (ret == LOTA_SERVER_ERR_INVALID_ARG) {
		PASS();
	} else {
		FAIL("expected INVALID_ARG");
	}

	TEST("lota_server_verify_token - too short token");
	uint8_t tiny[10] = { 0 };
	uint8_t fake_key[16] = { 0 };
	uint8_t expected_nonce[32] = { 0 };
	ret = lota_server_verify_token(tiny, sizeof(tiny), fake_key,
				       sizeof(fake_key), expected_nonce,
				       &claims);
	if (ret == LOTA_SERVER_ERR_BAD_TOKEN) {
		PASS();
	} else {
		char msg[64];
		snprintf(msg, sizeof(msg), "expected BAD_TOKEN, got %d", ret);
		FAIL(msg);
	}

	TEST("lota_server_verify_token - bad magic");
	uint8_t bad_magic[128] = { 0 };
	bad_magic[0] = 0xDE;
	bad_magic[1] = 0xAD;
	ret = lota_server_verify_token(bad_magic, sizeof(bad_magic), fake_key,
				       sizeof(fake_key), expected_nonce,
				       &claims);
	if (ret == LOTA_SERVER_ERR_BAD_TOKEN) {
		PASS();
	} else {
		FAIL("expected BAD_TOKEN for bad magic");
	}
}

static void test_unknown_hash_alg_rejected(EVP_PKEY *key,
					   const uint8_t *aik_der,
					   size_t aik_len)
{
	TEST("lota_server_verify_token - unknown hash_alg rejected");

	uint8_t nonce[32] = { 0 };
	uint8_t tokbuf[2048];
	size_t tok_written = 0;
	struct lota_server_claims claims;

	if (forge_token_sha256(key, (uint64_t)time(NULL) + 3600, 0, nonce,
			       tokbuf, sizeof(tokbuf),
			       &tok_written) != LOTA_OK) {
		FAIL("build_full_token_sha256 failed");
		return;
	}

	/* token header hash_alg field at offset 54 (little-endian) */
	tokbuf[54] = 0x34;
	tokbuf[55] = 0x12;

	int ret = lota_server_verify_token(tokbuf, tok_written, aik_der,
					   aik_len, nonce, &claims);
	if (ret == LOTA_SERVER_ERR_BAD_TOKEN) {
		PASS();
	} else {
		char msg[64];
		snprintf(msg, sizeof(msg), "expected BAD_TOKEN, got %d", ret);
		FAIL(msg);
	}

	TEST("lota_server_parse_token - unknown hash_alg rejected");

	struct lota_server_claims parsed;
	ret = lota_server_parse_token(tokbuf, tok_written, &parsed);
	if (ret == LOTA_SERVER_ERR_BAD_TOKEN) {
		PASS();
	} else {
		char msg[64];
		snprintf(msg, sizeof(msg), "expected BAD_TOKEN, got %d", ret);
		FAIL(msg);
	}
}

static void test_strerror(void)
{
	TEST("lota_server_strerror - all error codes");

	const char *s;
	int all_ok = 1;

	s = lota_server_strerror(LOTA_SERVER_OK);
	if (!s || strlen(s) == 0)
		all_ok = 0;

	s = lota_server_strerror(LOTA_SERVER_ERR_SIG_FAIL);
	if (!s || strlen(s) == 0)
		all_ok = 0;

	s = lota_server_strerror(LOTA_SERVER_ERR_NONCE_FAIL);
	if (!s || strlen(s) == 0)
		all_ok = 0;

	s = lota_server_strerror(LOTA_SERVER_ERR_ATTEST_PARSE);
	if (!s || strlen(s) == 0)
		all_ok = 0;

	s = lota_server_strerror(-999);
	if (!s || strlen(s) == 0)
		all_ok = 0;

	if (all_ok) {
		PASS();
	} else {
		FAIL("some strerror returned NULL or empty");
	}
}

static void test_sdk_version(void)
{
	TEST("lota_server_sdk_version - returns version string");

	const char *v = lota_server_sdk_version();
	if (v && v[0] != '\0') {
		PASS();
	} else {
		FAIL(v ? "empty" : "NULL");
	}
}

/*
 * Pending-update flag has to be reportable and must not collide with existing bit:
 * it rides in the same word the token carries, and collision would silently turn
 * one condition into another.
 */
static void test_update_pending_flag_is_distinct_and_named(void)
{
	TEST("LOTA_FLAG_UPDATE_PENDING - distinct bit, rendered by name");

	const uint32_t others = LOTA_FLAG_ATTESTED | LOTA_FLAG_TPM_OK |
				LOTA_FLAG_IOMMU_OK | LOTA_FLAG_BPF_LOADED |
				LOTA_FLAG_SECURE_BOOT;
	char buf[128];

	if (LOTA_FLAG_UPDATE_PENDING & others) {
		FAIL("collides with an existing status flag");
		return;
	}

	int n = lota_flags_to_string(LOTA_FLAG_ATTESTED |
					     LOTA_FLAG_UPDATE_PENDING,
				     buf, sizeof(buf));
	if (n < 0) {
		FAIL("lota_flags_to_string failed");
		return;
	}
	if (!strstr(buf, "UPDATE_PENDING")) {
		FAIL("flag is not rendered by name");
		return;
	}
	/* attested machine with update pending is still attested */
	if (!strstr(buf, "ATTESTED")) {
		FAIL("pending update masked the attested flag");
		return;
	}
	PASS();
}

/*
 * Both libraries report the build they were compiled from,
 * so they must report the same one.
 * Caller correlating a heartbeat with the client that produced it reads one of
 * these and cannot tell which.
 */
static void test_sdk_version_agrees_across_libraries(void)
{
	TEST("SDK version - gaming and server report the same build");

	const char *gaming = lota_sdk_version();
	const char *server = lota_server_sdk_version();

	if (!gaming || !server) {
		FAIL("NULL version string");
		return;
	}
	if (strcmp(gaming, server) != 0) {
		FAIL("gaming and server report different versions");
		return;
	}
	PASS();
}

/*
 * Version identifies a build for an advisory, a support ticket
 * or reproducible-build check, so library that cannot name its build is worse
 * than one that fails to compile.
 */
static void test_sdk_version_is_a_real_build(void)
{
	TEST("SDK version - names a build, not a placeholder");

	const char *v = lota_server_sdk_version();

	if (!v || v[0] == '\0') {
		FAIL(v ? "empty" : "NULL");
		return;
	}
	if (strcmp(v, "unknown") == 0) {
		FAIL("built without a version string");
		return;
	}
	PASS();
}

/* Append @n bytes of @v little-endian to @b at *@off. */
static void put_le(uint8_t *b, size_t *off, uint64_t v, int n)
{
	for (int i = 0; i < n; i++)
		b[(*off)++] = (uint8_t)(v >> (8 * i));
}

/*
 * A relying party hashes a fetched registry and compares the result with
 * the image digest the token carries, so the hash must be the documented
 * one: every object in list order, those without a digest included.
 */
static void test_registry_digest(void)
{
	uint8_t d1[32], d2[64];
	struct lota_server_registry_module mods[] = {
		{ "libc.so.6", "/usr/lib64/libc.so.6", 2048, 0x803, 17,
		  LOTA_REGISTRY_ROAD_VERITY, 0, sizeof(d2), d2 },
		{ "title.exe", "/opt/title/title.exe", 4096, 0x803, 42,
		  LOTA_REGISTRY_ROAD_NONE, 0, 0, NULL },
		{ "inject.so", NULL, 512, 0x2a, 7, LOTA_REGISTRY_ROAD_NONE,
		  LOTA_REGISTRY_OBJECT_UNMAPPED, 0, NULL },
		{ "libz.so.1", "/usr/lib64/libz.so.1", 1024, 0x803, 18,
		  LOTA_REGISTRY_ROAD_CONTENT, 0, sizeof(d1), d1 },
	};
	struct lota_server_registry_peer peers[] = {
		{ 3, 912345, 0x803, 99, 4242, 1000, 4100,
		  LOTA_REGISTRY_PEER_CONNECT, "injector", "wineserver" },
		{ 1, 912400, 0x803, 100, 4250, 1000, 4100,
		  LOTA_REGISTRY_PEER_SEND, "probe", "wineserver" },
	};
	const uint32_t flags = LOTA_REGISTRY_MEASURED;
	uint8_t buf[1024];
	uint8_t want[32], got[32], other[32];
	unsigned int wlen = 0;
	size_t off = 0;

	memset(d1, 0x11, sizeof(d1));
	memset(d2, 0x22, sizeof(d2));

	/* the layout of lota_registry_digest.h, spelled out */
	memcpy(buf, "lota-runtime-registry:v1", 25);
	off = 25;
	put_le(buf, &off, flags, 2);
	put_le(buf, &off, 4, 4);
	put_le(buf, &off, 2, 4);
	for (size_t i = 0; i < 4; i++) {
		const struct lota_server_registry_module *m = &mods[i];
		size_t slen = strlen(m->soname);
		size_t plen = m->path ? strlen(m->path) : 0;

		put_le(buf, &off, m->size, 8);
		put_le(buf, &off, m->dev, 8);
		put_le(buf, &off, m->ino, 8);
		buf[off++] = (uint8_t)m->road;
		buf[off++] = (uint8_t)m->digest_len;
		put_le(buf, &off, slen, 2);
		put_le(buf, &off, plen, 2);
		put_le(buf, &off, m->flags, 2);
		if (m->digest_len)
			memcpy(buf + off, m->digest, m->digest_len);
		off += m->digest_len;
		memcpy(buf + off, m->soname, slen);
		off += slen;
		if (plen)
			memcpy(buf + off, m->path, plen);
		off += plen;
	}
	for (size_t i = 0; i < 2; i++) {
		const struct lota_server_registry_peer *q = &peers[i];

		put_le(buf, &off, q->count, 8);
		put_le(buf, &off, q->start_ticks, 8);
		put_le(buf, &off, q->exe_dev, 8);
		put_le(buf, &off, q->exe_ino, 8);
		put_le(buf, &off, q->tgid, 4);
		put_le(buf, &off, q->uid, 4);
		put_le(buf, &off, q->owner_tgid, 4);
		put_le(buf, &off, q->kind, 4);
		memset(buf + off, 0, 32);
		memcpy(buf + off, q->comm, strlen(q->comm));
		memcpy(buf + off + 16, q->owner_comm, strlen(q->owner_comm));
		off += 32;
	}

	TEST("registry_digest hashes the documented layout");
	if (EVP_Digest(buf, off, want, &wlen, EVP_sha256(), NULL) != 1 ||
	    lota_server_registry_digest(flags, mods, 4, peers, 2, got) !=
		    LOTA_SERVER_OK ||
	    memcmp(want, got, sizeof(got)) != 0)
		FAIL("digest differs from the documented layout");
	else
		PASS();

	TEST("registry_digest binds what the list leaves out");
	{
		struct lota_server_registry_module swapped[4];
		struct lota_server_registry_module cut[3] = { mods[0], mods[1],
							      mods[3] };
		struct lota_server_registry_module edit[4];
		int ok = 1;

		/* an object without a digest dropped */
		ok &= lota_server_registry_digest(flags, cut, 3, peers, 2,
						  other) == LOTA_SERVER_OK &&
		      memcmp(other, got, sizeof(got)) != 0;
		/* reordered */
		memcpy(swapped, mods, sizeof(mods));
		swapped[0] = mods[3];
		swapped[3] = mods[0];
		ok &= lota_server_registry_digest(flags, swapped, 4, peers, 2,
						  other) == LOTA_SERVER_OK &&
		      memcmp(other, got, sizeof(got)) != 0;
		/* an unmapped object passed off as mapped */
		memcpy(edit, mods, sizeof(mods));
		edit[2].flags = 0;
		ok &= lota_server_registry_digest(flags, edit, 4, peers, 2,
						  other) == LOTA_SERVER_OK &&
		      memcmp(other, got, sizeof(got)) != 0;
		/* a path rewritten */
		memcpy(edit, mods, sizeof(mods));
		edit[1].path = "/opt/title/other.exe";
		ok &= lota_server_registry_digest(flags, edit, 4, peers, 2,
						  other) == LOTA_SERVER_OK &&
		      memcmp(other, got, sizeof(got)) != 0;
		/* a lost history hidden */
		ok &= lota_server_registry_digest(
			      flags | LOTA_REGISTRY_HISTORY_LOST, mods, 4,
			      peers, 2, other) == LOTA_SERVER_OK &&
		      memcmp(other, got, sizeof(got)) != 0;
		/* a peer dropped */
		ok &= lota_server_registry_digest(flags, mods, 4, peers, 1,
						  other) == LOTA_SERVER_OK &&
		      memcmp(other, got, sizeof(got)) != 0;
		/* a lost peer hidden */
		ok &= lota_server_registry_digest(
			      flags | LOTA_REGISTRY_PEERS_LOST, mods, 4, peers,
			      2, other) == LOTA_SERVER_OK &&
		      memcmp(other, got, sizeof(got)) != 0;
		{
			struct lota_server_registry_peer pe[2] = { peers[0],
								   peers[1] };

			/* a peer passed off as another executable */
			pe[0].exe_ino = 1;
			ok &= lota_server_registry_digest(flags, mods, 4, pe, 2,
							  other) ==
				      LOTA_SERVER_OK &&
			      memcmp(other, got, sizeof(got)) != 0;
			/* fewer contacts claimed */
			pe[0] = peers[0];
			pe[0].count = 1;
			ok &= lota_server_registry_digest(flags, mods, 4, pe, 2,
							  other) ==
				      LOTA_SERVER_OK &&
			      memcmp(other, got, sizeof(got)) != 0;
			/* bytes behind a name's NUL do not count */
			pe[0] = peers[0];
			pe[0].comm[14] = 'x';
			ok &= lota_server_registry_digest(flags, mods, 4, pe, 2,
							  other) ==
				      LOTA_SERVER_OK &&
			      memcmp(other, got, sizeof(got)) == 0;
		}
		/* NULL and empty path are one and the same */
		memcpy(edit, mods, sizeof(mods));
		edit[2].path = "";
		ok &= lota_server_registry_digest(flags, edit, 4, peers, 2,
						  other) == LOTA_SERVER_OK &&
		      memcmp(other, got, sizeof(got)) == 0;
		if (ok)
			PASS();
		else
			FAIL("an edit to the list kept the digest");
	}

	TEST("registry_digest refuses malformed modules");
	{
		struct lota_server_registry_module bad = mods[0];
		int ok = lota_server_registry_digest(flags, mods, 1, NULL, 0,
						     NULL) ==
				 LOTA_SERVER_ERR_INVALID_ARG &&
			 lota_server_registry_digest(flags, NULL, 1, NULL, 0,
						     got) ==
				 LOTA_SERVER_ERR_INVALID_ARG &&
			 lota_server_registry_digest(1U << 7, mods, 1, NULL, 0,
						     got) ==
				 LOTA_SERVER_ERR_INVALID_ARG;

		bad.digest_len = 20;
		ok = ok && lota_server_registry_digest(flags, &bad, 1, NULL, 0,
						       got) ==
				   LOTA_SERVER_ERR_INVALID_ARG;
		bad = mods[0];
		bad.soname = "";
		ok = ok && lota_server_registry_digest(flags, &bad, 1, NULL, 0,
						       got) ==
				   LOTA_SERVER_ERR_INVALID_ARG;
		bad = mods[0];
		bad.digest = NULL;
		ok = ok && lota_server_registry_digest(flags, &bad, 1, NULL, 0,
						       got) ==
				   LOTA_SERVER_ERR_INVALID_ARG;
		bad = mods[0];
		bad.road = 3;
		ok = ok && lota_server_registry_digest(flags, &bad, 1, NULL, 0,
						       got) ==
				   LOTA_SERVER_ERR_INVALID_ARG;
		bad = mods[1];
		bad.digest_len = 32;
		bad.digest = d1;
		ok = ok && lota_server_registry_digest(flags, &bad, 1, NULL, 0,
						       got) ==
				   LOTA_SERVER_ERR_INVALID_ARG;
		bad = mods[0];
		bad.flags = 1U << 4;
		ok = ok && lota_server_registry_digest(flags, &bad, 1, NULL, 0,
						       got) ==
				   LOTA_SERVER_ERR_INVALID_ARG;
		ok = ok &&
		     lota_server_registry_digest(
			     flags, mods, LOTA_SERVER_REGISTRY_MAX_OBJECTS + 1,
			     NULL, 0, got) == LOTA_SERVER_ERR_INVALID_ARG;
		if (ok)
			PASS();
		else
			FAIL("accepted a malformed module");
	}

	TEST("registry_digest refuses malformed peers");
	{
		struct lota_server_registry_peer bad = peers[0];
		int ok = lota_server_registry_digest(flags, mods, 4, NULL, 1,
						     got) ==
			 LOTA_SERVER_ERR_INVALID_ARG;

		bad.kind = 0;
		ok = ok && lota_server_registry_digest(flags, mods, 4, &bad, 1,
						       got) ==
				   LOTA_SERVER_ERR_INVALID_ARG;
		bad.kind = 3;
		ok = ok && lota_server_registry_digest(flags, mods, 4, &bad, 1,
						       got) ==
				   LOTA_SERVER_ERR_INVALID_ARG;
		bad = peers[0];
		memset(bad.comm, 'a', sizeof(bad.comm));
		ok = ok && lota_server_registry_digest(flags, mods, 4, &bad, 1,
						       got) ==
				   LOTA_SERVER_ERR_INVALID_ARG;
		bad = peers[0];
		memset(bad.owner_comm, 'a', sizeof(bad.owner_comm));
		ok = ok && lota_server_registry_digest(flags, mods, 4, &bad, 1,
						       got) ==
				   LOTA_SERVER_ERR_INVALID_ARG;
		ok = ok && lota_server_registry_digest(
				   flags, mods, 4, peers,
				   LOTA_SERVER_REGISTRY_MAX_PEERS + 1,
				   got) == LOTA_SERVER_ERR_INVALID_ARG;
		if (ok)
			PASS();
		else
			FAIL("accepted a malformed peer");
	}
}

int main(void)
{
	printf(BOLD "\n=== LOTA Server SDK - Test Suite ===\n\n" RESET);

	/* test RSA-2048 key pair */
	printf(YELLOW "Generating RSA-2048 test key pair..." RESET "\n");
	EVP_PKEY *key = forge_rsa_key();
	if (!key) {
		fprintf(stderr, "Failed to generate RSA key\n");
		return 1;
	}

	/* public key as DER */
	size_t aik_len = 0;
	uint8_t *aik_der = forge_pubkey_der(key, &aik_len);
	if (!aik_der) {
		fprintf(stderr, "Failed to export public key\n");
		return 1;
	}
	printf(YELLOW "AIK public key: %zu bytes (DER/PKIX)\n\n" RESET,
	       aik_len);

	printf(BOLD "Serialization (Gaming SDK):\n" RESET);
	test_serialize_basic();
	test_serialize_buffer_too_small();
	test_serialize_total_size_within_u16();

	printf(BOLD "\nParsing (Server SDK - untrusted):\n" RESET);
	test_parse_untrusted();

	printf(BOLD
	       "\nFull Verification (Server SDK - RSA + nonce binding):\n" RESET);
	test_verify_full_success(key, aik_der, aik_len);
	test_verify_full_success_sha384(key, aik_der, aik_len);
	test_verify_full_success_sha512(key, aik_der, aik_len);
	test_verify_with_expected_nonce(key, aik_der, aik_len);

	printf(BOLD "\nRejection Scenarios:\n" RESET);
	test_verify_wrong_nonce(key, aik_der, aik_len);
	test_verify_bad_signature(key, aik_der, aik_len);
	test_verify_tampered_flags(key, aik_der, aik_len);
	test_verify_tampered_pcr_mask(key, aik_der, aik_len);
	test_verify_tampered_image_digest_is_named(key, aik_der, aik_len);
	test_verify_mixed_pcr_banks_rejected(key, aik_der, aik_len);
	test_verify_expired(key, aik_der, aik_len);
	test_verify_beyond_freshness_window(key, aik_der, aik_len);
	test_verify_at_freshness_window(key, aik_der, aik_len);

	printf(BOLD "\nEdge Cases & Error Handling:\n" RESET);
	test_malformed_inputs();
	test_serialize_requires_protect_version();
	test_unknown_hash_alg_rejected(key, aik_der, aik_len);
	test_strerror();
	test_strerror_new_codes();
	test_sdk_version();
	test_update_pending_flag_is_distinct_and_named();
	test_sdk_version_agrees_across_libraries();
	test_sdk_version_is_a_real_build();
	test_registry_digest();

	printf(BOLD "\n=== Results: %d/%d passed" RESET, tests_pass, tests_run);
	if (tests_fail > 0) {
		printf(RED " (%d FAILED)" RESET, tests_fail);
	}
	printf("\n\n");

	free(aik_der);
	EVP_PKEY_free(key);

	return tests_fail > 0 ? 1 : 0;
}
