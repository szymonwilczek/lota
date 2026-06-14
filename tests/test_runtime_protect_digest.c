/* SPDX-License-Identifier: MIT */
/*
 * LOTA runtime protected-PID digest - Unit Tests
 *
 * Covers the v2 fold, which binds each protected PID together with its
 * kernel-anchored runtime image digest. Pins determinism, the documented
 * byte layout, sensitivity to PID set and per-PID image digest, the
 * canonical-order contract, and domain separation from v1.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <errno.h>
#include <openssl/types.h>

#include "lota_endian.h"
#include "lota_runtime_protect_digest.h"

static int tests_run;
static int tests_passed;

#define TEST(name)                                        \
	do {                                              \
		tests_run++;                              \
		printf("  [%2d] %-55s", tests_run, name); \
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

/* independent reference fold mirroring the documented v2 byte layout */
static int reference_v2(const uint32_t *pids, const uint8_t (*images)[32],
			uint32_t count, uint8_t out[32])
{
	static const char domain[] = "lota-runtime-protect-pids:v2\0";
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	unsigned int len = 0;
	uint8_t le[4];

	if (!ctx)
		return -1;
	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
	    EVP_DigestUpdate(ctx, domain, sizeof(domain) - 1) != 1)
		goto fail;
	lota__write_le32(le, count);
	if (EVP_DigestUpdate(ctx, le, 4) != 1)
		goto fail;
	for (uint32_t i = 0; i < count; i++) {
		lota__write_le32(le, pids[i]);
		if (EVP_DigestUpdate(ctx, le, 4) != 1 ||
		    EVP_DigestUpdate(ctx, images[i], 32) != 1)
			goto fail;
	}
	if (EVP_DigestFinal_ex(ctx, out, &len) != 1 || len != 32)
		goto fail;
	EVP_MD_CTX_free(ctx);
	return 0;
fail:
	EVP_MD_CTX_free(ctx);
	return -1;
}

int main(void)
{
	uint32_t pids[2] = { 1234, 5678 };
	uint8_t images[2][32];
	uint8_t a[32], b[32], ref[32];

	printf("Runtime protect digest (v2) tests:\n");

	memset(images[0], 0xa1, 32);
	memset(images[1], 0xb2, 32);

	TEST("v2 matches independent reference layout");
	if (lota_compute_runtime_protect_digest_v2(pids, images, 2, a) == 0 &&
	    reference_v2(pids, images, 2, ref) == 0 && memcmp(a, ref, 32) == 0)
		PASS();
	else
		FAIL("layout drift");

	TEST("v2 is deterministic");
	if (lota_compute_runtime_protect_digest_v2(pids, images, 2, b) == 0 &&
	    memcmp(a, b, 32) == 0)
		PASS();
	else
		FAIL("non-deterministic");

	TEST("PID change alters digest");
	pids[1] = 5679;
	if (lota_compute_runtime_protect_digest_v2(pids, images, 2, b) == 0 &&
	    memcmp(a, b, 32) != 0)
		PASS();
	else
		FAIL("pid not bound");
	pids[1] = 5678;

	TEST("image digest change alters digest");
	images[1][0] ^= 0xff;
	if (lota_compute_runtime_protect_digest_v2(pids, images, 2, b) == 0 &&
	    memcmp(a, b, 32) != 0)
		PASS();
	else
		FAIL("image digest not bound");
	images[1][0] ^= 0xff;

	TEST("PID count change alters digest");
	if (lota_compute_runtime_protect_digest_v2(pids, images, 1, b) == 0 &&
	    memcmp(a, b, 32) != 0)
		PASS();
	else
		FAIL("count not bound");

	TEST("v2 rejects unsorted PID list");
	{
		uint32_t bad[2] = { 5678, 1234 };
		if (lota_compute_runtime_protect_digest_v2(bad, images, 2, b) ==
		    -EINVAL)
			PASS();
		else
			FAIL("accepted unsorted");
	}

	TEST("v2 rejects NULL image array with non-zero count");
	if (lota_compute_runtime_protect_digest_v2(pids, NULL, 2, b) == -EINVAL)
		PASS();
	else
		FAIL("accepted NULL images");

	TEST("v2 empty set yields a defined digest");
	if (lota_compute_runtime_protect_digest_v2(NULL, NULL, 0, b) == 0 &&
	    reference_v2(NULL, NULL, 0, ref) == 0 && memcmp(b, ref, 32) == 0)
		PASS();
	else
		FAIL("empty set rejected");

	TEST("v2 is domain-separated from v1");
	{
		uint8_t zero[2][32] = { { 0 }, { 0 } };
		uint8_t v1[32], v2[32];
		if (lota_compute_runtime_protect_digest(pids, 2, v1) == 0 &&
		    lota_compute_runtime_protect_digest_v2(pids, zero, 2, v2) ==
			    0 &&
		    memcmp(v1, v2, 32) != 0)
			PASS();
		else
			FAIL("v1 and v2 collide");
	}

	TEST("v2 matches the cross-language known-answer vector");
	{
		/*
		 * Locks the C and Go v2 folds to the same bytes.
		 * pids {1,2}, image digests of 0xAA*32 and 0xBB*32
		 * Mirror in the Go verifier's TestRuntimeProtectDigestV2_KAT.
		 */
		static const uint8_t kat[32] = {
			0x8d, 0x45, 0x1c, 0x6d, 0x0e, 0x1e, 0xa5, 0x11,
			0xdf, 0xc0, 0xa0, 0x5c, 0x8b, 0xe3, 0x7f, 0x35,
			0x02, 0xc7, 0x3f, 0xfd, 0x7a, 0x06, 0x73, 0x6a,
			0x0a, 0xff, 0xbc, 0xe3, 0xdb, 0xd5, 0x1e, 0x9d
		};
		uint32_t kp[2] = { 1, 2 };
		uint8_t ki[2][32];
		memset(ki[0], 0xAA, 32);
		memset(ki[1], 0xBB, 32);
		if (lota_compute_runtime_protect_digest_v2(kp, ki, 2, b) == 0 &&
		    memcmp(b, kat, 32) == 0)
			PASS();
		else
			FAIL("KAT mismatch");
	}

	printf("\n%d/%d runtime protect digest tests passed\n", tests_passed,
	       tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
