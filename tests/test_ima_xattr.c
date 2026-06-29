/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Unit tests for the shared security.ima xattr signature-type predicate.
 *
 * Agent self-check and the installer's filesystem-integrity stage both use this
 * predicate to accept IMA appraisal as proof of binary immutability on
 * filesystems without fs-verity (XFS, ZFS, ...).
 * Only a signature variant binds the file content to a key in the .ima keyring;
 * bare digest can be recomputed by an offline attacker and must never count
 * as a signature.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "../include/lota_ima_xattr.h"

static int tests_run;
static int tests_passed;

#define TEST(name)                                         \
	do {                                               \
		tests_run++;                               \
		printf("  [%2d] %-55s ", tests_run, name); \
	} while (0)

#define PASS()                    \
	do {                      \
		tests_passed++;   \
		printf("PASS\n"); \
	} while (0)

#define FAIL(msg)                          \
	do {                               \
		printf("FAIL: %s\n", msg); \
	} while (0)

static void test_signature_types_accepted(void)
{
	const uint8_t digsig[] = { LOTA_IMA_XATTR_DIGSIG, 0x02, 0xab, 0xcd };
	const uint8_t verity[] = { LOTA_IMA_XATTR_VERITY_DIGSIG, 0x02, 0xab };

	TEST("DIGSIG (0x03) and VERITY_DIGSIG (0x05) count as signatures");
	if (!lota_ima_xattr_is_signature(digsig, sizeof(digsig))) {
		FAIL("DIGSIG not recognised as a signature");
		return;
	}
	if (!lota_ima_xattr_is_signature(verity, sizeof(verity))) {
		FAIL("VERITY_DIGSIG not recognised as a signature");
		return;
	}
	PASS();
}

static void test_bare_digest_rejected(void)
{
	const uint8_t digest[] = { LOTA_IMA_XATTR_DIGEST, 0xde, 0xad };
	const uint8_t digest_ng[] = { LOTA_IMA_XATTR_DIGEST_NG, 0x04, 0xbe };

	TEST("bare digest (0x01/0x04) is not a signature");
	if (lota_ima_xattr_is_signature(digest, sizeof(digest))) {
		FAIL("unsigned digest accepted as a signature");
		return;
	}
	if (lota_ima_xattr_is_signature(digest_ng, sizeof(digest_ng))) {
		FAIL("unsigned algo-tagged digest accepted as a signature");
		return;
	}
	PASS();
}

static void test_empty_and_null_rejected(void)
{
	const uint8_t one[] = { LOTA_IMA_XATTR_DIGSIG };

	TEST("NULL blob and zero length are not signatures");
	if (lota_ima_xattr_is_signature(NULL, 0)) {
		FAIL("NULL blob accepted");
		return;
	}
	if (lota_ima_xattr_is_signature(one, 0)) {
		FAIL("zero-length blob accepted");
		return;
	}
	PASS();
}

static void test_unknown_type_rejected(void)
{
	const uint8_t zero[] = { 0x00, 0x11 };
	const uint8_t high[] = { 0xff, 0x11 };

	TEST("unknown leading type byte is not a signature");
	if (lota_ima_xattr_is_signature(zero, sizeof(zero))) {
		FAIL("type 0x00 accepted");
		return;
	}
	if (lota_ima_xattr_is_signature(high, sizeof(high))) {
		FAIL("type 0xff accepted");
		return;
	}
	PASS();
}

int main(void)
{
	printf("IMA xattr signature predicate:\n");

	test_signature_types_accepted();
	test_bare_digest_rejected();
	test_empty_and_null_rejected();
	test_unknown_type_rejected();

	printf("%d/%d tests passed\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
