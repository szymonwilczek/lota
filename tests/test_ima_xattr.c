/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Unit tests for the shared security.ima xattr signature-type predicate.
 *
 * The installer's IMA scope stage uses it to tell a host that signs its
 * executables from one that does not. Only a signature variant binds the file
 * content to a key in the .ima keyring; a bare digest must never count as a
 * signature.
 */

#include <stddef.h>
#include <stdint.h>

#include "test.h"
#include "../include/lota_ima_xattr.h"

static void test_signature_types_accepted(void)
{
	const uint8_t digsig[] = { LOTA_IMA_XATTR_DIGSIG, 0x02, 0xab, 0xcd };
	const uint8_t portable[] = { LOTA_IMA_XATTR_PORTABLE_DIGSIG, 0x02,
				     0xab };
	const uint8_t verity[] = { LOTA_IMA_XATTR_VERITY_DIGSIG, 0x02, 0xab };

	TEST("DIGSIG (0x03), portable (0x05) and verity (0x06) are signatures");
	if (!lota_ima_xattr_is_signature(digsig, sizeof(digsig))) {
		FAIL("DIGSIG not recognised as a signature");
		return;
	}
	if (!lota_ima_xattr_is_signature(portable, sizeof(portable))) {
		FAIL("PORTABLE_DIGSIG not recognised as a signature");
		return;
	}
	if (!lota_ima_xattr_is_signature(verity, sizeof(verity))) {
		FAIL("VERITY_DIGSIG not recognised as a signature");
		return;
	}
}

static void test_bare_digest_rejected(void)
{
	const uint8_t digest[] = { 0x01, 0xde, 0xad };
	const uint8_t digest_ng[] = { 0x04, 0x04, 0xbe };

	TEST("bare digest (0x01/0x04) is not a signature");
	if (lota_ima_xattr_is_signature(digest, sizeof(digest))) {
		FAIL("unsigned digest accepted as a signature");
		return;
	}
	if (lota_ima_xattr_is_signature(digest_ng, sizeof(digest_ng))) {
		FAIL("unsigned algo-tagged digest accepted as a signature");
		return;
	}
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
}

int main(void)
{
	test_begin("ima xattr");

	test_signature_types_accepted();
	test_bare_digest_rejected();
	test_empty_and_null_rejected();
	test_unknown_type_rejected();

	return test_end();
}
