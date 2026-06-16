/* SPDX-License-Identifier: MIT */
/*
 * LOTA sealed-blob wire format - Unit Tests
 *
 * Exercises the portable framing in include/lota_seal.h: PCR-mask
 * validation, header serialize/parse, round-trip fidelity, and rejection
 * of every malformed-header and length-mismatch case. No TPM required.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "lota_seal.h"

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

static void fill_meta(struct lota_seal_meta *m)
{
	m->pcr_mask = LOTA_SEAL_DEFAULT_PCR_MASK;
	m->pcr_alg = LOTA_SEAL_PCR_ALG_SHA256;
	for (unsigned i = 0; i < LOTA_SEAL_PCR_DIGEST_SIZE; i++)
		m->pcr_digest[i] = (uint8_t)(0x10 + i);
	m->pub_len = 120;
	m->priv_len = 200;
}

static void test_mask_validation(void)
{
	TEST("pcr mask: 0 rejected, >23 rejected, valid accepted");
	if (lota_seal_validate_pcr_mask(0) != -EINVAL) {
		FAIL("empty mask accepted");
		return;
	}
	if (lota_seal_validate_pcr_mask(1u << 24) != -EINVAL) {
		FAIL("PCR24 accepted");
		return;
	}
	if (lota_seal_validate_pcr_mask(0x80000000u) != -EINVAL) {
		FAIL("high bit accepted");
		return;
	}
	if (lota_seal_validate_pcr_mask(LOTA_SEAL_DEFAULT_PCR_MASK) != 0) {
		FAIL("default mask rejected");
		return;
	}
	if (lota_seal_validate_pcr_mask(LOTA_SEAL_PCR_MASK_ALL) != 0) {
		FAIL("all-PCR mask rejected");
		return;
	}
	if (lota_seal_validate_pcr_mask(1u << 14) != 0) {
		FAIL("single PCR14 rejected");
		return;
	}
	PASS();
}

static void test_default_mask_contents(void)
{
	TEST("default mask is PCR 0-7 plus PCR14");
	uint32_t want = 0;
	for (int i = 0; i <= 7; i++)
		want |= (1u << i);
	want |= (1u << 14);
	if (LOTA_SEAL_DEFAULT_PCR_MASK != want) {
		FAIL("mask mismatch");
		return;
	}
	PASS();
}

static void test_serialize_roundtrip(void)
{
	struct lota_seal_meta in, out;
	uint8_t hdr[LOTA_SEAL_HEADER_SIZE];

	TEST("serialize -> parse round-trips the header fields");
	fill_meta(&in);
	if (lota_seal_serialize_header(hdr, &in) != 0) {
		FAIL("serialize");
		return;
	}

	/* assemble a full blob so the length check passes */
	uint8_t blob[LOTA_SEAL_MAX_BLOB];
	memcpy(blob, hdr, sizeof(hdr));
	memset(blob + LOTA_SEAL_HEADER_SIZE, 0xAB, in.pub_len + in.priv_len);
	size_t total = (size_t)LOTA_SEAL_HEADER_SIZE + in.pub_len + in.priv_len;

	size_t body_off = 0;
	if (lota_seal_parse_header(blob, total, &out, &body_off) != 0) {
		FAIL("parse");
		return;
	}
	if (body_off != LOTA_SEAL_HEADER_SIZE) {
		FAIL("body offset");
		return;
	}
	if (out.pcr_mask != in.pcr_mask || out.pcr_alg != in.pcr_alg ||
	    out.pub_len != in.pub_len || out.priv_len != in.priv_len ||
	    memcmp(out.pcr_digest, in.pcr_digest, LOTA_SEAL_PCR_DIGEST_SIZE) !=
		    0) {
		FAIL("field mismatch");
		return;
	}
	PASS();
}

static void test_serialize_rejects_bad_fields(void)
{
	struct lota_seal_meta m;
	uint8_t hdr[LOTA_SEAL_HEADER_SIZE];

	TEST("serialize rejects bad mask/alg/lengths and NULL");
	fill_meta(&m);
	m.pcr_mask = 0;
	if (lota_seal_serialize_header(hdr, &m) != -EINVAL) {
		FAIL("empty mask");
		return;
	}
	fill_meta(&m);
	m.pcr_alg = 9;
	if (lota_seal_serialize_header(hdr, &m) != -EINVAL) {
		FAIL("bad alg");
		return;
	}
	fill_meta(&m);
	m.pub_len = 0;
	if (lota_seal_serialize_header(hdr, &m) != -EINVAL) {
		FAIL("zero pub_len");
		return;
	}
	fill_meta(&m);
	m.priv_len = LOTA_SEAL_MAX_PRIV + 1;
	if (lota_seal_serialize_header(hdr, &m) != -EINVAL) {
		FAIL("oversize priv_len");
		return;
	}
	fill_meta(&m);
	if (lota_seal_serialize_header(NULL, &m) != -EINVAL) {
		FAIL("NULL out");
		return;
	}
	if (lota_seal_serialize_header(hdr, NULL) != -EINVAL) {
		FAIL("NULL meta");
		return;
	}
	PASS();
}

/* build a valid blob, then let the caller corrupt it before parsing */
static size_t build_blob(uint8_t *blob)
{
	struct lota_seal_meta m;
	fill_meta(&m);
	lota_seal_serialize_header(blob, &m);
	memset(blob + LOTA_SEAL_HEADER_SIZE, 0xCD, m.pub_len + m.priv_len);
	return (size_t)LOTA_SEAL_HEADER_SIZE + m.pub_len + m.priv_len;
}

static void test_parse_rejects_truncated(void)
{
	uint8_t blob[LOTA_SEAL_MAX_BLOB];
	struct lota_seal_meta out;

	TEST("parse rejects a header shorter than the fixed size");
	build_blob(blob);
	if (lota_seal_parse_header(blob, LOTA_SEAL_HEADER_SIZE - 1, &out,
				   NULL) != -EMSGSIZE) {
		FAIL("expected -EMSGSIZE");
		return;
	}
	PASS();
}

static void test_parse_rejects_bad_magic(void)
{
	uint8_t blob[LOTA_SEAL_MAX_BLOB];
	struct lota_seal_meta out;

	TEST("parse rejects bad magic");
	size_t n = build_blob(blob);
	blob[0] ^= 0xFF;
	if (lota_seal_parse_header(blob, n, &out, NULL) != -EINVAL) {
		FAIL("expected -EINVAL");
		return;
	}
	PASS();
}

static void test_parse_rejects_bad_version(void)
{
	uint8_t blob[LOTA_SEAL_MAX_BLOB];
	struct lota_seal_meta out;

	TEST("parse rejects unsupported version");
	size_t n = build_blob(blob);
	blob[4] = 0x99;
	if (lota_seal_parse_header(blob, n, &out, NULL) != -EINVAL) {
		FAIL("expected -EINVAL");
		return;
	}
	PASS();
}

static void test_parse_rejects_nonzero_reserved(void)
{
	uint8_t blob[LOTA_SEAL_MAX_BLOB];
	struct lota_seal_meta out;

	TEST("parse rejects non-zero reserved bytes");
	size_t n = build_blob(blob);
	blob[6] = 1; /* reserved after version */
	if (lota_seal_parse_header(blob, n, &out, NULL) != -EINVAL) {
		FAIL("reserved@6");
		return;
	}
	n = build_blob(blob);
	blob[14] = 1; /* reserved after pcr_alg */
	if (lota_seal_parse_header(blob, n, &out, NULL) != -EINVAL) {
		FAIL("reserved@14");
		return;
	}
	PASS();
}

static void test_parse_rejects_bad_mask_alg(void)
{
	uint8_t blob[LOTA_SEAL_MAX_BLOB];
	struct lota_seal_meta out;

	TEST("parse rejects empty mask and unknown pcr_alg");
	size_t n = build_blob(blob);
	lota__seal_write_le32(blob + 8, 0); /* empty mask */
	if (lota_seal_parse_header(blob, n, &out, NULL) != -EINVAL) {
		FAIL("empty mask");
		return;
	}
	n = build_blob(blob);
	blob[12] = 7; /* unknown alg */
	if (lota_seal_parse_header(blob, n, &out, NULL) != -EINVAL) {
		FAIL("bad alg");
		return;
	}
	PASS();
}

static void test_parse_rejects_length_mismatch(void)
{
	uint8_t blob[LOTA_SEAL_MAX_BLOB];
	struct lota_seal_meta out;

	TEST("parse rejects trailing slack and short body");
	size_t n = build_blob(blob);
	/* one extra trailing byte: declared bodies no longer fit exactly */
	if (lota_seal_parse_header(blob, n + 1, &out, NULL) != -EMSGSIZE) {
		FAIL("trailing slack");
		return;
	}
	if (lota_seal_parse_header(blob, n - 1, &out, NULL) != -EMSGSIZE) {
		FAIL("short body");
		return;
	}
	PASS();
}

static void test_parse_rejects_zero_lengths(void)
{
	uint8_t blob[LOTA_SEAL_MAX_BLOB];
	struct lota_seal_meta out;

	TEST("parse rejects zero pub_len / priv_len");
	size_t n = build_blob(blob);
	lota__seal_write_le16(blob + 48, 0); /* pub_len = 0 */
	if (lota_seal_parse_header(blob, n, &out, NULL) != -EINVAL) {
		FAIL("zero pub_len");
		return;
	}
	n = build_blob(blob);
	lota__seal_write_le16(blob + 50, 0); /* priv_len = 0 */
	if (lota_seal_parse_header(blob, n, &out, NULL) != -EINVAL) {
		FAIL("zero priv_len");
		return;
	}
	PASS();
}

int main(void)
{
	printf("Running LOTA sealed-blob format tests...\n\n");

	test_mask_validation();
	test_default_mask_contents();
	test_serialize_roundtrip();
	test_serialize_rejects_bad_fields();
	test_parse_rejects_truncated();
	test_parse_rejects_bad_magic();
	test_parse_rejects_bad_version();
	test_parse_rejects_nonzero_reserved();
	test_parse_rejects_bad_mask_alg();
	test_parse_rejects_length_mismatch();
	test_parse_rejects_zero_lengths();

	printf("\n%d/%d tests passed\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
