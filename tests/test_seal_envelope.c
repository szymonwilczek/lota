/* SPDX-License-Identifier: MIT */
/*
 * LOTA sealed-envelope format + AEAD - Unit Tests
 *
 * Exercises the portable framing in include/lota_envelope.h (header
 * serialize/parse, envelope-vs-direct discrimination, malformed-header
 * rejection) and the AES-256-GCM helpers in seal_envelope.c (round-trip
 * plus tamper rejection on ciphertext, tag, KEK, and AAD). No TPM required.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "lota_envelope.h"
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

static void fill_meta(struct lota_envelope_meta *m)
{
	m->kek_blob_len = 320;
	m->payload_len = 4096;
	for (unsigned i = 0; i < LOTA_ENVELOPE_NONCE_SIZE; i++)
		m->nonce[i] = (uint8_t)(0x20 + i);
	for (unsigned i = 0; i < LOTA_ENVELOPE_TAG_SIZE; i++)
		m->tag[i] = (uint8_t)(0x40 + i);
}

/* build a valid envelope blob (header + dummy bodies) */
static size_t build_blob(uint8_t *blob)
{
	struct lota_envelope_meta m;
	fill_meta(&m);
	lota_envelope_serialize_header(blob, &m);
	memset(blob + LOTA_ENVELOPE_HEADER_SIZE, 0xCD,
	       (size_t)m.kek_blob_len + m.payload_len);
	return (size_t)LOTA_ENVELOPE_HEADER_SIZE + m.kek_blob_len +
	       m.payload_len;
}

static void test_serialize_roundtrip(void)
{
	struct lota_envelope_meta in, out;
	uint8_t blob[LOTA_ENVELOPE_HEADER_SIZE + 320 + 4096];
	size_t body_off = 0;

	TEST("serialize -> parse round-trips the header fields");
	fill_meta(&in);
	if (lota_envelope_serialize_header(blob, &in) != 0) {
		FAIL("serialize");
		return;
	}
	memset(blob + LOTA_ENVELOPE_HEADER_SIZE, 0xAB,
	       (size_t)in.kek_blob_len + in.payload_len);
	size_t total = (size_t)LOTA_ENVELOPE_HEADER_SIZE + in.kek_blob_len +
		       in.payload_len;

	if (lota_envelope_parse_header(blob, total, &out, &body_off) != 0) {
		FAIL("parse");
		return;
	}
	if (body_off != LOTA_ENVELOPE_HEADER_SIZE) {
		FAIL("body offset");
		return;
	}
	if (out.kek_blob_len != in.kek_blob_len ||
	    out.payload_len != in.payload_len ||
	    memcmp(out.nonce, in.nonce, LOTA_ENVELOPE_NONCE_SIZE) != 0 ||
	    memcmp(out.tag, in.tag, LOTA_ENVELOPE_TAG_SIZE) != 0) {
		FAIL("field mismatch");
		return;
	}
	PASS();
}

static void test_serialize_rejects_bad_fields(void)
{
	struct lota_envelope_meta m;
	uint8_t hdr[LOTA_ENVELOPE_HEADER_SIZE];

	TEST("serialize rejects bad lengths and NULL");
	fill_meta(&m);
	m.kek_blob_len = 0;
	if (lota_envelope_serialize_header(hdr, &m) != -EINVAL) {
		FAIL("zero kek_blob_len");
		return;
	}
	fill_meta(&m);
	m.payload_len = 0;
	if (lota_envelope_serialize_header(hdr, &m) != -EINVAL) {
		FAIL("zero payload_len");
		return;
	}
	fill_meta(&m);
	m.payload_len = LOTA_ENVELOPE_MAX_PAYLOAD + 1;
	if (lota_envelope_serialize_header(hdr, &m) != -EINVAL) {
		FAIL("oversize payload_len");
		return;
	}
	fill_meta(&m);
	if (lota_envelope_serialize_header(NULL, &m) != -EINVAL) {
		FAIL("NULL out");
		return;
	}
	if (lota_envelope_serialize_header(hdr, NULL) != -EINVAL) {
		FAIL("NULL meta");
		return;
	}
	PASS();
}

static void test_parse_rejects_malformed(void)
{
	uint8_t blob[LOTA_ENVELOPE_HEADER_SIZE + 320 + 4096];
	struct lota_envelope_meta out;
	size_t n;

	TEST("parse rejects truncated/magic/version/reserved/lengths");
	build_blob(blob);
	if (lota_envelope_parse_header(blob, LOTA_ENVELOPE_HEADER_SIZE - 1,
				       &out, NULL) != -EMSGSIZE) {
		FAIL("short header");
		return;
	}
	n = build_blob(blob);
	blob[0] ^= 0xFF;
	if (lota_envelope_parse_header(blob, n, &out, NULL) != -EINVAL) {
		FAIL("bad magic");
		return;
	}
	n = build_blob(blob);
	blob[4] = 0x99;
	if (lota_envelope_parse_header(blob, n, &out, NULL) != -EINVAL) {
		FAIL("bad version");
		return;
	}
	n = build_blob(blob);
	blob[6] = 1; /* reserved after version */
	if (lota_envelope_parse_header(blob, n, &out, NULL) != -EINVAL) {
		FAIL("reserved@6");
		return;
	}
	n = build_blob(blob);
	blob[44] = 1; /* trailing reserved */
	if (lota_envelope_parse_header(blob, n, &out, NULL) != -EINVAL) {
		FAIL("reserved@44");
		return;
	}
	n = build_blob(blob);
	if (lota_envelope_parse_header(blob, n + 1, &out, NULL) != -EMSGSIZE) {
		FAIL("trailing slack");
		return;
	}
	if (lota_envelope_parse_header(blob, n - 1, &out, NULL) != -EMSGSIZE) {
		FAIL("short body");
		return;
	}
	PASS();
}

static void test_is_envelope(void)
{
	uint8_t env[LOTA_ENVELOPE_HEADER_SIZE + 320 + 4096];
	uint8_t direct[LOTA_SEAL_HEADER_SIZE];
	struct lota_seal_meta sm;

	TEST("is_envelope distinguishes LENV from a direct LSEL blob");
	build_blob(env);
	if (!lota_envelope_is_envelope(env, sizeof(env))) {
		FAIL("envelope not detected");
		return;
	}
	memset(&sm, 0, sizeof(sm));
	sm.pcr_mask = LOTA_SEAL_DEFAULT_PCR_MASK;
	sm.pcr_alg = LOTA_SEAL_PCR_ALG_SHA256;
	sm.pub_len = 64;
	sm.priv_len = 64;
	if (lota_seal_serialize_header(direct, &sm) != 0) {
		FAIL("seal header");
		return;
	}
	if (lota_envelope_is_envelope(direct, sizeof(direct))) {
		FAIL("direct blob misdetected as envelope");
		return;
	}
	if (lota_envelope_is_envelope(env, 3)) {
		FAIL("short buffer misdetected");
		return;
	}
	PASS();
}

static void test_aead_roundtrip(void)
{
	uint8_t kek[LOTA_ENVELOPE_KEK_SIZE];
	uint8_t nonce[LOTA_ENVELOPE_NONCE_SIZE];
	uint8_t aad[40];
	uint8_t pt[300];
	uint8_t ct[300];
	uint8_t got[300];
	uint8_t tag[LOTA_ENVELOPE_TAG_SIZE];

	TEST("AEAD seal -> open recovers the plaintext");
	for (unsigned i = 0; i < sizeof(kek); i++)
		kek[i] = (uint8_t)(i * 7 + 1);
	for (unsigned i = 0; i < sizeof(nonce); i++)
		nonce[i] = (uint8_t)(i + 3);
	for (unsigned i = 0; i < sizeof(aad); i++)
		aad[i] = (uint8_t)(i ^ 0x55);
	for (unsigned i = 0; i < sizeof(pt); i++)
		pt[i] = (uint8_t)(i * 3 + 9);

	if (lota_envelope_aead_seal(kek, nonce, aad, sizeof(aad), pt,
				    sizeof(pt), ct, tag) != 0) {
		FAIL("seal");
		return;
	}
	if (memcmp(ct, pt, sizeof(pt)) == 0) {
		FAIL("ciphertext equals plaintext");
		return;
	}
	if (lota_envelope_aead_open(kek, nonce, aad, sizeof(aad), ct,
				    sizeof(ct), tag, got) != 0) {
		FAIL("open");
		return;
	}
	if (memcmp(got, pt, sizeof(pt)) != 0) {
		FAIL("plaintext mismatch");
		return;
	}
	PASS();
}

static void test_aead_rejects_tamper(void)
{
	uint8_t kek[LOTA_ENVELOPE_KEK_SIZE] = { 0 };
	uint8_t nonce[LOTA_ENVELOPE_NONCE_SIZE] = { 0 };
	uint8_t aad[16];
	uint8_t pt[64];
	uint8_t ct[64];
	uint8_t got[64];
	uint8_t tag[LOTA_ENVELOPE_TAG_SIZE];

	TEST("AEAD open rejects tampered ct/tag/KEK/AAD with -EBADMSG");
	for (unsigned i = 0; i < sizeof(aad); i++)
		aad[i] = (uint8_t)i;
	for (unsigned i = 0; i < sizeof(pt); i++)
		pt[i] = (uint8_t)(0xF0 - i);

	if (lota_envelope_aead_seal(kek, nonce, aad, sizeof(aad), pt,
				    sizeof(pt), ct, tag) != 0) {
		FAIL("seal");
		return;
	}

	/* flip a ciphertext byte */
	uint8_t bad_ct[64];
	memcpy(bad_ct, ct, sizeof(ct));
	bad_ct[0] ^= 0x01;
	if (lota_envelope_aead_open(kek, nonce, aad, sizeof(aad), bad_ct,
				    sizeof(bad_ct), tag, got) != -EBADMSG) {
		FAIL("ciphertext tamper accepted");
		return;
	}

	/* flip a tag byte */
	uint8_t bad_tag[LOTA_ENVELOPE_TAG_SIZE];
	memcpy(bad_tag, tag, sizeof(tag));
	bad_tag[0] ^= 0x80;
	if (lota_envelope_aead_open(kek, nonce, aad, sizeof(aad), ct,
				    sizeof(ct), bad_tag, got) != -EBADMSG) {
		FAIL("tag tamper accepted");
		return;
	}

	/* wrong KEK */
	uint8_t bad_kek[LOTA_ENVELOPE_KEK_SIZE];
	memcpy(bad_kek, kek, sizeof(kek));
	bad_kek[5] ^= 0x10;
	if (lota_envelope_aead_open(bad_kek, nonce, aad, sizeof(aad), ct,
				    sizeof(ct), tag, got) != -EBADMSG) {
		FAIL("wrong KEK accepted");
		return;
	}

	/* tampered AAD */
	uint8_t bad_aad[16];
	memcpy(bad_aad, aad, sizeof(aad));
	bad_aad[2] ^= 0x04;
	if (lota_envelope_aead_open(kek, nonce, bad_aad, sizeof(bad_aad), ct,
				    sizeof(ct), tag, got) != -EBADMSG) {
		FAIL("AAD tamper accepted");
		return;
	}
	PASS();
}

static void test_aead_rejects_bad_args(void)
{
	uint8_t kek[LOTA_ENVELOPE_KEK_SIZE] = { 0 };
	uint8_t nonce[LOTA_ENVELOPE_NONCE_SIZE] = { 0 };
	uint8_t buf[16] = { 0 };
	uint8_t tag[LOTA_ENVELOPE_TAG_SIZE] = { 0 };

	TEST("AEAD helpers reject NULL and out-of-range lengths");
	if (lota_envelope_aead_seal(NULL, nonce, NULL, 0, buf, sizeof(buf), buf,
				    tag) != -EINVAL) {
		FAIL("seal NULL kek");
		return;
	}
	if (lota_envelope_aead_seal(kek, nonce, NULL, 0, buf, 0, buf, tag) !=
	    -EINVAL) {
		FAIL("seal zero len");
		return;
	}
	if (lota_envelope_aead_open(kek, nonce, NULL, 0, buf, 0, tag, buf) !=
	    -EINVAL) {
		FAIL("open zero len");
		return;
	}
	PASS();
}

int main(void)
{
	printf("Running LOTA sealed-envelope tests...\n\n");

	test_serialize_roundtrip();
	test_serialize_rejects_bad_fields();
	test_parse_rejects_malformed();
	test_is_envelope();
	test_aead_roundtrip();
	test_aead_rejects_tamper();
	test_aead_rejects_bad_args();

	printf("\n%d/%d tests passed\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
