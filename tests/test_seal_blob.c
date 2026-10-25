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
#include <stdbool.h>
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

/*
 * The default mask describes the machine, not the software running on it.
 * PCRs 0-7 are the firmware and Secure Boot set: they cannot be reproduced on
 * other hardware, which is the binding at-rest sealing wants, and they survive
 * both a reboot and an agent upgrade.
 */
static void test_default_mask_contents(void)
{
	TEST("default mask is the platform set, PCR 0-7");
	uint32_t want = 0;
	for (int i = 0; i <= 7; i++)
		want |= (1u << i);
	if (LOTA_SEAL_DEFAULT_PCR_MASK != want) {
		FAIL("mask mismatch");
		return;
	}
	PASS();
}

/*
 * PCR 14 is LOTA's boot commitment, and its value is a function of the agent
 * binary. Binding it in the default would make every agent upgrade destroy
 * every sealed secret on the host -- including the AIK authorization, whose
 * loss costs a re-enrollment with every publisher.
 */
static void test_default_mask_excludes_the_boot_commitment(void)
{
	TEST("default mask does not bind PCR14 (the agent binary)");
	if (LOTA_SEAL_DEFAULT_PCR_MASK &
	    (1u << LOTA_SEAL_BOOT_COMMITMENT_PCR)) {
		FAIL("default mask binds the agent-identity register");
		return;
	}
	PASS();
}

/*
 * Binding the agent is still expressible -- it is a different mask with its
 * own name, for a caller who wants a secret that a swapped agent cannot read
 * and who accepts losing it at every upgrade.
 */
static void test_agent_bound_mask_is_separate_and_named(void)
{
	TEST("the agent-bound mask is the platform set plus PCR14");
	if (LOTA_SEAL_AGENT_BOUND_PCR_MASK !=
	    (LOTA_SEAL_DEFAULT_PCR_MASK |
	     (1u << LOTA_SEAL_BOOT_COMMITMENT_PCR))) {
		FAIL("agent-bound mask is not the default plus PCR14");
		return;
	}
	if (LOTA_SEAL_AGENT_BOUND_PCR_MASK == LOTA_SEAL_DEFAULT_PCR_MASK) {
		FAIL("agent-bound mask is the default");
		return;
	}
	if (lota_seal_validate_pcr_mask(LOTA_SEAL_AGENT_BOUND_PCR_MASK) != 0) {
		FAIL("agent-bound mask rejected");
		return;
	}
	PASS();
}

/* read off written bytes; LENV twin in test_seal_envelope.c */
static void test_magic_is_the_four_bytes_the_header_names(void)
{
	struct lota_seal_meta m;
	uint8_t blob[LOTA_SEAL_MAX_BLOB];

	TEST("a sealed blob opens with the four bytes LSEL");
	fill_meta(&m);
	if (lota_seal_serialize_header(blob, &m) != 0) {
		FAIL("serialize");
		return;
	}
	if (memcmp(blob, "LSEL", 4) != 0) {
		FAIL("the blob does not start with LSEL");
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

/* each malformed field shares one -EINVAL; *why must name it */
static void test_parse_names_the_field_it_refused(void)
{
	uint8_t blob[LOTA_SEAL_MAX_BLOB];
	struct lota_seal_meta out;
	struct lota_blob_refusal why;
	size_t n;

	TEST("a refused header names the field it was refused on");

	n = build_blob(blob);
	if (lota_seal_parse_header_why(blob, n, &out, NULL, &why) != 0 ||
	    why.reason != LOTA_BLOB_OK) {
		FAIL("a good header did not parse cleanly");
		return;
	}

	n = build_blob(blob);
	blob[0] ^= 0xFF;
	if (lota_seal_parse_header_why(blob, n, &out, NULL, &why) != -EINVAL ||
	    why.reason != LOTA_BLOB_MAGIC) {
		FAIL("magic");
		return;
	}

	n = build_blob(blob);
	blob[4] = 0x09;
	if (lota_seal_parse_header_why(blob, n, &out, NULL, &why) != -EINVAL ||
	    why.reason != LOTA_BLOB_VERSION || why.value != 9 ||
	    why.expected != LOTA_SEAL_VERSION) {
		FAIL("version");
		return;
	}

	n = build_blob(blob);
	blob[13] = 1;
	if (lota_seal_parse_header_why(blob, n, &out, NULL, &why) != -EINVAL ||
	    why.reason != LOTA_BLOB_RESERVED) {
		FAIL("reserved");
		return;
	}

	n = build_blob(blob);
	lota__seal_write_le32(blob + 8, 0);
	if (lota_seal_parse_header_why(blob, n, &out, NULL, &why) != -EINVAL ||
	    why.reason != LOTA_BLOB_PCR_MASK) {
		FAIL("pcr mask");
		return;
	}

	n = build_blob(blob);
	blob[12] = 1;
	if (lota_seal_parse_header_why(blob, n, &out, NULL, &why) != -EINVAL ||
	    why.reason != LOTA_BLOB_PCR_ALG) {
		FAIL("pcr alg");
		return;
	}

	n = build_blob(blob);
	lota__seal_write_le16(blob + 48, 2000);
	if (lota_seal_parse_header_why(blob, n, &out, NULL, &why) != -EINVAL ||
	    why.reason != LOTA_BLOB_PUB_LEN || why.value != 2000 ||
	    why.expected != LOTA_SEAL_MAX_PUB) {
		FAIL("pub_len over the maximum");
		return;
	}

	n = build_blob(blob);
	lota__seal_write_le16(blob + 48, 0);
	if (lota_seal_parse_header_why(blob, n, &out, NULL, &why) != -EINVAL ||
	    why.reason != LOTA_BLOB_PUB_LEN || why.value != 0) {
		FAIL("zero pub_len");
		return;
	}

	n = build_blob(blob);
	lota__seal_write_le16(blob + 50, LOTA_SEAL_MAX_PRIV + 1);
	if (lota_seal_parse_header_why(blob, n, &out, NULL, &why) != -EINVAL ||
	    why.reason != LOTA_BLOB_PRIV_LEN ||
	    why.expected != LOTA_SEAL_MAX_PRIV) {
		FAIL("priv_len over the maximum");
		return;
	}

	PASS();
}

/* one byte short or long are both -EMSGSIZE; *why tells them apart */
static void test_parse_names_a_length_that_does_not_add_up(void)
{
	uint8_t blob[LOTA_SEAL_MAX_BLOB];
	struct lota_seal_meta out;
	struct lota_blob_refusal why;
	size_t n;

	TEST("a length refusal names the length, not the boot state");

	n = build_blob(blob);
	if (lota_seal_parse_header_why(blob, LOTA_SEAL_HEADER_SIZE - 1, &out,
				       NULL, &why) != -EMSGSIZE ||
	    why.reason != LOTA_BLOB_SHORT ||
	    why.value != LOTA_SEAL_HEADER_SIZE - 1 ||
	    why.expected != LOTA_SEAL_HEADER_SIZE) {
		FAIL("short header");
		return;
	}

	if (lota_seal_parse_header_why(blob, n + 1, &out, NULL, &why) !=
		    -EMSGSIZE ||
	    why.reason != LOTA_BLOB_BODY_LENGTH || why.value != n + 1 ||
	    why.expected != n) {
		FAIL("trailing slack");
		return;
	}

	if (lota_seal_parse_header_why(blob, n - 1, &out, NULL, &why) !=
		    -EMSGSIZE ||
	    why.reason != LOTA_BLOB_BODY_LENGTH || why.value != n - 1 ||
	    why.expected != n) {
		FAIL("short body");
		return;
	}

	PASS();
}

/* no reason text may blame the boot state: the blob never reached a TPM */
static void test_reason_text_is_about_the_file(void)
{
	static const enum lota_blob_reason all[] = {
		LOTA_BLOB_OK,	   LOTA_BLOB_SHORT,	  LOTA_BLOB_MAGIC,
		LOTA_BLOB_VERSION, LOTA_BLOB_RESERVED,	  LOTA_BLOB_PCR_MASK,
		LOTA_BLOB_PCR_ALG, LOTA_BLOB_PUB_LEN,	  LOTA_BLOB_PRIV_LEN,
		LOTA_BLOB_KEK_LEN, LOTA_BLOB_PAYLOAD_LEN, LOTA_BLOB_BODY_LENGTH,
	};

	TEST("every refusal reads as a complaint about the file");
	for (unsigned i = 0; i < sizeof(all) / sizeof(all[0]); i++) {
		const char *text = lota_blob_reason_str(all[i]);

		if (!text || text[0] == '\0') {
			FAIL("a reason has no text");
			return;
		}
		if (strstr(text, "boot") || strstr(text, "PCR state") ||
		    strstr(text, "host")) {
			FAIL("a framing refusal blames the host");
			return;
		}
	}
	PASS();
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

/*
 * --seal-pcrs usage is the only on-host statement of the default set. It must
 * name PCRs 0-7, keep PCR 14 out (an agent upgrade would destroy the secret),
 * and name 0x40FF as the agent-bound set.
 */
static void test_usage_states_the_default_seal_set(void)
{
	char line[512];
	char help[2048];
	FILE *fp;
	bool in_entry = false;
	size_t used = 0;

	TEST("--seal-pcrs usage matches the default mask");

	fp = fopen("src/agent/main_utils.c", "re");
	if (!fp)
		fp = fopen("../src/agent/main_utils.c", "re");
	if (!fp) {
		FAIL("could not open main_utils.c");
		return;
	}
	help[0] = '\0';
	while (fgets(line, sizeof(line), fp)) {
		if (strstr(line, "--seal-pcrs"))
			in_entry = true;
		else if (in_entry && strstr(line, "printf(\"  --"))
			break;
		if (!in_entry)
			continue;
		used += (size_t)snprintf(help + used, sizeof(help) - used, "%s",
					 line);
		if (used + 1 >= sizeof(help))
			break;
	}
	fclose(fp);

	if (!in_entry) {
		FAIL("no --seal-pcrs entry in the usage text");
		return;
	}

	if (LOTA_SEAL_DEFAULT_PCR_MASK &
	    (1u << LOTA_SEAL_BOOT_COMMITMENT_PCR)) {
		FAIL("the default mask now binds the boot commitment");
		return;
	}
	if (strstr(help, "PCR14") || strstr(help, "PCR 14")) {
		if (!strstr(help, "not")) {
			FAIL("the line names PCR 14 without saying it is out of the default");
			return;
		}
	}
	if (!strstr(help, "0-7")) {
		FAIL("the line does not name PCRs 0-7 as the default");
		return;
	}
	if (!strstr(help, "0x40FF") && !strstr(help, "0x40ff")) {
		FAIL("the line does not name the agent-bound set");
		return;
	}
	PASS();
}

int main(void)
{
	printf("Running LOTA sealed-blob format tests...\n\n");

	test_mask_validation();
	test_default_mask_contents();
	test_default_mask_excludes_the_boot_commitment();
	test_agent_bound_mask_is_separate_and_named();
	test_usage_states_the_default_seal_set();
	test_magic_is_the_four_bytes_the_header_names();
	test_serialize_roundtrip();
	test_serialize_rejects_bad_fields();
	test_parse_names_the_field_it_refused();
	test_parse_names_a_length_that_does_not_add_up();
	test_reason_text_is_about_the_file();
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
