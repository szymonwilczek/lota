/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for the attestation-CA enrollment wire codec (enroll.c).
 *
 * Byte layout is pinned here so the C agent and the Go CA
 * (src/attestca/wire) stay in lockstep: a "LCAE" magic, version 1, and
 * big-endian length-prefixed fields.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#include "../src/agent/enroll.h"
#include "lota_enroll.h"

static int g_failures;

#define CHECK(cond, msg)                                                       \
	do {                                                                   \
		if (!(cond)) {                                                 \
			fprintf(stderr, "FAIL: %s\n", msg);                    \
			g_failures++;                                          \
		} else {                                                       \
			printf("PASS: %s\n", msg);                             \
		}                                                              \
	} while (0)

static void test_encode_begin_layout(void)
{
	const uint8_t ek[] = {0xAA, 0xBB};
	const uint8_t aik[] = {0xCC};
	uint8_t out[64];
	ssize_t n = enroll_encode_begin(out, sizeof(out), ek, sizeof(ek), aik,
					sizeof(aik));

	const uint8_t want[] = {0x4C, 0x43, 0x41, 0x45, 0x00, 0x01, 0x00,
				0x02, 0xAA, 0xBB, 0x00, 0x01, 0xCC};

	CHECK(n == (ssize_t)sizeof(want), "encode_begin length");
	CHECK(n > 0 && memcmp(out, want, sizeof(want)) == 0,
	      "encode_begin byte layout matches the Go wire format");
}

static void test_encode_begin_bounds(void)
{
	uint8_t out[8];
	const uint8_t ek[4] = {0};
	const uint8_t aik[1] = {0};

	CHECK(enroll_encode_begin(out, sizeof(out), ek, sizeof(ek), aik,
				  sizeof(aik)) == -ENOSPC,
	      "encode_begin rejects an undersized buffer");

	uint8_t big_out[8192];
	uint8_t big_ek[LOTA_ENROLL_MAX_EK_CERT + 1];
	memset(big_ek, 0, sizeof(big_ek));
	CHECK(enroll_encode_begin(big_out, sizeof(big_out), big_ek,
				  sizeof(big_ek), aik,
				  sizeof(aik)) == -EMSGSIZE,
	      "encode_begin rejects an oversized EK certificate");
}

static void test_encode_complete(void)
{
	uint8_t out[128];
	const uint8_t secret[] = {0x01, 0x02, 0x03, 0x04};
	ssize_t n = enroll_encode_complete(out, sizeof(out), "sess", secret,
					   sizeof(secret));

	const uint8_t want[] = {0x4C, 0x43, 0x41, 0x45, 0x00, 0x01,
				0x00, 0x04, 's',  'e',	's',  's',
				0x00, 0x04, 0x01, 0x02, 0x03, 0x04};
	CHECK(n == (ssize_t)sizeof(want) &&
		  memcmp(out, want, sizeof(want)) == 0,
	      "encode_complete byte layout");
}

static void test_decode_challenge(void)
{
	const uint8_t body[] = {0x4C, 0x43, 0x41, 0x45, 0x00,
				0x01,	    /* magic, version */
				0x00, 0x00, /* status OK */
				0x00, 0x03, 'a',  'b',	'c', /* session id */
				0x00, 0x02, 0x01, 0x02,	 /* credential blob */
				0x00, 0x02, 0x03, 0x04}; /* encrypted secret */
	struct enroll_challenge ch;
	int ret = enroll_decode_challenge(body, sizeof(body), &ch);

	CHECK(ret == 0, "decode_challenge succeeds");
	CHECK(ch.status == LOTA_ENROLL_STATUS_OK, "challenge status OK");
	CHECK(strcmp(ch.session_id, "abc") == 0, "challenge session id");
	CHECK(ch.cred_blob_len == 2 && ch.cred_blob[0] == 0x01 &&
		  ch.cred_blob[1] == 0x02,
	      "challenge credential blob");
	CHECK(ch.enc_secret_len == 2 && ch.enc_secret[0] == 0x03 &&
		  ch.enc_secret[1] == 0x04,
	      "challenge encrypted secret");
}

static void test_decode_result(void)
{
	const uint8_t body[] = {0x4C, 0x43, 0x41, 0x45, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x02, 0x30, 0x82,
				0x00, 0x03, 'd',  'e',	'v'};
	struct enroll_result res;
	int ret = enroll_decode_result(body, sizeof(body), &res);

	CHECK(ret == 0, "decode_result succeeds");
	CHECK(res.status == LOTA_ENROLL_STATUS_OK, "result status OK");
	CHECK(res.aik_cert_len == 2 && res.aik_cert[0] == 0x30 &&
		  res.aik_cert[1] == 0x82,
	      "result AIK certificate bytes");
	CHECK(strcmp(res.device_id, "dev") == 0, "result device id");
}

static void test_decode_rejects_malformed(void)
{
	struct enroll_challenge ch;

	const uint8_t bad_magic[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
				     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
	CHECK(enroll_decode_challenge(bad_magic, sizeof(bad_magic), &ch) ==
		  -EPROTO,
	      "decode rejects bad magic");

	const uint8_t bad_version[] = {0x4C, 0x43, 0x41, 0x45, 0x00,
				       0xFF, 0x00, 0x00, 0x00, 0x00,
				       0x00, 0x00, 0x00, 0x00};
	CHECK(enroll_decode_challenge(bad_version, sizeof(bad_version), &ch) ==
		  -EPROTONOSUPPORT,
	      "decode rejects bad version");

	const uint8_t truncated[] = {0x4C, 0x43, 0x41, 0x45, 0x00, 0x01, 0x00};
	CHECK(enroll_decode_challenge(truncated, sizeof(truncated), &ch) < 0,
	      "decode rejects truncated frame");

	/* session id length claims 0x0400 bytes, far beyond the cap */
	const uint8_t oversize[] = {0x4C, 0x43, 0x41, 0x45, 0x00,
				    0x01, 0x00, 0x00, 0x04, 0x00};
	CHECK(enroll_decode_challenge(oversize, sizeof(oversize), &ch) ==
		  -EMSGSIZE,
	      "decode rejects an oversized field length");
}

int main(void)
{
	printf("=== enrollment wire codec tests ===\n");
	test_encode_begin_layout();
	test_encode_begin_bounds();
	test_encode_complete();
	test_decode_challenge();
	test_decode_result();
	test_decode_rejects_malformed();

	if (g_failures) {
		fprintf(stderr, "\n%d test(s) failed\n", g_failures);
		return 1;
	}
	printf("\nAll enrollment wire codec tests passed\n");
	return 0;
}
