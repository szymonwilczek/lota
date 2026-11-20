/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for the attestation-CA enrollment wire codec (enroll.c).
 *
 * Byte layout is pinned here so the C agent and the Go CA
 * (src/attestca/wire) stay in lockstep: a "LCAE" magic, the protocol version,
 * and big-endian length-prefixed fields. Optional fields are a zero length
 * or count, never a version.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#include "../src/agent/enroll.h"
#include "lota_enroll.h"

#include "test.h"

static void test_encode_begin_layout(void)
{
	const uint8_t ek[] = { 0xAA, 0xBB };
	const uint8_t aik[] = { 0xCC };
	uint8_t out[64];
	ssize_t n = enroll_encode_begin(out, sizeof(out), ek, sizeof(ek), aik,
					sizeof(aik), NULL, 0, NULL, 0);

	const uint8_t want[] = { 0x4C, 0x43, 0x41, 0x45, 0x00,
				 0x01, 0x00, 0x02, 0xAA, 0xBB, /* EK leaf */
				 0x00, 0x01, 0xCC, /* AIK template */
				 0x00, 0x00, /* no token */
				 0x00, 0x00 }; /* no intermediates */

	TEST("encode_begin length");
	if (n != (ssize_t)sizeof(want))
		FAIL("expected: n == (ssize_t)sizeof(want)");
	TEST("encode_begin byte layout matches the Go wire format");
	if (!(n > 0 && memcmp(out, want, sizeof(want)) == 0))
		FAIL("expected: n > 0 && memcmp(out, want, sizeof(want)) == 0");
}

static void test_encode_begin_bounds(void)
{
	uint8_t out[8];
	const uint8_t ek[4] = { 0 };
	const uint8_t aik[1] = { 0 };

	TEST("encode_begin rejects an undersized buffer");
	if (enroll_encode_begin(out, sizeof(out), ek, sizeof(ek), aik,
				sizeof(aik), NULL, 0, NULL, 0) != -ENOSPC)
		FAIL("expected: enroll_encode_begin(out, sizeof(out), ek, "
		     "sizeof(ek), aik, sizeof(aik), NULL, 0, NULL, 0) == "
		     "-ENOSPC");

	uint8_t big_out[8192];
	uint8_t big_ek[LOTA_ENROLL_MAX_EK_CERT + 1];
	memset(big_ek, 0, sizeof(big_ek));
	TEST("encode_begin rejects an oversized EK certificate");
	if (enroll_encode_begin(big_out, sizeof(big_out), big_ek,
				sizeof(big_ek), aik, sizeof(aik), NULL, 0, NULL,
				0) != -EMSGSIZE)
		FAIL("expected: enroll_encode_begin(big_out, sizeof(big_out), "
		     "big_ek, sizeof(big_ek), aik, sizeof(aik), NULL, 0, "
		     "NULL, 0) == -EMSGSIZE");

	uint8_t big_token[LOTA_ENROLL_MAX_TOKEN + 1];
	memset(big_token, 't', sizeof(big_token));
	TEST("encode_begin rejects an oversized token");
	if (enroll_encode_begin(big_out, sizeof(big_out), ek, sizeof(ek), aik,
				sizeof(aik), big_token, sizeof(big_token), NULL,
				0) != -EMSGSIZE)
		FAIL("expected: enroll_encode_begin(big_out, sizeof(big_out), "
		     "ek, sizeof(ek), aik, sizeof(aik), big_token, "
		     "sizeof(big_token), NULL, 0) == -EMSGSIZE");
}

static void test_encode_begin_token_layout(void)
{
	const uint8_t ek[] = { 0xAA, 0xBB };
	const uint8_t aik[] = { 0xCC };
	const uint8_t token[] = { 't', 'k' };
	uint8_t out[64];
	ssize_t n = enroll_encode_begin(out, sizeof(out), ek, sizeof(ek), aik,
					sizeof(aik), token, sizeof(token), NULL,
					0);

	/* pinned against the Go wire tests */
	const uint8_t want[] = { 0x4C, 0x43, 0x41, 0x45, 0x00,
				 0x01, 0x00, 0x02, 0xAA, 0xBB, /* EK leaf */
				 0x00, 0x01, 0xCC, /* AIK template */
				 0x00, 0x02, 't',  'k', /* the token */
				 0x00, 0x00 }; /* no intermediates */

	TEST("encode_begin token length");
	if (n != (ssize_t)sizeof(want))
		FAIL("expected: n == (ssize_t)sizeof(want)");
	TEST("encode_begin token byte layout matches the Go wire format");
	if (!(n > 0 && memcmp(out, want, sizeof(want)) == 0))
		FAIL("expected: n > 0 && memcmp(out, want, sizeof(want)) == 0");
}

static void test_encode_complete(void)
{
	uint8_t out[128];
	const uint8_t secret[] = { 0x01, 0x02, 0x03, 0x04 };
	ssize_t n = enroll_encode_complete(out, sizeof(out), "sess", secret,
					   sizeof(secret));

	const uint8_t want[] = { 0x4C, 0x43, 0x41, 0x45, 0x00, 0x01,
				 0x00, 0x04, 's',  'e',	 's',  's',
				 0x00, 0x04, 0x01, 0x02, 0x03, 0x04 };
	TEST("encode_complete byte layout");
	if (!(n == (ssize_t)sizeof(want) &&
	      memcmp(out, want, sizeof(want)) == 0))
		FAIL("expected: n == (ssize_t)sizeof(want) && memcmp(out, "
		     "want, sizeof(want)) == 0");
}

static void test_decode_challenge(void)
{
	const uint8_t body[] = {
		0x4C, 0x43, 0x41, 0x45, 0x00, 0x01, /* magic, version */
		0x00, 0x00, /* status OK */
		0x00, 0x03, 'a',  'b',	'c', /* session id */
		0x00, 0x02, 0x01, 0x02, /* credential blob */
		0x00, 0x02, 0x03, 0x04
	}; /* encrypted secret */
	struct enroll_challenge ch;
	int ret = enroll_decode_challenge(body, sizeof(body), &ch);

	TEST("decode_challenge succeeds");
	if (ret != 0)
		FAIL("expected: ret == 0");
	TEST("challenge status OK");
	if (ch.status != LOTA_ENROLL_STATUS_OK)
		FAIL("expected: ch.status == LOTA_ENROLL_STATUS_OK");
	TEST("challenge session id");
	if (strcmp(ch.session_id, "abc") != 0)
		FAIL("expected: strcmp(ch.session_id, \"abc\") == 0");
	TEST("challenge credential blob");
	if (!(ch.cred_blob_len == 2 && ch.cred_blob[0] == 0x01 &&
	      ch.cred_blob[1] == 0x02))
		FAIL("expected: ch.cred_blob_len == 2 && ch.cred_blob[0] == "
		     "0x01 && ch.cred_blob[1] == 0x02");
	TEST("challenge encrypted secret");
	if (!(ch.enc_secret_len == 2 && ch.enc_secret[0] == 0x03 &&
	      ch.enc_secret[1] == 0x04))
		FAIL("expected: ch.enc_secret_len == 2 && ch.enc_secret[0] == "
		     "0x03 && ch.enc_secret[1] == 0x04");
}

static void test_decode_result(void)
{
	const uint8_t body[] = { 0x4C, 0x43, 0x41, 0x45, 0x00, 0x01,
				 0x00, 0x00, 0x00, 0x02, 0x30, 0x82,
				 0x00, 0x03, 'd',  'e',	 'v' };
	struct enroll_result res;
	int ret = enroll_decode_result(body, sizeof(body), &res);

	TEST("decode_result succeeds");
	if (ret != 0)
		FAIL("expected: ret == 0");
	TEST("result status OK");
	if (res.status != LOTA_ENROLL_STATUS_OK)
		FAIL("expected: res.status == LOTA_ENROLL_STATUS_OK");
	TEST("result AIK certificate bytes");
	if (!(res.aik_cert_len == 2 && res.aik_cert[0] == 0x30 &&
	      res.aik_cert[1] == 0x82))
		FAIL("expected: res.aik_cert_len == 2 && res.aik_cert[0] == "
		     "0x30 && res.aik_cert[1] == 0x82");
	TEST("result device id");
	if (strcmp(res.device_id, "dev") != 0)
		FAIL("expected: strcmp(res.device_id, \"dev\") == 0");
}

static void test_decode_rejects_malformed(void)
{
	struct enroll_challenge ch;

	const uint8_t bad_magic[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
				      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	TEST("decode rejects bad magic");
	if (enroll_decode_challenge(bad_magic, sizeof(bad_magic), &ch) !=
	    -EPROTO)
		FAIL("expected: enroll_decode_challenge(bad_magic, "
		     "sizeof(bad_magic), &ch) == -EPROTO");

	const uint8_t bad_version[] = { 0x4C, 0x43, 0x41, 0x45, 0x00,
					0xFF, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00 };
	TEST("decode rejects bad version");
	if (enroll_decode_challenge(bad_version, sizeof(bad_version), &ch) !=
	    -EPROTONOSUPPORT)
		FAIL("expected: enroll_decode_challenge(bad_version, "
		     "sizeof(bad_version), &ch) == -EPROTONOSUPPORT");

	/* any other version, the old shape selectors included, is a newer CA */
	uint8_t reply[] = {
		0x4C, 0x43, 0x41, 0x45, 0x00, 0x01, /* magic, version */
		0x00, 0x00, /* status OK */
		0x00, 0x01, 'a', /* session id */
		0x00, 0x01, 0x01, /* credential blob */
		0x00, 0x01, 0x02 /* encrypted secret */
	};
	TEST("decode accepts the version in service");
	if (enroll_decode_challenge(reply, sizeof(reply), &ch) != 0)
		FAIL("expected: enroll_decode_challenge(reply, sizeof(reply), "
		     "&ch) == 0");

	static const uint8_t newer[] = { 0x00, 0x02, 0x03, 0x04 };

	for (size_t i = 0; i < sizeof(newer); i++) {
		char msg[64];

		snprintf(msg, sizeof(msg), "decode refuses version %u",
			 newer[i]);
		reply[5] = newer[i];
		TEST(msg);
		if (enroll_decode_challenge(reply, sizeof(reply), &ch) !=
		    -EPROTONOSUPPORT)
			FAIL("expected: enroll_decode_challenge(reply, sizeof(reply), "
			     "&ch) == -EPROTONOSUPPORT");
	}

	const uint8_t truncated[] = { 0x4C, 0x43, 0x41, 0x45, 0x00, 0x01, 0x00 };
	TEST("decode rejects truncated frame");
	if (enroll_decode_challenge(truncated, sizeof(truncated), &ch) >= 0)
		FAIL("expected: enroll_decode_challenge(truncated, "
		     "sizeof(truncated), &ch) < 0");

	/* session id length claims 0x0400 bytes, far beyond the cap */
	const uint8_t oversize[] = { 0x4C, 0x43, 0x41, 0x45, 0x00,
				     0x01, 0x00, 0x00, 0x04, 0x00 };
	TEST("decode rejects an oversized field length");
	if (enroll_decode_challenge(oversize, sizeof(oversize), &ch) !=
	    -EMSGSIZE)
		FAIL("expected: enroll_decode_challenge(oversize, "
		     "sizeof(oversize), &ch) == -EMSGSIZE");
}

/* trailing bytes in a reply are refused, not skipped */
static void test_decode_rejects_trailing_bytes(void)
{
	const uint8_t challenge[] = {
		0x4C, 0x43, 0x41, 0x45, 0x00, 0x01, /* magic, version */
		0x00, 0x00, /* status OK */
		0x00, 0x01, 'a', /* session id */
		0x00, 0x01, 0x01, /* credential blob */
		0x00, 0x01, 0x02 /* encrypted secret */
	};
	const uint8_t result[] = { 0x4C, 0x43, 0x41, 0x45,
				   0x00, 0x01, 0x00, 0x00, /* status OK */
				   0x00, 0x01, 0x30, /* AIK certificate */
				   0x00, 0x01, 'd' }; /* device id */
	uint8_t padded[32];
	struct enroll_challenge ch;
	struct enroll_result res;

	TEST("both replies decode whole");
	if (!(enroll_decode_challenge(challenge, sizeof(challenge), &ch) == 0 &&
	      enroll_decode_result(result, sizeof(result), &res) == 0))
		FAIL("expected: enroll_decode_challenge(challenge, "
		     "sizeof(challenge), &ch) == 0 && "
		     "enroll_decode_result(result, sizeof(result), &res) == 0");

	memcpy(padded, challenge, sizeof(challenge));
	padded[sizeof(challenge)] = 0x00;
	TEST("a challenge with a trailing byte is refused");
	if (enroll_decode_challenge(padded, sizeof(challenge) + 1, &ch) !=
	    -EBADMSG)
		FAIL("expected: enroll_decode_challenge(padded, "
		     "sizeof(challenge) + 1, &ch) == -EBADMSG");

	memcpy(padded, result, sizeof(result));
	padded[sizeof(result)] = 0x00;
	TEST("a result with a trailing byte is refused");
	if (enroll_decode_result(padded, sizeof(result) + 1, &res) != -EBADMSG)
		FAIL("expected: enroll_decode_result(padded, sizeof(result) + "
		     "1, &res) == -EBADMSG");

	/* a whole appended field, as a newer CA would send */
	memcpy(padded, result, sizeof(result));
	padded[sizeof(result)] = 0x00;
	padded[sizeof(result) + 1] = 0x01;
	padded[sizeof(result) + 2] = 0xFF;
	TEST("a result with an appended field is refused");
	if (enroll_decode_result(padded, sizeof(result) + 3, &res) != -EBADMSG)
		FAIL("expected: enroll_decode_result(padded, sizeof(result) + "
		     "3, &res) == -EBADMSG");
}

/*
 * The chain closes the frame: a count, then length-prefixed certificates.
 * Pinned byte for byte against the Go wire.
 */
static void test_encode_begin_chain_layout(void)
{
	const uint8_t ek[] = { 0xAA, 0xBB };
	const uint8_t aik[] = { 0xCC };
	const uint8_t c0[] = { 0x30, 0x01, 0xDD };
	const uint8_t c1[] = { 0x30, 0x01, 0xEE };
	const struct enroll_cert_ref chain[] = { { c0, sizeof(c0) },
						 { c1, sizeof(c1) } };
	uint8_t out[64];
	ssize_t n = enroll_encode_begin(out, sizeof(out), ek, sizeof(ek), aik,
					sizeof(aik), NULL, 0, chain, 2);

	const uint8_t want[] = { 0x4C, 0x43, 0x41, 0x45, 0x00,
				 0x01, 0x00, 0x02, 0xAA, 0xBB, /* EK leaf */
				 0x00, 0x01, 0xCC, /* AIK template */
				 0x00, 0x00, /* no token */
				 0x00, 0x02, /* two intermediates */
				 0x00, 0x03, 0x30, 0x01, 0xDD,
				 0x00, 0x03, 0x30, 0x01, 0xEE };

	TEST("encode_begin chain length");
	if (n != (ssize_t)sizeof(want))
		FAIL("expected: n == (ssize_t)sizeof(want)");
	TEST("encode_begin chain byte layout matches the Go wire format");
	if (!(n > 0 && memcmp(out, want, sizeof(want)) == 0))
		FAIL("expected: n > 0 && memcmp(out, want, sizeof(want)) == 0");
}

/*
 * The version is the agent's, whatever fields the request carries.
 */
static void test_encode_begin_version_is_the_agents(void)
{
	const uint8_t ek[] = { 0xAA };
	const uint8_t aik[] = { 0xCC };
	const uint8_t token[] = { 't' };
	const uint8_t cert[] = { 0x30, 0x01, 0xDD };
	const struct enroll_cert_ref chain[] = { { cert, sizeof(cert) } };
	uint8_t out[64];

	TEST("a request with neither field names the agent's version");
	if (!(enroll_encode_begin(out, sizeof(out), ek, sizeof(ek), aik,
				  sizeof(aik), NULL, 0, NULL, 0) > 0 &&
	      out[4] == 0x00 && out[5] == LOTA_ENROLL_VERSION))
		FAIL("expected: enroll_encode_begin(out, sizeof(out), ek, "
		     "sizeof(ek), aik, sizeof(aik), NULL, 0, NULL, 0) > 0 && "
		     "out[4] == 0x00 && out[5] == LOTA_ENROLL_VERSION");
	TEST("a token does not move the version");
	if (!(enroll_encode_begin(out, sizeof(out), ek, sizeof(ek), aik,
				  sizeof(aik), token, sizeof(token), NULL,
				  0) > 0 &&
	      out[5] == LOTA_ENROLL_VERSION))
		FAIL("expected: enroll_encode_begin(out, sizeof(out), ek, "
		     "sizeof(ek), aik, sizeof(aik), token, sizeof(token), "
		     "NULL, 0) > 0 && out[5] == LOTA_ENROLL_VERSION");
	TEST("a chain does not move the version");
	if (!(enroll_encode_begin(out, sizeof(out), ek, sizeof(ek), aik,
				  sizeof(aik), NULL, 0, chain, 1) > 0 &&
	      out[5] == LOTA_ENROLL_VERSION))
		FAIL("expected: enroll_encode_begin(out, sizeof(out), ek, "
		     "sizeof(ek), aik, sizeof(aik), NULL, 0, chain, 1) > 0 && "
		     "out[5] == LOTA_ENROLL_VERSION");
	TEST("both fields together do not move the version");
	if (!(enroll_encode_begin(out, sizeof(out), ek, sizeof(ek), aik,
				  sizeof(aik), token, sizeof(token), chain,
				  1) > 0 &&
	      out[5] == LOTA_ENROLL_VERSION))
		FAIL("expected: enroll_encode_begin(out, sizeof(out), ek, "
		     "sizeof(ek), aik, sizeof(aik), token, sizeof(token), "
		     "chain, 1) > 0 && out[5] == LOTA_ENROLL_VERSION");
}

/*
 * Begin and complete of one ceremony carry the same version.
 */
static void test_begin_and_complete_agree_on_version(void)
{
	const uint8_t ek[] = { 0xAA };
	const uint8_t aik[] = { 0xCC };
	const uint8_t token[] = { 't' };
	const uint8_t cert[] = { 0x30, 0x01, 0xDD };
	const struct enroll_cert_ref chain[] = { { cert, sizeof(cert) } };
	uint8_t begin[64];
	uint8_t complete[64];

	TEST("encode_complete succeeds");
	if (enroll_encode_complete(complete, sizeof(complete), "s", ek,
				   sizeof(ek)) <= 0)
		FAIL("expected: enroll_encode_complete(complete, "
		     "sizeof(complete), \"s\", ek, sizeof(ek)) > 0");
	TEST("begin and complete share one preamble");
	if (!(enroll_encode_begin(begin, sizeof(begin), ek, sizeof(ek), aik,
				  sizeof(aik), token, sizeof(token), chain,
				  1) > 0 &&
	      memcmp(begin, complete, 6) == 0))
		FAIL("expected: enroll_encode_begin(begin, sizeof(begin), ek, "
		     "sizeof(ek), aik, sizeof(aik), token, sizeof(token), "
		     "chain, 1) > 0 && memcmp(begin, complete, 6) == 0");
}

/*
 * The chain is vendor data that arrived over NV, so the encoder is the last
 * place that can refuse a request the frame cannot hold.
 */
static void test_encode_begin_chain_bounds(void)
{
	const uint8_t ek[] = { 0xAA };
	const uint8_t aik[] = { 0xCC };
	const uint8_t cert[] = { 0x30, 0x01, 0xDD };
	struct enroll_cert_ref chain[LOTA_ENROLL_MAX_EK_CHAIN_CERTS + 1];
	static uint8_t big_cert[LOTA_ENROLL_MAX_EK_CERT + 1];
	uint8_t out[512];

	for (size_t i = 0; i < LOTA_ENROLL_MAX_EK_CHAIN_CERTS + 1; i++) {
		chain[i].der = cert;
		chain[i].len = sizeof(cert);
	}
	TEST("encode_begin rejects too many intermediates");
	if (enroll_encode_begin(
		    out, sizeof(out), ek, sizeof(ek), aik, sizeof(aik), NULL, 0,
		    chain, LOTA_ENROLL_MAX_EK_CHAIN_CERTS + 1) != -EMSGSIZE)
		FAIL("expected: enroll_encode_begin(out, sizeof(out), ek, "
		     "sizeof(ek), aik, sizeof(aik), NULL, 0, chain, "
		     "LOTA_ENROLL_MAX_EK_CHAIN_CERTS + 1) == -EMSGSIZE");

	memset(big_cert, 0, sizeof(big_cert));
	chain[0].der = big_cert;
	chain[0].len = sizeof(big_cert);
	TEST("encode_begin rejects an oversized intermediate");
	if (enroll_encode_begin(out, sizeof(out), ek, sizeof(ek), aik,
				sizeof(aik), NULL, 0, chain, 1) != -EMSGSIZE)
		FAIL("expected: enroll_encode_begin(out, sizeof(out), ek, "
		     "sizeof(ek), aik, sizeof(aik), NULL, 0, chain, 1) == "
		     "-EMSGSIZE");
}

/*
 * TPM stores its manufacturer intermediates as one NV blob with the certificates
 * laid end to end and no framing of its own, so the only way to find the elements
 * is to walk the ASN.1 SEQUENCE headers.
 * Intel PTT keeps three of them there, and they are the certificates without which
 * no such host can build a path to its manufacturer root.
 */
static void test_split_cert_chain(void)
{
	/* three SEQUENCEs: short form, long form, short form */
	const uint8_t blob[] = { 0x30, 0x02, 0xAA, 0xBB, /* 4 bytes */
				 0x30, 0x82, 0x00, 0x03,
				 0x01, 0x02, 0x03, /* 7 bytes */
				 0x30, 0x01, 0xFF }; /* 3 bytes */
	struct enroll_cert_ref certs[LOTA_ENROLL_MAX_EK_CHAIN_CERTS];
	size_t count = 0;

	TEST("split accepts a concatenated certificate blob");
	if (enroll_split_cert_chain(blob, sizeof(blob), certs,
				    LOTA_ENROLL_MAX_EK_CHAIN_CERTS,
				    &count) != 0)
		FAIL("expected: enroll_split_cert_chain(blob, sizeof(blob), "
		     "certs, LOTA_ENROLL_MAX_EK_CHAIN_CERTS, &count) == 0");
	TEST("split finds every certificate in the blob");
	if (count != 3)
		FAIL("expected: count == 3");
	TEST("split sizes a short-form certificate");
	if (!(count == 3 && certs[0].der == blob && certs[0].len == 4))
		FAIL("expected: count == 3 && certs[0].der == blob && "
		     "certs[0].len == 4");
	TEST("split sizes a long-form certificate");
	if (!(count == 3 && certs[1].der == blob + 4 && certs[1].len == 7))
		FAIL("expected: count == 3 && certs[1].der == blob + 4 && "
		     "certs[1].len == 7");
	TEST("split sizes the last certificate");
	if (!(count == 3 && certs[2].der == blob + 11 && certs[2].len == 3))
		FAIL("expected: count == 3 && certs[2].der == blob + 11 && "
		     "certs[2].len == 3");
}

/*
 * NV contents are vendor data the host does not control, so the walk is lenient
 * in both directions: whatever stops looking like a certificate ends the list,
 * and a blob that yields nothing leaves the enrollment to proceed on the leaf
 * alone.
 */
static void test_split_cert_chain_tolerates_junk(void)
{
	const uint8_t padded[] = { 0x30, 0x01, 0xAA, 0x00, 0x00, 0x00, 0x00 };
	const uint8_t junk[] = { 0xFF, 0xFF, 0xFF, 0xFF };
	const uint8_t truncated[] = { 0x30, 0x08, 0xAA, 0xBB };
	struct enroll_cert_ref certs[LOTA_ENROLL_MAX_EK_CHAIN_CERTS];
	size_t count = 99;

	TEST("trailing NV padding ends the list");
	if (!(enroll_split_cert_chain(padded, sizeof(padded), certs,
				      LOTA_ENROLL_MAX_EK_CHAIN_CERTS,
				      &count) == 0 &&
	      count == 1))
		FAIL("expected: enroll_split_cert_chain(padded, "
		     "sizeof(padded), certs, LOTA_ENROLL_MAX_EK_CHAIN_CERTS, "
		     "&count) == 0 && count == 1");

	count = 99;
	TEST("a blob holding no certificate yields none");
	if (!(enroll_split_cert_chain(junk, sizeof(junk), certs,
				      LOTA_ENROLL_MAX_EK_CHAIN_CERTS,
				      &count) == 0 &&
	      count == 0))
		FAIL("expected: enroll_split_cert_chain(junk, sizeof(junk), "
		     "certs, LOTA_ENROLL_MAX_EK_CHAIN_CERTS, &count) == 0 && "
		     "count == 0");

	count = 99;
	TEST("a certificate running past the blob is dropped");
	if (!(enroll_split_cert_chain(truncated, sizeof(truncated), certs,
				      LOTA_ENROLL_MAX_EK_CHAIN_CERTS,
				      &count) == 0 &&
	      count == 0))
		FAIL("expected: enroll_split_cert_chain(truncated, "
		     "sizeof(truncated), certs, "
		     "LOTA_ENROLL_MAX_EK_CHAIN_CERTS, &count) == 0 && count "
		     "== 0");

	count = 99;
	TEST("split rejects a NULL blob");
	if (enroll_split_cert_chain(NULL, 0, certs,
				    LOTA_ENROLL_MAX_EK_CHAIN_CERTS,
				    &count) != -EINVAL)
		FAIL("expected: enroll_split_cert_chain(NULL, 0, certs, "
		     "LOTA_ENROLL_MAX_EK_CHAIN_CERTS, &count) == -EINVAL");
}

/*
 * Both caps are frame budget: the begin request has to fit LOTA_ENROLL_MAX_FRAME
 * beside the leaf, the AIK template and the token, so the walk stops at
 * the caller's array and at the byte budget rather than handing the encoder
 * a chain it would refuse.
 */
static void test_split_cert_chain_bounds(void)
{
	const uint8_t blob[] = { 0x30, 0x01, 0xAA, 0x30, 0x01,
				 0xBB, 0x30, 0x01, 0xCC };
	struct enroll_cert_ref certs[LOTA_ENROLL_MAX_EK_CHAIN_CERTS];
	size_t count = 0;

	TEST("split stops at the caller's array");
	if (!(enroll_split_cert_chain(blob, sizeof(blob), certs, 2, &count) ==
		      0 &&
	      count == 2))
		FAIL("expected: enroll_split_cert_chain(blob, sizeof(blob), "
		     "certs, 2, &count) == 0 && count == 2");

	/*
	 * one certificate one byte past the per-certificate cap:
	 * it is not a certificate this wire can carry, so the walk ends there
	 */
	static uint8_t oversized[LOTA_ENROLL_MAX_EK_CERT + 8];
	size_t body = LOTA_ENROLL_MAX_EK_CERT;

	memset(oversized, 0, sizeof(oversized));
	oversized[0] = 0x30;
	oversized[1] = 0x82;
	oversized[2] = (uint8_t)((body >> 8) & 0xFFu);
	oversized[3] = (uint8_t)(body & 0xFFu);
	count = 99;
	TEST("split drops a certificate past the per-certificate cap");
	if (!(enroll_split_cert_chain(oversized, sizeof(oversized), certs,
				      LOTA_ENROLL_MAX_EK_CHAIN_CERTS,
				      &count) == 0 &&
	      count == 0))
		FAIL("expected: enroll_split_cert_chain(oversized, "
		     "sizeof(oversized), certs, "
		     "LOTA_ENROLL_MAX_EK_CHAIN_CERTS, &count) == 0 && count "
		     "== 0");
}

static const char *write_token_file(const char *content, size_t len)
{
	static char path[256];
	int fd;

	snprintf(path, sizeof(path), "/tmp/lota-enroll-token-test.%d",
		 getpid());
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		return NULL;
	if (write(fd, content, len) != (ssize_t)len) {
		close(fd);
		return NULL;
	}
	close(fd);
	return path;
}

static void test_token_from_file(void)
{
	char token[LOTA_ENROLL_MAX_TOKEN + 1];
	const char *path;

	path = write_token_file("game-alpha-token\n", 17);
	TEST("token file with trailing newline loads");
	if (!(path && enroll_token_from_file(path, token, sizeof(token)) == 0))
		FAIL("expected: path && enroll_token_from_file(path, token, "
		     "sizeof(token)) == 0");
	TEST("trailing newline trimmed");
	if (strcmp(token, "game-alpha-token") != 0)
		FAIL("expected: strcmp(token, \"game-alpha-token\") == 0");

	path = write_token_file("  \n", 3);
	TEST("whitespace-only token file rejected");
	if (!(path &&
	      enroll_token_from_file(path, token, sizeof(token)) == -EINVAL))
		FAIL("expected: path && enroll_token_from_file(path, token, "
		     "sizeof(token)) == -EINVAL");

	path = write_token_file("bad token\n", 10);
	TEST("inner whitespace rejected");
	if (!(path &&
	      enroll_token_from_file(path, token, sizeof(token)) == -EINVAL))
		FAIL("expected: path && enroll_token_from_file(path, token, "
		     "sizeof(token)) == -EINVAL");

	char big[LOTA_ENROLL_MAX_TOKEN + 2];
	memset(big, 't', sizeof(big));
	big[sizeof(big) - 1] = '\n';
	path = write_token_file(big, sizeof(big));
	TEST("oversized token rejected");
	if (!(path &&
	      enroll_token_from_file(path, token, sizeof(token)) == -EMSGSIZE))
		FAIL("expected: path && enroll_token_from_file(path, token, "
		     "sizeof(token)) == -EMSGSIZE");

	TEST("missing token file is -ENOENT");
	if (enroll_token_from_file("/nonexistent/lota-token", token,
				   sizeof(token)) != -ENOENT)
		FAIL("expected: enroll_token_from_file(\"/nonexistent/lota-token\", "
		     "token, sizeof(token)) == -ENOENT");
	TEST("NULL path rejected");
	if (enroll_token_from_file(NULL, token, sizeof(token)) != -EINVAL)
		FAIL("expected: enroll_token_from_file(NULL, token, "
		     "sizeof(token)) == -EINVAL");
	TEST("undersized output buffer rejected");
	if (enroll_token_from_file("/tmp/x", token, 4) != -EINVAL)
		FAIL("expected: enroll_token_from_file(\"/tmp/x\", token, 4) "
		     "== -EINVAL");

	if (path)
		unlink(path);
}

int main(void)
{
	test_begin("enroll wire");
	test_encode_begin_layout();
	test_encode_begin_token_layout();
	test_encode_begin_bounds();
	test_encode_complete();
	test_decode_challenge();
	test_decode_result();
	test_decode_rejects_malformed();
	test_decode_rejects_trailing_bytes();
	test_encode_begin_chain_layout();
	test_encode_begin_version_is_the_agents();
	test_begin_and_complete_agree_on_version();
	test_encode_begin_chain_bounds();
	test_split_cert_chain();
	test_split_cert_chain_tolerates_junk();
	test_split_cert_chain_bounds();
	test_token_from_file();

	return test_end();
}
