// SPDX-License-Identifier: MIT
/*
 * Unit tests for the signed-clock TPMS_ATTEST parser exposed via
 * tpm_test_parse_signed_clockinfo() (LOTA_TPM_TESTING).
 *
 * The agent's tpm_extend_boot_commitment() captures resetCount /
 * restartCount through an AIK-signed TPM2_Quote so the value bound
 * into PCR14 matches the clockInfo carried by the later attestation
 * quote. Esys_ReadClock and Quote.clockInfo can diverge on TPM 2.0
 * simulators (observed on swtpm/Fedora 44) which previously made the
 * verifier reject every legitimate report.
 *
 * These tests cover the parsing layer that the agent relies on: a
 * round-trip through Tss2_MU_TPMS_ATTEST_Marshal must yield the same
 * resetCount/restartCount we marshalled, and malformed inputs must
 * fail safely without producing values.
 */

#define LOTA_INTERNAL_TESTS 1

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <tss2/tss2_mu.h>
#include <stdint.h>
#include <tss2/tss2_common.h>
#include <tss2/tss2_tpm2_types.h>

#include "../src/agent/tpm.h"

static int g_failures;
static const char *g_current_test;

#define TEST(name)                                 \
	do {                                       \
		g_current_test = name;             \
		printf("[ RUN      ] %s\n", name); \
	} while (0)

#define PASS()                                               \
	do {                                                 \
		printf("[       OK ] %s\n", g_current_test); \
	} while (0)

#define FAIL(fmt, ...)                                                        \
	do {                                                                  \
		fprintf(stderr, "[  FAILED  ] %s: " fmt "\n", g_current_test, \
			##__VA_ARGS__);                                       \
		g_failures++;                                                 \
		return;                                                       \
	} while (0)

#define EXPECT_EQ(got, want)                             \
	do {                                             \
		if ((got) != (want)) {                   \
			FAIL("expected %llu, got %llu",  \
			     (unsigned long long)(want), \
			     (unsigned long long)(got)); \
		}                                        \
	} while (0)

/*
 * marshal_attest builds a minimal TPMS_ATTEST_QUOTE with the given
 * resetCount/restartCount and returns the marshalled byte buffer.
 * Mirrors what the TPM hands back from Esys_Quote so the parsing
 * helper sees production-shaped input.
 */
static int marshal_attest(uint32_t reset_count, uint32_t restart_count,
			  uint8_t *buf, size_t buf_size, size_t *out_size)
{
	TPMS_ATTEST attest;
	size_t offset = 0;
	TSS2_RC rc;

	memset(&attest, 0, sizeof(attest));
	attest.magic = TPM2_GENERATED_VALUE;
	attest.type = TPM2_ST_ATTEST_QUOTE;

	attest.qualifiedSigner.size = 0;
	attest.extraData.size = 16;
	for (uint16_t i = 0; i < attest.extraData.size; i++)
		attest.extraData.buffer[i] = (uint8_t)(0x40 + i);

	attest.clockInfo.clock = 0xDEADBEEFCAFEBABEULL;
	attest.clockInfo.resetCount = reset_count;
	attest.clockInfo.restartCount = restart_count;
	attest.clockInfo.safe = TPM2_YES;

	attest.firmwareVersion = 0x0123456789ABCDEFULL;

	attest.attested.quote.pcrSelect.count = 1;
	attest.attested.quote.pcrSelect.pcrSelections[0].hash = TPM2_ALG_SHA256;
	attest.attested.quote.pcrSelect.pcrSelections[0].sizeofSelect = 3;
	attest.attested.quote.pcrSelect.pcrSelections[0].pcrSelect[1] =
		(uint8_t)(1U << (14 % 8));

	attest.attested.quote.pcrDigest.size = 32;
	for (uint16_t i = 0; i < attest.attested.quote.pcrDigest.size; i++)
		attest.attested.quote.pcrDigest.buffer[i] = (uint8_t)i;

	rc = Tss2_MU_TPMS_ATTEST_Marshal(&attest, buf, buf_size, &offset);
	if (rc != TSS2_RC_SUCCESS)
		return -EIO;
	*out_size = offset;
	return 0;
}

/*
 * Sanity: marshal -> parse round-trip returns the resetCount and
 * restartCount the caller asked the TPM to sign.
 */
static void test_round_trip_small_counters(void)
{
	uint8_t buf[1024];
	size_t buf_used = 0;
	uint32_t reset = 0;
	uint32_t restart = 0;

	TEST("parse_signed_clockinfo round-trips small counters");

	if (marshal_attest(9, 0, buf, sizeof(buf), &buf_used) != 0)
		FAIL("failed to marshal TPMS_ATTEST");

	int ret = tpm_test_parse_signed_clockinfo(buf, buf_used, &reset,
						  &restart);
	if (ret != 0)
		FAIL("parser returned %d", ret);
	EXPECT_EQ(reset, 9);
	EXPECT_EQ(restart, 0);
	PASS();
}

/*
 * Regression: the bug fixed in commit "agent: bind PCR14 to AIK-signed
 * clockInfo" surfaced on swtpm with resetCount=1973039075,
 * restartCount=2947164106 inside Quote.clockInfo while Esys_ReadClock
 * returned 9/0. If the parser ever loses a byte or swaps endianness
 * the verifier-side derivation would mismatch silently again.
 */
static void test_round_trip_swtpm_observed_counters(void)
{
	uint8_t buf[1024];
	size_t buf_used = 0;
	uint32_t reset = 0;
	uint32_t restart = 0;

	TEST("parse_signed_clockinfo preserves swtpm-observed counter values");

	if (marshal_attest(1973039075U, 2947164106U, buf, sizeof(buf),
			   &buf_used) != 0)
		FAIL("failed to marshal TPMS_ATTEST");

	int ret = tpm_test_parse_signed_clockinfo(buf, buf_used, &reset,
						  &restart);
	if (ret != 0)
		FAIL("parser returned %d", ret);
	EXPECT_EQ(reset, 1973039075U);
	EXPECT_EQ(restart, 2947164106U);
	PASS();
}

/*
 * Boundary: 0xFFFFFFFF in either counter must come back identically -
 * proves the parser uses uint32 storage end to end.
 */
static void test_round_trip_max_counters(void)
{
	uint8_t buf[1024];
	size_t buf_used = 0;
	uint32_t reset = 0;
	uint32_t restart = 0;

	TEST("parse_signed_clockinfo handles uint32 maximum values");

	if (marshal_attest(0xFFFFFFFFU, 0xFFFFFFFFU, buf, sizeof(buf),
			   &buf_used) != 0)
		FAIL("failed to marshal TPMS_ATTEST");

	int ret = tpm_test_parse_signed_clockinfo(buf, buf_used, &reset,
						  &restart);
	if (ret != 0)
		FAIL("parser returned %d", ret);
	EXPECT_EQ(reset, 0xFFFFFFFFU);
	EXPECT_EQ(restart, 0xFFFFFFFFU);
	PASS();
}

/*
 * Independence: the parser must not derive resetCount from restartCount
 * or vice versa - feed distinct values and make sure each lands in the
 * correct out parameter.
 */
static void test_round_trip_distinct_counters(void)
{
	uint8_t buf[1024];
	size_t buf_used = 0;
	uint32_t reset = 0;
	uint32_t restart = 0;

	TEST("parse_signed_clockinfo separates reset from restart");

	if (marshal_attest(0xA5A5A5A5U, 0x5A5A5A5AU, buf, sizeof(buf),
			   &buf_used) != 0)
		FAIL("failed to marshal TPMS_ATTEST");

	int ret = tpm_test_parse_signed_clockinfo(buf, buf_used, &reset,
						  &restart);
	if (ret != 0)
		FAIL("parser returned %d", ret);
	EXPECT_EQ(reset, 0xA5A5A5A5U);
	EXPECT_EQ(restart, 0x5A5A5A5AU);
	PASS();
}

/*
 * NULL/zero inputs return -EINVAL without writing out parameters.
 * Production code paths must be able to rely on the contract instead
 * of catching segfaults in the caller.
 */
static void test_rejects_null_arguments(void)
{
	uint8_t buf[8] = { 0 };
	uint32_t reset = 0xDEAD;
	uint32_t restart = 0xBEEF;

	TEST("parse_signed_clockinfo rejects NULL/zero arguments");

	if (tpm_test_parse_signed_clockinfo(NULL, sizeof(buf), &reset,
					    &restart) != -EINVAL)
		FAIL("NULL buf must yield -EINVAL");
	if (tpm_test_parse_signed_clockinfo(buf, 0, &reset, &restart) !=
	    -EINVAL)
		FAIL("zero length must yield -EINVAL");
	if (tpm_test_parse_signed_clockinfo(buf, sizeof(buf), NULL, &restart) !=
	    -EINVAL)
		FAIL("NULL reset_out must yield -EINVAL");
	if (tpm_test_parse_signed_clockinfo(buf, sizeof(buf), &reset, NULL) !=
	    -EINVAL)
		FAIL("NULL restart_out must yield -EINVAL");

	if (reset != 0xDEAD || restart != 0xBEEF)
		FAIL("out parameters were touched after -EINVAL");
	PASS();
}

/*
 * Truncated input must fail; a partial TPMS_ATTEST means the TPM
 * response was corrupted in transit and the verifier would otherwise
 * see uninitialised counter values.
 */
static void test_rejects_truncated_input(void)
{
	uint8_t buf[1024];
	size_t buf_used = 0;
	uint32_t reset = 0;
	uint32_t restart = 0;

	TEST("parse_signed_clockinfo rejects truncated input");

	if (marshal_attest(5, 3, buf, sizeof(buf), &buf_used) != 0)
		FAIL("failed to marshal TPMS_ATTEST");

	/* Drop everything after the magic so clockInfo is unreachable. */
	int ret = tpm_test_parse_signed_clockinfo(buf, 4, &reset, &restart);
	if (ret == 0)
		FAIL("truncated input must fail");
	PASS();
}

/*
 * Garbage bytes must fail without producing values. Tss2_MU
 * unmarshalling rejects bad magic; the helper must propagate that.
 */
static void test_rejects_garbage_input(void)
{
	uint8_t buf[64];
	uint32_t reset = 0;
	uint32_t restart = 0;

	TEST("parse_signed_clockinfo rejects garbage input");

	for (size_t i = 0; i < sizeof(buf); i++)
		buf[i] = (uint8_t)i;

	int ret = tpm_test_parse_signed_clockinfo(buf, sizeof(buf), &reset,
						  &restart);
	if (ret == 0)
		FAIL("garbage input must fail");
	PASS();
}

int main(void)
{
	test_round_trip_small_counters();
	test_round_trip_swtpm_observed_counters();
	test_round_trip_max_counters();
	test_round_trip_distinct_counters();
	test_rejects_null_arguments();
	test_rejects_truncated_input();
	test_rejects_garbage_input();

	if (g_failures == 0) {
		printf("\nAll tests passed.\n");
		return 0;
	}
	fprintf(stderr, "\n%d test(s) failed.\n", g_failures);
	return 1;
}
