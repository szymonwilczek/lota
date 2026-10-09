/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Unit tests for what --test-tpm does about the attestation key.
 *
 * The verb is described as a test that exits, and a reader reaches for it
 * precisely because they do not want to change anything. It provisioned an AIK
 * at the persistent handle instead, and on a firmware TPM the persistent pool
 * is the real ceiling on how many publishers a host can answer to -- so a probe
 * that takes one of those slots costs the machine something it was never asked
 * about.
 *
 * The decision is a pure function of one answer from the TPM: is a key already
 * at the handle.
 */

#include <errno.h>
#include <stdio.h>

#include "../src/agent/selftest.h"

static int g_failures;

#define CHECK(cond, msg)                                    \
	do {                                                \
		if (!(cond)) {                              \
			fprintf(stderr, "FAIL: %s\n", msg); \
			g_failures++;                       \
		} else {                                    \
			printf("PASS: %s\n", msg);          \
		}                                           \
	} while (0)

/* a key that is already there costs nothing to use and stays afterwards */
static void test_existing_key_is_used(void)
{
	CHECK(selftest_aik_plan(1) == SELFTEST_AIK_USE_EXISTING,
	      "an AIK already at the handle is quoted with");
}

/* a free handle is the case that caught this finding */
static void test_free_handle_creates_nothing(void)
{
	CHECK(selftest_aik_plan(0) == SELFTEST_AIK_SKIP,
	      "a free handle leaves the probe without a key rather than "
	      "provisioning one");
}

/*
 * a TPM that could not be asked is not evidence the handle is free,
 * and provisioning on a guess is how a probe writes to a machine twice over
 */
static void test_unreadable_tpm_creates_nothing(void)
{
	CHECK(selftest_aik_plan(-5) == SELFTEST_AIK_SKIP,
	      "an unreadable handle is not treated as an invitation to "
	      "provision");
}

/*
 * The failure the verb exists to catch.
 * A quote the TPM refuses is the one result that matters -- it is what
 * attestation needs and what spends a dictionary-attack attempt -- and a caller
 * gating on the command has only the exit status to read it from.
 */
static void test_a_failed_section_is_not_success(void)
{
	struct selftest_tally t = { .passed = 8, .failed = 1, .skipped = 0 };

	CHECK(selftest_verdict(&t) != 0,
	      "a probe with a failed section does not report success");
}

/* Nothing failed is success, however much was skipped. */
static void test_nothing_failed_is_success(void)
{
	struct selftest_tally all_good = { .passed = 9,
					   .failed = 0,
					   .skipped = 0 };
	struct selftest_tally skipped = { .passed = 7,
					  .failed = 0,
					  .skipped = 2 };

	CHECK(selftest_verdict(&all_good) == 0,
	      "a probe where everything worked reports success");
	CHECK(selftest_verdict(&skipped) == 0,
	      "a section that could not be reached is not a failure");
}

/* The tally is what the sections write into, so it has to record both ways. */
static void test_the_tally_counts_what_it_is_told(void)
{
	struct selftest_tally t = { 0 };

	selftest_record(&t, 0);
	selftest_record(&t, -EIO);
	selftest_skip(&t);

	CHECK(t.passed == 1 && t.failed == 1 && t.skipped == 1,
	      "a pass, a failure and a skip are counted apart");
}

int main(void)
{
	printf("=== --test-tpm attestation-key plan ===\n");
	test_existing_key_is_used();
	test_free_handle_creates_nothing();
	test_unreadable_tpm_creates_nothing();
	test_a_failed_section_is_not_success();
	test_nothing_failed_is_success();
	test_the_tally_counts_what_it_is_told();

	if (g_failures) {
		fprintf(stderr, "\n%d test(s) failed\n", g_failures);
		return 1;
	}
	printf("\nAll --test-tpm plan tests passed\n");
	return 0;
}
