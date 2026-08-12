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

int main(void)
{
	printf("=== --test-tpm attestation-key plan ===\n");
	test_existing_key_is_used();
	test_free_handle_creates_nothing();
	test_unreadable_tpm_creates_nothing();

	if (g_failures) {
		fprintf(stderr, "\n%d test(s) failed\n", g_failures);
		return 1;
	}
	printf("\nAll --test-tpm plan tests passed\n");
	return 0;
}
