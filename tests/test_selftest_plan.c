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
 * Both decisions are pure: whether a key is at the handle,
 * and whose key is quoted.
 */

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#include "../src/agent/selftest.h"
#include "../src/agent/tpm.h"

#include "test.h"

/* a key that is already there costs nothing to use and stays afterwards */
static void test_existing_key_is_used(void)
{
	TEST("an AIK already at the handle is quoted with");
	if (selftest_aik_plan(1) != SELFTEST_AIK_USE_EXISTING)
		FAIL("expected: selftest_aik_plan(1) == "
		     "SELFTEST_AIK_USE_EXISTING");
}

/* a free handle is the case that caught this finding */
static void test_free_handle_creates_nothing(void)
{
	TEST("a free handle leaves the probe without a key rather than "
	     "provisioning one");
	if (selftest_aik_plan(0) != SELFTEST_AIK_SKIP)
		FAIL("expected: selftest_aik_plan(0) == SELFTEST_AIK_SKIP");
}

/*
 * a TPM that could not be asked is not evidence the handle is free,
 * and provisioning on a guess is how a probe writes to a machine twice over
 */
static void test_unreadable_tpm_creates_nothing(void)
{
	TEST("an unreadable handle is not treated as an invitation to "
	     "provision");
	if (selftest_aik_plan(-5) != SELFTEST_AIK_SKIP)
		FAIL("expected: selftest_aik_plan(-5) == SELFTEST_AIK_SKIP");
}

/*
 * Once publishers hold keys, the pre-profile records pair the first
 * publisher's handle with a stale authorization: quoting fails and
 * spends a DA attempt.
 */
static void test_publisher_keys_are_what_is_quoted(void)
{
	TEST("one publisher holding a key is the key the probe quotes with");
	if (selftest_quote_key(1) != SELFTEST_QUOTE_PER_PUBLISHER)
		FAIL("expected: selftest_quote_key(1) == "
		     "SELFTEST_QUOTE_PER_PUBLISHER");
	TEST("several publishers holding keys are all the probe's to quote");
	if (selftest_quote_key(5) != SELFTEST_QUOTE_PER_PUBLISHER)
		FAIL("expected: selftest_quote_key(5) == "
		     "SELFTEST_QUOTE_PER_PUBLISHER");
}

static void test_no_publisher_leaves_the_pre_profile_key(void)
{
	TEST("with no publisher holding a key the pre-profile records are "
	     "the ones that describe this host");
	if (selftest_quote_key(0) != SELFTEST_QUOTE_PRE_PROFILE)
		FAIL("expected: selftest_quote_key(0) == "
		     "SELFTEST_QUOTE_PRE_PROFILE");
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

	TEST("a probe with a failed section does not report success");
	if (selftest_verdict(&t) == 0)
		FAIL("expected: selftest_verdict(&t) != 0");
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

	TEST("a probe where everything worked reports success");
	if (selftest_verdict(&all_good) != 0)
		FAIL("expected: selftest_verdict(&all_good) == 0");
	TEST("a section that could not be reached is not a failure");
	if (selftest_verdict(&skipped) != 0)
		FAIL("expected: selftest_verdict(&skipped) == 0");
}

/* The tally is what the sections write into, so it has to record both ways. */
static void test_the_tally_counts_what_it_is_told(void)
{
	struct selftest_tally t = { 0 };

	selftest_record(&t, 0);
	selftest_record(&t, -EIO);
	selftest_skip(&t);

	TEST("a pass, a failure and a skip are counted apart");
	if (!(t.passed == 1 && t.failed == 1 && t.skipped == 1))
		FAIL("expected: t.passed == 1 && t.failed == 1 && t.skipped "
		     "== 1");
}

/* a key with no authorization record is left for the daemon to rotate */
static void test_load_plan(void)
{
	TEST("a loaded authorization is quoted with");
	if (selftest_aik_load_plan(0) != SELFTEST_AIK_LOAD_QUOTE)
		FAIL("expected: selftest_aik_load_plan(0) == "
		     "SELFTEST_AIK_LOAD_QUOTE");
	TEST("a key with no authorization record is skipped");
	if (selftest_aik_load_plan(-ENOENT) != SELFTEST_AIK_LOAD_SKIP)
		FAIL("expected: selftest_aik_load_plan(-ENOENT) == "
		     "SELFTEST_AIK_LOAD_SKIP");
	TEST("a failed load is a failure");
	if (selftest_aik_load_plan(-EIO) != SELFTEST_AIK_LOAD_FAIL)
		FAIL("expected: selftest_aik_load_plan(-EIO) == "
		     "SELFTEST_AIK_LOAD_FAIL");
}

/* --test-tpm checks PCR 14 and leaves it to the daemon to extend */
static void test_check_writes_nothing(void)
{
	static const enum tpm_pcr14_state states[] = {
		TPM_PCR14_AWAITING_EXTEND,	 TPM_PCR14_ALREADY_COMMITTED,
		TPM_PCR14_LOCK_MISSING,		 TPM_PCR14_SPENT_BY_SHUTDOWN,
		TPM_PCR14_SPENT_BY_ERROR,	 TPM_PCR14_BINARY_CHANGED,
		TPM_PCR14_HANDOFF_CHANGED,	 TPM_PCR14_UNATTRIBUTABLE,
		TPM_PCR14_TAMPERED_BEFORE_START, TPM_PCR14_MUTATED_IN_SESSION,
		TPM_PCR14_STATE_ROLLBACK,
	};
	bool any = false;

	for (size_t i = 0; i < sizeof(states) / sizeof(states[0]); i++)
		any |= tpm_boot_commitment_writes(states[i], false);
	TEST("a check writes neither PCR 14 nor the snapshot");
	if (any)
		FAIL("expected: !any");
	TEST("the daemon extends a register awaiting the commitment");
	if (!tpm_boot_commitment_writes(TPM_PCR14_AWAITING_EXTEND, true))
		FAIL("expected: tpm_boot_commitment_writes(TPM_PCR14_AWAITING_EXTEND, "
		     "true)");
	TEST("the daemon saves the snapshot over a held commitment");
	if (!tpm_boot_commitment_writes(TPM_PCR14_ALREADY_COMMITTED, true))
		FAIL("expected: tpm_boot_commitment_writes(TPM_PCR14_ALREADY_COMMITTED, "
		     "true)");
	TEST("a refused verdict writes nothing");
	if (tpm_boot_commitment_writes(TPM_PCR14_BINARY_CHANGED, true))
		FAIL("expected: !tpm_boot_commitment_writes(TPM_PCR14_BINARY_CHANGED, "
		     "true)");
}

int main(void)
{
	test_begin("selftest plan");
	test_existing_key_is_used();
	test_free_handle_creates_nothing();
	test_unreadable_tpm_creates_nothing();
	test_publisher_keys_are_what_is_quoted();
	test_no_publisher_leaves_the_pre_profile_key();
	test_a_failed_section_is_not_success();
	test_nothing_failed_is_success();
	test_the_tally_counts_what_it_is_told();
	test_check_writes_nothing();
	test_load_plan();

	return test_end();
}
