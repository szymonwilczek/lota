/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for the host status bits the enforcement daemon publishes.
 *
 * Every bit in the status word is something title reads and acts on,
 * and a bit nobody produces is indistinguishable from machine that failed the check.
 * LOTA_STATUS_SECURE_BOOT was such a bit: defined, documented, read by the SDK,
 * and set by no code path in the agent, so every title on every host was told
 * Secure Boot was off.
 * Table with one entry per bit is what keeps that from happening again.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include "../src/agent/status_flags.h"

#include "test.h"

int main(void)
{
	struct agent_boot_state st;
	uint32_t flags;

	test_begin("status flags");

	/* nothing verified:
	 * every bit clear, which is the honest answer for host that has checked
	 * nothing rather than a host that passed */
	st = (struct agent_boot_state){ 0 };
	TEST("a host that verified nothing sets no bit");
	if (agent_status_flags(&st) != 0)
		FAIL("expected: agent_status_flags(&st) == 0");

	st = (struct agent_boot_state){ .tpm_ok = true };
	TEST("the TPM bit comes from the TPM probe");
	if (agent_status_flags(&st) != LOTA_STATUS_TPM_OK)
		FAIL("expected: agent_status_flags(&st) == LOTA_STATUS_TPM_OK");

	st = (struct agent_boot_state){ .iommu_ok = true };
	TEST("the IOMMU bit comes from the IOMMU probe");
	if (agent_status_flags(&st) != LOTA_STATUS_IOMMU_OK)
		FAIL("expected: agent_status_flags(&st) == "
		     "LOTA_STATUS_IOMMU_OK");

	st = (struct agent_boot_state){ .bpf_loaded = true };
	TEST("the BPF bit comes from the loader");
	if (agent_status_flags(&st) != LOTA_STATUS_BPF_LOADED)
		FAIL("expected: agent_status_flags(&st) == "
		     "LOTA_STATUS_BPF_LOADED");

	st = (struct agent_boot_state){ .kernel_appraisal = true };
	TEST("the appraisal bit comes from the IMA scope probe");
	if (agent_status_flags(&st) != LOTA_STATUS_KERNEL_APPRAISAL)
		FAIL("expected: agent_status_flags(&st) == "
		     "LOTA_STATUS_KERNEL_APPRAISAL");

	/* the one this file exists for */
	st = (struct agent_boot_state){ .secure_boot = true };
	TEST("the Secure Boot bit has a producer");
	if (agent_status_flags(&st) != LOTA_STATUS_SECURE_BOOT)
		FAIL("expected: agent_status_flags(&st) == "
		     "LOTA_STATUS_SECURE_BOOT");

	st = (struct agent_boot_state){ .bench = true };
	TEST("the bench bit comes from --bench");
	if (agent_status_flags(&st) != LOTA_STATUS_BENCH)
		FAIL("expected: agent_status_flags(&st) == LOTA_STATUS_BENCH");

	st = (struct agent_boot_state){ .tpm_lockout = true };
	TEST("the TPM lockout bit comes from the TPM context");
	if (agent_status_flags(&st) != LOTA_STATUS_TPM_LOCKOUT)
		FAIL("expected: agent_status_flags(&st) == "
		     "LOTA_STATUS_TPM_LOCKOUT");

	st = (struct agent_boot_state){
		.tpm_ok = true,
		.iommu_ok = true,
		.bpf_loaded = true,
		.secure_boot = true,
	};
	flags = agent_status_flags(&st);
	TEST("a fully verified host sets exactly its four bits");
	if (flags != (LOTA_STATUS_TPM_OK | LOTA_STATUS_IOMMU_OK |
		      LOTA_STATUS_BPF_LOADED | LOTA_STATUS_SECURE_BOOT))
		FAIL("expected: flags == (LOTA_STATUS_TPM_OK | "
		     "LOTA_STATUS_IOMMU_OK | LOTA_STATUS_BPF_LOADED | "
		     "LOTA_STATUS_SECURE_BOOT)");

	/*
	 * attestation verdict is not in this word:
	 * it is the attestation loop's, arrives over the sync, and is folded
	 * in by the socket owner.
	 * Producing it here would let host claim to be attested from local
	 * state alone.
	 */
	TEST("the attested bit is not produced from local state");
	if (flags & LOTA_STATUS_ATTESTED)
		FAIL("expected: !(flags & LOTA_STATUS_ATTESTED)");

	/*
	 * Runtime coverage.
	 * Host protecting nothing has measured nothing, and the publisher
	 * control this bit serves asks for the opposite.
	 */
	TEST("a round with nothing to measure is not full coverage");
	if (lota_coverage_is_full(0, true))
		FAIL("expected: !lota_coverage_is_full(0, true)");
	TEST("an empty round stays false however it is asked");
	if (lota_coverage_is_full(0, false))
		FAIL("expected: !lota_coverage_is_full(0, false)");
	TEST("one protected process with every object measured is full");
	if (!lota_coverage_is_full(1, true))
		FAIL("expected: lota_coverage_is_full(1, true)");
	TEST("an object left unmeasured is not full coverage");
	if (lota_coverage_is_full(3, false))
		FAIL("expected: !lota_coverage_is_full(3, false)");

	/* the fold puts that answer in the word both roads hand out */
	TEST("full coverage sets the bit");
	if (lota_status_fold_coverage(0, lota_coverage_is_full(1, true)) !=
	    LOTA_STATUS_IMAGE_FULLY_MEASURED)
		FAIL("expected: lota_status_fold_coverage(0, "
		     "lota_coverage_is_full(1, true)) == "
		     "LOTA_STATUS_IMAGE_FULLY_MEASURED");
	TEST("an empty round clears a bit an earlier round set");
	if (lota_status_fold_coverage(LOTA_STATUS_IMAGE_FULLY_MEASURED,
				      lota_coverage_is_full(0, true)) != 0)
		FAIL("expected: lota_status_fold_coverage(LOTA_STATUS_IMAGE_FULLY_MEASURED, "
		     "lota_coverage_is_full(0, true)) == 0");

	/*
	 * Policy.
	 * The word says what the host refuses, so a key the mode leaves inert
	 * reads as off, and a title cannot mistake a configured key for one
	 * that applies.
	 */
	{
		uint32_t keys = lota_status_policy_keys(true, false, false,
							false, true);
		uint32_t loaded = LOTA_STATUS_BPF_LOADED;

		TEST("each key maps to its own bit");
		if (keys !=
		    (LOTA_STATUS_STRICT_MMAP | LOTA_STATUS_BLOCK_PTRACE))
			FAIL("expected: keys == (LOTA_STATUS_STRICT_MMAP | "
			     "LOTA_STATUS_BLOCK_PTRACE)");
		TEST("the other three keys map to theirs");
		if (lota_status_policy_keys(false, true, true, true, false) !=
		    (LOTA_STATUS_STRICT_EXEC | LOTA_STATUS_STRICT_MODULES |
		     LOTA_STATUS_BLOCK_ANON_EXEC))
			FAIL("expected: lota_status_policy_keys(false, true, true, "
			     "true, false) == (LOTA_STATUS_STRICT_EXEC | "
			     "LOTA_STATUS_STRICT_MODULES | "
			     "LOTA_STATUS_BLOCK_ANON_EXEC)");

		TEST("enforce with the LSM loaded carries the mode and keys");
		if (lota_status_fold_policy(loaded, LOTA_MODE_ENFORCE, keys) !=
		    (loaded | LOTA_STATUS_ENFORCE | keys))
			FAIL("expected: lota_status_fold_policy(loaded, "
			     "LOTA_MODE_ENFORCE, keys) == (loaded | "
			     "LOTA_STATUS_ENFORCE | keys)");
		TEST("enforce with no key carries the mode alone");
		if (lota_status_fold_policy(loaded, LOTA_MODE_ENFORCE, 0) !=
		    (loaded | LOTA_STATUS_ENFORCE))
			FAIL("expected: lota_status_fold_policy(loaded, "
			     "LOTA_MODE_ENFORCE, 0) == (loaded | LOTA_STATUS_ENFORCE)");
		TEST("monitor carries no key, set or not");
		if (lota_status_fold_policy(loaded, LOTA_MODE_MONITOR, keys) !=
		    loaded)
			FAIL("expected: lota_status_fold_policy(loaded, "
			     "LOTA_MODE_MONITOR, keys) == loaded");
		TEST("enforce without the LSM refuses nothing and says so");
		if (lota_status_fold_policy(0, LOTA_MODE_ENFORCE, keys) != 0)
			FAIL("expected: lota_status_fold_policy(0, LOTA_MODE_ENFORCE, "
			     "keys) == 0");
		TEST("a switch to monitor clears what enforce set");
		if (lota_status_fold_policy(loaded | LOTA_STATUS_ENFORCE | keys,
					    LOTA_MODE_MONITOR, keys) != loaded)
			FAIL("expected: lota_status_fold_policy( loaded | "
			     "LOTA_STATUS_ENFORCE | keys, LOTA_MODE_MONITOR, keys) == "
			     "loaded");
		TEST("a bit outside the policy is not taken as a key");
		if (lota_status_fold_policy(loaded, LOTA_MODE_ENFORCE,
					    LOTA_STATUS_ATTESTED) !=
		    (loaded | LOTA_STATUS_ENFORCE))
			FAIL("expected: lota_status_fold_policy(loaded, "
			     "LOTA_MODE_ENFORCE, LOTA_STATUS_ATTESTED) == (loaded | "
			     "LOTA_STATUS_ENFORCE)");
	}

	return test_end();
}
