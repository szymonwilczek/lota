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
#include <stdio.h>

#include "../src/agent/status_flags.h"

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

int main(void)
{
	struct agent_boot_state st;
	uint32_t flags;

	printf("=== host status flag tests ===\n\n");

	/* nothing verified:
	 * every bit clear, which is the honest answer for host that has checked
	 * nothing rather than a host that passed */
	st = (struct agent_boot_state){ 0 };
	CHECK(agent_status_flags(&st) == 0,
	      "a host that verified nothing sets no bit");

	st = (struct agent_boot_state){ .tpm_ok = true };
	CHECK(agent_status_flags(&st) == LOTA_STATUS_TPM_OK,
	      "the TPM bit comes from the TPM probe");

	st = (struct agent_boot_state){ .iommu_ok = true };
	CHECK(agent_status_flags(&st) == LOTA_STATUS_IOMMU_OK,
	      "the IOMMU bit comes from the IOMMU probe");

	st = (struct agent_boot_state){ .bpf_loaded = true };
	CHECK(agent_status_flags(&st) == LOTA_STATUS_BPF_LOADED,
	      "the BPF bit comes from the loader");

	/* the one this file exists for */
	st = (struct agent_boot_state){ .secure_boot = true };
	CHECK(agent_status_flags(&st) == LOTA_STATUS_SECURE_BOOT,
	      "the Secure Boot bit has a producer");

	st = (struct agent_boot_state){ .tpm_lockout = true };
	CHECK(agent_status_flags(&st) == LOTA_STATUS_TPM_LOCKOUT,
	      "the TPM lockout bit comes from the TPM context");

	st = (struct agent_boot_state){
		.tpm_ok = true,
		.iommu_ok = true,
		.bpf_loaded = true,
		.secure_boot = true,
	};
	flags = agent_status_flags(&st);
	CHECK(flags == (LOTA_STATUS_TPM_OK | LOTA_STATUS_IOMMU_OK |
			LOTA_STATUS_BPF_LOADED | LOTA_STATUS_SECURE_BOOT),
	      "a fully verified host sets exactly its four bits");

	/*
	 * attestation verdict is not in this word:
	 * it is the attestation loop's, arrives over the sync, and is folded
	 * in by the socket owner.
	 * Producing it here would let host claim to be attested from local
	 * state alone.
	 */
	CHECK(!(flags & LOTA_STATUS_ATTESTED),
	      "the attested bit is not produced from local state");

	printf("\n%s\n", g_failures ? "FAILURES" : "All tests passed");
	return g_failures ? 1 : 0;
}
