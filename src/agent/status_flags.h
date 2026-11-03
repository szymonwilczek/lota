/* SPDX-License-Identifier: MIT */
/*
 * Host status bits, and where each one comes from.
 *
 * Title reads this word and decides whether to run, so bit with no producer is
 * worse than missing bit: it reads as machine that failed the check.
 * Keeping the mapping in one table, one field per bit, is what makes an unproduced
 * bit visible.
 *
 * What is deliberately absent is LOTA_STATUS_ATTESTED.
 * That is verifier's verdict, it reaches this process over SYNC_ATTEST, and host
 * that could set it from local state could call itself attested with nobody
 * having checked.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#ifndef LOTA_AGENT_STATUS_FLAGS_H
#define LOTA_AGENT_STATUS_FLAGS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../../include/lota.h"
#include "../../include/lota_ipc.h"

/* The key bits of the policy word, without the mode */
#define LOTA_STATUS_POLICY_KEYS                                     \
	(LOTA_STATUS_STRICT_MMAP | LOTA_STATUS_STRICT_EXEC |        \
	 LOTA_STATUS_STRICT_MODULES | LOTA_STATUS_BLOCK_ANON_EXEC | \
	 LOTA_STATUS_BLOCK_PTRACE)

#define LOTA_STATUS_POLICY (LOTA_STATUS_ENFORCE | LOTA_STATUS_POLICY_KEYS)

/* What the daemon has probed about the machine it enforces on */
struct agent_boot_state {
	bool tpm_ok; /* the TPM opened and answered */
	bool iommu_ok; /* DMA protection verified */
	bool bpf_loaded; /* the LSM object loaded */
	bool secure_boot; /* UEFI SecureBoot reports enabled */
	bool tpm_lockout; /* the TPM is in dictionary-attack lockout */
	bool ringbuf_drops; /* the event stream lost records */
	bool kernel_appraisal; /* IMA appraises every exec */
	bool bench; /* started with --bench */
};

static inline uint32_t agent_status_flags(const struct agent_boot_state *st)
{
	uint32_t flags = 0;

	if (!st)
		return 0;

	if (st->tpm_ok)
		flags |= LOTA_STATUS_TPM_OK;
	if (st->iommu_ok)
		flags |= LOTA_STATUS_IOMMU_OK;
	if (st->bpf_loaded)
		flags |= LOTA_STATUS_BPF_LOADED;
	if (st->secure_boot)
		flags |= LOTA_STATUS_SECURE_BOOT;
	if (st->tpm_lockout)
		flags |= LOTA_STATUS_TPM_LOCKOUT;
	if (st->ringbuf_drops)
		flags |= LOTA_STATUS_RINGBUF_DROPS;
	if (st->kernel_appraisal)
		flags |= LOTA_STATUS_KERNEL_APPRAISAL;
	if (st->bench)
		flags |= LOTA_STATUS_BENCH;

	return flags;
}

/*
 * Full coverage needs at least one protected process, and every object of
 * every measured process must be measurable.
 *
 * An empty round is not full coverage. A host that protects nothing has
 * measured nothing, and must not get LOTA_STATUS_IMAGE_FULLY_MEASURED.
 *
 * Both the status word and the token use this helper. The token binds
 * the flags into the quoted nonce, so the two must never disagree.
 */
static inline bool lota_coverage_is_full(size_t protected_count,
					 bool every_object_measured)
{
	return protected_count > 0 && every_object_measured;
}

/*
 * Set or clear LOTA_STATUS_IMAGE_FULLY_MEASURED in @flags.
 *
 * Coverage belongs to the host, not to the caller, so every path that hands
 * out a status word must fold it here.
 * @fully_measured is a cached walk, not one per caller.
 */
static inline uint32_t lota_status_fold_coverage(uint32_t flags,
						 bool fully_measured)
{
	if (fully_measured)
		return flags | LOTA_STATUS_IMAGE_FULLY_MEASURED;

	return flags & ~(uint32_t)LOTA_STATUS_IMAGE_FULLY_MEASURED;
}

/*
 * Set or clear LOTA_STATUS_IMAGE_CONTENT_HASHED in @flags, under the same
 * contract as the coverage bit. Set when any object of the fold was hashed.
 */
static inline uint32_t lota_status_fold_content_hash(uint32_t flags,
						     bool content_hashed)
{
	if (content_hashed)
		return flags | LOTA_STATUS_IMAGE_CONTENT_HASHED;

	return flags & ~(uint32_t)LOTA_STATUS_IMAGE_CONTENT_HASHED;
}

/* The policy keys the daemon holds, as status bits */
static inline uint32_t
lota_status_policy_keys(bool strict_mmap, bool strict_exec, bool strict_modules,
			bool block_anon_exec, bool block_ptrace)
{
	uint32_t keys = 0;

	if (strict_mmap)
		keys |= LOTA_STATUS_STRICT_MMAP;
	if (strict_exec)
		keys |= LOTA_STATUS_STRICT_EXEC;
	if (strict_modules)
		keys |= LOTA_STATUS_STRICT_MODULES;
	if (block_anon_exec)
		keys |= LOTA_STATUS_BLOCK_ANON_EXEC;
	if (block_ptrace)
		keys |= LOTA_STATUS_BLOCK_PTRACE;

	return keys;
}

/*
 * Set the policy bits of @flags from @mode and @keys.
 *
 * A key is only applied in enforce mode with the LSM loaded, so outside that
 * every policy bit is clear: the word says what the host refuses, not what
 * its configuration names.
 */
static inline uint32_t lota_status_fold_policy(uint32_t flags, int mode,
					       uint32_t keys)
{
	flags &= ~(uint32_t)LOTA_STATUS_POLICY;

	if (!(flags & LOTA_STATUS_BPF_LOADED) || mode != LOTA_MODE_ENFORCE)
		return flags;

	return flags | LOTA_STATUS_ENFORCE | (keys & LOTA_STATUS_POLICY_KEYS);
}

#endif /* LOTA_AGENT_STATUS_FLAGS_H */
