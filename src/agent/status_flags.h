/* SPDX-License-Identifier: MIT */
/*
 * Host status bits, and where each one comes from.
 *
 * LOTA_STATUS_ATTESTED is not among them: it is the verifier's verdict and
 * arrives over SYNC_ATTEST, never from local state.
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

/**
 * struct agent_boot_state - What the daemon probed about its machine.
 * @tpm_ok: the TPM opened and answered.
 * @iommu_ok: test_iommu() passed.
 * @bpf_loaded: the LSM object loaded.
 * @secure_boot: efivarfs shows SecureBoot=1.
 * @tpm_lockout: the TPM is in dictionary-attack lockout.
 * @kernel_appraisal: bpf_loader_kernel_appraises_exec() returned 0.
 * @bench: started with --bench.
 */
struct agent_boot_state {
	bool tpm_ok;
	bool iommu_ok;
	bool bpf_loaded;
	bool secure_boot;
	bool tpm_lockout;
	bool kernel_appraisal;
	bool bench;
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
	if (st->kernel_appraisal)
		flags |= LOTA_STATUS_KERNEL_APPRAISAL;
	if (st->bench)
		flags |= LOTA_STATUS_BENCH;

	return flags;
}

/*
 * Full coverage needs a protected process: a host that protects nothing has
 * measured nothing. The status word and the token both decide it here.
 */
static inline bool lota_coverage_is_full(size_t protected_count,
					 bool every_object_measured)
{
	return protected_count > 0 && every_object_measured;
}

/* coverage is the host's, so a path that hands out the word must fold it */
static inline uint32_t lota_status_fold_coverage(uint32_t flags,
						 bool fully_measured)
{
	if (fully_measured)
		return flags | LOTA_STATUS_IMAGE_FULLY_MEASURED;

	return flags & ~(uint32_t)LOTA_STATUS_IMAGE_FULLY_MEASURED;
}

/* as the coverage bit; set when any object of the fold was content hashed */
static inline uint32_t lota_status_fold_content_hash(uint32_t flags,
						     bool content_hashed)
{
	if (content_hashed)
		return flags | LOTA_STATUS_IMAGE_CONTENT_HASHED;

	return flags & ~(uint32_t)LOTA_STATUS_IMAGE_CONTENT_HASHED;
}

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
 * Outside enforce mode with the LSM loaded every policy bit is clear:
 * the word says what the host refuses, not what its configuration names.
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
