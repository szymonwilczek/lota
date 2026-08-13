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
#include <stdint.h>

#include "../../include/lota_ipc.h"

/* What the daemon has probed about the machine it enforces on */
struct agent_boot_state {
	bool tpm_ok; /* the TPM opened and answered */
	bool iommu_ok; /* DMA protection verified */
	bool bpf_loaded; /* the LSM object loaded */
	bool secure_boot; /* UEFI SecureBoot reports enabled */
	bool tpm_lockout; /* the TPM is in dictionary-attack lockout */
	bool ringbuf_drops; /* the event stream lost records */
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

	return flags;
}

#endif /* LOTA_AGENT_STATUS_FLAGS_H */
