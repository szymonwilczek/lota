/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * LOTA - TPM NV read chunk validation
 *
 * Pure helper for validating a single TPM2B_MAX_NV_BUFFER chunk returned by
 * Esys_NV_Read against what the agent requested, so the EK-certificate NV
 * read loop cannot be driven past its destination buffer or stalled by a
 * non-compliant TPM (firmware-TPM, virtual/emulated TPM, or a swtpm reached
 * over a socket are all less trustworthy than a discrete part).
 */
#ifndef LOTA_TPM_NV_H
#define LOTA_TPM_NV_H

#include <errno.h>
#include <stdint.h>

/*
 * Validate one NV-read chunk.
 * size_to_read is what the agent asked the TPM for this iteration (already
 * clamped to the remaining data and the TPM's maximum NV buffer);
 * chunk_size is what the TPM actually returned.
 * Returns 0 when the chunk is safe to copy, a negative errno otherwise.
 */
static inline int lota_tpm_nv_chunk_check(uint32_t chunk_size,
					  uint32_t size_to_read)
{
	(void)chunk_size;
	(void)size_to_read;
	/* no validation yet:
	 * this mirrors the original inline loop and
	 * is characterised by test_tpm_nv_chunk */
	return 0;
}

#endif /* LOTA_TPM_NV_H */
