/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Validation of one TPM2B_MAX_NV_BUFFER chunk from Esys_NV_Read, so a
 * non-compliant TPM can neither drive the EK certificate read loop past its
 * buffer nor stall it.
 */
#ifndef LOTA_TPM_NV_H
#define LOTA_TPM_NV_H

#include <errno.h>
#include <stdint.h>

/**
 * lota_tpm_nv_chunk_check() - Validate one NV read chunk.
 * @chunk_size: what the TPM returned.
 * @size_to_read: what the agent asked for, clamped to the remaining data and
 *                the TPM's maximum NV buffer.
 *
 * Return: 0 if safe to copy, -EBADMSG on an empty chunk, which would spin the
 * loop, -EOVERFLOW on more than was requested, which would overrun the buffer.
 */
static inline int lota_tpm_nv_chunk_check(uint32_t chunk_size,
					  uint32_t size_to_read)
{
	if (chunk_size == 0)
		return -EBADMSG;
	if (chunk_size > size_to_read)
		return -EOVERFLOW;
	return 0;
}

#endif /* LOTA_TPM_NV_H */
