/* SPDX-License-Identifier: MIT */
/*
 * LOTA - boot evidence for a token
 *
 * Wire format: include/lota_token.h. The relying party checks it against
 * the PCR digest a token quotes, so nothing here has to be trusted.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#ifndef LOTA_BOOT_EVIDENCE_H
#define LOTA_BOOT_EVIDENCE_H

#include <stddef.h>
#include <stdint.h>

#include "../../include/lota.h"

struct tpm_context;

/*
 * boot_evidence_encode - write the evidence for one boot
 * @log: TCG crypto-agile event log
 * @pcr_mask: the PCRs the token quotes; must include PCR 7
 * @pcrs: their values, indexed by PCR
 *
 * Returns 0 and sets @out_len, or
 *   -EINVAL   arguments, or a log this cannot parse
 *   -ENOMSG   a PCR 7 event has no SHA-256 digest
 *   -ENOSPC   the evidence does not fit @out_size
 */
int boot_evidence_encode(const uint8_t *log, size_t log_size, uint32_t pcr_mask,
			 const uint8_t pcrs[LOTA_PCR_COUNT][LOTA_HASH_SIZE],
			 uint8_t *out, size_t out_size, size_t *out_len);

/*
 * boot_evidence_collect - read the PCRs and the log, then encode
 *
 * Returns what boot_evidence_encode() returns, or the error of the
 * PCR or log read.
 */
int boot_evidence_collect(struct tpm_context *tpm, uint32_t pcr_mask,
			  uint8_t *out, size_t out_size, size_t *out_len);

#endif /* LOTA_BOOT_EVIDENCE_H */
