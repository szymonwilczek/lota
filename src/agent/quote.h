/* SPDX-License-Identifier: MIT */
/*
 * LOTA - TPM quote response
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_QUOTE_H
#define LOTA_QUOTE_H

#include <stdint.h>

#include "../../include/attestation.h"

/* A TPM quote, its signature and the PCR values read just before it */
struct tpm_quote_response {
	uint8_t attest_data[LOTA_MAX_ATTEST_SIZE];
	uint16_t attest_size;

	uint8_t signature[LOTA_MAX_SIG_SIZE];
	uint16_t signature_size;

	/* Signature algorithm (TPM2_ALG_RSASSA or TPM2_ALG_RSAPSS) */
	uint16_t sig_alg;

	/* Signature hash algorithm (TPM2_ALG_SHA256/SHA384/SHA512). */
	uint16_t hash_alg;

	uint32_t pcr_mask;

	uint8_t pcr_values[LOTA_PCR_COUNT][LOTA_HASH_SIZE];
} __attribute__((packed));

#endif /* LOTA_QUOTE_H */
