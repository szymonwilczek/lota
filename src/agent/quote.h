/* SPDX-License-Identifier: MIT */
/*
 * LOTA - TPM Quote Response Structure
 * Wire format for attestation evidence
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_QUOTE_H
#define LOTA_QUOTE_H

#include <stdint.h>

#include "../../include/lota.h"

/*
 * Maximum size of TPM2B_ATTEST structure.
 * Contains TPMS_ATTEST which includes:
 *   - magic (4 bytes)
 *   - type (2 bytes)
 *   - qualifiedSigner (variable, max ~256)
 *   - extraData (nonce, max 64)
 *   - clockInfo (17 bytes)
 *   - firmwareVersion (8 bytes)
 *   - quote info (PCR selection + digest)
 */
#define LOTA_MAX_ATTEST_SIZE 1024

/*
 * TPM Quote Response - complete attestation evidence
 *
 * Contains everything needed for remote verification:
 *   - The raw TPMS_ATTEST blob (signed by TPM)
 *   - The signature over the TPMS_ATTEST
 *   - PCR values at time of quote (for replay verification)
 *
 * Verifier:
 *   - Verifies signature using AIK public key
 *   - Parses TPMS_ATTEST to extract nonce and PCR digest
 *   - Computes expected PCR digest from provided values
 *   - Compares digests to ensure integrity
 */
struct tpm_quote_response {
  /* Raw attestation data */
  uint8_t attest_data[LOTA_MAX_ATTEST_SIZE];
  uint16_t attest_size;

  /* Signature over attest_data */
  uint8_t signature[LOTA_MAX_SIG_SIZE];
  uint16_t signature_size;

  /* Signature algorithm (TPM2_ALG_RSASSA or TPM2_ALG_RSAPSS) */
  uint16_t sig_alg;

  /* Hash algorithm used (TPM2_ALG_SHA256) */
  uint16_t hash_alg;

  /* Server-provided nonce (echoed in TPMS_ATTEST.extraData) */
  uint8_t nonce[LOTA_NONCE_SIZE];

  /* PCR selection mask used in quote */
  uint32_t pcr_mask;

  /* PCR values at time of quote */
  uint8_t pcr_values[LOTA_PCR_COUNT][LOTA_HASH_SIZE];
} __attribute__((packed));

#endif /* LOTA_QUOTE_H */
