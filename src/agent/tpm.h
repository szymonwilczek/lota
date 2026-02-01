/* SPDX-License-Identifier: MIT */
/*
 * LOTA - TPM 2.0 Operations Module
 * Handles TPM context, PCR reading, and Quote generation
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_TPM_H
#define LOTA_TPM_H

#include <stdbool.h>
#include <stdint.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tcti.h>

#include "../../include/lota.h"

#define TPM_DEVICE_PATH "/dev/tpmrm0"

/* * TODO: Implement dynamic AIK provisioning.
 * Currently using a hardcoded persistent handle for PoC purposes.
 * In the near future, this will be loaded via Tss2_Sys_Context or
 * retrieved from a trusted Key Broker Service, I'll explore it.
 */
#define TPM_AIK_HANDLE 0x81010001

/* Hash algorithm for PCR bank */
#define TPM_HASH_ALG TPM2_ALG_SHA256

/*
 * TPM context - holds ESYS context and session state.
 * Opaque to callers, accessed via tpm_* functions.
 */
struct tpm_context {
  ESYS_CONTEXT *esys_ctx;
  TSS2_TCTI_CONTEXT *tcti_ctx;
  bool initialized;
};

/*
 * TPM Quote result - contains signed PCR values
 */
struct tpm_quote_result {
  uint8_t pcr_digest[LOTA_HASH_SIZE];   /* Hash of selected PCRs */
  uint8_t signature[LOTA_MAX_SIG_SIZE]; /* TPM signature */
  uint16_t signature_size;
  uint8_t nonce[LOTA_NONCE_SIZE]; /* Echoed nonce from server */
};

/*
 * tpm_init - Initialize TPM context
 * @ctx: Pointer to context structure to initialize
 *
 * Opens connection to TPM via /dev/tpmrm0 (resource manager).
 * Must be paired with tpm_cleanup().
 *
 * Returns: 0 on success, negative errno on failure
 */
int tpm_init(struct tpm_context *ctx);

/*
 * tpm_cleanup - Release TPM context
 * @ctx: Context to clean up
 */
void tpm_cleanup(struct tpm_context *ctx);

/*
 * tpm_read_pcr - Read a single PCR value
 * @ctx: Initialized TPM context
 * @pcr_index: PCR index (0-23)
 * @hash_alg: Hash algorithm (TPM2_ALG_SHA256)
 * @value: Output buffer (must be LOTA_HASH_SIZE bytes)
 *
 * Returns: 0 on success, negative errno on failure
 */
int tpm_read_pcr(struct tpm_context *ctx, uint32_t pcr_index,
                 TPM2_ALG_ID hash_alg, uint8_t *value);

/*
 * tpm_read_pcrs_batch - Read multiple PCRs at once
 * @ctx: Initialized TPM context
 * @pcr_mask: Bitmask of PCRs to read (bit 0 = PCR 0, etc.)
 * @values: Output buffer for PCR values [24][LOTA_HASH_SIZE]
 *
 * Returns: 0 on success, negative errno on failure
 */
int tpm_read_pcrs_batch(struct tpm_context *ctx, uint32_t pcr_mask,
                        uint8_t values[LOTA_PCR_COUNT][LOTA_HASH_SIZE]);

/*
 * tpm_quote - Generate TPM Quote with nonce
 * @ctx: Initialized TPM context
 * @nonce: Server-provided nonce (LOTA_NONCE_SIZE bytes)
 * @pcr_mask: Bitmask of PCRs to include in quote
 * @result: Output quote result
 *
 * Uses AIK at TPM_AIK_HANDLE to sign the quote.
 * The signature covers: PCR digest + nonce + clock info.
 *
 * Returns: 0 on success, negative errno on failure
 */
int tpm_quote(struct tpm_context *ctx, const uint8_t *nonce, uint32_t pcr_mask,
              struct tpm_quote_result *result);

/*
 * tpm_hash_file - Calculate SHA-256 hash of a file
 * @path: Path to file (e.g., /boot/vmlinuz-*)
 * @hash: Output buffer (LOTA_HASH_SIZE bytes)
 *
 * Uses standard file I/O, not TPM (faster for large files).
 * For kernel image verification.
 *
 * Returns: 0 on success, negative errno on failure
 */
int tpm_hash_file(const char *path, uint8_t *hash);

/*
 * tpm_get_current_kernel_path - Find current running kernel image
 * @buf: Output buffer for path
 * @buf_len: Buffer size
 *
 * Returns path like "/boot/vmlinuz-6.7.0-0.rc5.20231205git.48.fc40.x86_64"
 *
 * Returns: 0 on success, negative errno on failure
 */
int tpm_get_current_kernel_path(char *buf, size_t buf_len);

/*
 * tpm_self_test - Run TPM self-test
 * @ctx: Initialized TPM context
 *
 * Returns: 0 if TPM passes self-test, negative errno on failure
 */
int tpm_self_test(struct tpm_context *ctx);

#endif /* LOTA_TPM_H */
