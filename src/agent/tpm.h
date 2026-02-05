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

struct tpm_quote_response;

#define TPM_DEVICE_PATH "/dev/tpmrm0"

/* * TODO: Implement dynamic AIK provisioning.
 * Currently using a hardcoded persistent handle for PoC purposes.
 * In the near future, this will be loaded via Tss2_Sys_Context or
 * retrieved from a trusted Key Broker Service, I'll explore it.
 *
 * Handle 0x81010002 chosen to avoid conflicts with existing keys
 * (Windows Hello, BitLocker, something more; at 0x81010001).
 */
#define TPM_AIK_HANDLE 0x81010002

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
 * @response: Output quote response (see quote.h)
 *
 * Uses AIK at TPM_AIK_HANDLE to sign the quote.
 * AIK must be provisioned first via tpm_provision_aik().
 *
 * Response contains:
 *   - Raw TPMS_ATTEST data (signed by TPM)
 *   - Signature over the attestation
 *   - PCR values at time of quote
 *
 * Returns: 0 on success, -ENOKEY if AIK not provisioned, negative errno on
 * failure
 */
int tpm_quote(struct tpm_context *ctx, const uint8_t *nonce, uint32_t pcr_mask,
              struct tpm_quote_response *response);

/*
 * tpm_provision_aik - Create and persist Attestation Identity Key
 * @ctx: Initialized TPM context
 *
 * Creates RSA 2048-bit restricted signing key under Endorsement Hierarchy
 * and persists it at TPM_AIK_HANDLE (0x81010001).
 *
 * Properties:
 *   - Restricted: Can only sign TPM-generated data (quotes/certify)
 *   - Non-duplicable: Bound to this specific TPM
 *   - RSASSA with SHA-256
 *
 * If AIK already exists at the handle, returns success without modification.
 * Requires owner hierarchy authorization (empty password assumed).
 *
 * Returns: 0 on success (or already exists), negative errno on failure
 */
int tpm_provision_aik(struct tpm_context *ctx);

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

/*
 * tpm_pcr_extend - Extend PCR with digest
 * @ctx: Initialized TPM context
 * @pcr_index: PCR index (0-23, typically 14-23 writable by OS)
 * @digest: SHA-256 digest to extend (LOTA_HASH_SIZE bytes)
 *
 * Performs cryptographic extend: new = Hash(old || digest).
 * Used for runtime measurements (e.g., self-measurement into PCR 14).
 *
 * Returns: 0 on success, negative errno on failure
 */
int tpm_pcr_extend(struct tpm_context *ctx, uint32_t pcr_index,
                   const uint8_t *digest);

/*
 * tpm_get_aik_public - Export AIK public key in DER SPKI format
 * @ctx: Initialized TPM context
 * @buf: Output buffer for DER-encoded public key
 * @buf_size: Size of output buffer (recommend LOTA_MAX_AIK_PUB_SIZE)
 * @out_size: Actual size of exported key
 *
 * Exports the AIK public key in SubjectPublicKeyInfo (SPKI) DER format,
 * compatible with x509.ParsePKIXPublicKey() in Go.
 *
 * Returns: 0 on success, -ENOKEY if AIK not provisioned, negative errno on
 * failure
 */
int tpm_get_aik_public(struct tpm_context *ctx, uint8_t *buf, size_t buf_size,
                       size_t *out_size);

/*
 * tpm_get_hardware_id - Compute unique hardware identifier
 * @ctx: Initialized TPM context
 * @hardware_id: Output buffer (LOTA_HARDWARE_ID_SIZE bytes)
 *
 * Computes SHA-256(EK public key) as a stable hardware identifier.
 * The Endorsement Key is unique per TPM and cannot be modified,
 * making it ideal for hardware binding.
 *
 * Returns: 0 on success, negative errno on failure
 */
int tpm_get_hardware_id(struct tpm_context *ctx, uint8_t *hardware_id);

#endif /* LOTA_TPM_H */
