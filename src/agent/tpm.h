/* SPDX-License-Identifier: MIT */
/*
 * LOTA - TPM 2.0 Operations Module
 * Handles TPM context, PCR reading, and Quote generation
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_TPM_H
#define LOTA_TPM_H

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tcti.h>

#include "../../include/lota.h"

struct tpm_quote_response;

#define TPM_DEVICE_PATH "/dev/tpmrm0"

/*
 * EK Certificate handle (RSA 2048)
 */
#define TPM_EK_CERT_HANDLE 0x01c00002

/*
 * Default AIK persistent handle.
 * Configurable via lota.conf
 *
 * Handle 0x81010002 chosen to avoid conflicts with existing keys
 * (Windows Hello, BitLocker, etc. at 0x81010001).
 */
#define TPM_AIK_HANDLE 0x81010002

/* Hash algorithm for PCR bank */
#define TPM_HASH_ALG TPM2_ALG_SHA256

/*
 * AIK rotation defaults.
 * Grace period allows the verifier to observe the previous key
 * alongside the new one for continuity verification.
 */
#define TPM_AIK_DEFAULT_TTL_SEC (30 * 24 * 3600) /* 30 days */
#define TPM_AIK_GRACE_PERIOD_SEC 3600            /* 1 hour */

/* AIK metadata file magic and version */
#define TPM_AIK_META_MAGIC 0x4D4B4941 /* "AIKM" */
#define TPM_AIK_META_VERSION 1

/* Default metadata path (install target creates /var/lib/lota/aiks/) */
#define TPM_AIK_META_PATH "/var/lib/lota/aik_meta.dat"

/*
 * AIK metadata - persisted to disk for tracking rotation state.
 *
 * Stored at TPM_AIK_META_PATH. The generation counter is monotonic
 * and never resets, allowing the verifier to detect rollback attacks.
 *
 * provisioned_at tracks the creation time of the current AIK so the
 * agent can determine when rotation is due without relying on the TPM
 * clock (which may drift or be unavailable).
 */
struct aik_metadata {
  uint32_t magic;
  uint32_t version;
  uint64_t generation;     /* monotonic rotation counter */
  int64_t provisioned_at;  /* time_t: current AIK creation */
  int64_t last_rotated_at; /* time_t: last rotation (0 if never) */
  uint8_t _reserved[64];
} __attribute__((packed));

/*
 * TPM context - holds ESYS context and session state.
 * Opaque to callers, accessed via tpm_* functions.
 */
struct tpm_context {
  ESYS_CONTEXT *esys_ctx;
  TSS2_TCTI_CONTEXT *tcti_ctx;
  bool initialized;

  /* Optional explicit kernel image path override */
  char kernel_path_override[PATH_MAX];

  /* AIK persistent handle (configurable, default TPM_AIK_HANDLE) */
  uint32_t aik_handle;

  /* AIK rotation state */
  struct aik_metadata aik_meta;
  bool aik_meta_loaded;
  char aik_meta_path[256];

  /* Grace period: previous AIK public key kept after rotation */
  uint8_t prev_aik_public[LOTA_MAX_AIK_PUB_SIZE];
  size_t prev_aik_public_size;
  time_t grace_deadline; /* 0 if no grace period active */
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
 * Creates RSA 2048-bit restricted signing key under Owner Hierarchy
 * and persists it at the configured AIK handle (default 0x81010002).
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
 * tpm_hash_fd - Calculate SHA-256 hash from an open file descriptor
 * @fd: Open file descriptor (read position should be at start)
 * @hash: Output buffer (LOTA_HASH_SIZE bytes)
 *
 * Returns: 0 on success, negative errno on failure
 */
int tpm_hash_fd(int fd, uint8_t *hash);

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
 * tpm_set_kernel_path - Configure explicit kernel image path
 * @ctx: TPM context storing runtime overrides
 * @path: Absolute path to kernel image, or NULL/empty to clear override
 *
 * When set, tpm_get_current_kernel_path() uses this path instead of
 * distro-specific autodetection fallback.
 *
 * Returns: 0 on success, negative errno on failure
 */
int tpm_set_kernel_path(struct tpm_context *ctx, const char *path);

/*
 * tpm_get_current_kernel_path - Find current running kernel image
 * @ctx: TPM context containing optional kernel path override
 * @buf: Output buffer for path
 * @buf_len: Buffer size
 *
 * Returns path like "/boot/vmlinuz-6.7.0-0.rc5.20231205git.48.fc40.x86_64"
 *
 * Returns: 0 on success, negative errno on failure
 */
int tpm_get_current_kernel_path(struct tpm_context *ctx, char *buf,
                                size_t buf_len);

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
 * tpm_get_ek_cert - Read Endorsement Key certificate from NVRAM
 * @ctx: Initialized TPM context
 * @buf: Output buffer for DER-encoded certificate
 * @buf_size: Size of output buffer (recommend LOTA_MAX_EK_CERT_SIZE)
 * @out_size: Actual size of read certificate
 *
 * Reads the EK certificate from the standard NV index 0x01c00002.
 * The certificate is stored in DER format (X.509).
 *
 * Returns: 0 on success, -ENOENT if not found, negative errno on failure
 */
int tpm_get_ek_cert(struct tpm_context *ctx, uint8_t *buf, size_t buf_size,
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
 * If the EK is not available at the standard persistent handle,
 * falls back to SHA-256(AIK public key) as the identifier.
 *
 * Returns: 0 on success (EK-based), 1 on success (AIK fallback),
 *          negative errno on failure
 */
int tpm_get_hardware_id(struct tpm_context *ctx, uint8_t *hardware_id);

/*
 * tpm_aik_load_metadata - Load AIK rotation metadata from disk
 * @ctx: Initialized TPM context
 *
 * Reads metadata from ctx->aik_meta_path (or TPM_AIK_META_PATH by
 * default). If the file does not exist, initializes default metadata
 * with provisioned_at = now and writes it.
 *
 * Must be called after tpm_provision_aik() so the AIK exists.
 *
 * Returns: 0 on success, negative errno on failure
 */
int tpm_aik_load_metadata(struct tpm_context *ctx);

/*
 * tpm_aik_save_metadata - Persist AIK metadata to disk
 * @ctx: TPM context with metadata to save
 *
 * Returns: 0 on success, negative errno on failure
 */
int tpm_aik_save_metadata(struct tpm_context *ctx);

/*
 * tpm_aik_age - Get current AIK age in seconds
 * @ctx: TPM context with loaded metadata
 *
 * Returns: age in seconds, or negative errno on error
 */
int64_t tpm_aik_age(struct tpm_context *ctx);

/*
 * tpm_aik_needs_rotation - Check if AIK rotation is due
 * @ctx: TPM context with loaded metadata
 * @max_age_sec: Maximum AIK age in seconds (0 = use default 30d)
 *
 * Returns: 1 if rotation needed, 0 if not, negative errno on error
 */
int tpm_aik_needs_rotation(struct tpm_context *ctx, uint32_t max_age_sec);

/*
 * tpm_rotate_aik - Rotate the Attestation Identity Key
 * @ctx: Initialized TPM context with loaded metadata
 *
 * Full rotation sequence:
 *   - Exports current AIK public key (preserved for grace period)
 *   - Evicts old persistent handle via Esys_EvictControl
 *   - Creates new AIK via Esys_CreatePrimary + Esys_EvictControl
 *   - Increments generation counter and updates provisioned_at
 *   - Persists metadata and starts grace period timer
 *
 * After rotation, tpm_aik_get_prev_public() returns the old public
 * key for the duration of the grace period.
 *
 * Returns: 0 on success, negative errno on failure
 */
int tpm_rotate_aik(struct tpm_context *ctx);

/*
 * tpm_aik_in_grace_period - Check if migration grace period is active
 * @ctx: TPM context
 *
 * Returns: 1 if grace period is active, 0 otherwise
 */
int tpm_aik_in_grace_period(struct tpm_context *ctx);

/*
 * tpm_aik_get_prev_public - Get previous AIK public key
 * @ctx: TPM context
 * @buf: Output buffer for DER-encoded public key
 * @buf_size: Size of output buffer
 * @out_size: Actual size of exported key
 *
 * Only available during the grace period after rotation.
 *
 * Returns: 0 on success, -ENOENT if no previous key, negative errno
 */
int tpm_aik_get_prev_public(struct tpm_context *ctx, uint8_t *buf,
                            size_t buf_size, size_t *out_size);

/*
 * TPM Event Log paths (tried in order)
 */
#define TPM_EVENTLOG_PATH_BIOS                                                 \
  "/sys/kernel/security/tpm0/binary_bios_measurements"
#define TPM_EVENTLOG_PATH_IMA                                                  \
  "/sys/kernel/security/ima/binary_runtime_measurements"

/* Maximum event log size (512 KB) */
#define TPM_MAX_EVENT_LOG_SIZE (512 * 1024)

/*
 * tpm_read_event_log - Read TPM event log from securityfs
 * @buf: Output buffer (caller allocates, recommend TPM_MAX_EVENT_LOG_SIZE)
 * @buf_size: Size of output buffer
 * @out_size: Actual bytes read (set even on -ENOSPC)
 *
 * Reads the TCG binary event log from
 * /sys/kernel/security/tpm0/binary_bios_measurements.
 * This log records all firmware/bootloader PCR extend operations.
 * The verifier uses it to independently replay and verify PCR values.
 *
 * Returns: 0 on success, -ENOSPC if the log was truncated (buffer too
 *          small), negative errno on other failures
 */
int tpm_read_event_log(uint8_t *buf, size_t buf_size, size_t *out_size);

#endif /* LOTA_TPM_H */
