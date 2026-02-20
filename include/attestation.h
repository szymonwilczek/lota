/* SPDX-License-Identifier: MIT */
/*
 * LOTA - Attestation Report Schema
 * Defines the structure sent to remote verifier
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_ATTESTATION_H
#define LOTA_ATTESTATION_H

#include "iommu_types.h"
#include "lota.h"
#include <stdint.h>
#include <sys/types.h>

/*
 * Attestation report header
 */
struct lota_report_header {
  uint32_t magic;   /* LOTA_MAGIC */
  uint32_t version; /* LOTA_VERSION */

  uint32_t report_size; /* Total size including variable data */
  uint32_t flags;       /* Report flags */
} __attribute__((packed));

/* Report flags */
#define LOTA_REPORT_FLAG_IOMMU_OK (1U << 0)     /* IOMMU verification passed */
#define LOTA_REPORT_FLAG_TPM_QUOTE_OK (1U << 1) /* TPM quote succeeded */
#define LOTA_REPORT_FLAG_KERNEL_HASH_OK                                        \
  (1U << 2) /* Boot measurement digest captured (kernel-relevant PCR) */
#define LOTA_REPORT_FLAG_BPF_ACTIVE (1U << 3) /* eBPF LSM is loaded */
#define LOTA_REPORT_FLAG_MODULE_SIG (1U << 4) /* Kernel enforces module sigs*/
#define LOTA_REPORT_FLAG_LOCKDOWN (1U << 5)   /* Kernel lockdown active */
#define LOTA_REPORT_FLAG_SECUREBOOT (1U << 6) /* Secure Boot enabled */
#define LOTA_REPORT_FLAG_ENFORCE (1U << 7)    /* LSM enforce mode active */

/*
 * Maximum size of TPMS_ATTEST structure returned by TPM2_Quote.
 * Contains: magic, type, qualifiedSigner, extraData (nonce),
 * clockInfo, firmwareVersion, and quote info (PCR selection + digest).
 */
#define LOTA_MAX_ATTEST_SIZE 1024

/*
 * Contains the raw TPMS_ATTEST blob which is cryptographically signed by TPM.
 * The verifier MUST verify the signature over attest_data, then parse it
 * to extract the nonce (extraData) and PCR digest for validation.
 *
 * The nonce field below is a convenience copy of TPMS_ATTEST.extraData.
 * It allows the verifier to perform O(1) nonce lookup without parsing
 * the TPMS_ATTEST structure first, while the authoritative value inside
 * attest_data is used for cryptographic verification.
 */
struct lota_tpm_evidence {
  /* PCR values - all 24 PCRs, SHA-256 */
  uint8_t pcr_values[LOTA_PCR_COUNT][LOTA_HASH_SIZE];

  /* Which PCRs are included (bitmask) */
  uint32_t pcr_mask;

  /* TPM Quote signature over attest_data */
  uint8_t quote_signature[LOTA_MAX_SIG_SIZE];
  uint16_t quote_sig_size;

  /*
   * Raw TPMS_ATTEST blob from TPM2_Quote.
   * Verifier must: SHA256(attest_data) == signed_digest
   */
  uint8_t attest_data[LOTA_MAX_ATTEST_SIZE];
  uint16_t attest_size;

  /*
   * AIK public key in DER-encoded SPKI format.
   * Used by verifier for TOFU registration and signature verification.
   * Format: SubjectPublicKeyInfo (x509.MarshalPKIXPublicKey compatible)
   */
  uint8_t aik_public[LOTA_MAX_AIK_PUB_SIZE];
  uint16_t aik_public_size;

  /*
   * AIK certificate in DER-encoded X.509 format (optional).
   * If present (aik_cert_size > 0), verifier validates the certificate
   * chain against trusted CAs before accepting the AIK.
   * If absent, TOFU mode is used for AIK registration.
   */
  uint8_t aik_certificate[LOTA_MAX_AIK_CERT_SIZE];
  uint16_t aik_cert_size;

  /*
   * EK certificate in DER-encoded X.509 format (optional).
   * Used for TPM identity verification. The EK certificate is issued
   * by the TPM manufacturer and proves the TPM is genuine.
   */
  uint8_t ek_certificate[LOTA_MAX_EK_CERT_SIZE];
  uint16_t ek_cert_size;

  /* Nonce from server */
  uint8_t nonce[LOTA_NONCE_SIZE];

  /*
   * Hardware identity derived from Endorsement Key.
   * SHA-256(EK public key) provides a unique, stable identifier
   * that is bound to the physical TPM and cannot be forged.
   * Used by verifier to detect hardware changes or cloning attempts.
   */
  uint8_t hardware_id[LOTA_HARDWARE_ID_SIZE];

  /*
   * AIK rotation metadata.
   * Generation is a monotonic counter incremented on every rotation.
   */
  uint64_t aik_generation;

  /*
   * Previous AIK public key (DER SPKI), populated during rotation
   * grace period. When prev_aik_public_size > 0 the agent just
   * rotated its AIK and includes the old key so the verifier can
   * verify continuity (same TPM, legitimate rotation).
   */
  uint8_t prev_aik_public[LOTA_MAX_AIK_PUB_SIZE];
  uint16_t prev_aik_public_size;

  /* Reserved for alignment */
  uint8_t _reserved[2];
} __attribute__((packed));

/*
 * System measurement section
 */
struct lota_system_measurement {
  /* TPM measured-boot digest (kernel-relevant PCR, SHA-256) */
  uint8_t kernel_hash[LOTA_HASH_SIZE];

  /* SHA-256 of lota-agent binary (self-measurement) */
  uint8_t agent_hash[LOTA_HASH_SIZE];

  /* Path to kernel image (for reference) */
  char kernel_path[256];

  /* IOMMU verification status */
  struct iommu_status iommu;
} __attribute__((packed));

/*
 * eBPF event summary - aggregated info about executed binaries
 * Full event details are in variable-length section
 */
struct lota_bpf_summary {
  uint32_t total_exec_events; /* Total exec events since agent start */
  uint32_t unique_binaries;   /* Unique binary hashes seen */
  uint64_t first_event_ts;    /* Timestamp of first event */
  uint64_t last_event_ts;     /* Timestamp of last event */
} __attribute__((packed));

/*
 * Complete attestation report
 *
 * Wire format:
 *   [lota_report_header]
 *   [lota_tpm_evidence]
 *   [lota_system_measurement]
 *   [lota_bpf_summary]
 *   [event_count: uint32_t]
 *   [lota_exec_event * event_count]
 *   [event_log_size: uint32_t]
 *   [tpm_event_log: uint8_t * event_log_size]
 */
struct lota_attestation_report {
  struct lota_report_header header;
  struct lota_tpm_evidence tpm;
  struct lota_system_measurement system;
  struct lota_bpf_summary bpf;

  /* Variable-length sections follow in serialized form */
} __attribute__((packed));

/*
 * serialize_report - Serialize report to wire format
 * @report: Report structure
 * @events: Array of BPF events (can be NULL)
 * @event_count: Number of events
 * @event_log: TPM event log (can be NULL)
 * @event_log_size: Size of event log
 * @out_buf: Output buffer (caller allocates)
 * @out_buf_size: Size of output buffer
 *
 * Returns: Number of bytes written, or negative errno
 */
ssize_t serialize_report(const struct lota_attestation_report *report,
                         const struct lota_exec_event *events,
                         uint32_t event_count, const uint8_t *event_log,
                         uint32_t event_log_size, uint8_t *out_buf,
                         size_t out_buf_size);

/*
 * calculate_report_size - Calculate serialized report size
 * @event_count: Number of BPF events
 * @event_log_size: Size of TPM event log
 *
 * Returns: Total size in bytes
 */
size_t calculate_report_size(uint32_t event_count, uint32_t event_log_size);

#endif /* LOTA_ATTESTATION_H */
