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

/*
 * Attestation report header
 */
struct lota_report_header {
  uint32_t magic;        /* LOTA_MAGIC */
  uint32_t version;      /* LOTA_VERSION */
  uint64_t timestamp;    /* Unix timestamp (seconds) */
  uint64_t timestamp_ns; /* Nanosecond precision */
  uint32_t report_size;  /* Total size including variable data */
  uint32_t flags;        /* Report flags */
} __attribute__((packed));

/* Report flags */
#define LOTA_REPORT_FLAG_IOMMU_OK (1U << 0)     /* IOMMU verification passed */
#define LOTA_REPORT_FLAG_TPM_QUOTE_OK (1U << 1) /* TPM quote succeeded */
#define LOTA_REPORT_FLAG_KERNEL_HASH_OK (1U << 2) /* Kernel hash computed */
#define LOTA_REPORT_FLAG_BPF_ACTIVE (1U << 3)     /* eBPF LSM is loaded */

/*
 * TPM evidence section
 */
struct lota_tpm_evidence {
  /* PCR values - all 24 PCRs, SHA-256 */
  uint8_t pcr_values[LOTA_PCR_COUNT][LOTA_HASH_SIZE];

  /* Which PCRs are included (bitmask) */
  uint32_t pcr_mask;

  /* TPM Quote signature */
  uint8_t quote_signature[LOTA_MAX_SIG_SIZE];
  uint16_t quote_sig_size;

  /* Nonce from server (echoed back) */
  uint8_t nonce[LOTA_NONCE_SIZE];

  /* Reserved for alignment */
  uint8_t _reserved[2];
} __attribute__((packed));

/*
 * System measurement section
 */
struct lota_system_measurement {
  /* SHA-256 of running kernel image */
  uint8_t kernel_hash[LOTA_HASH_SIZE];

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
