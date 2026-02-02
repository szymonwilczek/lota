/* SPDX-License-Identifier: MIT */
/*
 * LOTA - Attestation Report Wire Format
 * Packed C structures for agent-verifier communication
 *
 * Copyright (C) 2026 Szymon Wilczek
 *
 * This header defines the binary protocol between LOTA agent and remote
 * verifier. All structures use __attribute__((packed)) for consistent
 * wire format across architectures.
 *
 * Protocol versioning:
 *   - Major version change = breaking protocol change
 *   - Minor version change = backwards-compatible additions
 *
 * All multi-byte integers are little-endian.
 */

#ifndef LOTA_UAPI_REPORT_H
#define LOTA_UAPI_REPORT_H

#include <stdint.h>

#define LOTA_REPORT_MAGIC 0x41544F4C   /* LOTA little-endian */
#define LOTA_REPORT_VERSION 0x00010000 /* 1.0.0 */

/* Hash/crypto sizes */
#define LOTA_HASH_SIZE 32         /* SHA-256 */
#define LOTA_NONCE_SIZE 32        /* Challenge nonce */
#define LOTA_MAX_SIG_SIZE 512     /* RSA-4096 signature */
#define LOTA_MAX_ATTEST_SIZE 1024 /* TPM2B_ATTEST max */
#define LOTA_PCR_COUNT 24         /* TPM PCR bank size */

/* Maximum sizes for variable-length data */
#define LOTA_MAX_KERNEL_PATH 256
#define LOTA_MAX_EVENTS 1024 /* Max events in report */

/*
 * Report flags - indicate what data is present/valid
 */
#define LOTA_FLAG_TPM_QUOTE (1 << 0)     /* TPM quote included */
#define LOTA_FLAG_IOMMU_OK (1 << 1)      /* IOMMU verified */
#define LOTA_FLAG_SECUREBOOT (1 << 2)    /* Secure Boot enabled */
#define LOTA_FLAG_ENFORCE_MODE (1 << 3)  /* LSM enforcement active */
#define LOTA_FLAG_SELF_MEASURED (1 << 4) /* Agent self-measurement done */

/*
 * Report header - always at start of report
 *
 * Verifier checks:
 *   - magic == LOTA_REPORT_MAGIC
 *   - version compatibility
 *   - checksum over entire report
 */
struct lota_report_header {
  uint32_t magic;          /* LOTA_REPORT_MAGIC */
  uint32_t version;        /* Protocol version */
  uint32_t total_size;     /* Total report size including header */
  uint32_t flags;          /* LOTA_FLAG_* */
  uint64_t timestamp_sec;  /* Report generation time (UNIX epoch) */
  uint32_t timestamp_nsec; /* Nanosecond part */
  uint32_t checksum;       /* CRC32 of report (excluding this field) */
} __attribute__((packed));

/*
 * TPM Quote evidence - cryptographic proof of system state
 *
 * Contains:
 *   - Raw TPMS_ATTEST blob (TPM-generated, signed)
 *   - Signature over TPMS_ATTEST
 *   - PCR values at time of quote
 *   - Server nonce (for replay protection)
 */
struct lota_tpm_evidence {
  /* Server-provided nonce echoed in TPMS_ATTEST.extraData */
  uint8_t nonce[LOTA_NONCE_SIZE];

  /* PCR selection mask (bit N = PCR N included) */
  uint32_t pcr_mask;

  /* PCR values at quote time */
  uint8_t pcr_values[LOTA_PCR_COUNT][LOTA_HASH_SIZE];

  /* Raw attestation data from TPM (TPMS_ATTEST) */
  uint16_t attest_size;
  uint8_t attest_data[LOTA_MAX_ATTEST_SIZE];

  /* Signature algorithm: 0x0014=RSASSA, 0x0016=RSAPSS */
  uint16_t sig_alg;
  uint16_t hash_alg; /* Usually 0x000B = SHA-256 */

  /* AIK signature over attest_data */
  uint16_t signature_size;
  uint8_t signature[LOTA_MAX_SIG_SIZE];
} __attribute__((packed));

/*
 * System measurements - kernel and boot state
 */
struct lota_system_info {
  /* Running kernel hash (SHA-256 of /boot/vmlinuz-*) */
  uint8_t kernel_hash[LOTA_HASH_SIZE];

  /* Kernel path (null-terminated) */
  char kernel_path[LOTA_MAX_KERNEL_PATH];

  /* Agent binary hash (self-measurement) */
  uint8_t agent_hash[LOTA_HASH_SIZE];

  /* IOMMU status */
  uint32_t iommu_flags;      /* IOMMU_FLAG_* (see iommu_types.h) */
  uint32_t iommu_vendor;     /* 0=unknown, 1=Intel VT-d, 2=AMD-Vi */
  uint32_t iommu_unit_count; /* Number of IOMMU units detected */

  /* LSM enforcement mode: 0=monitor, 1=enforce, 2=maintenance */
  uint32_t lsm_mode;
} __attribute__((packed));

/*
 * BPF event summary - execution monitoring statistics
 *
 * Full event log not included to keep report size bounded.
 * Verifier can request full log via separate channel if needed.
 */
struct lota_bpf_summary {
  uint64_t total_execs;     /* Total executions observed */
  uint64_t events_sent;     /* Events delivered to userspace */
  uint64_t modules_blocked; /* Module loads blocked (ENFORCE mode) */
  uint64_t ringbuf_drops;   /* Events dropped due to full buffer */
  uint64_t first_event_ts;  /* Timestamp of first event (ns) */
  uint64_t last_event_ts;   /* Timestamp of last event (ns) */
} __attribute__((packed));

/*
 * Complete attestation report
 *
 * Wire format:
 *   [header][tpm_evidence][system_info][bpf_summary]
 *
 * Variable-length extensions (events, signatures) follow after
 * fixed structures, with offsets in header.
 */
struct lota_attestation_report {
  struct lota_report_header header;
  struct lota_tpm_evidence tpm;
  struct lota_system_info system;
  struct lota_bpf_summary bpf;
} __attribute__((packed));

/*
 * Challenge from verifier
 */
struct lota_challenge {
  uint32_t magic;                 /* LOTA_REPORT_MAGIC */
  uint32_t version;               /* Protocol version */
  uint8_t nonce[LOTA_NONCE_SIZE]; /* Random challenge */
  uint32_t pcr_mask;              /* PCRs to include in quote */
  uint32_t flags;                 /* Request flags (reserved) */
} __attribute__((packed));

/*
 * Verifier response
 */
#define LOTA_VERIFY_OK 0
#define LOTA_VERIFY_NONCE_FAIL 1  /* Nonce mismatch (replay?) */
#define LOTA_VERIFY_SIG_FAIL 2    /* Quote signature invalid */
#define LOTA_VERIFY_PCR_FAIL 3    /* PCR values dont match baseline */
#define LOTA_VERIFY_IOMMU_FAIL 4  /* IOMMU not properly enabled */
#define LOTA_VERIFY_OLD_VERSION 5 /* Agent version too old */

struct lota_verify_result {
  uint32_t magic;            /* LOTA_REPORT_MAGIC */
  uint32_t version;          /* Protocol version */
  uint32_t result;           /* LOTA_VERIFY_* */
  uint32_t flags;            /* Additional info flags */
  uint64_t valid_until;      /* Attestation valid until (UNIX time) */
  uint8_t session_token[32]; /* Session token for game server */
} __attribute__((packed));

/*
 * Helper: Calculate CRC32 checksum
 */
static inline uint32_t lota_crc32(const void *data, size_t len) {
  const uint8_t *p = (const uint8_t *)data;
  uint32_t crc = 0xFFFFFFFF;
  size_t i;

  for (i = 0; i < len; i++) {
    crc ^= p[i];
    for (int j = 0; j < 8; j++) {
      crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
    }
  }

  return ~crc;
}

#endif /* LOTA_UAPI_REPORT_H */
