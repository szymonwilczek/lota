/* SPDX-License-Identifier: MIT */
/*
 * LOTA attestation report, as sent to the verifier.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_ATTESTATION_H
#define LOTA_ATTESTATION_H

#include <stdint.h>
#include <sys/types.h>
#include <stddef.h>

#include "iommu_types.h"
#include "lota.h"

struct lota_report_header {
	uint32_t magic; /* LOTA_MAGIC */
	uint32_t version; /* LOTA_REPORT_VERSION */

	uint32_t report_size; /* Total size including variable data */
	uint32_t flags; /* Report flags */
} __attribute__((packed));

/* Report flags */
#define LOTA_REPORT_FLAG_IOMMU_OK (1U << 0) /* IOMMU verification passed */
#define LOTA_REPORT_FLAG_TPM_QUOTE_OK (1U << 1) /* TPM quote succeeded */
#define LOTA_REPORT_FLAG_KERNEL_HASH_OK \
	(1U << 2) /* Boot measurement digest captured (kernel-relevant PCR) */
#define LOTA_REPORT_FLAG_BPF_ACTIVE (1U << 3) /* daemon has its LSM loaded */
#define LOTA_REPORT_FLAG_MODULE_SIG (1U << 4) /* Kernel enforces module sigs*/
#define LOTA_REPORT_FLAG_LOCKDOWN (1U << 5) /* Kernel lockdown active */
#define LOTA_REPORT_FLAG_SECUREBOOT (1U << 6) /* Secure Boot enabled */
#define LOTA_REPORT_FLAG_ENFORCE (1U << 7) /* daemon enforces with its LSM */
#define LOTA_REPORT_FLAG_BOOT_COMMITMENT_V1 \
	(1U << 8) /* PCR14 bound by v1 boot-commitment derivation */

/*
 * verifier_challenge.flags: the PCR 14 derivation the verifier validates.
 * Every challenge carries v1.
 */
#define LOTA_CHALLENGE_FLAG_BOOT_COMMITMENT_V1 (1U << 0)

/*
 * lota-pcr14-lock (90lota dracut module) extended PCR 14 with
 * SHA256("LOTA-PCR14-INITRAMFS-LOCK-v1") before the agent ran, and the agent
 * extended its boot commitment on top:
 *     pcr14_lock = SHA256(baseline || initramfs_lock_commit)
 *     pcr14_final = SHA256(pcr14_lock || boot_commitment)
 *
 * The verifier has no other derivation: it refuses a report without both this
 * bit and LOTA_REPORT_FLAG_BOOT_COMMITMENT_V1.
 */
#define LOTA_REPORT_FLAG_INITRAMFS_LOCK_V1 (1U << 9)

/*
 * IMA is in a blocking mode and the loaded policy has an appraise rule on
 * BPRM_CHECK or with no func=. Clear on a stock host. Policy knob:
 * require_ima_appraisal.
 */
#define LOTA_REPORT_FLAG_IMA_APPRAISAL (1U << 10)

/* The daemon runs with --bench. Its policy is the same as without it. */
#define LOTA_REPORT_FLAG_BENCH (1U << 11)

/*
 * The policy keys the daemon applies. Set with LOTA_REPORT_FLAG_ENFORCE only:
 * a key the mode leaves inert is reported off.
 */
#define LOTA_REPORT_FLAG_STRICT_MMAP (1U << 12)
#define LOTA_REPORT_FLAG_STRICT_EXEC (1U << 13)
#define LOTA_REPORT_FLAG_STRICT_MODULES (1U << 14)
#define LOTA_REPORT_FLAG_BLOCK_ANON_EXEC (1U << 15)
#define LOTA_REPORT_FLAG_BLOCK_PTRACE (1U << 16)

/* The kernel left events out of the daemon's log. Enforcement is unaffected. */
#define LOTA_REPORT_FLAG_EVENTS_LOST (1U << 17)

/* Largest TPMS_ATTEST the agent accepts from TPM2_Quote. */
#define LOTA_MAX_ATTEST_SIZE 1024

/*
 * The verifier checks quote_signature over attest_data, then compares extraData
 * inside it with the binding nonce it computes.
 */
struct lota_tpm_evidence {
	/* SHA-256 */
	uint8_t pcr_values[LOTA_PCR_COUNT][LOTA_HASH_SIZE];

	/* Which PCRs are included (bitmask) */
	uint32_t pcr_mask;

	/* TPM Quote signature over attest_data */
	uint8_t quote_signature[LOTA_MAX_SIG_SIZE];
	uint16_t quote_sig_size;

	/* TPMS_ATTEST from TPM2_Quote */
	uint8_t attest_data[LOTA_MAX_ATTEST_SIZE];
	uint16_t attest_size;

	/* AIK public key, DER SPKI: verifies the quote signature */
	uint8_t aik_public[LOTA_MAX_AIK_PUB_SIZE];
	uint16_t aik_public_size;

	/* AIK certificate, DER X.509: a report without one is refused */
	uint8_t aik_certificate[LOTA_MAX_AIK_CERT_SIZE];
	uint16_t aik_cert_size;

	/*
	 * Challenge nonce, the key of the verifier's pending entry. extraData
	 * holds the binding nonce derived from it.
	 */
	uint8_t nonce[LOTA_NONCE_SIZE];

	/* TPM quote signature scheme (TPM2_ALG_RSASSA or TPM2_ALG_RSAPSS). */
	uint16_t quote_sig_alg;

	/* TPM quote signature hash algorithm (TPM2_ALG_SHA256/SHA384/SHA512).
	 */
	uint16_t quote_sig_hash_alg;
} __attribute__((packed));

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
 * ESRT System Firmware entry (fw_type == 1). fw_version is the verifier's
 * anti-rollback signal for self-service re-anchor; present == 0 puts the host
 * on the Low-Firmware-Assurance path.
 */
struct lota_esrt {
	uint32_t present; /* 1 if a System Firmware entry was found */
	uint32_t fw_version; /* ESRT fw_version */
	uint32_t lowest_supported; /* lowest_supported_fw_version */
	uint8_t fw_class[16]; /* fw_class GUID (raw 16 bytes) */
} __attribute__((packed));

/*
 * Wire format:
 *   [lota_report_header]
 *   [lota_tpm_evidence]
 *   [lota_system_measurement]
 *   [event_log_size: uint32_t]
 *   [tpm_event_log: uint8_t * event_log_size]
 *   [lota_esrt: 28 bytes]
 *   [mok_list_size: uint32_t]
 *   [mok_list: uint8_t * mok_list_size]  (EFI_SIGNATURE_LIST data of MokListRT)
 *
 * install_telemetry_summary in installer/stages.c lists these sections to the
 * player.
 */
struct lota_attestation_report {
	struct lota_report_header header;
	struct lota_tpm_evidence tpm;
	struct lota_system_measurement system;

	/* Variable-length sections follow in serialized form */
} __attribute__((packed));

/**
 * serialize_report() - Serialize a report to its wire format.
 * @report: Report.
 * @event_log: TPM event log, may be NULL.
 * @event_log_size: Size of @event_log.
 * @esrt: ESRT entry, mandatory; present == 0 reports a platform without one.
 * @mok_list: MokListRT data, may be NULL.
 * @mok_list_size: Size of @mok_list.
 * @out_buf: Output buffer.
 * @out_buf_size: Size of @out_buf.
 *
 * Return: Number of bytes written, or a negative errno.
 */
ssize_t serialize_report(const struct lota_attestation_report *report,
			 const uint8_t *event_log, uint32_t event_log_size,
			 const struct lota_esrt *esrt, const uint8_t *mok_list,
			 uint32_t mok_list_size, uint8_t *out_buf,
			 size_t out_buf_size);

/**
 * calculate_report_size() - Size of a serialized report.
 * @event_log_size: Size of the TPM event log.
 * @mok_list_size: Size of the MokListRT data.
 *
 * Return: Total size in bytes.
 */
size_t calculate_report_size(uint32_t event_log_size, uint32_t mok_list_size);

#endif /* LOTA_ATTESTATION_H */
