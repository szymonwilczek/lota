/* SPDX-License-Identifier: MIT */
/*
 * LOTA token and boot evidence wire formats.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_TOKEN_H
#define LOTA_TOKEN_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Token wire layout (little-endian):
 *
 *   Offset  Size  Field
 *   0       4     magic          (LOTA_TOKEN_MAGIC)
 *   4       2     version        (LOTA_TOKEN_VERSION)
 *   6       2     total_size     (header + variable data)
 *   8       8     valid_until    (Unix timestamp)
 *   16      4     flags          (LOTA_FLAG_* bitmask)
 *   20      32    nonce          (client nonce)
 *   52      2     sig_alg        (TPM signature algorithm)
 *   54      2     hash_alg       (TPM hash algorithm)
 *   56      4     pcr_mask       (PCR selection bitmask)
 *   60      32    policy_digest  (SHA-256 over startup enforcement policy)
 *   92      32    runtime_protect_digest
 *                         (SHA-256 over canonical protected PID runtime set)
 *   124     4     protect_pid_count
 *   128     2     pid_list_size  (bytes, must be protect_pid_count * 4)
 *   130     2     attest_size    (TPMS_ATTEST blob size)
 *   132     2     sig_size       (TPM signature size)
 *   134     2     runtime_protect_version (1 = PID set + registry digests)
 *   136     8     stopped_ms     (time the caller's instance stood stopped)
 *   ---     ---   --------------------------------
 *   144     var   protected_pids[protect_pid_count] (little-endian uint32)
 *   144+P   var   protected_registry_digests[protect_pid_count][32]
 *   144+P+I var   attest_data[attest_size]
 *   ...     var   signature[sig_size]
 *
 * runtime_protect_digest covers each PID and its registry digest, so the quote
 * attests what each protected process runs. The carried registry digests are
 * authenticated only by recomputing it and comparing with the quoted value.
 */
#define LOTA_TOKEN_MAGIC 0x4B544F4C /* "LOTK" in memory (little-endian) */
#define LOTA_TOKEN_VERSION 0x0001
#define LOTA_TOKEN_HEADER_SIZE 144
/*
 * Copy of LOTA_IPC_TOKEN_MAX_PROTECT_PIDS, as lota_ipc.h is not installed.
 * src/sdk/lota_gaming.c asserts they match.
 */
#define LOTA_TOKEN_MAX_PROTECT_PIDS 181
#define LOTA_TOKEN_MAX_PID_LIST_SIZE (LOTA_TOKEN_MAX_PROTECT_PIDS * 4)
#define LOTA_TOKEN_REGISTRY_DIGEST_SIZE 32

/* runtime_protect_version values */
#define LOTA_RUNTIME_PROTECT_V1 1 /* PID set + per-PID registry digest */

#define LOTA_TOKEN_MAX_REGISTRY_LIST_SIZE \
	(LOTA_TOKEN_MAX_PROTECT_PIDS * LOTA_TOKEN_REGISTRY_DIGEST_SIZE)

/* Full PID and registry digest lists, largest quote and signature. */
#define LOTA_TOKEN_MAX_SIZE                                      \
	(LOTA_TOKEN_HEADER_SIZE + LOTA_TOKEN_MAX_PID_LIST_SIZE + \
	 LOTA_TOKEN_MAX_REGISTRY_LIST_SIZE + 1024 + 512)

/* Fixed part of the layout above. */
struct lota_token_wire {
	uint32_t magic;
	uint16_t version;
	uint16_t total_size;
	uint64_t valid_until;
	uint32_t flags;
	uint8_t nonce[32];
	uint16_t sig_alg;
	uint16_t hash_alg;
	uint32_t pcr_mask;
	uint8_t policy_digest[32];
	uint8_t runtime_protect_digest[32];
	uint32_t protect_pid_count;
	uint16_t pid_list_size;
	uint16_t attest_size;
	uint16_t sig_size;
	uint16_t runtime_protect_version;
	uint64_t stopped_ms;
	/*
	 * followed by protected_pids[], protected_registry_digests[],
	 * attest_data[] and signature[]
	 */
} __attribute__((packed));

/*
 * Boot evidence: the values of the PCRs a token quotes and the PCR 7 events
 * behind them, so a relying party with no verifier can check how the machine
 * booted.
 *
 * Wire layout (little-endian):
 *
 *   Offset  Size  Field
 *   0       2     version      (LOTA_BOOT_EVIDENCE_VERSION)
 *   2       2     event_count
 *   4       4     pcr_mask     (the token's)
 *   8       32*N  pcr_values   (one per set bit of pcr_mask, lowest first)
 *   ---     ---   --------------------------------
 *   ...     var   events[event_count], in log order:
 *                   32  digest    (SHA-256 the firmware extended)
 *                   2   data_size
 *                   var data[data_size]
 *
 * An event carries data only when it measures the EFI global SecureBoot
 * variable. Nothing in the evidence is trusted until the PCR values hash to
 * the quoted PCR digest and the events replay to the PCR 7 value.
 */
#define LOTA_BOOT_EVIDENCE_VERSION 0x0001
#define LOTA_BOOT_EVIDENCE_HEADER_SIZE 8
#define LOTA_BOOT_EVIDENCE_EVENT_SIZE 34 /* digest + data_size */
#define LOTA_BOOT_EVIDENCE_MAX_SIZE 8192

#ifdef __cplusplus
}
#endif

#endif /* LOTA_TOKEN_H */
