/* SPDX-License-Identifier: MIT */
/*
 * LOTA Token Wire Format
 *
 * Shared definitions for the LOTA attestation token format.
 * Used by both the gaming SDK (client) and server SDK (verifier).
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
 * Token wire format constants
 *
 * Wire layout (little-endian):
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
 *   128     8     runtime_protect_epoch (monotonic PID-set mutation id)
 *   136     2     pid_list_size  (bytes, must be protect_pid_count * 4)
 *   138     2     attest_size    (TPMS_ATTEST blob size)
 *   140     2     sig_size       (TPM signature size)
 *   142     2     runtime_protect_version (0/1 = PID-set only,
 *                                          2 = PID-set + kernel image digests)
 *   ---     ---   --------------------------------
 *   144     var   protected_pids[protect_pid_count] (little-endian uint32)
 *   144+P   var   protected_image_digests[protect_pid_count][32]
 *                         (present only when runtime_protect_version == 2)
 *   144+P+I var   attest_data[attest_size]
 *   ...     var   signature[sig_size]
 *
 * In v2 the runtime_protect_digest binds, per PID, the kernel-anchored
 * runtime image digest carried in protected_image_digests, so the quote
 * attests what code each protected process is running, not just its
 * identity. The image digests are authenticated transitively: a verifier
 * recomputes runtime_protect_digest from the PID list and the carried image
 * digests and checks it against the quote-bound value.
 *
 * Maximum token size: 144 + (1024 * 4) + (1024 * 32) + 1024 + 512
 */
#define LOTA_TOKEN_MAGIC 0x4B544F4C /* "LOTK" in memory (little-endian) */
#define LOTA_TOKEN_VERSION 0x0003
#define LOTA_TOKEN_HEADER_SIZE 144
#define LOTA_TOKEN_MAX_PROTECT_PIDS 1024
#define LOTA_TOKEN_MAX_PID_LIST_SIZE (LOTA_TOKEN_MAX_PROTECT_PIDS * 4)
#define LOTA_TOKEN_IMAGE_DIGEST_SIZE 32

/* runtime_protect_version values */
#define LOTA_RUNTIME_PROTECT_V1 \
	1 /* PID set identity only (0 also accepted)   \
				   */
#define LOTA_RUNTIME_PROTECT_V2 2 /* PID set + per-PID kernel image digest */

/*
 * The optional v2 image-digest block is bounded at runtime by the carried
 * pid count, not folded into this compile-time maximum; an oversized token
 * is rejected during parsing.
 */
#define LOTA_TOKEN_MAX_SIZE \
	(LOTA_TOKEN_HEADER_SIZE + LOTA_TOKEN_MAX_PID_LIST_SIZE + 1024 + 512)

/*
 * Token wire format header (packed, little-endian)
 */
struct lota_token_wire {
	/* 6     2   total_size   (header + variable data) */
	/* 8     8   valid_until  (Unix timestamp) */
	/* 16    4   flags        (LOTA_FLAG_* bitmask) */
	/* 20    32  nonce        (client nonce) */
	/* 52    2   sig_alg      (TPM signature algorithm) */
	/* 54    2   hash_alg     (TPM hash algorithm) */
	/* 56    4   pcr_mask     (PCR selection bitmask) */
	/* 60    32  policy_digest (SHA-256 over startup enforcement policy) */
	/* 92    32  runtime_protect_digest (canonical runtime protected PID
	 * set) */
	/* 124   4   protect_pid_count */
	/* 128   8   runtime_protect_epoch */
	/* 136   2   pid_list_size (protect_pid_count * sizeof(uint32_t)) */
	/* 138   2   attest_size  (TPMS_ATTEST blob size) */
	/* 140   2   sig_size     (TPM signature size) */
	/* 142   2   runtime_protect_version (0/1 = PID set, 2 = + image) */
	/* ---   --- ----------------------------------- */
	/* 144   var protected_pids[protect_pid_count] */
	/* 144+P var protected_image_digests[protect_pid_count][32] (v2 only) */
	/* ...   var attest_data[attest_size] */
	/* ...   var signature[sig_size] */

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
	uint64_t runtime_protect_epoch;
	uint16_t pid_list_size;
	uint16_t attest_size;
	uint16_t sig_size;
	uint16_t runtime_protect_version;
	/*
	 * followed by protected_pids[], then (v2 only)
	 * protected_image_digests[], then attest_data[] and signature[]
	 */
} __attribute__((packed));

#ifdef __cplusplus
}
#endif

#endif /* LOTA_TOKEN_H */
