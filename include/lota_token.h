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
 *   8       8     issued_at      (Unix timestamp)
 *   16      8     valid_until    (Unix timestamp)
 *   24      4     flags          (LOTA_FLAG_* bitmask)
 *   28      32    nonce          (client nonce)
 *   60      2     sig_alg        (TPM signature algorithm)
 *   62      2     hash_alg       (TPM hash algorithm)
 *   64      4     pcr_mask       (PCR selection bitmask)
 *   68      2     attest_size    (TPMS_ATTEST blob size)
 *   70      2     sig_size       (TPM signature size)
 *   ---     ---   --------------------------------
 *   72      var   attest_data[attest_size]
 *   72+A    var   signature[sig_size]
 *
 * Maximum token size: 72 + 1024 + 512 = 1608 bytes
 */
#define LOTA_TOKEN_MAGIC 0x4B544F4C /* "LOTK" in memory (little-endian) */
#define LOTA_TOKEN_VERSION 0x0001
#define LOTA_TOKEN_HEADER_SIZE 64
#define LOTA_TOKEN_MAX_SIZE (LOTA_TOKEN_HEADER_SIZE + 1024 + 512)

/*
 * Token wire format header (packed, little-endian)
 */
struct lota_token_wire {
  /*   6       2     total_size     (header + variable data) */
  /*   8       8     valid_until    (Unix timestamp) */
  /*   16      4     flags          (LOTA_FLAG_* bitmask) */
  /*   20      32    nonce          (client nonce) */
  /*   52      2     sig_alg        (TPM signature algorithm) */
  /*   54      2     hash_alg       (TPM hash algorithm) */
  /*   56      4     pcr_mask       (PCR selection bitmask) */
  /*   60      2     attest_size    (TPMS_ATTEST blob size) */
  /*   62      2     sig_size       (TPM signature size) */
  /*   ---     ---   -------------------------------- */
  /*   64      var   attest_data[attest_size] */
  /*   64+A    var   signature[sig_size] */

  uint32_t magic;
  uint16_t version;
  uint16_t total_size;
  uint64_t valid_until;
  uint32_t flags;
  uint8_t nonce[32];
  uint16_t sig_alg;
  uint16_t hash_alg;
  uint32_t pcr_mask;
  uint16_t attest_size;
  uint16_t sig_size;
  /* followed by attest_data[attest_size] and signature[sig_size] */
} __attribute__((packed));

#ifdef __cplusplus
}
#endif

#endif /* LOTA_TOKEN_H */
