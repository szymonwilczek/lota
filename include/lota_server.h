/* SPDX-License-Identifier: MIT */
/*
 * LOTA Server-Side Token Verification SDK
 *
 * Library for game servers to verify attestation tokens received
 * from game clients running the LOTA Gaming SDK.
 *
 * Verification flow:
 *  1. Game server generates a random 32-byte nonce
 *  2. Game server sends nonce to game client
 *  3. Game client calls lota_get_token()
 *  4. Game client serializes: lota_token_serialize()
 *  5. Game client sends serialized bytes to game server
 *  6. Game server calls lota_server_verify_token()
 *
 * The AIK public key must be obtained from a trusted source - typically the
 * LOTA verifier's /api/v1/clients endpoint or a pre-enrollment database.
 *
 * Example:
 *
 *   struct lota_server_claims claims;
 *   int ret = lota_server_verify_token(
 *       token_bytes, token_len,
 *       aik_pub_der, aik_pub_len,
 *       server_nonce,
 *       60,          // max 60 seconds old
 *       &claims
 *   );
 *
 *   if (ret == LOTA_SERVER_OK) {
 *       // Client is attested and token is fresh
 *   }
 */

#ifndef LOTA_SERVER_H
#define LOTA_SERVER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Server SDK version
 */
#define LOTA_SERVER_SDK_VERSION_MAJOR 1
#define LOTA_SERVER_SDK_VERSION_MINOR 0
#define LOTA_SERVER_SDK_VERSION_PATCH 0

#include "lota_token.h"

/* TPM2 PCR composite digest can be SHA-256, SHA-384, or SHA-512. */
#define LOTA_SERVER_MAX_PCR_DIGEST_SIZE 64

/*
 * Server-side error codes
 */
enum lota_server_error {
  LOTA_SERVER_OK = 0,
  LOTA_SERVER_ERR_INVALID_ARG = -1,  /* NULL pointer or bad parameter */
  LOTA_SERVER_ERR_BAD_TOKEN = -2,    /* Token parse error (bad magic/size) */
  LOTA_SERVER_ERR_BAD_VERSION = -3,  /* Unsupported token version */
  LOTA_SERVER_ERR_SIG_FAIL = -4,     /* RSA signature verification failed */
  LOTA_SERVER_ERR_NONCE_FAIL = -5,   /* Nonce mismatch in TPMS_ATTEST */
  LOTA_SERVER_ERR_EXPIRED = -6,      /* Token has expired */
  LOTA_SERVER_ERR_ATTEST_PARSE = -7, /* Failed to parse TPMS_ATTEST */
  LOTA_SERVER_ERR_CRYPTO = -8,       /* OpenSSL internal error */
  LOTA_SERVER_ERR_BUFFER = -9,       /* Buffer too small */
};

/*
 * Verified claims extracted from a token
 *
 * After successful verification, these fields contain trusted data
 * that has been cryptographically validated.
 */
struct lota_server_claims {
  uint64_t valid_until;      /* Token expiry time (Unix timestamp) */
  uint32_t flags;            /* LOTA_FLAG_* bitmask at issue time */
  uint8_t nonce[32];         /* Client nonce echoed from token */
  uint32_t pcr_mask;         /* PCRs included in TPM quote */
  uint8_t policy_digest[32]; /* SHA-256 over startup enforcement policy */
  uint8_t pcr_digest[LOTA_SERVER_MAX_PCR_DIGEST_SIZE];
  size_t pcr_digest_len; /* Actual length of pcr_digest (0 if absent) */
  int expired;           /* 1 if token has expired, 0 otherwise */
};

/*
 * lota_server_verify_token - Verify a serialized attestation token
 *
 * @token_data:     Serialized token bytes (from lota_token_serialize)
 * @token_len:      Length of token_data
 * @aik_pub_der:    AIK public key in DER (PKIX/SPKI) format
 * @aik_pub_len:    Length of aik_pub_der
 * @expected_nonce: Optional 32-byte nonce to verify (NULL = skip nonce check)
 * @max_age_sec:    Maximum acceptable token age in seconds.
 *                  0 -> use LOTA_TOKEN_DEFAULT_MAX_AGE (300s).
 * @claims:         Output claims structure (always populated when the
 *                  return code is OK, TOO_OLD, EXPIRED, or FUTURE so
 *                  the caller can inspect age_seconds on rejection)
 *
 * Verification steps:
 *  1. Parse token wire format
 *  2. Verify RSA signature over attest_data using AIK public key
 *  3. Parse TPMS_ATTEST and extract extraData
 *  4. extraData == SHA256(issued_at || valid_until || flags || nonce)
 *  5. Optionally verify client nonce matches expected_nonce
 *  6. Check token expiry against current time
 *  7. Hard freshness check: reject if age > max_age_sec
 *  8. Hard future check: reject if issued_at > now + MAX_CLOCK_SKEW
 *  9. Extract PCR digest from TPMS_ATTEST QuoteInfo
 *
 * Returns: LOTA_SERVER_OK on success.
 *          LOTA_SERVER_ERR_EXPIRED if now > valid_until.
 *          LOTA_SERVER_ERR_TOO_OLD if token age > max_age_sec.
 *          LOTA_SERVER_ERR_FUTURE if token issued in the future.
 *          Other negative error codes on verification failure.
 */
int lota_server_verify_token(const uint8_t *token_data, size_t token_len,
                             const uint8_t *aik_pub_der, size_t aik_pub_len,
                             const uint8_t *expected_nonce,
                             struct lota_server_claims *claims);

/*
 * Parse token without cryptographic verification.
 *
 * Extracts claims from a serialized token WITHOUT verifying the
 * TPM signature. Useful for logging, debugging, or when the caller
 * handles verification separately.
 *
 * WARNING: Claims from this function are UNTRUSTED.
 *
 * Returns LOTA_SERVER_OK on success, negative error on parse failure.
 */
int lota_server_parse_token(const uint8_t *token_data, size_t token_len,
                            struct lota_server_claims *claims);

/*
 * Get error description.
 */
const char *lota_server_strerror(int error);

/*
 * Get SDK version string.
 */
const char *lota_server_sdk_version(void);

#ifdef __cplusplus
}
#endif

#endif /* LOTA_SERVER_H */
