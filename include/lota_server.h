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
 *       &claims
 *   );
 *
 *   if (ret == LOTA_SERVER_OK && !claims.expired) {
 *       // Client is attested - allow into game session
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
#define LOTA_TOKEN_HEADER_SIZE 72
#define LOTA_TOKEN_MAX_SIZE (LOTA_TOKEN_HEADER_SIZE + 1024 + 512)

/*
 * Token freshness policy defaults.
 *
 * LOTA_TOKEN_DEFAULT_MAX_AGE:
 *   Maximum acceptable age (in seconds) for a token. If the token's
 *   issued_at timestamp is older than (now - max_age), the token is
 *   considered stale. Default is 300 seconds (5 minutes).
 *   Game servers can override by checking claims.age_seconds directly.
 *
 * LOTA_TOKEN_MAX_CLOCK_SKEW:
 *   Maximum allowed clock difference (in seconds) between the token
 *   issuer and the verifier. Tokens with issued_at in the future
 *   (beyond this tolerance) are flagged as issued_in_future.
 *   Default is 60 seconds.
 */
#define LOTA_TOKEN_DEFAULT_MAX_AGE 300
#define LOTA_TOKEN_MAX_CLOCK_SKEW 60

/*
 * Token wire format header (packed, little-endian)
 */
struct lota_token_wire {
  uint32_t magic;
  uint16_t version;
  uint16_t total_size;
  uint64_t issued_at;
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
  uint64_t issued_at;     /* Token issue time (Unix timestamp) */
  uint64_t valid_until;   /* Token expiry time (Unix timestamp) */
  uint32_t flags;         /* LOTA_FLAG_* bitmask at issue time */
  uint8_t nonce[32];      /* Client nonce echoed from token */
  uint32_t pcr_mask;      /* PCRs included in TPM quote */
  uint8_t pcr_digest[32]; /* PCR composite hash from TPMS_ATTEST */
  size_t pcr_digest_len;  /* Actual length of pcr_digest (0 if absent) */
  int expired;            /* 1 if token has expired, 0 otherwise */
  int too_old;            /* 1 if age > LOTA_TOKEN_DEFAULT_MAX_AGE */
  int issued_in_future;   /* 1 if issued_at > now + LOTA_TOKEN_MAX_CLOCK_SKEW */
  int64_t age_seconds;    /* Token age: now - issued_at (negative if future) */
};

/*
 * lota_server_verify_token - Verify a serialized attestation token
 *
 * @token_data:  Serialized token bytes (from lota_token_serialize)
 * @token_len:   Length of token_data
 * @aik_pub_der: AIK public key in DER (PKIX/SPKI) format
 * @aik_pub_len: Length of aik_pub_der
 * @expected_nonce: Optional 32-byte nonce to verify (NULL = skip nonce check)
 * @claims:      Output claims structure (filled on success)
 *
 * Verification steps:
 *  1. Parse token wire format
 *  2. Verify RSA signature over attest_data using AIK public key
 *  3. Parse TPMS_ATTEST and extract extraData
 *  4. extraData == SHA256(issued_at || valid_until || flags || nonce)
 *  5. Optionally verify client nonce matches expected_nonce
 *  6. Check token expiry against current time
 *  7. Check token freshness (issued_at close to now)
 *  8. Extract PCR digest from TPMS_ATTEST QuoteInfo
 *
 * Freshness checks (soft - reported in claims, not hard errors):
 *  - claims->too_old: token age exceeds LOTA_TOKEN_DEFAULT_MAX_AGE
 *  - claims->issued_in_future: issued_at ahead of now by > MAX_CLOCK_SKEW
 *  - claims->age_seconds: signed age for custom policy decisions
 *
 * Returns LOTA_SERVER_OK on success (even if token is expired/stale -
 * check claims->expired and claims->too_old). Returns negative error
 * code on verification failure.
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
