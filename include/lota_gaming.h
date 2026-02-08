/* SPDX-License-Identifier: MIT */
/*
 * LOTA Gaming SDK
 *
 * Client library for games to query local attestation status.
 * Link with -llotagaming.
 *
 * Example usage:
 *
 *   struct lota_client *client = lota_connect();
 *   if (!client) {
 *       // LOTA agent not running or not installed
 *       return;
 *   }
 *
 *   if (lota_is_attested(client)) {
 *       struct lota_token token;
 *       if (lota_get_token(client, NULL, &token) == LOTA_OK) {
 *           // Send token.data (token.data_len bytes) to game server
 *       }
 *   }
 *
 *   lota_disconnect(client);
 */

#ifndef LOTA_GAMING_H
#define LOTA_GAMING_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * SDK version
 */
#define LOTA_SDK_VERSION_MAJOR 1
#define LOTA_SDK_VERSION_MINOR 0
#define LOTA_SDK_VERSION_PATCH 0

/*
 * Error codes
 */
enum lota_error {
  LOTA_OK = 0,
  LOTA_ERR_NOT_CONNECTED = -1,
  LOTA_ERR_CONNECTION_FAILED = -2,
  LOTA_ERR_TIMEOUT = -3,
  LOTA_ERR_PROTOCOL = -4,
  LOTA_ERR_NOT_ATTESTED = -5,
  LOTA_ERR_INVALID_ARG = -6,
  LOTA_ERR_BUFFER_TOO_SMALL = -7,
  LOTA_ERR_AGENT_ERROR = -8,
  LOTA_ERR_NO_MEMORY = -9,
  LOTA_ERR_RATE_LIMITED = -10,
  LOTA_ERR_ACCESS_DENIED = -11,
};

/*
 * Status flags
 */
#define LOTA_FLAG_ATTESTED (1 << 0)
#define LOTA_FLAG_TPM_OK (1 << 1)
#define LOTA_FLAG_IOMMU_OK (1 << 2)
#define LOTA_FLAG_BPF_LOADED (1 << 3)
#define LOTA_FLAG_SECURE_BOOT (1 << 4)

/*
 * Subscription event types
 *
 * Bitmask selecting which status changes trigger push notifications.
 * Pass to lota_subscribe() to control notification granularity.
 */
#define LOTA_EVENT_STATUS (1U << 0) /* Status flags changed */
#define LOTA_EVENT_ATTEST (1U << 1) /* Attestation completed (pass/fail) */
#define LOTA_EVENT_MODE (1U << 2)   /* Enforcement mode changed */
#define LOTA_EVENT_ALL 0xFFFFFFFFU

/*
 * Opaque client handle
 */
struct lota_client;

/*
 * Status information
 */
struct lota_status {
  uint32_t flags;            /* LOTA_FLAG_* bitmask */
  uint64_t last_attest_time; /* Unix timestamp of last successful attestation */
  uint64_t valid_until;      /* Token validity expiration (Unix timestamp) */
  uint32_t attest_count;     /* Total successful attestations */
  uint32_t fail_count;       /* Total failed attestations */
};

/*
 * Attestation token
 *
 * Contains a TPM Quote-based attestation statement.
 * The server validates by:
 * - Computing expected_nonce = SHA256(issued_at || valid_until || flags ||
 * nonce)
 * - Verifying TPM signature over attest_data using AIK public key
 * - Checking extraData in TPMS_ATTEST matches expected_nonce
 * - Verifying PCR digest matches expected policy
 */
struct lota_token {
  uint64_t issued_at;   /* When the token was issued (Unix timestamp) */
  uint64_t valid_until; /* Token expiration (Unix timestamp) */
  uint32_t flags;       /* Status flags at issue time */
  uint8_t nonce[32];    /* Client nonce (if provided) */

  /* TPM Quote data */
  uint16_t sig_alg;  /* Signature algorithm (TPM2_ALG_RSASSA/RSAPSS) */
  uint16_t hash_alg; /* Hash algorithm (TPM2_ALG_SHA256) */
  uint32_t pcr_mask; /* PCRs included in quote */

  uint8_t *attest_data; /* TPMS_ATTEST blob (heap allocated) */
  size_t attest_size;   /* Size of attest_data */
  uint8_t *signature;   /* TPM signature (heap allocated) */
  size_t signature_len; /* Signature length in bytes */
};

/*
 * Connection options
 */
struct lota_connect_opts {
  const char *socket_path; /* Custom socket path (NULL = default) */
  int timeout_ms;          /* Connection timeout in ms (0 = default 5000) */
};

/*
 * lota_connect - Connect to the LOTA agent
 *
 * Establishes a connection to the local LOTA agent.
 * Returns NULL if the agent is not running or connection fails.
 *
 * IMPORTANT: Returned handle must be freed with lota_disconnect().
 */
struct lota_client *lota_connect(void);

/*
 * lota_connect_opts - Connect with custom options
 *
 * Same as lota_connect() but allows specifying custom socket path
 * and timeout.
 */
struct lota_client *lota_connect_opts(const struct lota_connect_opts *opts);

/*
 * lota_disconnect - Disconnect from the LOTA agent
 *
 * Closes the connection and frees resources.
 * Safe to call with NULL.
 */
void lota_disconnect(struct lota_client *client);

/*
 * lota_ping - Check if agent is responsive
 *
 * Returns LOTA_OK if the agent responds, error code otherwise.
 * Optionally returns agent uptime in seconds.
 */
int lota_ping(struct lota_client *client, uint64_t *uptime_sec);

/*
 * lota_get_status - Get current attestation status
 *
 * Retrieves the current status from the agent.
 * The status structure is filled with current values.
 */
int lota_get_status(struct lota_client *client, struct lota_status *status);

/*
 * lota_is_attested - Quick attestation check
 *
 * Returns 1 if currently attested, 0 otherwise.
 * This is a convenience wrapper around lota_get_status().
 */
int lota_is_attested(struct lota_client *client);

/*
 * lota_get_token - Get attestation token for server verification
 * @client: Client handle
 * @nonce: Optional 32-byte nonce from game server (NULL = none)
 * @token: Output token structure
 *
 * Retrieves a signed attestation token that can be sent to
 * the game server for verification. The server must use the
 * LOTA verifier to validate the token.
 *
 * Returns LOTA_ERR_NOT_ATTESTED if no valid attestation exists.
 *
 * The caller must call lota_token_free() to free the token
 * when done.
 */
int lota_get_token(struct lota_client *client, const uint8_t *nonce,
                   struct lota_token *token);

/*
 * lota_token_free - Free token resources
 *
 * Frees the signature buffer allocated by lota_get_token().
 * Safe to call with uninitialized token (signature = NULL).
 */
void lota_token_free(struct lota_token *token);

/*
 * lota_token_serialized_size - Calculate serialized token size
 * @token: Token to measure
 *
 * Returns the number of bytes needed to serialize @token,
 * or 0 if the token is invalid.
 */
size_t lota_token_serialized_size(const struct lota_token *token);

/*
 * lota_token_serialize - Serialize token to wire format
 * @token: Token to serialize (from lota_get_token)
 * @buf: Output buffer
 * @buflen: Size of output buffer
 * @written: Output: number of bytes written (may be NULL)
 *
 * Writes a portable binary representation suitable for sending
 * to a game server. The server deserializes and verifies with
 * lota_server_verify_token() from lota_server.h.
 *
 * Returns LOTA_OK on success, LOTA_ERR_BUFFER_TOO_SMALL if buf
 * is too small (use lota_token_serialized_size to check first).
 */
int lota_token_serialize(const struct lota_token *token, uint8_t *buf,
                         size_t buflen, size_t *written);

/*
 * lota_strerror - Get error message for error code
 */
const char *lota_strerror(int error);

/*
 * lota_sdk_version - Get SDK version string
 *
 * Returns a static string like "1.0.0".
 */
const char *lota_sdk_version(void);

/*
 * lota_flags_to_string - Convert flags to human-readable string
 * @flags: LOTA_FLAG_* bitmask
 * @buf: Output buffer
 * @buflen: Buffer size
 *
 * Writes a string like "ATTESTED,TPM_OK,BPF_LOADED" to buf.
 * Returns number of bytes written (excluding null terminator),
 * or negative error if buffer too small.
 */
int lota_flags_to_string(uint32_t flags, char *buf, size_t buflen);

#ifdef __cplusplus
}
#endif

#endif /* LOTA_GAMING_H */
