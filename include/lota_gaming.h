/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
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
 *       LOTA agent not running or not installed.
 *       return;
 *   }
 *
 *   Pass the 32-byte challenge the server issued,
 *   never NULL in production:
 *   it is what stops the server accepting a replayed token.
 *
 *   if (lota_is_attested(client)) {
 *       struct lota_token token;
 *       if (lota_get_token(client, nonce, &token) == LOTA_OK) {
 *           size_t sz = lota_token_serialized_size(&token);
 *           uint8_t *buf = malloc(sz);
 *           size_t written = 0;
 *           if (lota_token_serialize(&token, buf, sz, &written) == LOTA_OK)
 *               Send buf (written bytes) to the game server.
 *           free(buf);
 *           lota_token_free(&token);
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
	/* the agent holds no enrollment for the requested publisher */
	LOTA_ERR_UNKNOWN_PROFILE = -12,
	/*
	 * Nobody on this machine has agreed to answer to that publisher yet.
	 * The player decides, not the title: show what the publisher would
	 * learn and let them accept, then connect again.
	 */
	LOTA_ERR_CONSENT_REQUIRED = -13,
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
 * The publisher this connection named verifies tokens itself.
 *
 * Publisher can run verifier, which judges the full attestation report and gives
 * this machine a verdict, or run none and check in their own backend the token
 * a title fetches.
 * With the second, nothing is reported from this machine for them,
 * so LOTA_FLAG_ATTESTED carries no verdict of theirs and stays clear
 * -- which does not mean the machine failed anything.
 *
 * Title whose publisher runs light reads this bit instead of lota_is_attested():
 * fetch token with lota_get_token(), send it to your backend, and let
 * lota_server_verify_token() (or the Go SDK's VerifyToken) decide there.
 * The token's TPM signature, its nonce binding and its PCR digest are the evidence
 * in that arrangement.
 */
#define LOTA_FLAG_TOKEN_ONLY (1 << 7)

/*
 * Subscription event types
 *
 * Bitmask selecting which status changes trigger push notifications.
 * Pass to lota_subscribe() to control notification granularity.
 */
#define LOTA_EVENT_STATUS (1U << 0) /* Status flags changed */
#define LOTA_EVENT_ATTEST (1U << 1) /* Attestation completed (pass/fail) */
#define LOTA_EVENT_MODE (1U << 2) /* Enforcement mode changed */
#define LOTA_EVENT_ALL 0xFFFFFFFFU

/*
 * Opaque client handle
 */
struct lota_client;

/*
 * Status information
 */
struct lota_status {
	uint32_t flags; /* LOTA_FLAG_* bitmask */
	uint64_t last_attest_time; /* Unix timestamp of last successful
				      attestation */
	uint64_t valid_until; /* Token validity expiration (Unix timestamp) */
	uint32_t attest_count; /* Total successful attestations */
	uint32_t fail_count; /* Total failed attestations */
};

/*
 * Attestation token
 *
 * Contains a TPM Quote-based attestation statement.
 * The server validates by:
 * - Verifying the TPM signature over attest_data with the AIK public key
 * - Checking extraData in TPMS_ATTEST equals
 *   SHA256(valid_until || flags || pcr_mask || nonce || policy_digest ||
 *   runtime_protect_digest || runtime_protect_epoch),
 *   which is what puts every field above inside the signature
 * - Checking the nonce is the one it issued
 * - Verifying PCR digest matches expected policy
 *
 * lota_server_verify_token() in lota_server.h does all of this;
 * relying party should call it rather than reimplement the binding.
 */
struct lota_token {
	uint64_t valid_until; /* Token expiration (Unix timestamp) */
	uint32_t flags; /* Status flags at issue time */
	uint8_t nonce[32]; /* Client nonce (if provided) */

	/* TPM Quote data */
	uint16_t sig_alg; /* Signature algorithm (TPM2_ALG_RSASSA/RSAPSS) */
	uint16_t hash_alg; /* Hash algorithm (TPM2_ALG_SHA256) */
	uint32_t pcr_mask; /* PCRs included in quote */

	/*
	 * SHA-256 over enforcement-relevant startup policy state (includes
	 * allowlist)
	 */
	uint8_t policy_digest[32];

	/* SHA-256 over canonical runtime protected PID set. */
	uint8_t runtime_protect_digest[32];
	uint64_t runtime_protect_epoch; /* Monotonic runtime PID-set mutation id */
	uint16_t runtime_protect_version; /* 0/1 = PID set, 2 = + image digests */
	uint32_t protect_pid_count;
	uint32_t *protected_pids; /* heap-allocated canonical list */

	/*
	 * v2 only: per-PID kernel-anchored runtime image digest, parallel to
	 * protected_pids. NULL when runtime_protect_version < 2.
	 */
	uint8_t (*protected_image_digests)[32];

	uint8_t *attest_data; /* TPMS_ATTEST blob (heap allocated) */
	size_t attest_size; /* Size of attest_data */
	uint8_t *signature; /* TPM signature (heap allocated) */
	size_t signature_len; /* Signature length in bytes */
};

/*
 * Connection options
 *
 * struct_size is set by the caller to sizeof(struct lota_connect_opts)
 * and is how this structure grows without second entry point:
 * the library reads only the members the caller's build knew about, and caller
 * built against a newer header than the library it links keeps working because
 * the library ignores what it does not understand.
 * Same contract as statx(2) and sched_setattr(2).
 *
 *     struct lota_connect_opts opts = { .struct_size = sizeof(opts) };
 *
 * Zero struct_size is refused rather than guessed at: it means the caller zeroed
 * the structure and never set the field, and guessing size would read members
 * the caller never wrote.
 */
struct lota_connect_opts {
	size_t struct_size; /* sizeof(struct lota_connect_opts) */
	const char *socket_path; /* Custom socket path (NULL = default) */
	int timeout_ms; /* Connection timeout in ms (0 = default 5000) */

	/*
	 * Which publisher this connection attests for:
	 * the lowercase hex SHA-256 of that publisher's attestation-CA trust
	 * anchor SubjectPublicKeyInfo (64 characters).
	 * Publisher knows this about their own CA and ships it in the title.
	 *
	 * Player's machine holds one enrollment per publisher, so naming one
	 * selects the AIK that signs this connection's tokens and makes
	 * lota_is_attested() report that publisher's verdict instead of every
	 * publisher on the host agreeing.
	 *
	 * NULL on a single-publisher host, which is every enterprise fleet:
	 * the agent then answers with its first profile and the host-wide verdict.
	 * Naming a publisher the machine has no enrollment for fails
	 * the connection rather than falling back to another publisher's evidence.
	 */
	const char *publisher_profile;
};

/* hex SHA-256, without a terminator */
#define LOTA_PUBLISHER_PROFILE_LEN 64

/*
 * Size of the structure as of the 1.0 surface.
 * Caller passing less than this is refused;
 * Caller passing more has members this library does not read.
 */
#define LOTA_CONNECT_OPTS_SIZE_MIN                               \
	(offsetof(struct lota_connect_opts, publisher_profile) + \
	 sizeof(const char *))

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
 * lota_connect_last_error - Why the last connect on this thread failed
 *
 * lota_connect() and lota_connect_opts() return NULL for several reasons
 * and title has to tell them apart: LOTA_ERR_CONNECTION_FAILED is "no agent here",
 * LOTA_ERR_UNKNOWN_PROFILE is
 * "this machine has no enrollment with the publisher you named",
 * and LOTA_ERR_CONSENT_REQUIRED is "nobody here has agreed to answer to them yet",
 * which is a screen to show rather than error to report.
 *
 * Set by every connect attempt on the calling thread, including successful ones
 * (LOTA_OK).
 * Reading it after anything else is meaningless.
 */
int lota_connect_last_error(void);

/*
 * lota_disconnect - Disconnect from the LOTA agent
 *
 * Closes the connection and frees resources.
 * Safe to call with NULL.
 */
void lota_disconnect(struct lota_client *client);

/*
 * lota_get_fd - Get the underlying socket file descriptor
 *
 * Returns the file descriptor or -1 if invalid.
 */
int lota_get_fd(struct lota_client *client);

/*
 * lota_ping - Check if agent is responsive
 *
 * Returns LOTA_OK if the agent responds, error code otherwise.
 * Optionally returns agent uptime in seconds.
 */
int lota_ping(struct lota_client *client, uint64_t *uptime_sec);

/*
 * lota_protect_self - Register the caller's PID as protected
 *
 * Sends LOTA_IPC_CMD_PROTECT_PID for the calling process. The
 * agent verifies the connection's SO_PEERCRED PID matches the
 * registration target and that the live start_time_ticks still
 * matches the credentials captured at connect(), so a recycled
 * PID cannot piggy-back on a prior registration. Self-registration
 * does not require the trusted-executable allowlist that other
 * PROTECT_PID callers must satisfy: opting yourself in to stricter
 * LSM enforcement is not a privilege escalation.
 *
 * Idempotent: a second call from the same task returns LOTA_OK
 * without mutating the runtime PID set.
 *
 * Once registered, the agent's BPF strict_mmap, block_anon_exec,
 * ptrace_access_check, and task_kill hooks gate every access into
 * or out of this process against the trust set.
 *
 * Returns LOTA_OK on success.
 *         LOTA_ERR_ACCESS_DENIED if the PID identity check fails.
 *         LOTA_ERR_RATE_LIMITED  if the caller's UID exceeded the
 *                                privileged-PID rate window.
 *         LOTA_ERR_PROTOCOL      on IPC framing errors.
 */
int lota_protect_self(struct lota_client *client);

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
 * Status change callback type
 *
 * @status:    Current attestation status snapshot
 * @events:    LOTA_EVENT_* bitmask describing what changed
 * @user_data: Opaque pointer from lota_subscribe()
 */
typedef void (*lota_status_callback_fn)(const struct lota_status *status,
					uint32_t events, void *user_data);

/*
 * lota_subscribe - Subscribe to status change notifications
 * @client:     Client handle
 * @event_mask: LOTA_EVENT_* bitmask (LOTA_EVENT_ALL for everything)
 * @callback:   Function called when a subscribed event occurs
 * @user_data:  Opaque pointer forwarded to callback
 *
 * After subscribing, the agent pushes notifications whenever
 * a subscribed event occurs.  Call lota_poll_events() to receive
 * them, or they are dispatched transparently during other SDK calls.
 *
 * Returns LOTA_OK on success.
 */
int lota_subscribe(struct lota_client *client, uint32_t event_mask,
		   lota_status_callback_fn callback, void *user_data);

/*
 * lota_unsubscribe - Cancel status change subscription
 * @client: Client handle
 *
 * Tells the agent to stop sending notifications on this connection.
 *
 * Returns LOTA_OK on success.
 */
int lota_unsubscribe(struct lota_client *client);

/*
 * lota_poll_events - Poll for pending notifications
 * @client:     Client handle (must be subscribed)
 * @timeout_ms: Maximum wait time in milliseconds
 *              (0 = non-blocking, -1 = block indefinitely)
 *
 * Reads from the connection and dispatches pending notifications
 * via the callback registered with lota_subscribe().
 *
 * Returns: number of notifications dispatched (>= 0),
 *          or negative LOTA_ERR_* on error.
 */
int lota_poll_events(struct lota_client *client, int timeout_ms);

const char *lota_strerror(int error);

/*
 * lota_sdk_version - Identify the build this library came from
 *
 * Returns static string naming the LOTA release the library was compiled from,
 * the same one lota_server_sdk_version() reports.
 * It answers "which build is this" for a log line, a support ticket
 * or an advisory.
 * Treat it as opaque: the format carries no promise, so match it, do not parse it.
 *
 * It is NOT the answer to "what may I link against".
 * Binary compatibility is the soname the loader resolves and the ABI version
 * the pkg-config module reports;
 * see Documentation/contributor/development/api-stability.rst.
 *
 * SECURITY:
 * This executes inside the calling process, which on a player's machine is memory
 * an attacker controls. Relying party must never decide trust from a version
 * a client reports about itself. The build identity that carries weight is
 * the agent binary hash pinned in the verifier's policy and committed to PCR 14.
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
