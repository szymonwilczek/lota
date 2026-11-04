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
	/*
	 * This process's own executable carries no measurable identity,
	 * so the agent cannot state what is running and will not issue
	 * a token for it.
	 * The agent's log names the object and why: an executable on a
	 * filesystem the host does not serve itself (FUSE, a network
	 * mount) with no fs-verity digest, memory with no file, or a
	 * measurement that broke.
	 *
	 * It is about this process and no other.  A different protected
	 * process being unmeasurable never produces this code:
	 * the token is issued with LOTA_FLAG_IMAGE_FULLY_MEASURED clear
	 * instead, and how much coverage a publisher requires is theirs
	 * to decide.
	 */
	LOTA_ERR_UNMEASURABLE_SELF = -14,
	/*
	 * The agent on this machine holds no TPM, so it cannot sign a token
	 * and will not issue an unsigned one. Nothing the caller does changes
	 * that: retrying, waiting or asking again for a different publisher
	 * all end here.
	 * It is not LOTA_ERR_AGENT_ERROR and not a TPM that failed
	 * -- there is no TPM.
	 */
	LOTA_ERR_NO_TPM = -15,
	/*
	 * The agent on the other end enforces nothing: it applied no policy
	 * and loaded no LSM object, which is what a diagnostic server is.
	 * A call that asks it to change runtime enforcement is refused by
	 * design and no retry changes that.
	 */
	LOTA_ERR_NO_ENFORCEMENT = -16,
	/*
	 * The publisher is known and consented to, but the agent's
	 * attestation-key handle range is full. No retry helps: somebody
	 * at the machine must forget a publisher or reclaim a handle
	 * another program left in the range.
	 */
	LOTA_ERR_NO_KEY_SLOT = -17,

	/*
	 * The TPM is in dictionary-attack lockout and signs nothing until
	 * the lockout lapses or somebody at the machine clears it.
	 * Unlike LOTA_ERR_NOT_ATTESTED, retrying next round does not help.
	 */
	LOTA_ERR_TPM_LOCKED = -18,

	/*
	 * The process asked about was not measured by the last token round:
	 * nobody protected it, or it exited before the round reached it.
	 */
	LOTA_ERR_NOT_PROTECTED = -19,
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
 * Package update replaced the agent binary and takes effect on the next cold boot.
 * Attestation is NOT failing: PCR 14 commits to the build that is still running
 * and the token names that build, so everything continues to work.
 *
 * What the flag says is that the machine will present a different agent after
 * its next restart, and that PCR 14 cannot be re-extended without hardware reset.
 *
 * It exists so a title can say that in one sentence at a moment of its choosing,
 * instead of the player meeting it as a launch failure later.
 * The flag is informational and never a reason to refuse a session on its own.
 */
#define LOTA_FLAG_UPDATE_PENDING (1 << 7)

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
#define LOTA_FLAG_TOKEN_ONLY (1 << 8)

/*
 * Runtime image measurement covered every object the protected processes map.
 *
 * Each token folds a kernel-anchored measurement of the live code of every process
 * in the protected set, and that measurement can only cover an object the kernel
 * holds an fs-verity digest for.
 * On a host where a distribution ships its libraries without one, some objects
 * are absent from the fold: the measurement is honest about what it saw,
 * and this bit says whether it saw everything.
 *
 * It is a policy input, not a verdict.
 * Publisher who requires full coverage puts this bit in the flags their backend
 * demands, and one who does not ignores it; either way what a title's own binary
 * maps is the publisher's to make measurable, and the agent refuses token
 * outright when the title's own executable cannot be measured.
 */
#define LOTA_FLAG_IMAGE_FULLY_MEASURED (1 << 9)

/*
 * Protected process was ended through the agent on this host since it booted.
 *
 * The agent ends a protected process on request, for whoever kill(2) would
 * have allowed, the owner of the process or root. An ordinary signal reaches
 * it as well; this route is the one that leaves a record.
 * This bit is what the publisher gets, and it stays set until the host
 * reboots.
 *
 * It says a session was ended on the machine rather than a process quietly
 * disappearing.
 *
 * It is not an accusation: closing a hung game is the ordinary reason for it.
 * What pairs with it is the protected set the token carries -- publisher that
 * knows which of its processes should be in that set can see which one left.
 */
#define LOTA_FLAG_PROTECTED_TERMINATED (1 << 10)

/*
 * The kernel appraises the executables on this host: IMA is in a blocking
 * mode and the loaded policy has an appraise rule that reaches exec.
 *
 * Clear on a stock host. The agent binary is still bound by fs-verity
 * and PCR 14; this bit extends that to everything the host executes.
 */
#define LOTA_FLAG_KERNEL_APPRAISAL (1 << 11)

/*
 * An object of a protected process, its executable or a guarded library,
 * had no fs-verity digest and was measured by a kernel content hash: a read
 * of its bytes while nothing may write them, not a property the kernel enforces.
 * Typical of a store install; a publisher that wants fs-verity only refuses it.
 */
#define LOTA_FLAG_IMAGE_CONTENT_HASHED (1 << 12)

/*
 * The agent runs with --bench and writes what it and the protected set cost.
 * Its policy is the same as without it; a publisher that wants no measuring
 * agent on its hosts refuses it.
 */
#define LOTA_FLAG_BENCH (1 << 13)

/*
 * The policy the host applies, as its operator set it.
 *
 * LOTA_FLAG_ENFORCE says the host runs in enforce mode with the LSM loaded;
 * each other bit says one policy key is on and applies. In monitor mode every
 * one of them is clear. The agent and the protected processes are guarded
 * either way, so a clear bit takes nothing from the protection a title asked
 * for. Whether a title needs one of them is its publisher's call.
 */
#define LOTA_FLAG_ENFORCE (1 << 14)
/* a protected process maps no file outside the allowlist executable */
#define LOTA_FLAG_STRICT_MMAP (1 << 15)
/* an exec of a file outside the allowlist is refused */
#define LOTA_FLAG_STRICT_EXEC (1 << 16)
/* a module or firmware load outside the allowlist is refused */
#define LOTA_FLAG_STRICT_MODULES (1 << 17)
/* a protected process makes no anonymous mapping executable */
#define LOTA_FLAG_BLOCK_ANON_EXEC (1 << 18)
/* a ptrace attach on any task is refused */
#define LOTA_FLAG_BLOCK_PTRACE (1 << 19)

/*
 * The agent answering was not the first of this boot: an earlier one ended
 * without a shutdown, and was started again. PCR 14 still held the boot's
 * commitment, which the agent cannot forge or reset, so the restart is
 * certain while what led to it is not.
 *
 * Every record the earlier agent kept ended with it. A token that carries
 * this bit says nothing of what happened on the host before the restart,
 * PROTECTED_TERMINATED included. It stays set until the host reboots.
 */
#define LOTA_FLAG_AGENT_RESTARTED (1 << 20)

/*
 * The kernel left an event out of the agent's log: the agent did not keep up,
 * or something produced more events than the log takes. What the agent refuses
 * is still refused and the token's lists are kept apart from that log, so only
 * the lines are gone. It stays set until the agent ends, and it can arrive up
 * to a second after the loss, later on an agent short of CPU.
 */
#define LOTA_FLAG_EVENTS_LOST (1 << 6)

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
	uint64_t last_attest_time; /* Last attestation (Unix time), 0 if none */
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
 *   runtime_protect_digest || runtime_protect_epoch || stopped_ms),
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
	uint16_t runtime_protect_version; /* 1 = PID set + image digests */
	uint32_t protect_pid_count;
	uint32_t *protected_pids; /* heap-allocated canonical list */

	/* per-PID kernel-anchored runtime image digest,
	 * parallel to protected_pids */
	uint8_t (*protected_image_digests)[32];

	uint8_t *attest_data; /* TPMS_ATTEST blob (heap allocated) */
	size_t attest_size; /* Size of attest_data */
	uint8_t *signature; /* TPM signature (heap allocated) */
	size_t signature_len; /* Signature length in bytes */

	/* milliseconds any thread of the instance stood stopped, suspend aside */
	uint64_t stopped_ms;
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
	 * the agent then answers with its one profile and the host-wide verdict.
	 * A host that answers for several refuses a connection that names none.
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
 * and title has to tell them apart: LOTA_ERR_CONNECTION_FAILED is "no agent
 * here, or it hung up unanswered", LOTA_ERR_TIMEOUT is "it did not answer in
 * time", LOTA_ERR_UNKNOWN_PROFILE is "this machine has no enrollment with the
 * publisher you named", only ever the agent's own answer,
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
 * lota_set_request_timeout - Set the deadline for a request's answer
 * @client:     Client handle
 * @timeout_ms: Milliseconds a request may wait for its answer (> 0)
 *
 * The connect timeout bounds reaching the local socket. An answer can take
 * longer: a status call may first measure a large protected process.
 * With one shared deadline a busy agent is reported as a missing one.
 * Does not affect a request already in flight.
 *
 * Returns LOTA_OK, or LOTA_ERR_INVALID_ARG for no client or timeout_ms <= 0.
 */
int lota_set_request_timeout(struct lota_client *client, int timeout_ms);

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
 * Once registered, the agent's BPF strict_mmap, block_anon_exec and
 * ptrace_access_check hooks gate every access into or out of this
 * process against the trust set, and task_kill records every signal
 * at it. Every process it
 * creates from then on is protected with it, from its first instruction.
 *
 * Under strict_mmap a protected task maps only files with an allowed
 * fs-verity digest or a trusted_libs inode; lota-protect protects a
 * program from its first instruction.
 *
 * Returns LOTA_OK on success.
 *         LOTA_ERR_ACCESS_DENIED if the PID identity check fails, or a
 *                                tracer already holds the process.
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
 * Returns LOTA_ERR_NOT_ATTESTED if no valid attestation exists, and
 * LOTA_ERR_UNKNOWN_PROFILE when the connection named no publisher on a host
 * that answers for several (see lota_connect_opts.publisher_profile).
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
 * lota_get_boot_evidence - Fetch the evidence behind a token's boot PCRs
 * @client:  Client handle
 * @buf:     Output buffer; LOTA_BOOT_EVIDENCE_MAX_SIZE (lota_token.h) holds any
 * @buflen:  Size of @buf
 * @written: Output: number of bytes written (may be NULL)
 *
 * The values of the PCRs a token quotes and the PCR 7 events behind them,
 * in the wire format lota_token.h describes. Send it with a token to a
 * server that runs no verifier: lota_server_verify_boot_evidence() checks it
 * against the token and says whether the machine booted with Secure Boot on.
 * Fetch it next to the token it goes with: it matches a token only while
 * the quoted PCRs hold the same values.
 *
 * Returns LOTA_OK, LOTA_ERR_BUFFER_TOO_SMALL, LOTA_ERR_NO_TPM,
 * LOTA_ERR_RATE_LIMITED (it counts against the same per-user limit as
 * lota_get_token()), or another negative LOTA_ERR_*.
 */
int lota_get_boot_evidence(struct lota_client *client, uint8_t *buf,
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
 * event_mask is narrowed to the events the agent publishes to titles,
 * which are the three LOTA_EVENT_* above; LOTA_EVENT_ALL therefore
 * subscribes to all three and never fails for naming more.
 *
 * A subscription lasts as long as the connection.  It does not survive
 * a reconnect, so resubscribe after LOTA_ERR_NOT_CONNECTED.
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

/* Upper bounds of the strings in a registry object, terminator included */
#define LOTA_REGISTRY_SONAME_MAX 256
#define LOTA_REGISTRY_PATH_MAX 320

/* How a registry object's digest was taken */
#define LOTA_REGISTRY_ROAD_NONE 0 /* no digest */
#define LOTA_REGISTRY_ROAD_VERITY 1 /* fs-verity measurement */
#define LOTA_REGISTRY_ROAD_CONTENT 2 /* contents hashed while running */

/* image_digest is the token's entry for the process */
#define LOTA_REGISTRY_MEASURED (1U << 0)
/* an executable mapping went unrecorded; the list may miss an object */
#define LOTA_REGISTRY_HISTORY_LOST (1U << 1)
/* an actor went unrecorded; the list may miss a process that reached in */
#define LOTA_REGISTRY_ACTORS_LOST (1U << 2)
/*
 * The image was executed under protection, so the list starts at its exec.
 * Without it the list starts when protection did: an object loaded and dropped
 * earlier is not there, and a late start looks otherwise the same.
 */
#define LOTA_REGISTRY_FROM_EXEC (1U << 3)

/*
 * Mapped since protection began, gone from the address space when
 * measured: no path and no digest, the soname is the file's name.
 */
#define LOTA_REGISTRY_OBJECT_UNMAPPED (1U << 0)
/*
 * When a protected process mapped it executable, something else held it
 * open for write or mapped it shared writable, or it was a memfd or shm
 * segment with no write seal, which anyone holding an fd can write: the
 * code could change without the file being written again.
 */
#define LOTA_REGISTRY_OBJECT_WRITABLE (1U << 1)
/* backed by memory only (memfd, shm, tmpfs, hugetlbfs), no file on disk */
#define LOTA_REGISTRY_OBJECT_MEMORY (1U << 2)

/*
 * One code object a protected process mapped executable.
 * The token's image digest binds every field.
 */
struct lota_registry_object {
	uint64_t size;
	uint64_t dev;
	uint64_t ino;
	uint32_t road; /* LOTA_REGISTRY_ROAD_* */
	uint32_t flags; /* LOTA_REGISTRY_OBJECT_* */
	uint32_t digest_len; /* 0, 32 or 64 */
	uint8_t digest[64];
	char soname[LOTA_REGISTRY_SONAME_MAX];
	char path[LOTA_REGISTRY_PATH_MAX];
};

/* How an actor reached the instance: from outside, through a unix socket */
#define LOTA_REGISTRY_ACTOR_CONNECT 1 /* connected to a stream socket */
#define LOTA_REGISTRY_ACTOR_SEND 2 /* sent a datagram */
/* from inside, one process of the instance to another */
#define LOTA_REGISTRY_ACTOR_PTRACE_READ 3 /* read-mode ptrace access */
#define LOTA_REGISTRY_ACTOR_PTRACE_ATTACH 4 /* ptrace, process_vm_*, mem */
#define LOTA_REGISTRY_ACTOR_SIGNAL 5 /* sent a signal */
/* a process of the instance to itself: owner_tgid is tgid */
#define LOTA_REGISTRY_ACTOR_ANON_EXEC 6 /* made anonymous memory executable */

/*
 * One process that reached a process of the instance of a protected
 * process: from outside, through a unix socket a process of the instance
 * owns, or from inside, by a ptrace access or a signal. Or one process of
 * the instance that made its own anonymous memory executable.
 * The token's image digest binds every field.
 */
struct lota_registry_actor {
	uint64_t count; /* times it did so */
	uint64_t start_ticks; /* the actor's start time, in clock ticks */
	uint64_t exe_dev; /* device of the actor's executable */
	uint64_t exe_ino; /* inode of the actor's executable */
	uint32_t tgid;
	uint32_t uid;
	uint32_t owner_tgid; /* the instance process it reached */
	uint32_t kind; /* LOTA_REGISTRY_ACTOR_* */
	char comm[16];
	char owner_comm[16];
};

/*
 * The code objects the last token round found mapped in one process and
 * the processes that acted on it.
 */
struct lota_registry {
	uint64_t round; /* measurement round the list comes from */
	uint32_t pid;
	uint32_t flags; /* LOTA_REGISTRY_* */
	uint8_t image_digest[32];
	uint32_t count;
	struct lota_registry_object *objects;
	uint32_t actor_count;
	struct lota_registry_actor *actors;
};

/*
 * lota_get_registry - Fetch what the last token round found mapped in @pid
 * @client: Connected client
 * @pid:    A protected process the caller owns, or any one for root
 * @out:    Receives a registry to release with lota_registry_free()
 *
 * Every object is listed, those the agent could not measure included.
 * The token binds the list: with LOTA_REGISTRY_MEASURED set, image_digest
 * is the token's protected_image_digests entry for @pid, and
 * lota_server_registry_digest() over the objects and actors reproduces it.
 * A relying party checks both before trusting the list.
 *
 * Returns: LOTA_OK, LOTA_ERR_NOT_PROTECTED for a process the last round
 *          did not measure, LOTA_ERR_ACCESS_DENIED for somebody else's,
 *          or another negative LOTA_ERR_*.
 */
int lota_get_registry(struct lota_client *client, uint32_t pid,
		      struct lota_registry **out);

/* Release a registry from lota_get_registry(); NULL is a no-op. */
void lota_registry_free(struct lota_registry *reg);

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
