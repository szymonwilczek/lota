/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * LOTA Gaming SDK: client library for games to query local attestation status.
 * Link with -llotagaming.
 */

#ifndef LOTA_GAMING_H
#define LOTA_GAMING_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

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
	/*
	 * no profile for the named publisher, or none named on a host that
	 * answers for several
	 */
	LOTA_ERR_UNKNOWN_PROFILE = -12,
	/*
	 * Nobody on this machine agreed to answer to that publisher.
	 * The player decides: show what the publisher would learn, then connect
	 * again.
	 */
	LOTA_ERR_CONSENT_REQUIRED = -13,
	/*
	 * This process's own executable has no measurable identity, so no token
	 * is issued. The agent's log names the object and why. Another
	 * protected process without one clears LOTA_FLAG_IMAGE_FULLY_MEASURED.
	 */
	LOTA_ERR_UNMEASURABLE_SELF = -14,
	/* The agent holds no TPM to sign a token with; no retry helps. */
	LOTA_ERR_NO_TPM = -15,
	/*
	 * The agent applied no policy and loaded no LSM object, so a call that
	 * changes runtime enforcement is refused; no retry helps.
	 */
	LOTA_ERR_NO_ENFORCEMENT = -16,
	/*
	 * The publisher is known and consented to, but the agent's
	 * attestation-key handle range is full. No retry helps: somebody at the
	 * machine must forget a publisher or reclaim a handle.
	 */
	LOTA_ERR_NO_KEY_SLOT = -17,
	/*
	 * The TPM refused with dictionary-attack lockout, which holds until it
	 * lapses or is cleared.
	 */
	LOTA_ERR_TPM_LOCKED = -18,
	/*
	 * The process was not measured by the last token round: nobody
	 * protected it, or it exited before the round reached it.
	 */
	LOTA_ERR_NOT_PROTECTED = -19,
};

#define LOTA_FLAG_ATTESTED (1 << 0)
#define LOTA_FLAG_TPM_OK (1 << 1)
#define LOTA_FLAG_IOMMU_OK (1 << 2)
#define LOTA_FLAG_BPF_LOADED (1 << 3)
#define LOTA_FLAG_SECURE_BOOT (1 << 4)

/*
 * A package update replaced the agent binary and takes effect on the next boot.
 * Attestation keeps succeeding: PCR 14 commits to the running build until that
 * boot resets it.
 */
#define LOTA_FLAG_UPDATE_PENDING (1 << 7)

/*
 * The publisher this connection named runs no verifier or, with none named, no
 * publisher of this host does, so LOTA_FLAG_ATTESTED carries no verdict and
 * stays clear. A title fetches a token with lota_get_token() and its backend
 * checks it with lota_server_verify_token().
 */
#define LOTA_FLAG_TOKEN_ONLY (1 << 8)

/*
 * Every file-backed executable mapping of every protected process was measured.
 * Clear when an object could not be measured or nothing is protected.
 * A policy input for the publisher, not a verdict.
 */
#define LOTA_FLAG_IMAGE_FULLY_MEASURED (1 << 9)

/*
 * A protected process was ended through this agent, for its owner or root. An
 * ordinary signal reaches it as well; this route leaves a record. With the
 * protected set the token carries, a publisher can see which process left. Set
 * until the agent ends; a restart shows as LOTA_FLAG_AGENT_RESTARTED.
 */
#define LOTA_FLAG_PROTECTED_TERMINATED (1 << 10)

/*
 * IMA is in a blocking mode and the loaded policy has an appraise rule on
 * BPRM_CHECK or with no func=.
 */
#define LOTA_FLAG_KERNEL_APPRAISAL (1 << 11)

/*
 * An object of a protected process, its executable or a write-guarded library,
 * had no fs-verity digest and was measured by a kernel content hash: a read of
 * its bytes while nothing may write them, not a property the kernel enforces.
 */
#define LOTA_FLAG_IMAGE_CONTENT_HASHED (1 << 12)

/*
 * The agent runs with --bench and writes what it and the protected set cost.
 * Its policy is the same.
 */
#define LOTA_FLAG_BENCH (1 << 13)

/*
 * The policy the host applies. LOTA_FLAG_ENFORCE is enforce mode with the LSM
 * loaded; each other bit is one policy key that is on and applies. All are
 * clear in monitor mode. The agent and the protected processes stay guarded
 * with all of them clear.
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
 * An earlier agent of this boot ended without a shutdown: PCR 14 still held the
 * boot's commitment. A token with this bit says nothing of what happened before
 * the restart, PROTECTED_TERMINATED included. Set until the host reboots.
 */
#define LOTA_FLAG_AGENT_RESTARTED (1 << 20)

/*
 * The kernel left an event out of the agent's log: the agent did not keep up,
 * or something produced more events than the log takes. Refusals still hold and
 * the token's lists are kept apart from that log. Set until the agent ends; it
 * can arrive a second after the loss, later on an agent short of CPU.
 */
#define LOTA_FLAG_EVENTS_LOST (1 << 6)

/* Event bits of lota_subscribe() */
#define LOTA_EVENT_STATUS (1U << 0) /* Status flags changed */
#define LOTA_EVENT_ATTEST (1U << 1) /* Attestation completed (pass/fail) */
#define LOTA_EVENT_MODE (1U << 2) /* Enforcement mode changed */
#define LOTA_EVENT_ALL 0xFFFFFFFFU

/* Opaque client handle */
struct lota_client;

/* Status information */
struct lota_status {
	uint32_t flags; /* LOTA_FLAG_* bitmask */
	uint64_t last_attest_time; /* Last attestation (Unix time), 0 if none */
	uint64_t valid_until; /* Unix time the verdict lapses, 0 if none */
	uint32_t attest_count; /* Total successful attestations */
	uint32_t fail_count; /* Total failed attestations */
};

/*
 * Attestation token: a TPM Quote-based attestation statement.
 *
 * lota_server_verify_token() in lota_server.h checks the signature, the binding
 * of every field by extraData, the nonce and the expiry. A relying party calls
 * it and does not reimplement the binding.
 */
struct lota_token {
	uint64_t valid_until; /* Token expiration (Unix timestamp) */
	uint32_t flags; /* Status flags at issue time */
	uint8_t nonce[32]; /* Client nonce (if provided) */

	/* TPM Quote data */
	uint16_t sig_alg; /* Signature algorithm (TPM2_ALG_RSASSA/RSAPSS) */
	uint16_t hash_alg; /* Hash algorithm (TPM2_ALG_SHA256) */
	uint32_t pcr_mask; /* PCRs included in quote */

	/* SHA-256 over startup enforcement policy, allowlist included */
	uint8_t policy_digest[32];

	/* SHA-256 over the protected PIDs and their registry digests */
	uint8_t runtime_protect_digest[32];
	uint64_t runtime_protect_epoch; /* Monotonic PID-set mutation id */
	uint16_t runtime_protect_version; /* 1 = PID set + registry digests */
	uint32_t protect_pid_count;
	uint32_t *protected_pids; /* heap-allocated canonical list */

	/* per-PID registry digest, parallel to protected_pids */
	uint8_t (*protected_registry_digests)[32];

	uint8_t *attest_data; /* TPMS_ATTEST blob (heap allocated) */
	size_t attest_size; /* Size of attest_data */
	uint8_t *signature; /* TPM signature (heap allocated) */
	size_t signature_len; /* Signature length in bytes */

	/* ms any thread of the instance stood stopped, suspend aside */
	uint64_t stopped_ms;
};

/*
 * Connection options
 *
 * @struct_size lets the structure grow: the library ignores members it does not
 * know. Zero is refused: the caller zeroed the structure and never set the
 * field, and guessing a size would read members the caller never wrote.
 */
struct lota_connect_opts {
	size_t struct_size; /* sizeof(struct lota_connect_opts) */
	const char *socket_path; /* Custom socket path (NULL = default) */
	int timeout_ms; /* Connection timeout in ms (0 = default 5000) */

	/*
	 * Hex SHA-256 of the publisher's attestation-CA trust anchor
	 * SubjectPublicKeyInfo. Selects the AIK that signs this connection's
	 * tokens and the verdict lota_is_attested() reports.
	 *
	 * With NULL, a single-publisher host answers with its one profile and
	 * the host-wide verdict; a host that answers for several refuses a
	 * token. The connection fails when the agent cannot answer for the
	 * publisher named: falling back would hand the title another
	 * publisher's evidence.
	 */
	const char *publisher_profile;
};

/* hex SHA-256, without a terminator */
#define LOTA_PUBLISHER_PROFILE_LEN 64

/* Smallest struct_size the library accepts */
#define LOTA_CONNECT_OPTS_SIZE_MIN                               \
	(offsetof(struct lota_connect_opts, publisher_profile) + \
	 sizeof(const char *))

/**
 * lota_connect() - Connect to the local LOTA agent.
 *
 * Return: a handle to release with lota_disconnect(), NULL on failure
 * (lota_connect_last_error() says why).
 */
struct lota_client *lota_connect(void);

/**
 * lota_connect_opts() - lota_connect() with custom options.
 * @opts: socket path, timeout and publisher; NULL for the defaults.
 *
 * Return: as for lota_connect().
 */
struct lota_client *lota_connect_opts(const struct lota_connect_opts *opts);

/**
 * lota_connect_last_error() - Why the last connect on this thread failed.
 *
 * Set by every connect attempt on the calling thread, LOTA_OK included.
 * Meaningless after anything else.
 *
 * Return: LOTA_OK if it connected, LOTA_ERR_INVALID_ARG for bad options or
 * publisher or a refusal not named here, LOTA_ERR_NO_MEMORY,
 * LOTA_ERR_CONNECTION_FAILED for no agent or one that hung up unanswered,
 * LOTA_ERR_TIMEOUT for no answer in time, LOTA_ERR_PROTOCOL for a malformed
 * answer, LOTA_ERR_UNKNOWN_PROFILE for a publisher this machine has no profile
 * for, LOTA_ERR_CONSENT_REQUIRED for one nobody here agreed to answer to,
 * LOTA_ERR_NO_KEY_SLOT for no attestation-key slot left.
 */
int lota_connect_last_error(void);

/**
 * lota_disconnect() - Close the connection and free the handle.
 * @client: may be NULL.
 */
void lota_disconnect(struct lota_client *client);

/**
 * lota_get_fd() - Get the underlying socket file descriptor.
 * @client: connection from lota_connect().
 *
 * Return: the descriptor, -1 without a client.
 */
int lota_get_fd(struct lota_client *client);

/**
 * lota_set_request_timeout() - Set the deadline for a request's answer.
 * @client: connection from lota_connect().
 * @timeout_ms: milliseconds a request may wait for its answer, above 0.
 *
 * The connect timeout bounds reaching the local socket. An answer can take
 * longer: a status call may first measure a large protected process, and one
 * shared deadline reports a busy agent as a missing one.
 * Does not affect a request already in flight.
 *
 * Return: LOTA_OK, LOTA_ERR_INVALID_ARG for no client or timeout_ms <= 0.
 */
int lota_set_request_timeout(struct lota_client *client, int timeout_ms);

/**
 * lota_ping() - Check that the agent is responsive.
 * @client: connection from lota_connect().
 * @uptime_sec: receives the agent's uptime; may be NULL.
 *
 * Return: LOTA_OK, or a negative LOTA_ERR_*.
 */
int lota_ping(struct lota_client *client, uint64_t *uptime_sec);

/**
 * lota_protect_self() - Register the calling process as protected.
 * @client: connection from lota_connect().
 *
 * The agent checks that the connection's SO_PEERCRED PID is the target and that
 * its start time still matches, so a recycled PID cannot use a prior
 * registration. No trusted executable is needed: opting in to stricter
 * enforcement is not a privilege escalation. A second call from the same task
 * leaves the runtime PID set alone and, unless rate limited, returns LOTA_OK.
 *
 * The LSM hooks guard the process and what it creates from then on, from its
 * first instruction. As the event budget and ring buffer allow, task_kill
 * records a signal at it unless it comes from the process itself, the agent, a
 * BPF admin or the kernel, or is a permitted probe.
 * Under strict_mmap a protected task maps only files with an allowed fs-verity
 * digest or a trusted_libs inode.
 *
 * Return: LOTA_OK, LOTA_ERR_ACCESS_DENIED if the PID identity check fails or a
 * tracer already holds the process, LOTA_ERR_RATE_LIMITED if the caller's UID
 * exceeded the rate window, or another negative LOTA_ERR_*.
 */
int lota_protect_self(struct lota_client *client);

/**
 * lota_get_status() - Get the current attestation status.
 * @client: connection from lota_connect().
 * @status: receives the status.
 *
 * Return: LOTA_OK, or a negative LOTA_ERR_*.
 */
int lota_get_status(struct lota_client *client, struct lota_status *status);

/**
 * lota_is_attested() - Check LOTA_FLAG_ATTESTED through lota_get_status().
 * @client: connection from lota_connect().
 *
 * Return: 1 if attested, 0 otherwise or on error.
 */
int lota_is_attested(struct lota_client *client);

/**
 * lota_get_token() - Get an attestation token for server verification.
 * @client: connection from lota_connect().
 * @nonce: 32-byte challenge from the server; what stops the server accepting a
 *         replayed token. NULL for none.
 * @token: receives the token; release it with lota_token_free().
 *
 * Return: LOTA_OK, LOTA_ERR_NOT_ATTESTED if no valid attestation exists,
 * LOTA_ERR_UNKNOWN_PROFILE if the connection named no publisher on a host that
 * answers for several, or another negative LOTA_ERR_*.
 */
int lota_get_token(struct lota_client *client, const uint8_t *nonce,
		   struct lota_token *token);

/**
 * lota_token_free() - Free the buffers lota_get_token() allocated.
 * @token: may be NULL, zeroed or already freed.
 */
void lota_token_free(struct lota_token *token);

/**
 * lota_token_serialized_size() - Calculate the serialized size of a token.
 * @token: token from lota_get_token().
 *
 * Return: bytes needed, 0 if the token is invalid.
 */
size_t lota_token_serialized_size(const struct lota_token *token);

/**
 * lota_token_serialize() - Serialize a token to its wire format.
 * @token: token from lota_get_token().
 * @buf: receives the wire bytes.
 * @buflen: size of @buf.
 * @written: receives the bytes written; may be NULL.
 *
 * The server verifies the result with lota_server_verify_token().
 *
 * Return: LOTA_OK, LOTA_ERR_BUFFER_TOO_SMALL if @buf is too small,
 * LOTA_ERR_INVALID_ARG for an invalid token.
 */
int lota_token_serialize(const struct lota_token *token, uint8_t *buf,
			 size_t buflen, size_t *written);

/**
 * lota_get_boot_evidence() - Fetch the evidence behind a token's boot PCRs.
 * @client: connection from lota_connect().
 * @buf: LOTA_BOOT_EVIDENCE_MAX_SIZE (lota_token.h) holds any.
 * @buflen: size of @buf.
 * @written: receives the bytes written; may be NULL.
 *
 * The values of the PCRs a token quotes and the PCR 7 events behind them, in
 * the wire format of lota_token.h, for a server that runs no verifier:
 * lota_server_verify_boot_evidence() checks them against the token. Fetch it
 * next to its token: it matches only while the quoted PCRs hold the same
 * values.
 *
 * Return: LOTA_OK, LOTA_ERR_BUFFER_TOO_SMALL, LOTA_ERR_NO_TPM,
 * LOTA_ERR_RATE_LIMITED (the per-user limit of lota_get_token()), or another
 * negative LOTA_ERR_*.
 */
int lota_get_boot_evidence(struct lota_client *client, uint8_t *buf,
			   size_t buflen, size_t *written);

/**
 * lota_get_refusal() - The last file the gate refused this process to map.
 * @client: connection from lota_connect().
 * @object: receives the file's path as this process sees it, or only its
 *          name for a memory file (memfd, shared memory, /dev/zero) or when
 *          the gate could not give the path; "" when there was none.
 * @len: size of @object; 256 holds any.
 * @at_ns: receives the CLOCK_MONOTONIC time of the refusal, 0 when there was
 *         none; may be NULL.
 *
 * The agent keeps the last refusal of a process that was protected when the
 * gate refused it, a dependency the loader pulled in as much as the object
 * the process asked for, and answers it only to that process. A process
 * given its PID in the refusal's clock tick, or across a suspend before the
 * agent read the refusal, is taken for it. A refusal the gate left out of
 * its events is not kept.
 *
 * Return: LOTA_OK, LOTA_ERR_BUFFER_TOO_SMALL when @object cannot hold the
 * name, or another negative LOTA_ERR_*.
 */
int lota_get_refusal(struct lota_client *client, char *object, size_t len,
		     uint64_t *at_ns);

/**
 * typedef lota_status_callback_fn - Status change callback.
 * @status: current status snapshot.
 * @events: LOTA_EVENT_* that changed.
 * @user_data: pointer given to lota_subscribe().
 */
typedef void (*lota_status_callback_fn)(const struct lota_status *status,
					uint32_t events, void *user_data);

/**
 * lota_subscribe() - Subscribe to status change notifications.
 * @client: connection from lota_connect().
 * @event_mask: LOTA_EVENT_* bitmask.
 * @callback: receives each notification.
 * @user_data: passed to @callback.
 *
 * @callback runs from lota_poll_events() and from other SDK calls that read a
 * notification. @event_mask is narrowed to the events the agent publishes to
 * titles, so LOTA_EVENT_ALL subscribes to the three above.
 *
 * A subscription lasts as long as the connection: resubscribe after
 * LOTA_ERR_NOT_CONNECTED.
 *
 * Return: LOTA_OK, or a negative LOTA_ERR_*.
 */
int lota_subscribe(struct lota_client *client, uint32_t event_mask,
		   lota_status_callback_fn callback, void *user_data);

/**
 * lota_unsubscribe() - Stop notifications on this connection.
 * @client: connection from lota_connect().
 *
 * Return: LOTA_OK, or a negative LOTA_ERR_*.
 */
int lota_unsubscribe(struct lota_client *client);

/**
 * lota_poll_events() - Dispatch pending notifications to the callback.
 * @client: connection from lota_connect().
 * @timeout_ms: maximum wait; 0 does not block, -1 blocks indefinitely.
 *
 * Return: notifications dispatched, or a negative LOTA_ERR_*.
 */
int lota_poll_events(struct lota_client *client, int timeout_ms);

/* Upper bounds of the strings in a registry object, terminator included */
#define LOTA_REGISTRY_SONAME_MAX 256
#define LOTA_REGISTRY_PATH_MAX 320

/* How a registry object's digest was taken */
#define LOTA_REGISTRY_ROAD_NONE 0 /* no digest */
#define LOTA_REGISTRY_ROAD_VERITY 1 /* fs-verity measurement */
#define LOTA_REGISTRY_ROAD_CONTENT 2 /* contents hashed while running */

/* registry_digest is the token's entry for the process */
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
 * The process had more executable mappings than one measurement holds: those
 * past the limit are unmeasured, and an object listed as unmapped may be one.
 */
#define LOTA_REGISTRY_TRUNCATED (1U << 4)

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
 * The token's registry digest binds every field.
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
#define LOTA_REGISTRY_ACTOR_CONNECT 1 /* stream or seqpacket connect */
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
 * The token's registry digest binds every field.
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
	uint8_t registry_digest[32];
	uint32_t count;
	struct lota_registry_object *objects;
	uint32_t actor_count;
	struct lota_registry_actor *actors;
};

/**
 * lota_get_registry() - Fetch what the last token round found in a process.
 * @client: connection from lota_connect().
 * @pid: a protected process the caller owns, any one for root.
 * @out: receives a registry to release with lota_registry_free().
 *
 * Objects the agent could not measure are listed too. The LOTA_REGISTRY_* flags
 * say what the list may miss.
 * The token binds the list: with LOTA_REGISTRY_MEASURED set, registry_digest is
 * the token's protected_registry_digests entry for @pid, and
 * lota_server_registry_digest() over the objects and actors reproduces it.
 * A relying party checks both before trusting the list.
 *
 * Return: LOTA_OK, LOTA_ERR_NOT_PROTECTED for a process the last round did not
 * measure, LOTA_ERR_ACCESS_DENIED for somebody else's, or another negative
 * LOTA_ERR_*.
 */
int lota_get_registry(struct lota_client *client, uint32_t pid,
		      struct lota_registry **out);

/**
 * lota_registry_free() - Release a registry from lota_get_registry().
 * @reg: may be NULL.
 */
void lota_registry_free(struct lota_registry *reg);

/**
 * lota_strerror() - Describe a LOTA_ERR_* code.
 * @error: LOTA_ERR_* code.
 *
 * Return: a static string.
 */
const char *lota_strerror(int error);

/**
 * lota_sdk_version() - Name the LOTA release this library was compiled from.
 *
 * The same one lota_server_sdk_version() reports. Treat it as opaque: match it,
 * do not parse it. Binary compatibility is the soname and the ABI version of
 * the pkg-config module.
 *
 * Runs inside the calling process, which on a player's machine is memory an
 * attacker controls, so a relying party must never decide trust from it.
 *
 * Return: a static string.
 */
const char *lota_sdk_version(void);

/**
 * lota_flags_to_string() - Write flags as "ATTESTED,TPM_OK,BPF_LOADED".
 * @flags: LOTA_FLAG_* bitmask.
 * @buf: receives the string.
 * @buflen: size of @buf.
 *
 * Return: bytes written without the terminator, or a negative LOTA_ERR_*.
 */
int lota_flags_to_string(uint32_t flags, char *buf, size_t buflen);

#ifdef __cplusplus
}
#endif

#endif /* LOTA_GAMING_H */
