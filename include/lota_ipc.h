/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * LOTA IPC protocol: the wire between the agent and its SDK.
 *
 * Not installed and without a compatibility promise: a direct caller is pinned
 * to the agent build it was compiled against. Integrators use lota_gaming.h.
 */

#ifndef LOTA_IPC_H
#define LOTA_IPC_H

#include <stdint.h>

#define LOTA_IPC_SOCKET_PATH "/run/lota/lota.sock"

#define LOTA_IPC_MAGIC 0x4C4F5441 /* "LOTA" */
/*
 * The agent refuses any other version: it ships together with the SDK, so
 * there is nothing to negotiate.
 */
#define LOTA_IPC_VERSION 1
/*
 * Per-frame payload cap of the agent's socket parser: bounds per-connection
 * buffers and holds a maximum token, as ipc.c asserts.
 */
#define LOTA_IPC_MAX_PAYLOAD 8192

enum lota_ipc_cmd {
	LOTA_IPC_CMD_PING = 0x01, /* Whether agent is alive */
	LOTA_IPC_CMD_GET_STATUS = 0x02, /* Attestation status */
	LOTA_IPC_CMD_GET_TOKEN = 0x03, /* Signed attestation token */
	LOTA_IPC_CMD_SUBSCRIBE = 0x04, /* Subscribe to status changes */
	LOTA_IPC_CMD_PROTECT_PID =
		0x05, /* Add a protected PID (own PID, or privileged actor) */
	LOTA_IPC_CMD_UNPROTECT_PID =
		0x06, /* Remove a protected PID (privileged actor) */
	LOTA_IPC_CMD_SHUTDOWN = 0x07, /* Stop the agent (privileged actor) */
	LOTA_IPC_CMD_SET_PROFILE =
		0x08, /* Bind this connection to one publisher profile */
	LOTA_IPC_CMD_SYNC_ATTEST =
		0x09, /* Exchange state with the attestation loop */
	LOTA_IPC_CMD_TERMINATE_PROTECTED =
		0x0A, /* End a protected process on behalf of its owner */
	LOTA_IPC_CMD_GET_REGISTRY =
		0x0B, /* Code objects the last measurement found in a process */
	LOTA_IPC_CMD_GET_BOOT_EVIDENCE =
		0x0C, /* Quoted PCR values and PCR 7 events (lota_token.h) */
};

/*
 * Publishers one host answers to. Mirrors LOTA_CONFIG_MAX_PROFILES of the
 * agent's configuration parser, which the SDK does not see; ipc.c asserts they
 * match.
 */
#define LOTA_IPC_MAX_PROFILES 8

enum lota_ipc_result {
	LOTA_IPC_OK = 0x00,
	LOTA_IPC_ERR_UNKNOWN_CMD = 0x01,
	LOTA_IPC_ERR_BAD_REQUEST = 0x02,
	LOTA_IPC_ERR_NOT_ATTESTED = 0x03,
	LOTA_IPC_ERR_TPM_FAILURE = 0x04,
	LOTA_IPC_ERR_INTERNAL = 0x05,
	LOTA_IPC_ERR_RATE_LIMITED = 0x06,
	LOTA_IPC_ERR_ACCESS_DENIED = 0x07,
	LOTA_IPC_ERR_BAD_VERSION = 0x08,
	LOTA_IPC_ERR_TPM_LOCKOUT = 0x09,
	LOTA_IPC_ERR_TOO_MANY_PROTECTED_PIDS = 0x0A,
	/*
	 * no profile for the named publisher, or none named on a host that
	 * answers for several
	 */
	LOTA_IPC_ERR_UNKNOWN_PROFILE = 0x0B,
	/* nobody on this machine agreed to answer to that publisher */
	LOTA_IPC_ERR_CONSENT_REQUIRED = 0x0C,
	/* that process is not protected */
	LOTA_IPC_ERR_NOT_PROTECTED = 0x0D,
	/* PID 0, PID 1 or the agent */
	LOTA_IPC_ERR_TARGET_REFUSED = 0x0E,
	/*
	 * the caller's own executable has no measurable identity; another
	 * protected process without one clears LOTA_STATUS_IMAGE_FULLY_MEASURED
	 */
	LOTA_IPC_ERR_UNMEASURABLE_SELF = 0x0F,
	/* this agent holds no TPM to sign a token with */
	LOTA_IPC_ERR_NO_TPM = 0x10,
	/* this agent enforces nothing */
	LOTA_IPC_ERR_NO_ENFORCEMENT = 0x11,
	/* known, consented publisher, but the AIK handle range is full */
	LOTA_IPC_ERR_NO_KEY_SLOT = 0x12,
	LOTA_IPC_NOTIFY = 0x80,
};

#define LOTA_STATUS_ATTESTED (1 << 0) /* Successfully attested */
#define LOTA_STATUS_TPM_OK (1 << 1) /* TPM initialized */
#define LOTA_STATUS_IOMMU_OK (1 << 2) /* IOMMU verified */
#define LOTA_STATUS_BPF_LOADED (1 << 3) /* BPF LSM active */
#define LOTA_STATUS_SECURE_BOOT (1 << 4) /* Secure Boot enabled */
#define LOTA_STATUS_TPM_LOCKOUT (1 << 5) /* TPM signaled DA lockout */
/*
 * The kernel left out an event: ring full, yielded under pressure or a refusal
 * past its budget. The event log is incomplete, enforcement is not affected.
 * Set until the agent ends.
 */
#define LOTA_STATUS_EVENTS_LOST (1 << 6)
/*
 * The agent binary on disk differs from the running one: an update takes
 * effect on the next boot, and attestation is unaffected until then.
 */
#define LOTA_STATUS_UPDATE_PENDING (1 << 7)
/*
 * The publisher this connection named runs no verifier or, with none named,
 * no publisher of this host does. ATTESTED carries no verdict and the token is
 * the evidence, issued without one under a validity the agent bounds itself.
 */
#define LOTA_STATUS_TOKEN_ONLY (1 << 8)
/*
 * Every file-backed executable mapping of every protected process was measured.
 * Clear when an object could not be measured or nothing is protected.
 */
#define LOTA_STATUS_IMAGE_FULLY_MEASURED (1 << 9)
/*
 * An object, executable or write-guarded library, was measured by a kernel
 * content hash, not an fs-verity digest.
 */
#define LOTA_STATUS_IMAGE_CONTENT_HASHED (1 << 12)
/*
 * IMA is in a blocking mode and the loaded policy has an appraise rule on
 * BPRM_CHECK or with no func=.
 */
#define LOTA_STATUS_KERNEL_APPRAISAL (1 << 11)
/* The agent runs with --bench: it writes what it costs, same policy */
#define LOTA_STATUS_BENCH (1 << 13)

/*
 * The policy the daemon applies. Set only while the LSM is loaded and the mode
 * is enforce, so a key the mode leaves inert reads as off. The agent and the
 * protected processes stay guarded with all of these clear.
 */
#define LOTA_STATUS_ENFORCE (1 << 14) /* mode = enforce */
#define LOTA_STATUS_STRICT_MMAP (1 << 15) /* strict_mmap applies */
#define LOTA_STATUS_STRICT_EXEC (1 << 16) /* strict_exec applies */
#define LOTA_STATUS_STRICT_MODULES (1 << 17) /* strict_modules applies */
#define LOTA_STATUS_BLOCK_ANON_EXEC (1 << 18) /* block_anon_exec applies */
#define LOTA_STATUS_BLOCK_PTRACE (1 << 19) /* block_ptrace applies */

/*
 * This agent found PCR 14 already holding the boot's commitment: an earlier one
 * ended in this boot without a shutdown, and what it recorded,
 * PROTECTED_TERMINATED included, ended with it. Set until the next boot.
 */
#define LOTA_STATUS_AGENT_RESTARTED (1 << 20)
/*
 * This agent ended a protected process for its owner or root. Set until the
 * agent ends, in the status word and the token alike, so a session ended
 * locally can be told from a process that vanished. A restart shows as
 * AGENT_RESTARTED.
 */
#define LOTA_STATUS_PROTECTED_TERMINATED (1 << 10)

/* Request header; the payload follows it. */
struct lota_ipc_request {
	uint32_t magic; /* LOTA_IPC_MAGIC */
	uint32_t version; /* LOTA_IPC_VERSION */
	uint32_t cmd; /* enum lota_ipc_cmd */
	uint32_t payload_len;
} __attribute__((packed));

#define LOTA_IPC_REQUEST_SIZE sizeof(struct lota_ipc_request)

/* Response header; the payload follows it. */
struct lota_ipc_response {
	uint32_t magic; /* LOTA_IPC_MAGIC */
	uint32_t version; /* LOTA_IPC_VERSION */
	uint32_t result; /* enum lota_ipc_result */
	uint32_t payload_len;
} __attribute__((packed));

#define LOTA_IPC_RESPONSE_SIZE sizeof(struct lota_ipc_response)

/* PING response payload */
struct lota_ipc_ping_response {
	uint64_t uptime_sec; /* Agent uptime in seconds */
	uint32_t pid; /* Agent PID */
} __attribute__((packed));

/* GET_STATUS response payload */
struct lota_ipc_status {
	uint32_t flags; /* LOTA_STATUS_* bitmask */
	uint32_t _reserved1;
	uint64_t last_attest_time; /* Last attestation (Unix time), 0 if none */
	uint64_t valid_until; /* Unix time the verdict lapses, 0 if none */
	uint32_t attest_count; /* Total successful attestations */
	uint32_t fail_count; /* Total failed attestations */
	uint8_t mode; /* Current mode (enum lota_mode) */
	uint8_t reserved[3];
} __attribute__((packed));

/*
 * SET_PROFILE request payload
 *
 * Binds the connection to one publisher, named by the SHA-256 of their CA trust
 * anchor SubjectPublicKeyInfo, the identity their enrollment is stored under.
 * An endpoint cannot name one: it is mutable and two publishers can share a
 * hostname.
 *
 * Later answers on the connection are that publisher's: GET_TOKEN quotes with
 * their AIK and GET_STATUS reports their verifier's verdict. A connection that
 * never sends this gets the host-wide answers.
 */
struct lota_ipc_set_profile {
	uint8_t profile_id[32];
} __attribute__((packed));

/* GET_TOKEN request payload (optional) */
struct lota_ipc_token_request {
	uint8_t nonce[32]; /* Client-provided nonce (optional, zeros = none) */
} __attribute__((packed));

/*
 * GET_TOKEN response payload: a signed attestation statement using TPM Quote.
 *
 * Verification:
 * - Recompute runtime_protect_digest from protected_pids[] and
 *   protected_registry_digests[] (lota_runtime_protect_digest.h)
 * - Compute the expected nonce with lota_compute_token_quote_nonce()
 * - Verify the TPM signature over attest_data with the AIK public key
 * - Parse attest_data and check that extraData is the expected nonce
 * - Check the PCR digest in attest_data against the expected policy
 */
struct lota_ipc_token {
	uint64_t valid_until; /* Unix timestamp */
	uint32_t flags; /* LOTA_STATUS_* at issue time */
	uint8_t client_nonce[32]; /* Echo of client nonce */

	/* TPM Quote data */
	uint16_t attest_size; /* Size of TPMS_ATTEST blob */
	uint16_t sig_size; /* Size of signature */
	uint16_t sig_alg; /* TPM2_ALG_RSASSA or TPM2_ALG_RSAPSS */
	uint16_t hash_alg; /* TPM2_ALG_SHA256 */
	uint32_t pcr_mask; /* PCRs included in quote */
	uint8_t policy_digest[32]; /* SHA-256 over enforcement startup policy */
	uint8_t runtime_protect_digest[32]; /* SHA-256 over runtime set */
	uint32_t protect_pid_count; /* Number of protected PIDs in payload */
	uint64_t runtime_protect_epoch; /* Monotonic PID-set mutation id */
	uint16_t pid_list_size; /* Bytes for protected_pids[] */
	uint16_t runtime_protect_version; /* 1 = PID set + registry digests */
	uint64_t stopped_ms; /* Time the caller's instance stood stopped */

	/*
	 * Variable-length data follows:
	 *   - protected_pids[protect_pid_count] (little-endian uint32)
	 *   - protected_registry_digests[protect_pid_count][32]
	 *   - attest_data[attest_size]  (TPMS_ATTEST)
	 *   - signature[sig_size]       (RSA signature)
	 */
} __attribute__((packed));

#define LOTA_IPC_TOKEN_HEADER_SIZE sizeof(struct lota_ipc_token)
#define LOTA_IPC_TOKEN_MAX_ATTEST 1024
#define LOTA_IPC_TOKEN_MAX_SIG 512
#define LOTA_IPC_TOKEN_REGISTRY_DIGEST_SIZE 32
/* Bytes one protected PID adds to a token: its value and its registry digest */
#define LOTA_IPC_TOKEN_PROTECT_ENTRY_SIZE \
	(4 + LOTA_IPC_TOKEN_REGISTRY_DIGEST_SIZE)
/*
 * Protected PIDs that fit the payload beside the header, a maximum quote and a
 * maximum signature. handle_get_token() enforces it.
 */
#define LOTA_IPC_TOKEN_MAX_PROTECT_PIDS                         \
	((LOTA_IPC_MAX_PAYLOAD - LOTA_IPC_TOKEN_HEADER_SIZE -   \
	  LOTA_IPC_TOKEN_MAX_ATTEST - LOTA_IPC_TOKEN_MAX_SIG) / \
	 LOTA_IPC_TOKEN_PROTECT_ENTRY_SIZE)
#define LOTA_IPC_TOKEN_MAX_PID_LIST_SIZE (LOTA_IPC_TOKEN_MAX_PROTECT_PIDS * 4)
#define LOTA_IPC_TOKEN_MAX_REGISTRY_LIST_SIZE \
	(LOTA_IPC_TOKEN_MAX_PROTECT_PIDS * LOTA_IPC_TOKEN_REGISTRY_DIGEST_SIZE)

/* runtime_protect_version values (mirror of lota_token.h) */
#define LOTA_IPC_RUNTIME_PROTECT_V1 1 /* PID set + per-PID registry digest */

/*
 * Header, full PID and registry digest lists, largest quote and signature.
 * ipc.c asserts it fits LOTA_IPC_MAX_PAYLOAD; the SDK sizes its receive buffer
 * from it.
 */
#define LOTA_IPC_TOKEN_MAX_SIZE                                              \
	(LOTA_IPC_TOKEN_HEADER_SIZE + LOTA_IPC_TOKEN_MAX_PID_LIST_SIZE +     \
	 LOTA_IPC_TOKEN_MAX_REGISTRY_LIST_SIZE + LOTA_IPC_TOKEN_MAX_ATTEST + \
	 LOTA_IPC_TOKEN_MAX_SIG)

/* Event bits of a SUBSCRIBE mask and a push notification */
#define LOTA_IPC_EVENT_STATUS (1U << 0) /* Status flags changed */
#define LOTA_IPC_EVENT_ATTEST (1U << 1) /* Attestation completed (pass/fail) */
#define LOTA_IPC_EVENT_MODE (1U << 2) /* Enforcement mode changed */

/*
 * A title opened or closed a session with a publisher, or selected one this
 * host never enrolled with. Reserved to the attestation loop, which syncing
 * subscribes: a title just launched would wait out the loop's sleep for its
 * first report. SUBSCRIBE drops this bit for every other connection.
 */
#define LOTA_IPC_EVENT_PROFILE (1U << 3)

/*
 * SUBSCRIBE request payload: per-connection push notifications.
 *
 * Open to every client the socket admits, as GET_STATUS is. Bits the caller may
 * not have are dropped; a mask left empty by that is answered
 * LOTA_IPC_ERR_BAD_REQUEST.
 */
struct lota_ipc_subscribe_request {
	uint32_t event_mask; /* LOTA_IPC_EVENT_* bitmask (0 = unsubscribe) */
} __attribute__((packed));

/* Push notification payload */
struct lota_ipc_notify {
	uint32_t events; /* LOTA_IPC_EVENT_* that triggered this */
	uint32_t flags; /* Current LOTA_STATUS_* bitmask */
	uint64_t last_attest_time; /* Unix timestamp of last attestation */
	uint64_t valid_until; /* Unix time the verdict lapses, 0 if none */
	uint32_t attest_count; /* Total successful attestations */
	uint32_t fail_count; /* Total failed attestations */
	uint8_t mode; /* Current mode (enum lota_mode) */
	uint8_t reserved[3];
} __attribute__((packed));

/*
 * SYNC_ATTEST: the state exchange between the two agent units.
 *
 * Enforcement and attestation are separate processes so a network-facing TLS
 * client cannot reach the BPF policy. The enforcement daemon owns
 * LOTA_IPC_SOCKET_PATH and the boot state a title asks about, but holds no
 * verifier's verdict.
 *
 * The attestation loop connects as a local actor and in one round trip sends
 * the verdict it holds for every publisher, and reads back which publishers a
 * title plays for and which one a title asked this host to enrol with.
 *
 * The SDK never sends this; the daemon refuses it from any uid but its own.
 */
struct lota_ipc_attest_verdict {
	uint8_t profile_id[32]; /* SHA-256 of the publisher CA anchor SPKI */
	uint8_t attested; /* the verifier accepted the last report */
	uint8_t reserved[7];
	uint64_t valid_until; /* Unix timestamp the verdict lapses at */
} __attribute__((packed));

struct lota_ipc_attest_sync {
	uint32_t count; /* verdicts that follow */
	uint32_t attest_count; /* successful rounds since the loop started */
	uint32_t fail_count;
	uint32_t host_flags; /* LOTA_IPC_SYNC_HOST_FLAGS the loop observed */
	uint64_t last_attest_time;
	/* struct lota_ipc_attest_verdict verdicts[count] follows */
} __attribute__((packed));

/*
 * Status bits only the loop observes: it calls the TPM every round, the daemon
 * may not. Bits the daemon can set itself stay out.
 */
#define LOTA_IPC_SYNC_HOST_FLAGS LOTA_STATUS_TPM_LOCKOUT

/*
 * What only the socket owner knows of a publisher: a title holds a session with
 * them, or selected them with no enrollment on this host.
 */
struct lota_ipc_profile_demand {
	uint8_t profile_id[32];
	uint32_t sessions; /* connections currently bound to this publisher */
	uint8_t enroll_pending; /* title asked for it with no enrollment */
	uint8_t reserved[3];
} __attribute__((packed));

struct lota_ipc_attest_sync_response {
	uint32_t count; /* demands that follow */
	uint32_t _reserved1;
	/* struct lota_ipc_profile_demand demands[count] follows */
} __attribute__((packed));

#define LOTA_IPC_ATTEST_SYNC_MAX_SIZE          \
	(sizeof(struct lota_ipc_attest_sync) + \
	 LOTA_IPC_MAX_PROFILES * sizeof(struct lota_ipc_attest_verdict))

#define LOTA_IPC_ATTEST_SYNC_RESPONSE_MAX_SIZE          \
	(sizeof(struct lota_ipc_attest_sync_response) + \
	 LOTA_IPC_MAX_PROFILES * sizeof(struct lota_ipc_profile_demand))

/* PROTECT_PID / UNPROTECT_PID request payload */
struct lota_ipc_pid_request {
	uint32_t pid;
} __attribute__((packed));

/* PROTECT_PID / UNPROTECT_PID response payload */
struct lota_ipc_policy_update {
	uint8_t policy_digest[32];
	uint32_t protect_pid_count;
	uint32_t _reserved1;
} __attribute__((packed));

/*
 * TERMINATE_PROTECTED request payload
 *
 * Its owner asks the agent to end a protected process, which journals it.
 * Only SIGTERM and SIGKILL are relayed.
 */
struct lota_ipc_terminate_request {
	uint32_t pid;
	uint32_t signal;
} __attribute__((packed));

/* TERMINATE_PROTECTED response payload */
struct lota_ipc_terminate_response {
	uint32_t pid;
	uint32_t signal;
	uint32_t other_protect_pid_count; /* protected set minus @pid */
	uint32_t _reserved1;
} __attribute__((packed));

/*
 * GET_REGISTRY request payload
 *
 * Asks for what the last token round found in @pid, from entry @start on:
 * the code objects, then the actors.
 * Answered for the owner of the process or root.
 */
struct lota_ipc_registry_request {
	uint32_t pid;
	uint32_t start;
} __attribute__((packed));

/* registry_digest is the token's entry for @pid */
#define LOTA_IPC_REGISTRY_MEASURED (1U << 0)
/* an executable mapping of @pid went unrecorded; the list may miss one */
#define LOTA_IPC_REGISTRY_HISTORY_LOST (1U << 1)
/* a reach into a socket of @pid's instance went unrecorded */
#define LOTA_IPC_REGISTRY_ACTORS_LOST (1U << 2)
/* @pid's image was executed under protection: the list starts at its exec */
#define LOTA_IPC_REGISTRY_FROM_EXEC (1U << 3)
/*
 * @pid had more executable mappings than one measurement holds: those past
 * the limit are unmeasured, and any of them the history knows is listed as
 * unmapped
 */
#define LOTA_IPC_REGISTRY_TRUNCATED (1U << 4)

/* mapped since protection began, gone from the address space when measured */
#define LOTA_IPC_REGISTRY_ENTRY_UNMAPPED (1U << 0)
/*
 * when mapped executable, open for write or mapped shared writable
 * elsewhere, or a memfd or shm segment no seal kept from writes
 */
#define LOTA_IPC_REGISTRY_ENTRY_WRITABLE (1U << 1)
/* backed by memory only: memfd, shm, tmpfs or hugetlbfs */
#define LOTA_IPC_REGISTRY_ENTRY_MEMORY (1U << 2)
#define LOTA_IPC_REGISTRY_ENTRY_KNOWN                                          \
	(LOTA_IPC_REGISTRY_ENTRY_UNMAPPED | LOTA_IPC_REGISTRY_ENTRY_WRITABLE | \
	 LOTA_IPC_REGISTRY_ENTRY_MEMORY)

/* objects listed for one process: those mapped, then those unmapped */
#define LOTA_IPC_REGISTRY_MAX_OBJECTS 1024
/* actors listed for one process; more set LOTA_IPC_REGISTRY_ACTORS_LOST */
#define LOTA_IPC_REGISTRY_MAX_ACTORS 256

/*
 * GET_REGISTRY response payload
 *
 * A page header followed by @count entries. Entry i of the listing is
 * object i while i < @total and actor i - @total after it.
 * @round names the measurement round the list comes from:
 * pages of one listing that carry different rounds do not belong together.
 *
 * The token binds the list. With LOTA_IPC_REGISTRY_MEASURED set,
 * hashing @flags, @total, @actor_total, every object and every actor in
 * order as lota_registry_digest.h does yields @registry_digest, the token's
 * entry for @pid.
 */
struct lota_ipc_registry_page {
	uint64_t round;
	uint32_t pid;
	uint32_t total; /* objects the round found in @pid */
	uint32_t actor_total; /* actors of @pid's instance */
	uint32_t start;
	uint16_t count; /* entries in this page */
	uint16_t flags; /* LOTA_IPC_REGISTRY_* */
	uint8_t registry_digest[32];
} __attribute__((packed));

/* How an entry's digest was taken */
enum lota_ipc_registry_road {
	LOTA_IPC_REGISTRY_ROAD_NONE = 0, /* no digest */
	LOTA_IPC_REGISTRY_ROAD_VERITY = 1, /* fs-verity measurement */
	LOTA_IPC_REGISTRY_ROAD_CONTENT = 2, /* kernel hash of the contents */
};

/*
 * One registry entry, followed by @soname_len bytes of soname and
 * @path_len bytes of path, neither NUL-terminated.
 */
struct lota_ipc_registry_entry {
	uint64_t size;
	uint64_t dev; /* makedev() of the backing device */
	uint64_t ino;
	uint8_t road; /* enum lota_ipc_registry_road */
	uint8_t digest_len; /* 0, 32 or 64 */
	uint16_t soname_len;
	uint16_t path_len;
	uint16_t flags; /* LOTA_IPC_REGISTRY_ENTRY_* */
	uint8_t digest[64];
} __attribute__((packed));

/* How an actor reached the instance */
enum lota_ipc_registry_actor_kind {
	/* from outside, through a unix socket of the instance */
	LOTA_IPC_REGISTRY_ACTOR_CONNECT = 1, /* stream or seqpacket connect */
	LOTA_IPC_REGISTRY_ACTOR_SEND = 2, /* datagram sent */
	/* from inside, one process of the instance to another */
	LOTA_IPC_REGISTRY_ACTOR_PTRACE_READ = 3, /* read-mode ptrace access */
	LOTA_IPC_REGISTRY_ACTOR_PTRACE_ATTACH =
		4, /* attach-mode ptrace access */
	LOTA_IPC_REGISTRY_ACTOR_SIGNAL = 5, /* signal sent */
	/* one process of the instance to itself: owner_tgid is tgid */
	LOTA_IPC_REGISTRY_ACTOR_ANON_EXEC =
		6, /* anonymous memory made executable, refused or not */
	LOTA_IPC_REGISTRY_ACTOR_KIND_MAX = LOTA_IPC_REGISTRY_ACTOR_ANON_EXEC,
};

/*
 * A process that reached a process of the instance of @pid: from outside,
 * through a unix socket a process of the instance made, bound or listened
 * on; or from inside, by a ptrace access or a signal. Or a process of the
 * instance that made its own anonymous memory executable.
 * The command names are NUL-terminated and zero-padded.
 */
struct lota_ipc_registry_actor {
	uint64_t count; /* times it did so */
	uint64_t start_ticks; /* the actor's, /proc/<tgid>/stat field 22 */
	uint64_t exe_dev; /* makedev() of the actor executable's device */
	uint64_t exe_ino; /* 0 when the actor had no executable */
	uint32_t tgid; /* the actor */
	uint32_t uid; /* the actor's real uid at its first reach */
	uint32_t owner_tgid; /* the process of the instance it reached */
	uint32_t kind; /* enum lota_ipc_registry_actor_kind */
	char comm[16];
	char owner_comm[16];
} __attribute__((packed));

#endif /* LOTA_IPC_H */
