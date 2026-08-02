/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * LOTA IPC Protocol
 *
 * Binary protocol for local attestation queries.
 *
 * Internal to the agent and the SDK that ships with it:
 * this is the wire between the two, not surface an integrator builds against.
 * It is not installed, and it carries no compatibility promise -- caller that
 * speaks the socket directly is pinned to the agent build it was compiled against.
 *
 * Use the gaming SDK (include/lota_gaming.h), which owns this protocol and keeps its own ABI.
 */

#ifndef LOTA_IPC_H
#define LOTA_IPC_H

#include <stdint.h>

#define LOTA_IPC_SOCKET_PATH "/run/lota/lota.sock"

/* Protocol constants */
#define LOTA_IPC_MAGIC 0x4C4F5441 /* "LOTA" */
/*
 * Version 2 adds SET_PROFILE.
 * Agent refuses any other version outright:
 * this header is internal and the agent and the SDK that speaks to it ship
 * together, so there is nothing to negotiate with.
 */
#define LOTA_IPC_VERSION 2
/*
 * Practical per-frame payload cap enforced by the agent socket parser.
 * The largest production payload is GET_TOKEN: token header, protected PID
 * list, TPMS_ATTEST, and RSA signature. Keep this bound small enough that
 * malformed local clients cannot force large per-connection buffers, but
 * large enough for the maximum token layout below.
 */
#define LOTA_IPC_MAX_PAYLOAD 8192

/*
 * IPC Commands
 */
enum lota_ipc_cmd {
	LOTA_IPC_CMD_PING = 0x01, /* Whether agent is alive */
	LOTA_IPC_CMD_GET_STATUS = 0x02, /* Attestation status */
	LOTA_IPC_CMD_GET_TOKEN = 0x03, /* Signed attestation token */
	LOTA_IPC_CMD_SUBSCRIBE =
		0x04, /* Subscribe to status changes (requires privileged peer) */
	LOTA_IPC_CMD_PROTECT_PID =
		0x05, /* Hot-add protected PID (requires privileged peer) */
	LOTA_IPC_CMD_UNPROTECT_PID =
		0x06, /* Hot-remove protected PID (requires privileged peer) */
	LOTA_IPC_CMD_SHUTDOWN =
		0x07, /* Graceful agent self-shutdown (requires privileged peer) */
	LOTA_IPC_CMD_SET_PROFILE =
		0x08, /* Bind this connection to one publisher profile */
	LOTA_IPC_CMD_SYNC_ATTEST =
		0x09, /* Exchange state with the attestation loop (agent peer only) */
};

/*
 * How many publishers one host answers to.
 *
 * Mirrors LOTA_CONFIG_MAX_PROFILES, which this header cannot include:
 * the SDK ships it and the agent's configuration parser is not public surface.
 * The agent asserts the two against each other.
 */
#define LOTA_IPC_MAX_PROFILES 8

/*
 * Response codes
 */
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
	LOTA_IPC_ERR_UNKNOWN_PROFILE = 0x0B,
	/* nobody on this machine has agreed to answer to that publisher */
	LOTA_IPC_ERR_CONSENT_REQUIRED = 0x0C,
	LOTA_IPC_NOTIFY = 0x80,
};

/*
 * Attestation status flags
 */
#define LOTA_STATUS_ATTESTED (1 << 0) /* Successfully attested */
#define LOTA_STATUS_TPM_OK (1 << 1) /* TPM initialized */
#define LOTA_STATUS_IOMMU_OK (1 << 2) /* IOMMU verified */
#define LOTA_STATUS_BPF_LOADED (1 << 3) /* BPF LSM active */
#define LOTA_STATUS_SECURE_BOOT (1 << 4) /* Secure Boot enabled */
#define LOTA_STATUS_TPM_LOCKOUT (1 << 5) /* TPM signaled DA lockout */
#define LOTA_STATUS_RINGBUF_DROPS \
	(1                        \
	 << 6) /* BPF events ringbuf dropped at least one event since last     \
		  poll; forensic stream incomplete, enforcement unaffected */
#define LOTA_STATUS_UPDATE_PENDING \
	(1                         \
	 << 7) /* Agent binary on disk differs from the running one: package \
		  update landed and takes effect on the next cold boot.        \
		  Attestation is unaffected until then */

#define LOTA_STATUS_TOKEN_ONLY \
	(1                     \
	 << 8) /* the publisher this connection named runs no verifier here,  \
		  so ATTESTED carries no verdict of theirs and the token is   \
		  the evidence */

#define LOTA_STATUS_IMAGE_FULLY_MEASURED \
	(1                               \
	 << 9) /* every file-backed executable mapping of every protected     \
		  process carried an fs-verity digest, so the runtime image   \
		  measurement covers all of their code. Clear means some      \
		  object could not be measured and is absent from the fold;   \
		  what that is worth is the relying party's policy */

/*
 * Request header
 *
 * All requests start with this header.
 * Payload follows immediately after.
 */
struct lota_ipc_request {
	uint32_t magic; /* LOTA_IPC_MAGIC */
	uint32_t version; /* LOTA_IPC_VERSION */
	uint32_t cmd; /* enum lota_ipc_cmd */
	uint32_t payload_len;
} __attribute__((packed));

#define LOTA_IPC_REQUEST_SIZE sizeof(struct lota_ipc_request)

/*
 * Response header
 *
 * All responses start with this header.
 * Payload follows immediately after.
 */
struct lota_ipc_response {
	uint32_t magic; /* LOTA_IPC_MAGIC */
	uint32_t version; /* LOTA_IPC_VERSION */
	uint32_t result; /* enum lota_ipc_result */
	uint32_t payload_len;
} __attribute__((packed));

#define LOTA_IPC_RESPONSE_SIZE sizeof(struct lota_ipc_response)

/*
 * PING response payload
 */
struct lota_ipc_ping_response {
	uint64_t uptime_sec; /* Agent uptime in seconds */
	uint32_t pid; /* Agent PID */
} __attribute__((packed));

/*
 * GET_STATUS response payload
 */
struct lota_ipc_status {
	uint32_t flags; /* LOTA_STATUS_* bitmask */
	uint32_t _reserved1; /* Padding for alignment */
	uint64_t last_attest_time; /* Unix timestamp of last attestation */
	uint64_t valid_until; /* Token valid until (Unix timestamp) */
	uint32_t attest_count; /* Total successful attestations */
	uint32_t fail_count; /* Total failed attestations */
	uint8_t mode; /* Current mode (enum lota_mode) */
	uint8_t reserved[3];
} __attribute__((packed));

/*
 * SET_PROFILE request payload
 *
 * Binds the connection to one publisher, named by the SHA-256 of that publisher's
 * CA trust anchor SubjectPublicKeyInfo -- the same identity the host stores
 * the publisher's enrollment under.
 * The endpoint is not the identity: address is mutable and two publishers can
 * share a hostname, while the anchor's key is what enrollment verifies against.
 *
 * Every later answer on the connection is that publisher's:
 * GET_TOKEN quotes with their AIK, and GET_STATUS reports whether *their*
 * verifier is satisfied rather than whether every publisher on the host is.
 *
 * Connection that never sends this keeps the host-wide answers.
 */
struct lota_ipc_set_profile {
	uint8_t profile_id[32];
} __attribute__((packed));

/*
 * GET_TOKEN request payload (optional)
 */
struct lota_ipc_token_request {
	uint8_t nonce[32]; /* Client-provided nonce (optional, zeros = none) */
} __attribute__((packed));

/*
 * GET_TOKEN response payload
 *
 * Contains a signed attestation statement using TPM Quote.
 * Verification:
 * - Recompute runtime_protect_digest from protected_pids[]
 * - Compute expected_nonce = SHA256(valid_until_LE || flags_LE || pcr_mask_LE
 * || client_nonce || policy_digest || runtime_protect_digest ||
 * runtime_protect_epoch_LE)
 * - Verify TPM signature over attest_data using AIK public key
 * - Parse attest_data, check extraData == expected_nonce
 * - Check PCR digest in attest_data matches expected policy
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
	uint8_t runtime_protect_digest[32]; /* SHA-256 over canonical runtime set */
	uint32_t protect_pid_count; /* Number of protected PIDs in payload */
	uint64_t runtime_protect_epoch; /* Monotonic runtime protection mutation
					   id */
	uint16_t pid_list_size; /* Bytes for protected_pids[] */
	uint16_t runtime_protect_version; /* 0/1 = PID set, 2 = + image digests */

	/*
	 * Variable-length data follows:
	 *   - protected_pids[protect_pid_count] (little-endian uint32)
	 *   - protected_image_digests[protect_pid_count][32]
	 *         (present only when runtime_protect_version == 2)
	 *   - attest_data[attest_size]  (TPMS_ATTEST)
	 *   - signature[sig_size]       (RSA signature)
	 */
} __attribute__((packed));

#define LOTA_IPC_TOKEN_HEADER_SIZE sizeof(struct lota_ipc_token)
#define LOTA_IPC_TOKEN_MAX_ATTEST 1024
#define LOTA_IPC_TOKEN_MAX_SIG 512
#define LOTA_IPC_TOKEN_IMAGE_DIGEST_SIZE 32
/*
 * Worst-case bytes one protected PID contributes to a v2 token:
 * its 4-byte value plus its 32-byte kernel image digest
 */
#define LOTA_IPC_TOKEN_PROTECT_ENTRY_SIZE (4 + LOTA_IPC_TOKEN_IMAGE_DIGEST_SIZE)
/*
 * Cap the per-token protected-PID count at what actually fits the IPC payload
 * once the fixed header, a maximum quote and a maximum signature are accounted
 * for, so the runtime count guard in handle_get_token() is the real binding
 * limit.
 */
#define LOTA_IPC_TOKEN_MAX_PROTECT_PIDS                         \
	((LOTA_IPC_MAX_PAYLOAD - LOTA_IPC_TOKEN_HEADER_SIZE -   \
	  LOTA_IPC_TOKEN_MAX_ATTEST - LOTA_IPC_TOKEN_MAX_SIG) / \
	 LOTA_IPC_TOKEN_PROTECT_ENTRY_SIZE)
#define LOTA_IPC_TOKEN_MAX_PID_LIST_SIZE (LOTA_IPC_TOKEN_MAX_PROTECT_PIDS * 4)
#define LOTA_IPC_TOKEN_MAX_IMAGE_LIST_SIZE \
	(LOTA_IPC_TOKEN_MAX_PROTECT_PIDS * LOTA_IPC_TOKEN_IMAGE_DIGEST_SIZE)

/* runtime_protect_version values (mirror of lota_token.h) */
#define LOTA_IPC_RUNTIME_PROTECT_V1 1 /* PID set identity only */
#define LOTA_IPC_RUNTIME_PROTECT_V2 \
	2 /* PID set + per-PID kernel image digest */

/*
 * Worst-case v2 token:
 * the header, the full protected-PID list, the per-PID image-digest list,
 * and a maximum quote plus signature.
 * Protected-PID cap above is derived so this stays within LOTA_IPC_MAX_PAYLOAD
 * asserted in ipc.c.
 * SDK sizes its receive buffer from this bound.
 */
#define LOTA_IPC_TOKEN_MAX_SIZE                                           \
	(LOTA_IPC_TOKEN_HEADER_SIZE + LOTA_IPC_TOKEN_MAX_PID_LIST_SIZE +  \
	 LOTA_IPC_TOKEN_MAX_IMAGE_LIST_SIZE + LOTA_IPC_TOKEN_MAX_ATTEST + \
	 LOTA_IPC_TOKEN_MAX_SIG)

/*
 * Subscription event types (bitmask for SUBSCRIBE request)
 *
 * Controls which state changes trigger push notifications.
 */
#define LOTA_IPC_EVENT_STATUS (1U << 0) /* Status flags changed */
#define LOTA_IPC_EVENT_ATTEST \
	(1U << 1) /* Attestation completed (pass/fail)     \
				       */
#define LOTA_IPC_EVENT_MODE (1U << 2) /* Enforcement mode changed */

/*
 * Title opened or closed session with publisher, or selected one this host has
 * never enrolled with.
 * Only the attestation loop subscribes: it acts on the change, and waiting out
 * its sleep would make title that has just launched wait an interval for its
 * first report.
 */
#define LOTA_IPC_EVENT_PROFILE (1U << 3)
#define LOTA_IPC_EVENT_ALL 0xFFFFFFFFU

/*
 * SUBSCRIBE request payload
 *
 * Registers or cancels per-connection push notifications.
 * event_mask selects which events trigger notifications.
 * Sending event_mask = 0 cancels the subscription.
 *
 * Access control: agent may require the peer UID to match the local account
 * running the agent process.
 *
 * Server responds with LOTA_IPC_OK on success.
 */
struct lota_ipc_subscribe_request {
	uint32_t event_mask; /* LOTA_IPC_EVENT_* bitmask (0 = unsubscribe) */
} __attribute__((packed));

/*
 * Push notification payload
 */
struct lota_ipc_notify {
	uint32_t events; /* LOTA_IPC_EVENT_* that triggered this */
	uint32_t flags; /* Current LOTA_STATUS_* bitmask */
	uint64_t last_attest_time; /* Unix timestamp of last attestation */
	uint64_t valid_until; /* Token valid until (Unix timestamp) */
	uint32_t attest_count; /* Total successful attestations */
	uint32_t fail_count; /* Total failed attestations */
	uint8_t mode; /* Current mode (enum lota_mode) */
	uint8_t reserved[3];
} __attribute__((packed));

/*
 * SYNC_ATTEST -- the state exchange between the two agent units.
 *
 * Enforcement and attestation run as separate processes so a network-facing
 * TLS client cannot reach the BPF policy, and only one of them can own
 * LOTA_IPC_SOCKET_PATH.
 * Enforcement daemon owns it: it is the always-on unit, it is what the packaged
 * socket unit activates, and it is the one holding the BPF context,
 * the enforcement policy digest and the boot state a title asks about.
 * What it does not have is a verifier's verdict.
 *
 * So the attestation loop connects to that socket as a local peer and trades what
 * each side knows in one round trip: it sends the verdict it holds for every
 * publisher, and reads back which publishers a title is currently playing for
 * and which one a title has asked this host to enrol with.
 *
 * Not public surface -- the SDK never sends this, and the daemon refuses it
 * from anything but the agent binary running as the agent's own user.
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
	uint32_t _reserved1;
	uint64_t last_attest_time;
	/* struct lota_ipc_attest_verdict verdicts[count] follows */
} __attribute__((packed));

/*
 * What a publisher is owed, as only the socket owner can know it:
 * title holding session with them, or title having selected a publisher this
 * host has never enrolled with.
 */
struct lota_ipc_profile_demand {
	uint8_t profile_id[32];
	uint32_t sessions; /* connections currently bound to this publisher */
	uint8_t enroll_pending; /* title asked for publisher with no enrollment */
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

#endif /* LOTA_IPC_H */
