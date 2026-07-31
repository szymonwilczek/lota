/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * LOTA Agent - IPC Server Module
 *
 * One process serves LOTA_IPC_SOCKET_PATH: the enforcement daemon.
 * It is the unit systemd's socket activation starts, the one that stays up whether
 * or not a publisher is configured, and the one holding the BPF context,
 * the enforcement policy digest and the boot state a title asks about.
 *
 * The attestation loop is a client of this server, not a second one.
 * It sends SYNC_ATTEST with the verdict it holds for each publisher and reads
 * back the sessions and enrollment requests only the socket owner can see.
 * Two servers on one path meant whichever bound last answered, with half the state.
 */

#ifndef LOTA_AGENT_IPC_H
#define LOTA_AGENT_IPC_H

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

#include "attest_targets.h"

struct tpm_context;
struct dbus_context;
struct ipc_client;

/*
 * Rate limiting for GET_TOKEN, in two layers that measure different things.
 *
 * Every GET_TOKEN costs fresh TPM quote, so the limiter exists to stop one
 * caller monopolising the TPM.
 *
 * Connection is the session: title holds one, and the agent already authenticates
 * its peer.
 * So the per-session budget is what title spends, sized so no realistic heartbeat
 * reaches it, and the per-UID ceiling stays as the bound on total TPM cost,
 * sized for several titles at once.
 *
 * Neither alone is enough: without the session budget one title can spend the whole
 * uid allowance, and without the uid ceiling a caller opens connections until
 * the TPM is saturated.
 */
#define TOKEN_RATE_LIMIT_PER_SESSION 20 /* requests, ~3 s heartbeat */
#define TOKEN_RATE_LIMIT 60 /* requests per uid, several titles */
#define TOKEN_RATE_WINDOW_SEC 60 /* per minute */

/*
 * The fastest heartbeat any reference integration uses, in seconds.
 * Per-session budget is checked against it below so change to either one
 * cannot quietly starve a title.
 */
#define LOTA_REFERENCE_HEARTBEAT_SEC 5

/*
 * Title on the reference cadence must fit inside its session budget with room
 * to spare, or the limiter is throttling correct behaviour.
 */
_Static_assert(TOKEN_RATE_LIMIT_PER_SESSION >
		       TOKEN_RATE_WINDOW_SEC / LOTA_REFERENCE_HEARTBEAT_SEC,
	       "session token budget must exceed the reference heartbeat rate");

/*
 * The uid ceiling has to hold several sessions at once, or the second title
 * player launches is refused for what the first one spent.
 */
_Static_assert(TOKEN_RATE_LIMIT >= 2 * TOKEN_RATE_LIMIT_PER_SESSION,
	       "uid token ceiling must cover at least two concurrent sessions");

/*
 * The session budget is the inner bound; session may never outspend the uid
 * it belongs to.
 */
_Static_assert(TOKEN_RATE_LIMIT_PER_SESSION < TOKEN_RATE_LIMIT,
	       "session budget must be tighter than the uid ceiling");

/*
 * fd -> client lookup table.
 */
#define IPC_CLIENT_MAP_SIZE 4096 /* must be a power of two */

struct ipc_client_map_entry {
	int fd; /* -1 empty, -2 tombstone */
	struct ipc_client *client;
};

/*
 * Maximum number of extra listener sockets.
 */
#define IPC_MAX_EXTRA_LISTENERS 4

/*
 * Extra listener socket.
 */
struct ipc_listener {
	int fd; /* Listening fd (-1 if unused) */
	char path[PATH_MAX]; /* Socket path for cleanup */
};

/*
 * IPC server context
 */
struct ipc_context {
	int listen_fd; /* Primary listening socket */
	int epoll_fd; /* epoll instance */
	bool running;
	uint64_t start_time_sec; /* CLOCK_MONOTONIC seconds for uptime */

	/* Connected clients (lifetime bound) */
	struct ipc_client *client_list;
	int client_count;

	/* O(1) lookup of client by fd (in addition to the linked list). */
	struct ipc_client_map_entry client_map[IPC_CLIENT_MAP_SIZE];

	/* Extra listener sockets */
	struct ipc_listener extra[IPC_MAX_EXTRA_LISTENERS];
	int extra_count;

	/*
	 * TPM context for token signing.
	 *
	 * Borrowed, not owned. In the production daemon this points at
	 * g_agent.tpm_ctx and is used only from the same single-threaded
	 * epoll loop that owns all TPM mutations. ipc_context provides no
	 * locking around the pointer or the pointed-to tpm_context; a future
	 * threaded IPC implementation must serialize GET_TOKEN against the
	 * attestation loop, AIK rotation, lockout reconciliation, and cleanup.
	 */
	struct tpm_context *tpm;
	uint32_t quote_pcr_mask;

	/* D-Bus context (optional, NULL if D-Bus unavailable) */
	struct dbus_context *dbus;
	int dbus_fd;

	/* Attestation state */
	uint32_t status_flags;
	uint64_t last_attest_time;
	uint64_t valid_until;
	uint32_t attest_count;
	uint32_t fail_count;
	uint8_t mode;

	/* AIK rotation state, surfaced read-only over D-Bus */
	uint64_t aik_generation; /* monotonic rotation counter */
	uint64_t aik_provisioned_at; /* current AIK creation (Unix time) */
	uint64_t aik_last_rotated_at; /* last rotation (Unix time, 0 if never) */
	uint64_t aik_rotation_deadline; /* provisioned_at + TTL (0 if unknown) */
	uint64_t aik_grace_deadline; /* end of post-rotation grace (0 if none) */
	bool aik_reenroll_required; /* stored cert outdated by a rotation */

	/*
	 * Publisher profiles this host attests for, borrowed from the attestation
	 * loop that owns them.
	 *
	 * Connection may bind itself to one of these with SET_PROFILE,
	 * and every later answer is then that publisher's: its AIK signs the token,
	 * and its verifier's verdict is the status.
	 * Without the list the agent has nothing to bind to,
	 * so SET_PROFILE is refused; that is the case for the diagnostic
	 * IPC servers, which attest to nobody.
	 *
	 * Same borrowing rule as tpm above:
	 * read from the single-threaded epoll loop that also owns the writes.
	 */
	struct attest_target *profiles;
	size_t profile_count;

	/*
	 * Session opened or closed, or title asked for a publisher this host
	 * has not enrolled with.
	 * Raised where it happens and acted on once the epoll pass is over,
	 * because both places run with a client being created or destroyed
	 * underneath them.
	 */
	bool profiles_changed;

	/*
	 * Called once the attestation loop has synced.
	 *
	 * Loop is the process that rotates the AIK and it writes the rotation
	 * record to disk, so the socket owner republishes that state by
	 * re-reading the file rather than carrying it on the wire:
	 * the file is the source both processes already share,
	 * and a wire field would be a second copy to keep true.
	 */
	void (*on_attest_sync)(void *user);
	void *on_attest_sync_user;

	/* true when using socket activation (do not unlink socket) */
	bool activated;
};

/*
 * ipc_init - Initialize IPC server
 * @ctx: Context to initialize
 *
 * Creates Unix socket at /run/lota/lota.sock and
 * sets up epoll for non-blocking operation.
 *
 * Returns: 0 on success, negative errno on failure
 */
int ipc_init(struct ipc_context *ctx);

/*
 * ipc_cleanup - Shutdown IPC server
 * @ctx: Context to clean up
 *
 * Closes all connections and removes socket file.
 */
void ipc_cleanup(struct ipc_context *ctx);

/*
 * ipc_process - Process pending IPC events
 * @ctx: Server context
 * @timeout_ms: Max time to wait (-1 = block, 0 = poll)
 *
 * Non-blocking if timeout_ms is 0.
 *
 * Returns: Number of events processed, negative errno on error
 */
int ipc_process(struct ipc_context *ctx, int timeout_ms);

/*
 * ipc_get_fd - Get epoll fd for external select/poll
 * @ctx: Server context
 *
 * Returns: epoll file descriptor, or -1 if not initialized
 */
int ipc_get_fd(struct ipc_context *ctx);

/*
 * ipc_update_status - Update attestation status
 * @ctx: Server context
 * @flags: New LOTA_STATUS_* flags
 * @valid_until: Token validity timestamp
 */
void ipc_update_status(struct ipc_context *ctx, uint32_t flags,
		       uint64_t valid_until);

/*
 * ipc_record_attestation - Record attestation attempt
 * @ctx: Server context
 * @success: Whether attestation succeeded
 */
void ipc_record_attestation(struct ipc_context *ctx, bool success);

/*
 * ipc_update_rotation - Publish AIK rotation state.
 * @ctx: Server context
 * @generation: Current AIK generation counter
 * @provisioned_at: Current AIK creation time (Unix seconds)
 * @last_rotated_at: Last rotation time (Unix seconds, 0 if never)
 * @rotation_deadline: provisioned_at + TTL (0 if unknown)
 * @grace_deadline: End of post-rotation grace window (0 if none)
 * @reenroll_required: True when a rotation has outdated the stored cert
 *
 * Updates the rotation fields and, when D-Bus is attached and a field
 * changed, emits a PropertiesChanged for the rotation properties.
 */
void ipc_update_rotation(struct ipc_context *ctx, uint64_t generation,
			 uint64_t provisioned_at, uint64_t last_rotated_at,
			 uint64_t rotation_deadline, uint64_t grace_deadline,
			 bool reenroll_required);

/*
 * ipc_set_mode - Update current mode
 * @ctx: Server context
 * @mode: New mode (enum lota_mode)
 */
void ipc_set_mode(struct ipc_context *ctx, uint8_t mode);

/*
 * ipc_set_profiles - Hand the IPC layer the publisher profiles
 * @ctx: Server context
 * @profiles: Targets owned by the attestation loop, borrowed for the run
 * @count: How many
 *
 * Until this is called a connection has no publisher to bind to
 * and SET_PROFILE is refused.
 * Passing NULL/0 clears the list.
 */
void ipc_set_profiles(struct ipc_context *ctx, struct attest_target *profiles,
		      size_t count);

/*
 * ipc_set_attest_sync_hook - Run @fn after the attestation loop syncs
 * @ctx: Server context
 * @fn: Callback, or NULL to clear
 * @user: Opaque argument handed back to @fn
 *
 * The socket owner learns from a sync that the loop has been round the course,
 * which is the moment any state the loop keeps on disk -- the AIK rotation
 * record -- is worth re-reading.
 */
void ipc_set_attest_sync_hook(struct ipc_context *ctx, void (*fn)(void *),
			      void *user);

/*
 * ipc_set_tpm - Set TPM context for token signing
 * @ctx: Server context
 * @tpm: Initialized TPM context (or NULL to disable signing)
 * @pcr_mask: PCRs to include in token quotes
 *
 * When TPM context is set, GET_TOKEN will generate fresh
 * TPM quotes signed by the AIK. Without TPM context,
 * GET_TOKEN returns unsigned tokens for development/testing.
 */
void ipc_set_tpm(struct ipc_context *ctx, struct tpm_context *tpm,
		 uint32_t pcr_mask);

/*
 * ipc_add_listener - Add an extra listener socket.
 * @ctx: Initialized IPC context.
 * @socket_path: Absolute path for the new Unix socket.
 *
 * Creates an additional listening socket and registers it with
 * the epoll set. The socket directory must already exist.
 * Connections accepted on extra listeners are handled identically
 * to the primary socket.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int ipc_add_listener(struct ipc_context *ctx, const char *socket_path);

/*
 * ipc_is_listener - Check if an fd is any listener socket.
 * @ctx: Server context.
 * @fd:  File descriptor to check.
 *
 * Returns: 1 if fd is the primary or any extra listener, 0 otherwise.
 */
int ipc_is_listener(struct ipc_context *ctx, int fd);

/*
 * ipc_init_activated - Initialize IPC from a systemd socket-activated fd.
 * @ctx: Context to initialize.
 * @fd:  Pre-created listening socket fd (from sd_listen_fds).
 *
 * Uses the passed fd as the primary listener instead of creating
 * a new socket. The fd must be an AF_UNIX SOCK_STREAM socket
 * already in listening state. Ownership transfers to the IPC
 * context; the fd will be closed by ipc_cleanup().
 *
 * Returns: 0 on success, negative errno on failure.
 */
int ipc_init_activated(struct ipc_context *ctx, int fd);

/*
 * ipc_set_dbus - Attach D-Bus context for signal emission.
 * @ctx: Server context.
 * @dbus: D-Bus context (or NULL to detach).
 *
 * When set, ipc_update_status/ipc_record_attestation/ipc_set_mode
 * will automatically emit corresponding D-Bus signals.
 */
void ipc_set_dbus(struct ipc_context *ctx, struct dbus_context *dbus);

#endif /* LOTA_AGENT_IPC_H */
