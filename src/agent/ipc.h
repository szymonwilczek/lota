/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * LOTA Agent - IPC server.
 *
 * The enforcement daemon serves LOTA_IPC_SOCKET_PATH. The attestation loop is
 * its client: SYNC_ATTEST carries the verdict held for each publisher and reads
 * back the sessions and enrollment requests the socket owner sees.
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
 * GET_TOKEN limits per TOKEN_RATE_WINDOW_SEC. A token costs a TPM quote.
 *
 * The session budget keeps one title from spending its uid's allowance;
 * the uid ceiling bounds the quotes of a caller that opens more connections.
 */
#define TOKEN_RATE_LIMIT_PER_SESSION 20 /* requests, ~3 s heartbeat */
#define TOKEN_RATE_LIMIT 60 /* requests per uid, several titles */
#define TOKEN_RATE_WINDOW_SEC 60 /* per minute */

/* demo_anticheat's default heartbeat, in seconds */
#define LOTA_REFERENCE_HEARTBEAT_SEC 5

_Static_assert(TOKEN_RATE_LIMIT_PER_SESSION >
		       TOKEN_RATE_WINDOW_SEC / LOTA_REFERENCE_HEARTBEAT_SEC,
	       "session token budget must exceed the reference heartbeat rate");

_Static_assert(TOKEN_RATE_LIMIT >= 2 * TOKEN_RATE_LIMIT_PER_SESSION,
	       "uid token ceiling must cover at least two concurrent sessions");

_Static_assert(TOKEN_RATE_LIMIT_PER_SESSION < TOKEN_RATE_LIMIT,
	       "session budget must be tighter than the uid ceiling");

#define IPC_CLIENT_MAP_SIZE 4096 /* must be a power of two */

struct ipc_client_map_entry {
	int fd; /* -1 empty, -2 tombstone */
	struct ipc_client *client;
};

#define IPC_MAX_EXTRA_LISTENERS 4

struct ipc_listener {
	int fd; /* Listening fd (-1 if unused) */
	char path[PATH_MAX];
};

struct ipc_context {
	int listen_fd; /* Primary listening socket */
	int epoll_fd;

	/*
	 * (device, inode) at the primary socket path when it was bound,
	 * and the inotify watch on its directory (-1: not watching).
	 */
	dev_t listen_dev;
	ino_t listen_ino;
	int sock_watch_fd;
	bool running;
	uint64_t start_time_sec; /* CLOCK_MONOTONIC seconds for uptime */

	struct ipc_client *client_list;
	int client_count;

	struct ipc_client_map_entry client_map[IPC_CLIENT_MAP_SIZE];

	struct ipc_listener extra[IPC_MAX_EXTRA_LISTENERS];
	int extra_count;

	/*
	 * TPM context for token signing. Borrowed; ipc_context does no locking:
	 * used from the epoll loop's thread.
	 */
	struct tpm_context *tpm;
	uint32_t quote_pcr_mask;

	/* NULL if D-Bus is unavailable */
	struct dbus_context *dbus;
	int dbus_fd;

	/*
	 * A protected process was ended for its owner. Set until the agent
	 * ends.
	 *
	 * Kept apart from status_flags with the two below: each round replaces
	 * that word and ipc_update_status() folds them back in.
	 */
	bool protected_terminated;

	/* an earlier agent of this boot ended without a shutdown */
	bool agent_restarted;

	/* the kernel left out an event; set until the agent ends */
	bool events_lost;

	uint32_t status_flags;
	uint64_t last_attest_time;
	uint64_t valid_until;
	uint32_t attest_count;
	uint32_t fail_count;
	uint8_t mode;
	uint32_t policy_keys; /* LOTA_STATUS_POLICY_KEYS the daemon holds */

	/*
	 * Publisher profiles, borrowed from the caller of ipc_set_profiles().
	 * Read from the epoll loop's thread, as tpm is.
	 *
	 * A connection binds to one with SET_PROFILE: its AIK then signs that
	 * connection's tokens and its verifier's verdict is its status.
	 * With an empty list SET_PROFILE is refused.
	 */
	struct attest_target *profiles;
	size_t profile_count;

	/*
	 * A session opened or closed, a title named a publisher not enrolled
	 * here, or the list was replaced. Acted on after the epoll pass:
	 * notifying walks the client list, which client_destroy() is changing
	 * where this is raised.
	 */
	bool profiles_changed;

	/* socket-activated: ipc_cleanup() leaves the primary path in place */
	bool activated;
};

/**
 * ipc_init() - Serve LOTA_IPC_SOCKET_PATH.
 * @ctx: Context to initialize.
 *
 * Return: 0 on success, -EADDRINUSE when a process still answers on the path,
 * other negative errno on failure.
 */
int ipc_init(struct ipc_context *ctx);

/**
 * ipc_cleanup() - Shut the IPC server down.
 * @ctx: Context to clean up.
 *
 * Closes every connection and listener. Unlinks the extra listeners' paths,
 * and the primary path unless it was socket-activated.
 */
void ipc_cleanup(struct ipc_context *ctx);

/**
 * ipc_process() - Process pending IPC events.
 * @ctx: Server context.
 * @timeout_ms: Max time to wait (-1 = block, 0 = poll).
 *
 * Return: Number of events processed, negative errno on error.
 */
int ipc_process(struct ipc_context *ctx, int timeout_ms);

/**
 * ipc_get_fd() - Get the epoll fd for external select/poll.
 * @ctx: Server context.
 *
 * Return: The epoll fd.
 */
int ipc_get_fd(struct ipc_context *ctx);

/**
 * ipc_update_status() - Publish the attestation status.
 * @ctx: Server context.
 * @flags: New LOTA_STATUS_* flags; the bits this context holds are folded in.
 * @valid_until: Token validity timestamp.
 */
void ipc_update_status(struct ipc_context *ctx, uint32_t flags,
		       uint64_t valid_until);

/**
 * ipc_record_attestation() - Record an attestation attempt.
 * @ctx: Server context.
 * @success: Whether attestation succeeded.
 */
void ipc_record_attestation(struct ipc_context *ctx, bool success);

/**
 * ipc_set_agent_restarted() - Raise LOTA_STATUS_AGENT_RESTARTED.
 * @ctx: Server context.
 *
 * An earlier agent of this boot ended without a shutdown.
 */
void ipc_set_agent_restarted(struct ipc_context *ctx);

/**
 * ipc_set_events_lost() - Raise LOTA_STATUS_EVENTS_LOST until the agent ends.
 * @ctx: Server context.
 *
 * The kernel left out an event of the log.
 */
void ipc_set_events_lost(struct ipc_context *ctx);

/**
 * ipc_set_mode() - Update the current mode.
 * @ctx: Server context.
 * @mode: New mode (enum lota_mode).
 */
void ipc_set_mode(struct ipc_context *ctx, uint8_t mode);

/**
 * ipc_set_policy() - Set the policy keys the daemon applies.
 * @ctx: Server context.
 * @keys: LOTA_STATUS_POLICY_KEYS bits; lota_status_fold_policy() decides when
 *        the status word carries them.
 */
void ipc_set_policy(struct ipc_context *ctx, uint32_t keys);

/**
 * ipc_host_status_flags() - Get the word of a caller naming no publisher.
 * @ctx: Server context, or NULL.
 *
 * Return: The stored word with the runtime coverage and content-hash bits
 * folded in at the call, 0 when @ctx is NULL.
 */
uint32_t ipc_host_status_flags(const struct ipc_context *ctx);

/**
 * ipc_runtime_coverage_forget() - Drop the cached coverage verdict.
 *
 * The next read walks the protected set again.
 */
void ipc_runtime_coverage_forget(void);

/**
 * ipc_runtime_measure_stats() - Count what the measurement reports left out.
 * @repeated: Out: rounds that repeated a written answer.
 * @unremembered: Out: answers written without room to compare.
 */
void ipc_runtime_measure_stats(uint64_t *repeated, uint64_t *unremembered);

/**
 * ipc_token_answer_stats() - Count token rounds left out of the journal.
 * @repeated: Out: rounds that repeated a journalled answer.
 */
void ipc_token_answer_stats(uint64_t *repeated);

/**
 * ipc_set_profiles() - Hand the IPC layer the publisher profiles.
 * @ctx: Server context.
 * @profiles: Targets, borrowed for the run.
 * @count: How many; NULL/0 clears the list.
 *
 * A live connection is bound again to the publisher it named, or left unbound
 * when that publisher is gone.
 */
void ipc_set_profiles(struct ipc_context *ctx, struct attest_target *profiles,
		      size_t count);

/**
 * ipc_set_tpm() - Set the TPM context for token signing.
 * @ctx: Server context.
 * @tpm: Initialized TPM context; NULL makes GET_TOKEN answer
 *       LOTA_IPC_ERR_NO_TPM.
 * @pcr_mask: PCRs to include in token quotes.
 */
void ipc_set_tpm(struct ipc_context *ctx, struct tpm_context *tpm,
		 uint32_t pcr_mask);

/**
 * ipc_can_issue_tokens() - Tell whether a TPM is bound to sign tokens.
 * @ctx: Server context, or NULL.
 *
 * Return: true when @ctx has a TPM context.
 */
bool ipc_can_issue_tokens(const struct ipc_context *ctx);

/**
 * ipc_token_capability_str() - Say in one line what GET_TOKEN will answer.
 * @ctx: Server context, or NULL.
 *
 * Return: A static string for the diagnostic servers to print, never NULL.
 */
const char *ipc_token_capability_str(const struct ipc_context *ctx);

/**
 * ipc_add_listener() - Add an extra listener socket.
 * @ctx: Initialized IPC context.
 * @socket_path: Absolute path of the new Unix socket; its directory must exist.
 *
 * Return: 0 on success, -EADDRINUSE when a process still answers on the path,
 * other negative errno on failure.
 */
int ipc_add_listener(struct ipc_context *ctx, const char *socket_path);

/**
 * ipc_remove_listener() - Drop an extra listener socket.
 * @ctx: Initialized IPC context.
 * @socket_path: Path the listener was added under.
 *
 * Unregisters and closes the socket, unlinks the path and frees the slot.
 *
 * Return: 0 on success, -ENOENT when no listener holds that path.
 */
int ipc_remove_listener(struct ipc_context *ctx, const char *socket_path);

/**
 * ipc_is_listener() - Check if an fd is any listener socket.
 * @ctx: Server context.
 * @fd: File descriptor to check.
 *
 * Return: 1 if @fd is the primary or any extra listener, 0 otherwise.
 */
int ipc_is_listener(struct ipc_context *ctx, int fd);

/**
 * ipc_init_activated() - Initialize IPC from a systemd socket-activated fd.
 * @ctx: Context to initialize.
 * @fd: AF_UNIX SOCK_STREAM socket already listening (from sd_listen_fds).
 *
 * On success @ctx owns @fd and ipc_cleanup() closes it.
 *
 * Return: 0 on success, negative errno on failure.
 */
int ipc_init_activated(struct ipc_context *ctx, int fd);

/**
 * ipc_watch_socket_path() - Watch the directory holding the primary socket.
 * @ctx: Server context.
 *
 * Restarting a socket unit with RemoveOnStop=yes binds a new inode at the path:
 * titles connect to it while this daemon accepts on the old one. Without the
 * watch the daemon cannot rebind on its own.
 *
 * Return: The inotify fd to add to the caller's poll set, negative errno on
 * failure.
 */
int ipc_watch_socket_path(struct ipc_context *ctx);

/**
 * ipc_socket_watch_fd() - Get the watch descriptor.
 * @ctx: Server context, or NULL.
 *
 * Return: The inotify fd, or -1 when not watching.
 */
int ipc_socket_watch_fd(const struct ipc_context *ctx);

/**
 * ipc_socket_was_replaced() - Tell whether @path stopped naming our socket.
 * @path: Socket path the listener was bound at.
 * @dev: Device of the inode it was bound to.
 * @ino: Inode it was bound to; 0 means none was recorded.
 *
 * A listening fd outlives its path, so only the file at the name can answer.
 *
 * Return: 1 when the path is gone or names another inode, 0 otherwise.
 */
int ipc_socket_was_replaced(const char *path, dev_t dev, ino_t ino);

/**
 * ipc_recheck_socket() - Rebind if the path no longer names our socket.
 * @ctx: Server context.
 *
 * Call whenever the watch fd reports readable.
 *
 * Return: 1 when the listener was rebound, 0 when nothing changed, negative
 * errno on failure.
 */
int ipc_recheck_socket(struct ipc_context *ctx);

/**
 * ipc_set_dbus() - Attach a D-Bus context for signal emission.
 * @ctx: Server context.
 * @dbus: D-Bus context, or NULL to detach.
 *
 * Its fd joins the epoll set and state changes emit D-Bus signals on it.
 */
void ipc_set_dbus(struct ipc_context *ctx, struct dbus_context *dbus);

#endif /* LOTA_AGENT_IPC_H */
