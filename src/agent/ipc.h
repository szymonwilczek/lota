/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - IPC Server Module
 */

#ifndef LOTA_AGENT_IPC_H
#define LOTA_AGENT_IPC_H

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

struct tpm_context;
struct dbus_context;
struct ipc_client;

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
  int fd;              /* Listening fd (-1 if unused) */
  char path[PATH_MAX]; /* Socket path for cleanup */
};

/*
 * IPC server context
 */
struct ipc_context {
  int listen_fd; /* Primary listening socket */
  int epoll_fd;  /* epoll instance */
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

  /* TPM context for token signing */
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
 * ipc_set_mode - Update current mode
 * @ctx: Server context
 * @mode: New mode (enum lota_mode)
 */
void ipc_set_mode(struct ipc_context *ctx, uint8_t mode);

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
