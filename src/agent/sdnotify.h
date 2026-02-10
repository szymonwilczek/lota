/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - systemd Integration
 *
 * Detection:
 *   sdnotify_under_systemd() checks for NOTIFY_SOCKET or
 *   INVOCATION_ID in the environment. When neither is present,
 *   all sd_notify calls are silently skipped.
 *
 * Lifecycle:
 *   sdnotify_ready()     ->  READY=1
 *   sdnotify_reloading() ->  RELOADING=1
 *   sdnotify_stopping()  ->  STOPPING=1
 *   sdnotify_status()    ->  STATUS=<text>
 *
 * Watchdog:
 *   sdnotify_watchdog_enabled()  -> read WATCHDOG_USEC
 *   sdnotify_watchdog_ping()     -> WATCHDOG=1
 *
 * Socket activation:
 *   sdnotify_listen_fds()        -> count of inherited fds
 *   sdnotify_is_unix_socket()    -> check fd type
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_AGENT_SDNOTIFY_H
#define LOTA_AGENT_SDNOTIFY_H

#include <stdbool.h>
#include <stdint.h>

/*
 * sdnotify_under_systemd - Detect if running under systemd.
 *
 * Checks NOTIFY_SOCKET and INVOCATION_ID environment variables.
 *
 * Returns: true if systemd-managed, false otherwise.
 */
bool sdnotify_under_systemd(void);

/*
 * sdnotify_ready - Signal readiness to systemd.
 *
 * Sends READY=1. For Type=notify services this unblocks
 * "systemctl start" and transitions the unit to active.
 *
 * Returns: 0 on success (or not under systemd), negative errno on error.
 */
int sdnotify_ready(void);

/*
 * sdnotify_reloading - Signal configuration reload in progress.
 *
 * Sends RELOADING=1.
 *
 * Returns: 0 on success, negative errno on error.
 */
int sdnotify_reloading(void);

/*
 * sdnotify_stopping - Signal graceful shutdown.
 *
 * Sends STOPPING=1.
 *
 * Returns: 0 on success, negative errno on error.
 */
int sdnotify_stopping(void);

/*
 * sdnotify_status - Send a human-readable status string.
 *
 * @fmt: printf-style format string.
 *
 * The status appears in "systemctl status lota-agent" output.
 * Maximum length is 256 bytes (excess is silently truncated).
 *
 * Returns: 0 on success, negative errno on error.
 */
__attribute__((format(printf, 1, 2))) int sdnotify_status(const char *fmt, ...);

/*
 * sdnotify_watchdog_enabled - Check if watchdog is active.
 *
 * @interval_usec: If non-NULL, receives the watchdog interval
 *                 in microseconds from WATCHDOG_USEC.
 *
 * Returns: true if WATCHDOG_USEC is set and > 0.
 */
bool sdnotify_watchdog_enabled(uint64_t *interval_usec);

/*
 * sdnotify_watchdog_ping - Pet the watchdog.
 *
 * Sends WATCHDOG=1. Must be called at least every
 * WATCHDOG_USEC/2 microseconds to prevent systemd from
 * killing the process.
 *
 * Returns: 0 on success, negative errno on error.
 */
int sdnotify_watchdog_ping(void);

/*
 * SD_LISTEN_FDS_START - First file descriptor passed by systemd.
 *
 * Inherited fds start at this number. fd 3 corresponds to
 * the first socket in the .socket unit's Listen* directives.
 */
#define SD_LISTEN_FDS_START 3

/*
 * sdnotify_listen_fds - Return the number of file descriptors
 *                       passed by systemd socket activation.
 *
 * Reads LISTEN_FDS and validates LISTEN_PID. On success,
 * inherited fds are [SD_LISTEN_FDS_START, SD_LISTEN_FDS_START+n).
 *
 * Returns: Number of fds (>= 0), or negative errno on error.
 */
int sdnotify_listen_fds(void);

/*
 * sdnotify_is_unix_socket - Check if an fd is a Unix stream socket.
 *
 * @fd: File descriptor to check.
 *
 * Returns: true if fd is an AF_UNIX SOCK_STREAM socket.
 */
bool sdnotify_is_unix_socket(int fd);

#endif /* LOTA_AGENT_SDNOTIFY_H */
