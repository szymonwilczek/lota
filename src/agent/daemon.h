/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - Daemon utilities
 *
 * Provides Unix daemonization and SIGHUP-driven
 * configuration reload support.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_DAEMON_H
#define LOTA_DAEMON_H

#include <signal.h>
#include <sys/types.h>

/* Default PID file path */
#define DAEMON_DEFAULT_PID_FILE "/run/lota/lota-agent.pid"

/* Maximum PID string length: "4194304\n" (kernel max PID) + NUL */
#define DAEMON_PID_STR_MAX 16

/*
 * Daemonize the current process.
 *
 * Performs the classic Unix double-fork sequence:
 *   First fork  -> parent exits, child continues
 *   setsid()    -> new session, detach from controlling terminal
 *   Second fork -> session leader exits, grandchild continues
 *   chdir("/")  -> release working directory
 *   umask(0)    -> clear file creation mask
 *   Close stdin/stdout/stderr, redirect to /dev/null
 *
 * Returns: 0 in the daemon process, does not return in parent
 *          (parent calls _exit(0)).
 *          Negative errno on failure.
 */
int daemonize(void);

/*
 * Create and lock PID file.
 *
 * Creates the parent directory if needed, writes the current PID,
 * and holds an exclusive flock() on the file. The lock is inherited
 * across exec but released on process exit, providing automatic
 * stale PID file cleanup.
 *
 * @path: PID file path (NULL for default /run/lota/lota-agent.pid)
 *
 * Returns: file descriptor (>= 0) on success (caller must keep it open),
 *          -EEXIST if another instance holds the lock,
 *          negative errno on other failures.
 */
int pidfile_create(const char *path);

/*
 * Remove PID file and release lock.
 *
 * @path: PID file path (must match the path used in pidfile_create)
 * @fd:   file descriptor returned by pidfile_create (-1 to skip close)
 */
void pidfile_remove(const char *path, int fd);

/*
 * Install signal handlers for daemon operation.
 *
 * Installs handlers for:
 *   SIGTERM -> set g_running = 0 (graceful shutdown)
 *   SIGINT  -> set g_running = 0 (graceful shutdown)
 *   SIGHUP  -> set g_reload = 1  (configuration reload)
 *   SIGPIPE -> ignored (broken network connections)
 *
 * @running: pointer to volatile sig_atomic_t for shutdown flag
 * @reload:  pointer to volatile sig_atomic_t for reload flag
 *
 * Returns: 0 on success, negative errno on failure
 */
int daemon_install_signals(volatile sig_atomic_t *running,
                           volatile sig_atomic_t *reload);

/*
 * Redirect stdout and stderr to a log file.
 *
 * When running as a daemon, output needs to go somewhere persistent.
 * In systemd mode (Type=simple, no --daemon), stdout/stderr go to
 * the journal automatically.  This function is for standalone daemon
 * mode only.
 *
 * @log_path: Path to log file (NULL to redirect to /dev/null)
 *
 * Returns: 0 on success, negative errno on failure
 */
int daemon_redirect_output(const char *log_path);

#endif /* LOTA_DAEMON_H */
