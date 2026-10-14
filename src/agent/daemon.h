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
#include <stdbool.h>
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
 * The launching process does not exit at the fork. It waits on a pipe until
 * the daemon reports how its startup ended, and exits with that status,
 * so a caller that gets its shell back has been told something true.
 * See daemon_notify_started().
 *
 * Returns: 0 in the daemon process, does not return in the launching process.
 *          Negative errno on failure.
 */
int daemonize(void);

/*
 * Report the startup verdict to the process that launched a daemon.
 *
 * Called once with 0 when the daemon is serving, and once with the exit status
 * on any path that gives up before that. The first call wins and the rest are
 * ignored, so an exit path may call it without knowing whether startup already
 * succeeded.
 *
 * A no-op when the process was not daemonised.
 *
 * @status: exit status the launching process should carry.
 */
void daemon_notify_started(int status);

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
 * Whether a SIGHUP has been taken since the last time this was asked,
 * and clearing it in the same call.
 *
 * The enforcement daemon reads its own flag off a signalfd inside its event
 * loop. The attestation loop has no event loop to hang one on and only needs
 * to know, between rounds, whether the publisher list has to be re-read
 * -- so it asks the handler that daemon_install_signals() already put in place.
 */
bool daemon_reload_taken(void);

/* Whether a SIGHUP is waiting, without taking it.
 * Lets a loop stop sleeping for a reload it will act on at the top of its
 * next pass. */
bool daemon_reload_pending(void);

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
