/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - Daemon utilities
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_DAEMON_H
#define LOTA_DAEMON_H

#include <signal.h>
#include <stdbool.h>
#include <sys/types.h>

#define DAEMON_DEFAULT_PID_FILE "/run/lota/lota-agent.pid"

/* "%d\n" of a pid, and the NUL */
#define DAEMON_PID_STR_MAX 16

/**
 * daemonize() - Detach into the background.
 *
 * Forks twice with setsid() between, changes to /, sets the umask to 0077
 * and points stdin, stdout and stderr at /dev/null. The launching process
 * waits for daemon_notify_started() and exits with the reported status,
 * or with 1 when the daemon exits without reporting.
 *
 * Return: 0 in the daemon, or a negative errno. Once the first fork()
 * succeeds, the launching process does not return.
 */
int daemonize(void);

/**
 * daemon_notify_started() - Report the startup verdict to the launcher.
 * @status: Exit status for the launching process.
 *
 * The first call wins and later calls do nothing, so an exit path may call it
 * after startup succeeded. Does nothing without daemonize().
 */
void daemon_notify_started(int status);

/**
 * daemon_pidfile_path() - The PID file path a caller means.
 * @path: Path, or NULL.
 *
 * Return: @path, or DAEMON_DEFAULT_PID_FILE for NULL.
 */
const char *daemon_pidfile_path(const char *path);

/**
 * pidfile_create() - Create, lock and fill the PID file.
 * @path: Path, or NULL for DAEMON_DEFAULT_PID_FILE.
 *
 * Creates a missing parent directory with mode 0700. The flock() lasts while
 * the returned descriptor is open; the descriptor is close-on-exec.
 *
 * Return: the descriptor, -EEXIST when another process holds the lock,
 * -EPERM when the parent lacks the sticky bit and is world-writable or owned by
 * another user, or when the file is owned by another user, -ENOTDIR for
 * a parent that is not a directory, -EINVAL for a file that is not regular or
 * has another link, or a negative errno.
 */
int pidfile_create(const char *path);

/**
 * pidfile_remove() - Unlink the PID file and drop its lock.
 * @path: Path given to pidfile_create().
 * @fd: Its descriptor, or -1.
 */
void pidfile_remove(const char *path, int fd);

/**
 * pidfile_wait_released() - Wait until no process holds the PID file's lock.
 * @path: Path, or NULL for DAEMON_DEFAULT_PID_FILE.
 * @timeout_ms: How long to wait.
 *
 * The daemon drops the lock in pidfile_remove(), after run_daemon() returns.
 *
 * Return: 0 when the lock is free or the file is missing, -ETIMEDOUT when it is
 * still held, or a negative errno.
 */
int pidfile_wait_released(const char *path, unsigned int timeout_ms);

/**
 * daemon_reload_taken() - Take a pending SIGHUP.
 *
 * For the attestation loop, which checks between rounds; the enforcement
 * daemon reads SIGHUP from a signalfd.
 *
 * Return: true when a SIGHUP came since the last call.
 */
bool daemon_reload_taken(void);

/**
 * daemon_reload_pending() - Is a SIGHUP waiting?
 *
 * Return: true when daemon_reload_taken() would take one; it stays pending.
 */
bool daemon_reload_pending(void);

/**
 * daemon_install_signals() - Handle SIGTERM, SIGINT and SIGHUP.
 * @running: Set to 0 on SIGTERM and SIGINT.
 * @reload: Set to 1 on SIGHUP.
 *
 * SIGPIPE is ignored.
 *
 * Return: 0 or a negative errno.
 */
int daemon_install_signals(volatile sig_atomic_t *running,
			   volatile sig_atomic_t *reload);

#endif /* LOTA_DAEMON_H */
