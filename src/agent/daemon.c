/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - Daemon utilities
 *
 * Unix daemonization, PID file management, and signal handling.
 *
 * When running under systemd (Type=simple), daemonization is NOT needed
 * because systemd manages the process lifecycle.  In that case, only
 * the PID file and signal handlers are relevant.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include "daemon.h"

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * Pointers to the caller's flags, set by daemon_install_signals().
 * These are module-level so that the async-signal-safe handlers
 * (which cannot take arguments) can reach them.
 */
static volatile sig_atomic_t *g_daemon_running;
static volatile sig_atomic_t *g_daemon_reload;

/*
 * Signal handler: graceful shutdown (SIGTERM, SIGINT).
 * Async-signal-safe: only writes to a volatile sig_atomic_t.
 */
static void sigterm_handler(int sig)
{
	(void)sig;
	if (g_daemon_running)
		*g_daemon_running = 0;
}

/*
 * Signal handler: configuration reload (SIGHUP).
 * Async-signal-safe: only writes to a volatile sig_atomic_t.
 */
static void sighup_handler(int sig)
{
	(void)sig;
	if (g_daemon_reload)
		*g_daemon_reload = 1;
}

/*
 * Write end of the pipe the daemon reports its startup verdict on,
 * held by the daemon process for as long as it has not reported.
 * -1 when the process was not daemonised, which is what makes
 * daemon_notify_started() a no-op in the foreground.
 */
static int g_startup_pipe = -1;

void daemon_notify_started(int status)
{
	ssize_t written;

	if (g_startup_pipe < 0)
		return;

	do {
		written = write(g_startup_pipe, &status, sizeof(status));
	} while (written < 0 && errno == EINTR);

	close(g_startup_pipe);
	g_startup_pipe = -1;
}

/*
 * The launching process, once it has forked: wait for the daemon to say how
 * its startup ended and exit with that.
 *
 * This is the half of daemonising that has to stay: a caller that gets its
 * shell back has been told the agent is up, and only the daemon knows whether
 * it is.
 * Reading blocks for as long as startup takes, which is the same wait
 * a foreground start asks for.
 */
static void daemon_await_child(int read_fd) __attribute__((noreturn));

static void daemon_await_child(int read_fd)
{
	int status = 0;
	ssize_t got;

	do {
		got = read(read_fd, &status, sizeof(status));
	} while (got < 0 && errno == EINTR);

	if (got == (ssize_t)sizeof(status)) {
		if (status != 0)
			/*
			 * Reported as the caller will see it:
			 * an exit status is the low byte, and the daemon reports
			 * negative errnos among its own.
			 */
			fprintf(stderr,
				"lota-agent: startup refused (exit %d). "
				"The reason is in the journal: "
				"journalctl -t lota-agent\n",
				status & 0xff);
		_exit(status);
	}

	/*
	 * The pipe closed with nothing on it, so the daemon died before it
	 * reached either verdict.
	 * This is a failed start too, and the caller is told so.
	 */
	fprintf(stderr,
		"lota-agent: the agent exited before startup completed. "
		"The reason is in the journal: journalctl -t lota-agent\n");
	_exit(1);
}

int daemonize(void)
{
	pid_t pid;
	int fd;
	int startup_pipe[2];

	if (pipe(startup_pipe) < 0)
		return -errno;

	/*
	 * first fork: detach from parent process
	 */
	pid = fork();
	if (pid < 0) {
		int err = errno;
		close(startup_pipe[0]);
		close(startup_pipe[1]);
		return -err;
	}
	if (pid > 0) {
		close(startup_pipe[1]);
		daemon_await_child(startup_pipe[0]); /* does not return */
	}

	close(startup_pipe[0]);

	/*
	 * create new session and process group
	 */
	if (setsid() < 0)
		return -errno;

	/*
	 * second fork: ensure the daemon can never accidentally
	 * re-acquire a controlling terminal
	 * Grandchild is NOT a session leader
	 */
	pid = fork();
	if (pid < 0)
		return -errno;
	if (pid > 0)
		_exit(0); /* session leader exits */

	/*
	 * The daemon proper.
	 * It owns the verdict from here, and holding the write end is what
	 * makes the launching process wait.
	 */
	g_startup_pipe = startup_pipe[1];
	(void)fcntl(g_startup_pipe, F_SETFD, FD_CLOEXEC);

	if (chdir("/") < 0)
		return -errno;

	umask(0077);

	/*
	 * close inherited file descriptors and redirect standard
	 * streams to /dev/null
	 */
	fd = open("/dev/null", O_RDWR);
	if (fd < 0)
		return -errno;

	if (dup2(fd, STDIN_FILENO) < 0 || dup2(fd, STDOUT_FILENO) < 0 ||
	    dup2(fd, STDERR_FILENO) < 0) {
		int err = errno;
		close(fd);
		return -err;
	}

	if (fd > STDERR_FILENO)
		close(fd);

	return 0;
}

/*
 * Create parent directories for a path.
 * Only creates the final directory component's parent.
 */
static int ensure_parent_dir(const char *path)
{
	char *pathcopy;
	char *dir;
	struct stat st;
	int ret = 0;
	uid_t euid = geteuid();

	pathcopy = strdup(path);
	if (!pathcopy)
		return -ENOMEM;

	dir = dirname(pathcopy);

	if (stat(dir, &st) == 0) {
		if (!S_ISDIR(st.st_mode))
			ret = -ENOTDIR;
		else if ((st.st_mode & S_IWOTH) && !(st.st_mode & S_ISVTX))
			ret = -EPERM;
		else if (st.st_uid != euid && !(st.st_mode & S_ISVTX))
			ret = -EPERM;
		goto out;
	}

	if (mkdir(dir, 0700) < 0 && errno != EEXIST) {
		ret = -errno;
		goto out;
	}

out:
	free(pathcopy);
	return ret;
}

int pidfile_create(const char *path)
{
	int fd;
	int ret;
	char pidbuf[DAEMON_PID_STR_MAX];
	ssize_t len;
	int flags;
	struct stat st;
	uid_t euid = geteuid();

	if (!path)
		path = DAEMON_DEFAULT_PID_FILE;

	ret = ensure_parent_dir(path);
	if (ret < 0)
		return ret;

	flags = O_RDWR | O_CREAT | O_CLOEXEC;
#ifdef O_NOFOLLOW
	flags |= O_NOFOLLOW;
#endif

	fd = open(path, flags, 0600);
	if (fd < 0)
		return -errno;

	if (fstat(fd, &st) < 0) {
		ret = -errno;
		close(fd);
		return ret;
	}

	if (!S_ISREG(st.st_mode) || st.st_nlink != 1) {
		close(fd);
		return -EINVAL;
	}

	if (st.st_uid != euid) {
		close(fd);
		return -EPERM;
	}

	if (fchmod(fd, 0600) < 0) {
		ret = -errno;
		close(fd);
		unlink(path);
		return ret;
	}

	if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
		int err = errno;
		close(fd);
		return (err == EWOULDBLOCK) ? -EEXIST : -err;
	}

	if (ftruncate(fd, 0) < 0) {
		ret = -errno;
		close(fd);
		unlink(path);
		return ret;
	}

	len = snprintf(pidbuf, sizeof(pidbuf), "%d\n", (int)getpid());
	if (len < 0 || write(fd, pidbuf, (size_t)len) != len) {
		ret = (len < 0) ? -EIO : -errno;
		close(fd);
		unlink(path);
		return ret;
	}

	fsync(fd);

	/* fd stays open -> lock persists until process exit */
	return fd;
}

void pidfile_remove(const char *path, int fd)
{
	if (!path)
		path = DAEMON_DEFAULT_PID_FILE;

	unlink(path);

	if (fd >= 0)
		close(fd);
}

bool daemon_reload_pending(void)
{
	return g_daemon_reload && *g_daemon_reload != 0;
}

bool daemon_reload_taken(void)
{
	if (!g_daemon_reload || *g_daemon_reload == 0)
		return false;

	*g_daemon_reload = 0;
	return true;
}

int daemon_install_signals(volatile sig_atomic_t *running,
			   volatile sig_atomic_t *reload)
{
	struct sigaction sa;

	if (!running || !reload)
		return -EINVAL;

	g_daemon_running = running;
	g_daemon_reload = reload;

	/*
	 * SIGTERM / SIGINT -> graceful shutdown.
	 * SA_RESTART: restart interrupted syscalls
	 */
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sigterm_handler;
	sa.sa_flags = SA_RESTART;
	sigemptyset(&sa.sa_mask);

	if (sigaction(SIGTERM, &sa, NULL) < 0)
		return -errno;
	if (sigaction(SIGINT, &sa, NULL) < 0)
		return -errno;

	/*
	 * SIGHUP -> reload configuration
	 */
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sighup_handler;
	sa.sa_flags = SA_RESTART;
	sigemptyset(&sa.sa_mask);

	if (sigaction(SIGHUP, &sa, NULL) < 0)
		return -errno;

	/*
	 * SIGPIPE -> ignore
	 */
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_IGN;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);

	if (sigaction(SIGPIPE, &sa, NULL) < 0)
		return -errno;

	return 0;
}

int daemon_redirect_output(const char *log_path)
{
	int fd;

	if (!log_path)
		log_path = "/dev/null";

	fd = open(log_path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0640);
	if (fd < 0)
		return -errno;

	if (dup2(fd, STDOUT_FILENO) < 0 || dup2(fd, STDERR_FILENO) < 0) {
		int err = errno;
		close(fd);
		return -err;
	}

	if (fd > STDERR_FILENO)
		close(fd);

	return 0;
}
