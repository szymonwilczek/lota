/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - Daemon utilities
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
#include <time.h>
#include <unistd.h>

/* the handlers take no context */
static volatile sig_atomic_t *g_daemon_running;
static volatile sig_atomic_t *g_daemon_reload;

static void sigterm_handler(int sig)
{
	(void)sig;
	if (g_daemon_running)
		*g_daemon_running = 0;
}

static void sighup_handler(int sig)
{
	(void)sig;
	if (g_daemon_reload)
		*g_daemon_reload = 1;
}

/* write end of the startup pipe until the verdict; -1 without daemonize() */
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
			/* the low byte, as the shell sees it */
			fprintf(stderr,
				"lota-agent: startup refused (exit %d). "
				"The reason is in the journal: "
				"journalctl -t lota-agent\n",
				status & 0xff);
		_exit(status);
	}

	/* every write end closed without a verdict */
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

	if (setsid() < 0)
		return -errno;

	/* not a session leader, so no controlling terminal can be acquired */
	pid = fork();
	if (pid < 0)
		return -errno;
	if (pid > 0)
		_exit(0); /* session leader exits */

	/* the launcher reads until this end is written or closed */
	g_startup_pipe = startup_pipe[1];
	(void)fcntl(g_startup_pipe, F_SETFD, FD_CLOEXEC);

	if (chdir("/") < 0)
		return -errno;

	umask(0077);

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

/* One level only. An existing parent must not let others replace the file. */
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

const char *daemon_pidfile_path(const char *path)
{
	return path ? path : DAEMON_DEFAULT_PID_FILE;
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

	path = daemon_pidfile_path(path);

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

	return fd;
}

void pidfile_remove(const char *path, int fd)
{
	path = daemon_pidfile_path(path);

	unlink(path);

	if (fd >= 0)
		close(fd);
}

#define PIDFILE_WAIT_STEP_MS 50

int pidfile_wait_released(const char *path, unsigned int timeout_ms)
{
	const struct timespec step = {
		.tv_nsec = PIDFILE_WAIT_STEP_MS * 1000000L,
	};
	int flags = O_RDONLY | O_CLOEXEC;
	unsigned int waited = 0;
	int fd;
	int ret;

#ifdef O_NOFOLLOW
	flags |= O_NOFOLLOW;
#endif
	fd = open(daemon_pidfile_path(path), flags);
	if (fd < 0)
		return errno == ENOENT ? 0 : -errno;

	for (;;) {
		if (flock(fd, LOCK_SH | LOCK_NB) == 0) {
			ret = 0;
			break;
		}
		if (errno == EINTR)
			continue;
		if (errno != EWOULDBLOCK) {
			ret = -errno;
			break;
		}
		if (waited >= timeout_ms) {
			ret = -ETIMEDOUT;
			break;
		}
		nanosleep(&step, NULL);
		waited += PIDFILE_WAIT_STEP_MS;
	}

	close(fd);
	return ret;
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

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sigterm_handler;
	sa.sa_flags = SA_RESTART;
	sigemptyset(&sa.sa_mask);

	if (sigaction(SIGTERM, &sa, NULL) < 0)
		return -errno;
	if (sigaction(SIGINT, &sa, NULL) < 0)
		return -errno;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sighup_handler;
	sa.sa_flags = SA_RESTART;
	sigemptyset(&sa.sa_mask);

	if (sigaction(SIGHUP, &sa, NULL) < 0)
		return -errno;

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_IGN;
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);

	if (sigaction(SIGPIPE, &sa, NULL) < 0)
		return -errno;

	return 0;
}
