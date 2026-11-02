/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for daemon utilities (daemon.h / daemon.c).
 *
 * Tests PID file management, signal installation, and output
 * redirection.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "test.h"
#include "../src/agent/daemon.h"

static char tmp_dir[128];

static void setup_tmp_dir(void)
{
	snprintf(tmp_dir, sizeof(tmp_dir), "/tmp/lota_td_%d", getpid());
	mkdir(tmp_dir, 0755);
}

static void cleanup_tmp_dir(void)
{
	char cmd[512];
	snprintf(cmd, sizeof(cmd), "rm -rf %s", tmp_dir);
	int ret = system(cmd);
	(void)ret;
}

static void test_pidfile_create_remove(void)
{
	char path[256];
	int fd;
	char buf[32];
	ssize_t n;
	struct stat st;

	TEST("pidfile_create + pidfile_remove");

	snprintf(path, sizeof(path), "%s/test.pid", tmp_dir);

	fd = pidfile_create(path);
	if (fd < 0) {
		FAIL("pidfile_create returned error");
		return;
	}

	/* fstat the descriptor we created, not the name, to avoid a TOCTOU
	 * window between the permission check and the read-back below */
	if (fstat(fd, &st) < 0) {
		FAIL("fstat on PID file failed");
		pidfile_remove(path, fd);
		return;
	}

	if ((st.st_mode & 077) != 0) {
		FAIL("PID file permissions are too permissive (expected 0600)");
		pidfile_remove(path, fd);
		return;
	}

	/* verify file exists and contains our PID */
	{
		int rfd = open(path, O_RDONLY);
		if (rfd < 0) {
			FAIL("PID file not readable");
			pidfile_remove(path, fd);
			return;
		}
		n = read(rfd, buf, sizeof(buf) - 1);
		close(rfd);

		if (n <= 0) {
			FAIL("PID file empty");
			pidfile_remove(path, fd);
			return;
		}
		buf[n] = '\0';

		int file_pid = atoi(buf);
		if (file_pid != getpid()) {
			FAIL("PID file contains wrong PID");
			pidfile_remove(path, fd);
			return;
		}
	}

	pidfile_remove(path, fd);

	/* verify file removed */
	if (access(path, F_OK) == 0) {
		FAIL("PID file not removed");
		return;
	}

	PASS();
}

static void test_pidfile_double_lock(void)
{
	char path[256];
	int fd1, fd2;

	TEST("pidfile double lock -> -EEXIST");

	snprintf(path, sizeof(path), "%s/lock.pid", tmp_dir);

	fd1 = pidfile_create(path);
	if (fd1 < 0) {
		FAIL("first pidfile_create failed");
		return;
	}

	/* second call should fail with -EEXIST */
	fd2 = pidfile_create(path);
	if (fd2 != -EEXIST) {
		char msg[128];
		snprintf(msg, sizeof(msg), "expected -EEXIST, got %d", fd2);
		FAIL(msg);
		if (fd2 >= 0)
			close(fd2);
		pidfile_remove(path, fd1);
		return;
	}

	pidfile_remove(path, fd1);
	PASS();
}

static void test_pidfile_lock_release_on_close(void)
{
	char path[256];
	int fd1, fd2;

	TEST("pidfile lock released after close");

	snprintf(path, sizeof(path), "%s/release.pid", tmp_dir);

	fd1 = pidfile_create(path);
	if (fd1 < 0) {
		FAIL("first pidfile_create failed");
		return;
	}

	/* close fd -> lock released */
	close(fd1);
	unlink(path);

	/* now second create should succeed */
	fd2 = pidfile_create(path);
	if (fd2 < 0) {
		char msg[128];
		snprintf(msg, sizeof(msg), "second pidfile_create failed: %d",
			 fd2);
		FAIL(msg);
		return;
	}

	pidfile_remove(path, fd2);
	PASS();
}

/* resolve only: creating the default would clobber a running agent's file */
static void test_pidfile_default_path(void)
{
	const char *resolved;

	TEST("a NULL pid file resolves to the shipped default");

	resolved = daemon_pidfile_path(NULL);
	if (!resolved) {
		FAIL("daemon_pidfile_path(NULL) returned NULL");
		return;
	}
	if (strcmp(resolved, DAEMON_DEFAULT_PID_FILE) != 0) {
		char msg[256];
		snprintf(msg, sizeof(msg), "resolved to %s, expected %s",
			 resolved, DAEMON_DEFAULT_PID_FILE);
		FAIL(msg);
		return;
	}
	/* a relative default would land in whatever directory started us */
	if (resolved[0] != '/') {
		FAIL("the default path is not absolute");
		return;
	}
	PASS();
}

static void test_pidfile_explicit_path_is_kept(void)
{
	char path[256];
	const char *resolved;

	TEST("pidfile path given by the caller is used as given");

	snprintf(path, sizeof(path), "%s/explicit.pid", tmp_dir);

	resolved = daemon_pidfile_path(path);
	if (!resolved || strcmp(resolved, path) != 0) {
		FAIL("caller path was not returned unchanged");
		return;
	}
	PASS();
}

static void test_pidfile_creates_parent_dir(void)
{
	char path[256];
	int fd;
	struct stat st;

	TEST("pidfile_create creates parent directory");

	snprintf(path, sizeof(path), "%s/subdir/nested.pid", tmp_dir);

	fd = pidfile_create(path);
	if (fd < 0) {
		char msg[128];
		snprintf(msg, sizeof(msg), "pidfile_create failed: %d (%s)", fd,
			 strerror(-fd));
		FAIL(msg);
		return;
	}

	/* verify parent dir exists */
	{
		char dir[256];
		snprintf(dir, sizeof(dir), "%s/subdir", tmp_dir);
		if (stat(dir, &st) < 0 || !S_ISDIR(st.st_mode)) {
			FAIL("parent directory not created");
			pidfile_remove(path, fd);
			return;
		}
		if ((st.st_mode & 022) != 0) {
			FAIL("parent directory is group/world writable");
			pidfile_remove(path, fd);
			return;
		}
	}

	pidfile_remove(path, fd);
	PASS();
}

static void test_pidfile_rejects_symlink_path(void)
{
	char target[256];
	char linkpath[256];
	int tfd;
	int fd;
	char before[32] = { 0 };
	char after[32] = { 0 };
	ssize_t n;

	TEST("pidfile_create rejects symlink path");

	snprintf(target, sizeof(target), "%s/target.txt", tmp_dir);
	snprintf(linkpath, sizeof(linkpath), "%s/link.pid", tmp_dir);

	tfd = open(target, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (tfd < 0) {
		FAIL("failed to create target file");
		return;
	}
	if (write(tfd, "SAFE", 4) != 4) {
		close(tfd);
		FAIL("failed to seed target file");
		return;
	}
	close(tfd);

	if (symlink(target, linkpath) < 0) {
		FAIL("failed to create symlink");
		return;
	}

	fd = pidfile_create(linkpath);
	if (fd >= 0) {
		pidfile_remove(linkpath, fd);
		FAIL("expected pidfile_create to reject symlink path");
		return;
	}

	tfd = open(target, O_RDONLY | O_CLOEXEC);
	if (tfd < 0) {
		FAIL("failed to reopen target file");
		return;
	}
	n = read(tfd, before, sizeof(before) - 1);
	close(tfd);
	if (n < 0) {
		FAIL("failed to read target file");
		return;
	}
	before[n] = '\0';

	if (strcmp(before, "SAFE") != 0) {
		snprintf(after, sizeof(after), "target modified: '%s'", before);
		FAIL(after);
		return;
	}

	PASS();
}

static long elapsed_ms(const struct timespec *from)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	return (now.tv_sec - from->tv_sec) * 1000 +
	       (now.tv_nsec - from->tv_nsec) / 1000000;
}

/* a child takes the PID file, says so on @ready, holds it @hold_ms, exits */
static pid_t hold_pidfile(const char *path, int hold_ms)
{
	int pfd[2];
	pid_t pid;
	char c;

	if (pipe(pfd) < 0)
		return -1;

	pid = fork();
	if (pid == 0) {
		int fd = pidfile_create(path);

		close(pfd[0]);
		c = fd >= 0 ? 'y' : 'n';
		if (write(pfd[1], &c, 1) != 1)
			_exit(1);
		usleep((useconds_t)hold_ms * 1000);
		pidfile_remove(path, fd);
		_exit(0);
	}

	close(pfd[1]);
	if (pid < 0 || read(pfd[0], &c, 1) != 1 || c != 'y') {
		close(pfd[0]);
		if (pid > 0)
			waitpid(pid, NULL, 0);
		return -1;
	}
	close(pfd[0]);
	return pid;
}

static void test_pidfile_wait_missing(void)
{
	char path[256];
	int ret;

	TEST("pidfile_wait_released: no file -> 0");

	snprintf(path, sizeof(path), "%s/none.pid", tmp_dir);
	ret = pidfile_wait_released(path, 1000);
	if (ret != 0) {
		char msg[64];

		snprintf(msg, sizeof(msg), "expected 0, got %d", ret);
		FAIL(msg);
		return;
	}
	PASS();
}

static void test_pidfile_wait_stale(void)
{
	char path[256];
	int fd;
	int ret;

	TEST("pidfile_wait_released: file nobody holds -> 0");

	snprintf(path, sizeof(path), "%s/stale.pid", tmp_dir);
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0) {
		FAIL("cannot create stale pid file");
		return;
	}
	close(fd);

	ret = pidfile_wait_released(path, 1000);
	unlink(path);
	if (ret != 0) {
		char msg[64];

		snprintf(msg, sizeof(msg), "expected 0, got %d", ret);
		FAIL(msg);
		return;
	}
	PASS();
}

static void test_pidfile_wait_until_holder_exits(void)
{
	struct timespec start;
	char path[256];
	pid_t pid;
	long ms;
	int ret;

	TEST("pidfile_wait_released: returns once the holder exits");

	snprintf(path, sizeof(path), "%s/held.pid", tmp_dir);
	pid = hold_pidfile(path, 300);
	if (pid < 0) {
		FAIL("child could not take the pid file");
		return;
	}

	clock_gettime(CLOCK_MONOTONIC, &start);
	ret = pidfile_wait_released(path, 5000);
	ms = elapsed_ms(&start);
	waitpid(pid, NULL, 0);

	if (ret != 0 || ms < 200) {
		char msg[96];

		snprintf(msg, sizeof(msg),
			 "expected 0 after the holder exits, got %d in %ld ms",
			 ret, ms);
		FAIL(msg);
		return;
	}
	PASS();
}

static void test_pidfile_wait_times_out(void)
{
	struct timespec start;
	char path[256];
	pid_t pid;
	long ms;
	int ret;

	TEST("pidfile_wait_released: held past the timeout -> -ETIMEDOUT");

	snprintf(path, sizeof(path), "%s/stuck.pid", tmp_dir);
	pid = hold_pidfile(path, 2000);
	if (pid < 0) {
		FAIL("child could not take the pid file");
		return;
	}

	clock_gettime(CLOCK_MONOTONIC, &start);
	ret = pidfile_wait_released(path, 300);
	ms = elapsed_ms(&start);
	kill(pid, SIGKILL);
	waitpid(pid, NULL, 0);
	unlink(path);

	if (ret != -ETIMEDOUT || ms < 200 || ms > 1500) {
		char msg[96];

		snprintf(msg, sizeof(msg),
			 "expected -ETIMEDOUT after ~300 ms, got %d in %ld ms",
			 ret, ms);
		FAIL(msg);
		return;
	}
	PASS();
}

static void test_signal_install(void)
{
	volatile sig_atomic_t running = 1;
	volatile sig_atomic_t reload = 0;
	int ret;

	TEST("daemon_install_signals installs handlers");

	ret = daemon_install_signals(&running, &reload);
	if (ret < 0) {
		char msg[128];
		snprintf(msg, sizeof(msg), "daemon_install_signals failed: %d",
			 ret);
		FAIL(msg);
		return;
	}

	/* verify handlers are installed by checking sigaction */
	{
		struct sigaction sa;
		sigaction(SIGTERM, NULL, &sa);
		if (sa.sa_handler == SIG_DFL || sa.sa_handler == SIG_IGN) {
			FAIL("SIGTERM handler not installed");
			return;
		}

		sigaction(SIGHUP, NULL, &sa);
		if (sa.sa_handler == SIG_DFL || sa.sa_handler == SIG_IGN) {
			FAIL("SIGHUP handler not installed");
			return;
		}

		sigaction(SIGPIPE, NULL, &sa);
		if (sa.sa_handler != SIG_IGN) {
			FAIL("SIGPIPE not ignored");
			return;
		}
	}

	PASS();
}

static void test_signal_null_args(void)
{
	int ret;

	TEST("daemon_install_signals(NULL, ...) -> -EINVAL");

	ret = daemon_install_signals(NULL, NULL);
	if (ret != -EINVAL) {
		char msg[128];
		snprintf(msg, sizeof(msg), "expected -EINVAL, got %d", ret);
		FAIL(msg);
		return;
	}

	PASS();
}

static void test_sighup_sets_reload(void)
{
	volatile sig_atomic_t running = 1;
	volatile sig_atomic_t reload = 0;

	TEST("SIGHUP sets reload flag");

	daemon_install_signals(&running, &reload);

	/* send SIGHUP to self */
	kill(getpid(), SIGHUP);

	if (reload != 1) {
		FAIL("reload flag not set");
		return;
	}

	if (running != 1) {
		FAIL("running flag should still be 1");
		return;
	}

	PASS();
}

static void test_sigterm_clears_running(void)
{
	volatile sig_atomic_t running = 1;
	volatile sig_atomic_t reload = 0;

	TEST("SIGTERM clears running flag");

	pid_t child = fork();
	if (child < 0) {
		FAIL("fork failed");
		return;
	}

	if (child == 0) {
		/* child */
		daemon_install_signals(&running, &reload);
		kill(getpid(), SIGTERM);

		/* running should be 0 */
		_exit(running == 0 ? 0 : 1);
	}

	int status;
	waitpid(child, &status, 0);

	if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
		PASS();
	} else {
		FAIL("child did not exit cleanly with running=0");
	}
}

static void test_daemonize(void)
{
	char marker_path[256];

	TEST("daemonize -> grandchild writes marker file");

	snprintf(marker_path, sizeof(marker_path), "%s/daemon_marker", tmp_dir);

	pid_t child = fork();
	if (child < 0) {
		FAIL("fork failed");
		return;
	}

	if (child == 0) {
		int ret = daemonize();
		if (ret < 0)
			_exit(1);

		/* grandchild daemon now */
		int mfd = open(marker_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
		FILE *f = mfd >= 0 ? fdopen(mfd, "w") : NULL;
		if (mfd >= 0 && !f)
			close(mfd);
		if (f) {
			fprintf(f, "%d\n", getpid());
			fclose(f);
		}
		_exit(0);
	}

	/* wait for the child */
	int status;
	waitpid(child, &status, 0);

	/* give the grandchild a moment to write the marker */
	usleep(200000); /* 200ms */

	/* open directly and rely on the result instead of access()+open,
	 * which races on the marker path */
	FILE *f = fopen(marker_path, "r");
	if (f) {
		int daemon_pid = 0;
		if (fscanf(f, "%d", &daemon_pid) == 1) {
			if (daemon_pid != child && daemon_pid != getpid()) {
				PASS();
			} else {
				FAIL("daemon PID should differ from "
				     "child and parent");
			}
		} else {
			FAIL("could not read daemon PID from marker");
		}
		fclose(f);
	} else {
		FAIL("daemon did not write marker file");
	}
}

int main(void)
{
	printf("=== Daemon Module Tests ===\n\n");

	setup_tmp_dir();

	/* PID file tests */
	test_pidfile_create_remove();
	test_pidfile_double_lock();
	test_pidfile_lock_release_on_close();
	test_pidfile_default_path();
	test_pidfile_explicit_path_is_kept();
	test_pidfile_creates_parent_dir();
	test_pidfile_rejects_symlink_path();
	test_pidfile_wait_missing();
	test_pidfile_wait_stale();
	test_pidfile_wait_until_holder_exits();
	test_pidfile_wait_times_out();

	/* signal tests */
	test_signal_install();
	test_signal_null_args();
	test_sighup_sets_reload();
	test_sigterm_clears_running();

	/* daemonize */
	test_daemonize();

	cleanup_tmp_dir();

	printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
	return (tests_passed == tests_run) ? 0 : 1;
}
