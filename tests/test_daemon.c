/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for daemon utilities (daemon.h / daemon.c).
 *
 * Tests PID file management, signal installation, and output
 * redirection.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../src/agent/daemon.h"

static int tests_run;
static int tests_passed;

#define TEST(name)                                         \
	do {                                               \
		tests_run++;                               \
		printf("  [%2d] %-50s ", tests_run, name); \
	} while (0)

#define PASS()                    \
	do {                      \
		tests_passed++;   \
		printf("PASS\n"); \
	} while (0)

#define FAIL(msg)                          \
	do {                               \
		printf("FAIL: %s\n", msg); \
	} while (0)

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

static void test_pidfile_default_path(void)
{
	int fd;

	TEST("pidfile_create(NULL) uses default path");

	fd = pidfile_create(NULL);
	if (fd >= 0) {
		/* running as root - clean up */
		pidfile_remove(NULL, fd);
		PASS();
		return;
	}

	/*
	 * non-root or sandboxed test runner: expect a permission/path error.
	 * important thing is it does not crash
	 */
	if (fd == -EACCES || fd == -ENOENT || fd == -ENOTDIR || fd == -EPERM ||
	    fd == -EROFS) {
		PASS();
	} else {
		char msg[128];
		snprintf(msg, sizeof(msg), "unexpected error: %d (%s)", fd,
			 strerror(-fd));
		FAIL(msg);
	}
}

/*
 * The sources are found relative to the binary when the runner is not
 * standing in the tree: build/<name> -> ../tests.
 */
static bool exe_relative_tests_dir(char *out, size_t len)
{
	char exe[PATH_MAX];
	ssize_t n;
	char *slash;

	n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
	if (n <= 0)
		return false;
	exe[n] = '\0';

	slash = strrchr(exe, '/');
	if (!slash)
		return false;
	*slash = '\0';

	if (snprintf(out, len, "%s/../tests", exe) >= (int)len)
		return false;
	return true;
}

static void scan_source_for_default_pidfile(const char *dir, const char *name,
					    unsigned *hits)
{
	static const char *const fns[] = { "pidfile_create", "pidfile_remove" };
	char path[PATH_MAX + 256];
	char line[512];
	FILE *fp;
	size_t i;
	unsigned lineno = 0;

	snprintf(path, sizeof(path), "%s/%s", dir, name);
	fp = fopen(path, "re");
	if (!fp)
		return;

	while (fgets(line, sizeof(line), fp)) {
		lineno++;
		for (i = 0; i < sizeof(fns) / sizeof(fns[0]); i++) {
			char needle[64];

			/*
			 * assembled rather than written out,
			 * so this scanner does not name what it refuses
			 */
			snprintf(needle, sizeof(needle), "%s(%s", fns[i],
				 "NULL");
			if (!strstr(line, needle))
				continue;
			printf("\n       %s:%u: %s", name, lineno, needle);
			(*hits)++;
		}
	}

	fclose(fp);
}

/*
 * The default path is the file a running agent holds. A case that asks
 * for it either fails against the live daemon's lock or, worse, takes
 * the success branch and unlinks it. No case may name it.
 */
static void test_no_case_touches_the_shipped_pid_file(void)
{
	static const char *const roots[] = { "tests", "../tests",
					     "../../tests" };
	char from_exe[PATH_MAX];
	struct dirent *ent;
	const char *dir = NULL;
	unsigned hits = 0;
	size_t i;
	DIR *d = NULL;

	TEST("no test case creates the shipped pid file");

	for (i = 0; i < sizeof(roots) / sizeof(roots[0]); i++) {
		d = opendir(roots[i]);
		if (d) {
			dir = roots[i];
			break;
		}
	}
	/* run from elsewhere: the sources sit beside the build directory */
	if (!d && exe_relative_tests_dir(from_exe, sizeof(from_exe))) {
		d = opendir(from_exe);
		if (d)
			dir = from_exe;
	}
	if (!d) {
		FAIL("could not open the tests directory");
		return;
	}

	while ((ent = readdir(d)) != NULL) {
		const char *dot = strrchr(ent->d_name, '.');

		if (!dot || strcmp(dot, ".c") != 0)
			continue;
		scan_source_for_default_pidfile(dir, ent->d_name, &hits);
	}
	closedir(d);

	if (hits) {
		printf("\n       ");
		FAIL("a case resolves the pid file to the shipped default");
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

static void test_redirect_to_devnull(void)
{
	TEST("daemon_redirect_output(NULL) -> /dev/null");

	pid_t child = fork();
	if (child < 0) {
		FAIL("fork failed");
		return;
	}

	if (child == 0) {
		int ret = daemon_redirect_output(NULL);
		if (ret < 0)
			_exit(1);

		/* stdout should now be /dev/null - write should succeed
		 * silently */
		if (printf("test\n") < 0)
			_exit(2);

		_exit(0);
	}

	int status;
	waitpid(child, &status, 0);
	if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
		PASS();
	} else {
		FAIL("redirect to /dev/null failed in child");
	}
}

static void test_redirect_to_file(void)
{
	char log_path[256];

	TEST("daemon_redirect_output(file) appends log");

	snprintf(log_path, sizeof(log_path), "%s/test.log", tmp_dir);

	pid_t child = fork();
	if (child < 0) {
		FAIL("fork failed");
		return;
	}

	if (child == 0) {
		int ret = daemon_redirect_output(log_path);
		if (ret < 0)
			_exit(1);

		printf("stdout line\n");
		fflush(stdout);
		fprintf(stderr, "stderr line\n");
		fflush(stderr);

		_exit(0);
	}

	int status;
	waitpid(child, &status, 0);

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		FAIL("child process failed");
		return;
	}

	/* verify log file contents */
	{
		FILE *f = fopen(log_path, "r");
		if (!f) {
			FAIL("log file not created");
			return;
		}
		char buf[256];
		int found_stdout = 0, found_stderr = 0;
		while (fgets(buf, sizeof(buf), f)) {
			if (strstr(buf, "stdout line"))
				found_stdout = 1;
			if (strstr(buf, "stderr line"))
				found_stderr = 1;
		}
		fclose(f);

		if (!found_stdout || !found_stderr) {
			FAIL("log file missing expected content");
			return;
		}
	}

	PASS();
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
	test_pidfile_creates_parent_dir();
	test_no_case_touches_the_shipped_pid_file();
	test_pidfile_rejects_symlink_path();

	/* signal tests */
	test_signal_install();
	test_signal_null_args();
	test_sighup_sets_reload();
	test_sigterm_clears_running();

	/* output redirection */
	test_redirect_to_devnull();
	test_redirect_to_file();

	/* daemonize */
	test_daemonize();

	cleanup_tmp_dir();

	printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
	return (tests_passed == tests_run) ? 0 : 1;
}
