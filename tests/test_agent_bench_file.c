/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for the --bench snapshot file.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../src/agent/bench.h"

#include "test.h"

static char g_dir[] = "/tmp/lota-bench-file-XXXXXX";
static char g_path[PATH_MAX];
static char g_tmp[PATH_MAX];
static char g_decoy[PATH_MAX];

static struct bench_writer g_w;

static void cleanup(void)
{
	unlink(g_path);
	unlink(g_tmp);
	unlink(g_decoy);
}

static int read_file(const char *path, char *buf, size_t max)
{
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	ssize_t n;

	if (fd < 0)
		return -1;
	n = read(fd, buf, max - 1);
	close(fd);
	if (n < 0)
		return -1;
	buf[n] = '\0';
	return 0;
}

static int write_file(const char *path, const char *s)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	ssize_t n;

	if (fd < 0)
		return -1;
	n = write(fd, s, strlen(s));
	close(fd);
	return n == (ssize_t)strlen(s) ? 0 : -1;
}

static int is_regular(const char *path)
{
	struct stat st;

	return lstat(path, &st) == 0 && S_ISREG(st.st_mode);
}

static int commit(const char *body)
{
	bench_append(&g_w, "%s", body);
	return bench_commit_in(&g_w, g_dir);
}

static void test_fixed_path(void)
{
	TEST("the snapshot path is /run/lota/bench.json");
	if (strcmp(LOTA_BENCH_PATH, "/run/lota/bench.json") != 0)
		FAIL("expected: strcmp(LOTA_BENCH_PATH, "
		     "\"/run/lota/bench.json\") == 0");
}

static void test_replaces_whole(void)
{
	char buf[64];

	cleanup();
	TEST("first snapshot written");
	if (commit("{\"seq\":1}\n") != 0)
		FAIL("expected: commit(\"{\\\"seq\\\":1}\\n\") == 0");
	TEST("second snapshot written");
	if (commit("{}\n") != 0)
		FAIL("expected: commit(\"{}\\n\") == 0");
	TEST("a snapshot replaces the previous one whole");
	if (!(read_file(g_path, buf, sizeof(buf)) == 0 &&
	      strcmp(buf, "{}\n") == 0))
		FAIL("expected: read_file(g_path, buf, sizeof(buf)) == 0 && "
		     "strcmp(buf, \"{}\\n\") == 0");
	TEST("no temporary file is left behind");
	if (!(access(g_tmp, F_OK) < 0 && errno == ENOENT))
		FAIL("expected: access(g_tmp, F_OK) < 0 && errno == ENOENT");
}

static void test_stale_tmp_symlink(void)
{
	char buf[64];

	cleanup();
	TEST("decoy written");
	if (write_file(g_decoy, "decoy\n") != 0)
		FAIL("expected: write_file(g_decoy, \"decoy\\n\") == 0");
	TEST("symlink planted at .bench.tmp");
	if (symlink(g_decoy, g_tmp) != 0)
		FAIL("expected: symlink(g_decoy, g_tmp) == 0");
	TEST("snapshot written past a stale symlink");
	if (commit("{}\n") != 0)
		FAIL("expected: commit(\"{}\\n\") == 0");
	TEST("the symlink target is untouched");
	if (!(read_file(g_decoy, buf, sizeof(buf)) == 0 &&
	      strcmp(buf, "decoy\n") == 0))
		FAIL("expected: read_file(g_decoy, buf, sizeof(buf)) == 0 && "
		     "strcmp(buf, \"decoy\\n\") == 0");
	TEST("bench.json is a regular file");
	if (!is_regular(g_path))
		FAIL("expected: is_regular(g_path)");
}

static void test_target_symlink(void)
{
	char buf[64];

	cleanup();
	TEST("decoy written");
	if (write_file(g_decoy, "decoy\n") != 0)
		FAIL("expected: write_file(g_decoy, \"decoy\\n\") == 0");
	TEST("symlink planted at bench.json");
	if (symlink(g_decoy, g_path) != 0)
		FAIL("expected: symlink(g_decoy, g_path) == 0");
	TEST("snapshot written over a symlink");
	if (commit("{}\n") != 0)
		FAIL("expected: commit(\"{}\\n\") == 0");
	TEST("the symlink target is untouched");
	if (!(read_file(g_decoy, buf, sizeof(buf)) == 0 &&
	      strcmp(buf, "decoy\n") == 0))
		FAIL("expected: read_file(g_decoy, buf, sizeof(buf)) == 0 && "
		     "strcmp(buf, \"decoy\\n\") == 0");
	TEST("the symlink is replaced, not followed");
	if (!is_regular(g_path))
		FAIL("expected: is_regular(g_path)");
}

static int fds_on_snapshot(void)
{
	DIR *d = opendir("/proc/self/fd");
	struct dirent *de;
	int found = 0;

	if (!d)
		return -1;
	while ((de = readdir(d)) != NULL) {
		char link[PATH_MAX], target[PATH_MAX];
		ssize_t n;

		snprintf(link, sizeof(link), "/proc/self/fd/%s", de->d_name);
		n = readlink(link, target, sizeof(target) - 1);
		if (n < 0)
			continue;
		target[n] = '\0';
		if (strncmp(target, g_dir, strlen(g_dir)) == 0)
			found++;
	}
	closedir(d);
	return found;
}

static void test_no_fd_held(void)
{
	cleanup();
	TEST("snapshot written");
	if (commit("{}\n") != 0)
		FAIL("expected: commit(\"{}\\n\") == 0");
	TEST("no descriptor to the file or its directory outlives a write");
	if (fds_on_snapshot() != 0)
		FAIL("expected: fds_on_snapshot() == 0");
}

static void test_overflow_skips(void)
{
	char big[LOTA_BENCH_MAX + 1];
	char buf[64];

	cleanup();
	TEST("snapshot written");
	if (commit("{\"seq\":1}\n") != 0)
		FAIL("expected: commit(\"{\\\"seq\\\":1}\\n\") == 0");

	memset(big, 'x', sizeof(big) - 1);
	big[sizeof(big) - 1] = '\0';
	bench_append(&g_w, "%s", big);
	TEST("the buffer never grows past the cap");
	if (g_w.len >= LOTA_BENCH_MAX)
		FAIL("expected: g_w.len < LOTA_BENCH_MAX");
	TEST("an oversized snapshot is refused");
	if (bench_commit_in(&g_w, g_dir) != -EMSGSIZE)
		FAIL("expected: bench_commit_in(&g_w, g_dir) == -EMSGSIZE");
	TEST("the dropped snapshot is counted");
	if (g_w.skipped != 1)
		FAIL("expected: g_w.skipped == 1");
	TEST("the previous snapshot stays in place");
	if (!(read_file(g_path, buf, sizeof(buf)) == 0 &&
	      strcmp(buf, "{\"seq\":1}\n") == 0))
		FAIL("expected: read_file(g_path, buf, sizeof(buf)) == 0 && "
		     "strcmp(buf, \"{\\\"seq\\\":1}\\n\") == 0");
	TEST("the writer recovers after a drop");
	if (commit("{}\n") != 0)
		FAIL("expected: commit(\"{}\\n\") == 0");
}

static void test_mode(void)
{
	struct stat st;
	mode_t old = umask(0077);

	cleanup();
	TEST("snapshot written under umask 0077");
	if (commit("{}\n") != 0)
		FAIL("expected: commit(\"{}\\n\") == 0");
	umask(old);
	TEST("the snapshot is 0640 whatever the umask");
	if (!(stat(g_path, &st) == 0 && (st.st_mode & 07777) == 0640))
		FAIL("expected: stat(g_path, &st) == 0 && (st.st_mode & "
		     "07777) == 0640");
	TEST("the snapshot carries the reader group");
	if (st.st_gid != getegid())
		FAIL("expected: st.st_gid == getegid()");
}

static void test_fifo_not_read(void)
{
	cleanup();
	TEST("FIFO planted at bench.json");
	if (mkfifo(g_path, 0600) != 0)
		FAIL("expected: mkfifo(g_path, 0600) == 0");
	alarm(5);
	TEST("snapshot written over a FIFO");
	if (commit("{}\n") != 0)
		FAIL("expected: commit(\"{}\\n\") == 0");
	alarm(0);
	TEST("the FIFO is replaced, never opened");
	if (!is_regular(g_path))
		FAIL("expected: is_regular(g_path)");
}

static void test_missing_dir(void)
{
	char gone[PATH_MAX];

	snprintf(gone, sizeof(gone), "%s/absent", g_dir);
	bench_append(&g_w, "{}\n");
	TEST("a missing directory is reported");
	if (bench_commit_in(&g_w, gone) != -ENOENT)
		FAIL("expected: bench_commit_in(&g_w, gone) == -ENOENT");
	TEST("the buffer is reset after a failed write");
	if (g_w.len != 0)
		FAIL("expected: g_w.len == 0");
}

int main(void)
{
	test_begin("agent bench file");

	if (!mkdtemp(g_dir)) {
		perror("mkdtemp");
		return 1;
	}
	snprintf(g_path, sizeof(g_path), "%s/%s", g_dir, LOTA_BENCH_NAME);
	snprintf(g_tmp, sizeof(g_tmp), "%s/%s", g_dir, LOTA_BENCH_TMP_NAME);
	snprintf(g_decoy, sizeof(g_decoy), "%s/decoy", g_dir);

	bench_writer_init(&g_w, getegid());

	test_fixed_path();
	test_replaces_whole();
	test_stale_tmp_symlink();
	test_target_symlink();
	test_no_fd_held();
	test_overflow_skips();
	test_mode();
	test_fifo_not_read();
	test_missing_dir();

	cleanup();
	rmdir(g_dir);

	return test_end();
}
