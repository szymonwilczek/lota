/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Unit tests for lota-bench's cgroup v2 reader, on synthetic cgroup
 * directories.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "test.h"
#include "../tools/lota-bench/cgroup.h"

static char root[] = "/tmp/lota-bench-cgroup-XXXXXX";

static void put(const char *dir, const char *name, const char *body)
{
	char path[512];
	FILE *f;
	int fd;

	snprintf(path, sizeof(path), "%s/%s/%s", root, dir, name);
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	f = fd < 0 ? NULL : fdopen(fd, "w");
	if (!f) {
		perror(path);
		exit(1);
	}
	fputs(body, f);
	fclose(f);
}

static int mkcg(const char *dir)
{
	char path[512];
	int fd;

	snprintf(path, sizeof(path), "%s/%s", root, dir);
	if (mkdir(path, 0700) && errno != EEXIST) {
		perror(path);
		exit(1);
	}
	fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (fd < 0) {
		perror(path);
		exit(1);
	}
	return fd;
}

static int has(const struct bench_sample *s, enum bench_metric m)
{
	return !!(s->have & (1u << m));
}

static void test_full_cgroup(void)
{
	struct bench_sample s;
	int fd;

	TEST("every file present: every metric read");

	fd = mkcg("full");
	put("full", "cpu.stat",
	    "usage_usec 9000\nuser_usec 6000\nsystem_usec 3000\n"
	    "nr_periods 0\nnr_throttled 0\n");
	put("full", "memory.current", "1048576\n");
	put("full", "memory.peak", "2097152\n");
	put("full", "memory.stat",
	    "anon 4096\nfile 8192\nkernel 512\nshmem 0\n"
	    "pgfault 77\npgmajfault 3\n");
	put("full", "io.stat",
	    "8:0 rbytes=100 wbytes=200 rios=1 wios=2 dbytes=0 dios=0\n"
	    "259:0 rbytes=1000 wbytes=2000 rios=10 wios=20 dbytes=0 dios=0\n");

	if (bench_cgroup_read(fd, &s) != 0) {
		FAIL("read failed");
		goto out;
	}
	if (s.have != (1u << BM_COUNT) - 1) {
		FAIL("a metric is unset");
		goto out;
	}
	if (s.v[BM_CPU_USAGE_USEC] != 9000 || s.v[BM_CPU_USER_USEC] != 6000 ||
	    s.v[BM_CPU_SYSTEM_USEC] != 3000) {
		FAIL("cpu.stat misread");
		goto out;
	}
	if (s.v[BM_MEMORY_CURRENT_BYTES] != 1048576 ||
	    s.v[BM_MEMORY_PEAK_BYTES] != 2097152) {
		FAIL("memory.current / memory.peak misread");
		goto out;
	}
	if (s.v[BM_MEMORY_ANON_BYTES] != 4096 ||
	    s.v[BM_MEMORY_FILE_BYTES] != 8192 ||
	    s.v[BM_MEMORY_KERNEL_BYTES] != 512 || s.v[BM_PGFAULT] != 77 ||
	    s.v[BM_PGMAJFAULT] != 3) {
		FAIL("memory.stat misread");
		goto out;
	}
	if (s.v[BM_IO_READ_BYTES] != 1100 || s.v[BM_IO_WRITE_BYTES] != 2200 ||
	    s.v[BM_IO_READ_OPS] != 11 || s.v[BM_IO_WRITE_OPS] != 22) {
		FAIL("io.stat is not summed over devices");
		goto out;
	}
out:
	close(fd);
}

static void test_controllers_off(void)
{
	struct bench_sample s;
	int fd;

	TEST("no memory/io controller: only cpu metrics set");

	fd = mkcg("cpuonly");
	put("cpuonly", "cpu.stat",
	    "usage_usec 5\nuser_usec 3\nsystem_usec 2\n");

	if (bench_cgroup_read(fd, &s) != 0) {
		FAIL("read failed");
		goto out;
	}
	if (s.have != ((1u << BM_CPU_USAGE_USEC) | (1u << BM_CPU_USER_USEC) |
		       (1u << BM_CPU_SYSTEM_USEC))) {
		FAIL("a metric without its file is set");
		goto out;
	}
out:
	close(fd);
}

static void test_gone(void)
{
	struct bench_sample s;
	int fd;

	TEST("no cpu.stat: the cgroup is gone");

	fd = mkcg("gone");
	if (bench_cgroup_read(fd, &s) != -ENOENT)
		FAIL("an empty directory reads as a cgroup");
	close(fd);
}

static void test_malformed_values(void)
{
	struct bench_sample s;
	int fd;

	TEST("malformed values are left unset, not read as zero");

	fd = mkcg("bad");
	put("bad", "cpu.stat",
	    "usage_usec -1\nuser_usec 12abc\nsystem_usec 18446744073709551616\n");
	put("bad", "memory.current", "max\n");
	put("bad", "memory.stat", "anon\nfile  8\npgfault 4\n");

	if (bench_cgroup_read(fd, &s) != 0) {
		FAIL("read failed");
		goto out;
	}
	if (has(&s, BM_CPU_USAGE_USEC) || has(&s, BM_CPU_USER_USEC) ||
	    has(&s, BM_CPU_SYSTEM_USEC)) {
		FAIL("a malformed cpu.stat value is set");
		goto out;
	}
	if (has(&s, BM_MEMORY_CURRENT_BYTES) || has(&s, BM_MEMORY_ANON_BYTES) ||
	    has(&s, BM_MEMORY_FILE_BYTES)) {
		FAIL("a malformed memory value is set");
		goto out;
	}
	if (!has(&s, BM_PGFAULT) || s.v[BM_PGFAULT] != 4) {
		FAIL("a well-formed line after bad ones is lost");
		goto out;
	}
out:
	close(fd);
}

static void test_io_wrap(void)
{
	struct bench_sample s;
	int fd;

	TEST("an io.stat sum that would wrap is left unset");

	fd = mkcg("wrap");
	put("wrap", "cpu.stat", "usage_usec 1\nuser_usec 1\nsystem_usec 0\n");
	put("wrap", "io.stat",
	    "8:0 rbytes=18446744073709551615 wbytes=1 rios=1 wios=1\n"
	    "8:16 rbytes=1 wbytes=1 rios=1 wios=1\n");

	if (bench_cgroup_read(fd, &s) != 0) {
		FAIL("read failed");
		goto out;
	}
	if (has(&s, BM_IO_READ_BYTES)) {
		FAIL("a wrapped sum is recorded");
		goto out;
	}
	if (!has(&s, BM_IO_WRITE_BYTES) || s.v[BM_IO_WRITE_BYTES] != 2) {
		FAIL("the other io sums are lost");
		goto out;
	}
out:
	close(fd);
}

static void test_empty_io_stat(void)
{
	struct bench_sample s;
	int fd;

	TEST("an empty io.stat reads as no I/O yet");

	fd = mkcg("idle");
	put("idle", "cpu.stat", "usage_usec 1\nuser_usec 1\nsystem_usec 0\n");
	put("idle", "io.stat", "");

	if (bench_cgroup_read(fd, &s) != 0) {
		FAIL("read failed");
		goto out;
	}
	if (!has(&s, BM_IO_READ_BYTES) || s.v[BM_IO_READ_BYTES] != 0) {
		FAIL("an idle cgroup has no io metrics");
		goto out;
	}
out:
	close(fd);
}

static void test_names(void)
{
	int m;

	TEST("every metric has a recorded name");

	for (m = 0; m < BM_COUNT; m++) {
		if (!bench_metric_names[m] || !bench_metric_names[m][0]) {
			FAIL("a metric has no name");
			return;
		}
	}
}

int main(void)
{
	test_begin("bench cgroup");
	char cmd[256];

	if (!mkdtemp(root)) {
		perror("mkdtemp");
		return 1;
	}

	test_full_cgroup();
	test_controllers_off();
	test_gone();
	test_malformed_values();
	test_io_wrap();
	test_empty_io_stat();
	test_names();

	snprintf(cmd, sizeof(cmd), "rm -rf -- '%s'", root);
	if (system(cmd) != 0)
		fprintf(stderr, "cleanup of %s failed\n", root);

	return test_end();
}
