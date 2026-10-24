/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for the cgroup.kill walk, against a built directory tree:
 * no cgroups, no root, no agent.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../src/agent/cgroup_guard.h"
#include "../src/agent/sb_dev.h"

static int g_failures;

#define CHECK(cond, msg)                                    \
	do {                                                \
		if (!(cond)) {                              \
			fprintf(stderr, "FAIL: %s\n", msg); \
			g_failures++;                       \
		} else {                                    \
			printf("PASS: %s\n", msg);          \
		}                                           \
	} while (0)

static char g_tmpdir[64];

static void write_file(const char *path, const char *content)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	FILE *f = fd < 0 ? NULL : fdopen(fd, "w");

	if (!f) {
		fprintf(stderr, "cannot write %s: %s\n", path, strerror(errno));
		if (fd >= 0)
			close(fd);
		exit(1);
	}
	if (content)
		fputs(content, f);
	fclose(f);
}

static void make_cgroup_dir(const char *rel, int with_kill_file)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s%s", g_tmpdir, rel);
	if (mkdir(path, 0755) != 0 && errno != EEXIST) {
		fprintf(stderr, "cannot mkdir %s: %s\n", path, strerror(errno));
		exit(1);
	}
	if (!with_kill_file)
		return;

	snprintf(path, sizeof(path), "%s%s/cgroup.kill", g_tmpdir, rel);
	write_file(path, "0\n");
}

static unsigned long long ino_of(const char *rel)
{
	char path[PATH_MAX];
	struct stat st = { 0 };

	snprintf(path, sizeof(path), "%s%s/cgroup.kill", g_tmpdir, rel);
	if (stat(path, &st) != 0)
		return 0;
	return (unsigned long long)st.st_ino;
}

static void test_self_path(void)
{
	char proc_path[PATH_MAX];
	char out[PATH_MAX];
	int ret;

	snprintf(proc_path, sizeof(proc_path), "%s/proc-cgroup", g_tmpdir);

	write_file(proc_path, "0::/system.slice/lota-agent.service\n");
	ret = cgroup_guard_self_path(proc_path, out, sizeof(out));
	CHECK(ret == 0 && strcmp(out, "/system.slice/lota-agent.service") == 0,
	      "the unified-hierarchy record names the agent's cgroup");

	/* hybrid host: v1 controller records come first */
	write_file(proc_path, "3:devices:/system.slice\n"
			      "1:name=systemd:/system.slice/other.service\n"
			      "0::/system.slice/lota-agent.service\n");
	ret = cgroup_guard_self_path(proc_path, out, sizeof(out));
	CHECK(ret == 0 && strcmp(out, "/system.slice/lota-agent.service") == 0,
	      "v1 controller records are not mistaken for the unified one");

	write_file(proc_path, "3:devices:/system.slice\n");
	ret = cgroup_guard_self_path(proc_path, out, sizeof(out));
	CHECK(ret == -ENOENT,
	      "a host with no unified hierarchy is reported, not guessed at");

	write_file(proc_path, "0::/system.slice/../other.service\n");
	ret = cgroup_guard_self_path(proc_path, out, sizeof(out));
	CHECK(ret == -EINVAL, "a record that walks upwards is refused");

	write_file(proc_path, "0::/system.slice/lota-agent.service\n");
	ret = cgroup_guard_self_path(proc_path, out, 8);
	CHECK(ret == -ENAMETOOLONG,
	      "a path longer than the caller's buffer is refused, not cut");
}

static void test_collect(void)
{
	struct cgroup_guard_file files[LOTA_CGROUP_GUARD_MAX];
	char noroot[PATH_MAX];
	char root[PATH_MAX];
	int ret;

	make_cgroup_dir("/root", 1);
	make_cgroup_dir("/root/system.slice", 1);
	make_cgroup_dir("/root/system.slice/lota-agent.service", 1);

	snprintf(root, sizeof(root), "%s/root", g_tmpdir);

	ret = cgroup_guard_collect(root, "/system.slice/lota-agent.service",
				   files, LOTA_CGROUP_GUARD_MAX);
	CHECK(ret == 3, "the agent's cgroup and both ancestors are collected");
	if (ret == 3) {
		CHECK(files[0].ino ==
			      ino_of("/root/system.slice/lota-agent.service"),
		      "the agent's own cgroup.kill comes first");
		CHECK(files[1].ino == ino_of("/root/system.slice") &&
			      files[2].ino == ino_of("/root"),
		      "each ancestor's cgroup.kill follows it");
		CHECK(files[0].dev != 0 && files[0].dev == files[2].dev,
		      "every file carries the hierarchy's superblock device");
	}

	/* the root cgroup has no cgroup.kill */
	snprintf(noroot, sizeof(noroot), "%s/noroot", g_tmpdir);
	make_cgroup_dir("/noroot", 0);
	make_cgroup_dir("/noroot/system.slice", 1);
	ret = cgroup_guard_collect(noroot, "/system.slice", files,
				   LOTA_CGROUP_GUARD_MAX);
	CHECK(ret == 1, "a level with no cgroup.kill is skipped, not fatal");

	ret = cgroup_guard_collect(root, "/system.slice/lota-agent.service",
				   files, 2);
	CHECK(ret == -ENOSPC,
	      "more kill files than the caller can hold is refused, not cut");

	ret = cgroup_guard_collect(root, "/system.slice/../other", files,
				   LOTA_CGROUP_GUARD_MAX);
	CHECK(ret == -EINVAL, "a cgroup path that walks upwards is refused");

	ret = cgroup_guard_collect(root, "/", files, LOTA_CGROUP_GUARD_MAX);
	CHECK(ret == 1, "the root of the hierarchy is one level, not two");
}

int main(void)
{
	char tmpl[] = "/tmp/lota-cgroup-guard-XXXXXX";
	char cmd[sizeof(g_tmpdir) + 32];
	unsigned long long dev = 0;
	int fd;

	if (!mkdtemp(tmpl)) {
		perror("mkdtemp");
		return 1;
	}
	snprintf(g_tmpdir, sizeof(g_tmpdir), "%s", tmpl);

	printf("=== cgroup kill-guard tests ===\n");

	test_self_path();

	/* a sandbox hiding the tmpdir's mount has no superblock dev: skip */
	fd = open(g_tmpdir, O_PATH | O_CLOEXEC);
	if (fd >= 0 && sb_dev_from_fd(fd, &dev) == 0 && dev != 0) {
		close(fd);
		test_collect();
	} else {
		if (fd >= 0)
			close(fd);
		printf("SKIP: collection (no superblock device for %s)\n",
		       g_tmpdir);
	}

	snprintf(cmd, sizeof(cmd), "rm -rf %s", g_tmpdir);
	if (system(cmd) != 0)
		fprintf(stderr, "warning: could not remove %s\n", g_tmpdir);

	printf("=== %s ===\n", g_failures ? "FAILURES" : "all passed");
	return g_failures ? 1 : 0;
}
