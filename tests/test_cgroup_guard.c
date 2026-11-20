/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for the cgroup.kill and cgroup.freeze walk, against a built
 * directory tree: no cgroups, no root, no agent.
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

#include "../include/lota.h"
#include "../src/agent/cgroup_guard.h"
#include "../src/agent/sb_dev.h"

#include "test.h"

static char g_tmpdir[64];

static void write_file(const char *path, const char *content)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	FILE *f = fd < 0 ? NULL : fdopen(fd, "w");

	if (!f) {
		FAIL("cannot write %s: %s", path, strerror(errno));
		if (fd >= 0)
			close(fd);
		exit(1);
	}
	if (content)
		fputs(content, f);
	fclose(f);
}

static void make_cgroup_file(const char *rel, const char *name)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s%s/%s", g_tmpdir, rel, name);
	write_file(path, "0\n");
}

static void make_cgroup_dir(const char *rel, int with_kill_file)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s%s", g_tmpdir, rel);
	if (mkdir(path, 0755) != 0 && errno != EEXIST) {
		FAIL("cannot mkdir %s: %s", path, strerror(errno));
		exit(1);
	}
	if (!with_kill_file)
		return;

	make_cgroup_file(rel, "cgroup.kill");
}

static unsigned long long ino_of_file(const char *rel, const char *name)
{
	char path[PATH_MAX];
	struct stat st = { 0 };

	snprintf(path, sizeof(path), "%s%s/%s", g_tmpdir, rel, name);
	if (stat(path, &st) != 0)
		return 0;
	return (unsigned long long)st.st_ino;
}

static unsigned long long ino_of(const char *rel)
{
	return ino_of_file(rel, "cgroup.kill");
}

static void test_self_path(void)
{
	char proc_path[PATH_MAX];
	char out[PATH_MAX];
	int ret;

	snprintf(proc_path, sizeof(proc_path), "%s/proc-cgroup", g_tmpdir);

	write_file(proc_path, "0::/system.slice/lota-agent.service\n");
	ret = cgroup_guard_self_path(proc_path, out, sizeof(out));
	TEST("the unified-hierarchy record names the agent's cgroup");
	if (!(ret == 0 && strcmp(out, "/system.slice/lota-agent.service") == 0))
		FAIL("expected: ret == 0 && strcmp(out, "
		     "\"/system.slice/lota-agent.service\") == 0");

	/* hybrid host: v1 controller records come first */
	write_file(proc_path, "3:devices:/system.slice\n"
			      "1:name=systemd:/system.slice/other.service\n"
			      "0::/system.slice/lota-agent.service\n");
	ret = cgroup_guard_self_path(proc_path, out, sizeof(out));
	TEST("v1 controller records are not mistaken for the unified one");
	if (!(ret == 0 && strcmp(out, "/system.slice/lota-agent.service") == 0))
		FAIL("expected: ret == 0 && strcmp(out, "
		     "\"/system.slice/lota-agent.service\") == 0");

	write_file(proc_path, "3:devices:/system.slice\n");
	ret = cgroup_guard_self_path(proc_path, out, sizeof(out));
	TEST("a host with no unified hierarchy is reported, not guessed at");
	if (ret != -ENOENT)
		FAIL("expected: ret == -ENOENT");

	write_file(proc_path, "0::/system.slice/../other.service\n");
	ret = cgroup_guard_self_path(proc_path, out, sizeof(out));
	TEST("a record that walks upwards is refused");
	if (ret != -EINVAL)
		FAIL("expected: ret == -EINVAL");

	write_file(proc_path, "0::/system.slice/lota-agent.service\n");
	ret = cgroup_guard_self_path(proc_path, out, 8);
	TEST("a path longer than the caller's buffer is refused, not cut");
	if (ret != -ENAMETOOLONG)
		FAIL("expected: ret == -ENAMETOOLONG");
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
	TEST("the agent's cgroup and both ancestors are collected");
	if (ret != 3)
		FAIL("expected: ret == 3");
	if (ret == 3) {
		TEST("the agent's own cgroup.kill comes first");
		if (files[0].ino !=
		    ino_of("/root/system.slice/lota-agent.service"))
			FAIL("expected: files[0].ino == "
			     "ino_of(\"/root/system.slice/lota-agent.service\")");
		TEST("each ancestor's cgroup.kill follows it");
		if (!(files[1].ino == ino_of("/root/system.slice") &&
		      files[2].ino == ino_of("/root")))
			FAIL("expected: files[1].ino == "
			     "ino_of(\"/root/system.slice\") && files[2].ino == "
			     "ino_of(\"/root\")");
		TEST("every file carries the hierarchy's superblock device");
		if (!(files[0].dev != 0 && files[0].dev == files[2].dev))
			FAIL("expected: files[0].dev != 0 && files[0].dev == "
			     "files[2].dev");
	}

	/* the root cgroup has no cgroup.kill */
	snprintf(noroot, sizeof(noroot), "%s/noroot", g_tmpdir);
	make_cgroup_dir("/noroot", 0);
	make_cgroup_dir("/noroot/system.slice", 1);
	ret = cgroup_guard_collect(noroot, "/system.slice", files,
				   LOTA_CGROUP_GUARD_MAX);
	TEST("a level with no cgroup.kill is skipped, not fatal");
	if (ret != 1)
		FAIL("expected: ret == 1");

	ret = cgroup_guard_collect(root, "/system.slice/lota-agent.service",
				   files, 2);
	TEST("more kill files than the caller can hold is refused, not cut");
	if (ret != -ENOSPC)
		FAIL("expected: ret == -ENOSPC");

	ret = cgroup_guard_collect(root, "/system.slice/../other", files,
				   LOTA_CGROUP_GUARD_MAX);
	TEST("a cgroup path that walks upwards is refused");
	if (ret != -EINVAL)
		FAIL("expected: ret == -EINVAL");

	ret = cgroup_guard_collect(root, "/", files, LOTA_CGROUP_GUARD_MAX);
	TEST("the root of the hierarchy is one level, not two");
	if (ret != 1)
		FAIL("expected: ret == 1");
}

/* cgroup.freeze stops the agent past every signal hook as cgroup.kill ends it */
static void test_collect_freeze(void)
{
	struct cgroup_guard_file files[LOTA_CGROUP_GUARD_MAX];
	char root[PATH_MAX];
	int ret;

	make_cgroup_dir("/froot", 0);
	make_cgroup_dir("/froot/system.slice", 1);
	make_cgroup_file("/froot/system.slice", "cgroup.freeze");
	make_cgroup_dir("/froot/system.slice/lota-agent.service", 1);
	make_cgroup_file("/froot/system.slice/lota-agent.service",
			 "cgroup.freeze");

	snprintf(root, sizeof(root), "%s/froot", g_tmpdir);
	ret = cgroup_guard_collect(root, "/system.slice/lota-agent.service",
				   files, LOTA_CGROUP_GUARD_MAX);
	TEST("both files of both levels are collected");
	if (ret != 4)
		FAIL("expected: ret == 4");
	if (ret == 4) {
		TEST("each level gives its kill file, then its freeze file");
		if (!(files[0].kind == LOTA_GUARD_CGROUP_KILL &&
		      files[1].kind == LOTA_GUARD_CGROUP_FREEZE))
			FAIL("expected: files[0].kind == LOTA_GUARD_CGROUP_KILL && "
			     "files[1].kind == LOTA_GUARD_CGROUP_FREEZE");
		TEST("the agent's own cgroup.freeze is guarded");
		if (files[1].ino !=
		    ino_of_file("/froot/system.slice/lota-agent.service",
				"cgroup.freeze"))
			FAIL("expected: files[1].ino == ino_of_file( "
			     "\"/froot/system.slice/lota-agent.service\", "
			     "\"cgroup.freeze\")");
		TEST("an ancestor's cgroup.freeze is guarded");
		if (files[3].ino !=
		    ino_of_file("/froot/system.slice", "cgroup.freeze"))
			FAIL("expected: files[3].ino == "
			     "ino_of_file(\"/froot/system.slice\", \"cgroup.freeze\")");
	}

	ret = cgroup_guard_collect(root, "/system.slice/lota-agent.service",
				   files, 3);
	TEST("a freeze file past the caller's room is refused");
	if (ret != -ENOSPC)
		FAIL("expected: ret == -ENOSPC");
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

	test_begin("cgroup guard");

	test_self_path();

	/* a sandbox hiding the tmpdir's mount has no superblock dev: skip */
	fd = open(g_tmpdir, O_PATH | O_CLOEXEC);
	if (fd >= 0 && sb_dev_from_fd(fd, &dev) == 0 && dev != 0) {
		close(fd);
		test_collect();
		test_collect_freeze();
	} else {
		if (fd >= 0)
			close(fd);
		SKIP("collection (no superblock device for %s)", g_tmpdir);
	}

	snprintf(cmd, sizeof(cmd), "rm -rf %s", g_tmpdir);
	if (system(cmd) != 0)
		fprintf(stderr, "warning: could not remove %s\n", g_tmpdir);

	return test_end();
}
