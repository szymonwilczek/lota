/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
#ifndef LOTA_AGENT_CGROUP_GUARD_H
#define LOTA_AGENT_CGROUP_GUARD_H

#include <stddef.h>

/*
 * cgroup.kill and cgroup.freeze end or stop a whole cgroup without task_kill;
 * the agent's cgroup and each ancestor below the root carry both.
 */
#define LOTA_CGROUP_GUARD_MAX 64 /* two per level; a packaged unit is 2 deep */
#define LOTA_CGROUP_MOUNT_ROOT "/sys/fs/cgroup" /* unified hierarchy */

/* a guarded cgroup file's inode as the BPF side reads it */
struct cgroup_guard_file {
	unsigned long long dev; /* superblock dev, kernel MKDEV layout */
	unsigned long long ino;
	unsigned int kind; /* LOTA_GUARD_CGROUP_* */
};

/**
 * cgroup_guard_self_path() - Read the unified-hierarchy path.
 * @proc_cgroup_path: A /proc/<pid>/cgroup file.
 * @out: Receives the path.
 * @out_len: Size of @out.
 *
 * Return: 0, -ENOENT when the file has no unified-hierarchy record,
 * or another negative errno.
 */
int cgroup_guard_self_path(const char *proc_cgroup_path, char *out,
			   size_t out_len);

/**
 * cgroup_guard_collect() - List the guarded files up to the root.
 * @mount_root: Where the hierarchy is mounted.
 * @cgroup_path: Path below @mount_root.
 * @out: Filled deepest first.
 * @max: Capacity of @out.
 *
 * Skips a file it cannot resolve; the root cgroup has neither.
 *
 * Return: the count, or a negative errno.
 */
int cgroup_guard_collect(const char *mount_root, const char *cgroup_path,
			 struct cgroup_guard_file *out, size_t max);

#endif /* LOTA_AGENT_CGROUP_GUARD_H */
