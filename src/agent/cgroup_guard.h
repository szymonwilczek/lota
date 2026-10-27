/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
#ifndef LOTA_AGENT_CGROUP_GUARD_H
#define LOTA_AGENT_CGROUP_GUARD_H

#include <stddef.h>

/*
 * cgroup.kill SIGKILLs a whole cgroup from cgroup code, past task_kill;
 * the agent's cgroup and each ancestor carry one.
 */
#define LOTA_CGROUP_GUARD_MAX 32 /* cgroup path depth; a packaged unit is 2 */
#define LOTA_CGROUP_MOUNT_ROOT "/sys/fs/cgroup" /* unified hierarchy */

/* a cgroup.kill inode as the BPF side reads it */
struct cgroup_guard_file {
	unsigned long long dev; /* superblock dev, kernel MKDEV layout */
	unsigned long long ino;
};

/*
 * Copy the unified-hierarchy path in @proc_cgroup_path into @out.
 * Return 0 or -errno; -ENOENT on a cgroup-v1-only host.
 */
int cgroup_guard_self_path(const char *proc_cgroup_path, char *out,
			   size_t out_len);

/*
 * Fill @out with cgroup.kill of @cgroup_path under @mount_root and of each
 * ancestor, deepest first. Return the count or -errno. A level whose file
 * cannot be resolved is skipped: the root cgroup has none.
 */
int cgroup_guard_collect(const char *mount_root, const char *cgroup_path,
			 struct cgroup_guard_file *out, size_t max);

#endif /* LOTA_AGENT_CGROUP_GUARD_H */
