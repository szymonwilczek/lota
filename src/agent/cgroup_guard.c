/* SPDX-License-Identifier: MIT */
/*
 * LOTA - the cgroup files that end the agent without a signal
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "cgroup_guard.h"
#include "sb_dev.h"

/* a /proc/<pid>/cgroup record is one cgroup path plus a short prefix */
#define CGROUP_LINE_MAX 4096

/* reject "." and "..": such a path names a cgroup the agent is not in */
static int path_is_descending(const char *path)
{
	const char *p = path;

	if (path[0] != '/')
		return 0;

	while (*p) {
		size_t len;

		while (*p == '/')
			p++;

		len = strcspn(p, "/");
		if (len == 0)
			break;
		if (len == 1 && p[0] == '.')
			return 0;
		if (len == 2 && p[0] == '.' && p[1] == '.')
			return 0;

		p += len;
	}

	return 1;
}

int cgroup_guard_self_path(const char *proc_cgroup_path, char *out,
			   size_t out_len)
{
	char line[CGROUP_LINE_MAX];
	FILE *f;
	int ret = -ENOENT;

	if (!proc_cgroup_path || !out || out_len == 0)
		return -EINVAL;

	f = fopen(proc_cgroup_path, "re");
	if (!f)
		return -errno;

	while (fgets(line, sizeof(line), f)) {
		char *path;
		size_t len;

		if (strchr(line, '\n') == NULL) {
			int c;

			while ((c = fgetc(f)) != EOF && c != '\n')
				;
		}

		/* the unified hierarchy is the record with no controller name */
		if (strncmp(line, "0::", 3) != 0)
			continue;

		path = line + 3;
		len = strcspn(path, "\n");
		path[len] = '\0';

		if (len >= out_len) {
			ret = -ENAMETOOLONG;
			break;
		}
		if (!path_is_descending(path)) {
			ret = -EINVAL;
			break;
		}

		memcpy(out, path, len + 1);
		ret = 0;
		break;
	}

	fclose(f);
	return ret;
}

/* superblock dev, not st_dev: the BPF hook compares the former */
static int guard_file_ids(const char *dir, struct cgroup_guard_file *out)
{
	char path[PATH_MAX];
	struct stat st = { 0 };
	unsigned long long dev = 0;
	int fd;
	int ret;

	if (snprintf(path, sizeof(path), "%s/cgroup.kill", dir) >=
	    (int)sizeof(path))
		return -ENAMETOOLONG;

	fd = open(path, O_PATH | O_CLOEXEC);
	if (fd < 0)
		return -errno;

	if (fstat(fd, &st) != 0) {
		ret = -errno;
		close(fd);
		return ret;
	}

	ret = sb_dev_from_fd(fd, &dev);
	close(fd);
	if (ret < 0)
		return ret;

	if (dev == 0 || st.st_ino == 0)
		return -ENODEV;

	out->dev = dev;
	out->ino = (unsigned long long)st.st_ino;
	return 0;
}

int cgroup_guard_collect(const char *mount_root, const char *cgroup_path,
			 struct cgroup_guard_file *out, size_t max)
{
	char dir[PATH_MAX];
	size_t root_len;
	size_t count = 0;

	if (!mount_root || !cgroup_path || !out || max == 0)
		return -EINVAL;

	if (!path_is_descending(cgroup_path))
		return -EINVAL;

	root_len = strlen(mount_root);
	while (root_len > 1 && mount_root[root_len - 1] == '/')
		root_len--;
	if (root_len == 0)
		return -EINVAL;

	if (snprintf(dir, sizeof(dir), "%.*s%s", (int)root_len, mount_root,
		     cgroup_path) >= (int)sizeof(dir))
		return -ENAMETOOLONG;

	/* the root cgroup is "/": drop the trailing separator before walking */
	for (size_t len = strlen(dir); len > root_len && dir[len - 1] == '/';
	     len--)
		dir[len - 1] = '\0';

	for (;;) {
		char *slash;

		if (count == max)
			return -ENOSPC;

		if (guard_file_ids(dir, &out[count]) == 0)
			count++;

		if (strlen(dir) <= root_len)
			break;

		slash = strrchr(dir + root_len, '/');
		if (!slash)
			break;
		*slash = '\0';
	}

	return (int)count;
}
