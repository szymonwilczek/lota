/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */

#include "container_watch.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <unistd.h>

#define WATCH_EVENTS \
	(IN_CREATE | IN_MOVED_TO | IN_DELETE | IN_MOVED_FROM | IN_ONLYDIR)

static int watch_slot_of_uid(const struct container_watch *w, uint32_t uid)
{
	for (int i = 0; i < w->uid_count; i++) {
		if (w->uids[i] == uid)
			return i;
	}
	return -1;
}

static bool runtime_dir_present(const struct container_watch *w, uint32_t uid)
{
	char path[PATH_MAX];
	struct stat st;
	int n;

	n = snprintf(path, sizeof(path), "%s/%u", w->root, uid);
	if (n < 0 || (size_t)n >= sizeof(path))
		return false;

	if (stat(path, &st) < 0)
		return false;

	return S_ISDIR(st.st_mode);
}

/*
 * Events are drained unread: a rescan also covers IN_Q_OVERFLOW and a directory
 * made while the watch went in.
 *
 * Returns 1 when this call bound the UID.
 */
static int watch_sync_uid(struct container_watch *w, int slot)
{
	bool present = runtime_dir_present(w, w->uids[slot]);

	if (present && !w->bound[slot]) {
		if (!w->ops.bind)
			return 0;
		if (w->ops.bind(w->uids[slot], w->ops.user) < 0)
			return 0;
		w->bound[slot] = true;
		return 1;
	}

	if (!present && w->bound[slot]) {
		w->bound[slot] = false;
		if (w->ops.unbind)
			w->ops.unbind(w->uids[slot], w->ops.user);
	}

	return 0;
}

static void watch_drain_mounts(struct container_watch *w)
{
	char buf[4096];
	ssize_t got;

	if (w->mnt_fd < 0)
		return;

	if (lseek(w->mnt_fd, 0, SEEK_SET) < 0)
		return;

	do {
		got = read(w->mnt_fd, buf, sizeof(buf));
	} while (got > 0 || (got < 0 && errno == EINTR));
}

static void watch_drain_events(struct container_watch *w)
{
	char buf[4096]
		__attribute__((aligned(__alignof__(struct inotify_event))));
	ssize_t got;

	if (w->fd < 0)
		return;

	do {
		got = read(w->fd, buf, sizeof(buf));
	} while (got > 0 || (got < 0 && errno == EINTR));
}

static int watch_start(struct container_watch *w)
{
	int fd, wd;

	w->mnt_fd = open("/proc/self/mountinfo", O_RDONLY | O_CLOEXEC);
	if (w->mnt_fd >= 0)
		watch_drain_mounts(w);

	fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
	if (fd < 0)
		return -errno;

	wd = inotify_add_watch(fd, w->root, WATCH_EVENTS);
	if (wd < 0) {
		int ret = -errno;

		close(fd);
		return ret;
	}

	w->fd = fd;
	return 0;
}

int container_watch_uid_of_runtime_dir(const char *runtime_dir, uint32_t *uid)
{
	const char *tail;
	char *end;
	unsigned long value;
	size_t root_len = strlen(CONTAINER_WATCH_RUNTIME_ROOT);

	if (!runtime_dir || !uid)
		return -EINVAL;

	if (strncmp(runtime_dir, CONTAINER_WATCH_RUNTIME_ROOT, root_len) != 0 ||
	    runtime_dir[root_len] != '/')
		return -ENOENT;

	tail = runtime_dir + root_len + 1;
	if (*tail == '\0')
		return -ENOENT;

	errno = 0;
	value = strtoul(tail, &end, 10);

	/* trailing slash is the only thing allowed after the number */
	if (errno != 0 || end == tail || value > UINT32_MAX)
		return -EINVAL;
	if (*end == '/')
		end++;
	if (*end != '\0')
		return -EINVAL;

	*uid = (uint32_t)value;
	return 0;
}

int container_watch_plan(const uint32_t *cfg_uids, int cfg_uid_count,
			 const char *runtime_dir, uint32_t *out, int max_out)
{
	if (!out || max_out <= 0)
		return -EINVAL;

	if (cfg_uid_count < 0)
		return -EINVAL;

	if (cfg_uid_count > 0) {
		if (!cfg_uids)
			return -EINVAL;
		if (cfg_uid_count > max_out)
			return -E2BIG;

		for (int i = 0; i < cfg_uid_count; i++)
			out[i] = cfg_uids[i];
		return cfg_uid_count;
	}

	if (runtime_dir) {
		uint32_t uid;

		if (container_watch_uid_of_runtime_dir(runtime_dir, &uid) ==
		    0) {
			out[0] = uid;
			return 1;
		}
	}

	return 0;
}

int container_watch_init(struct container_watch *w, const char *root,
			 const uint32_t *uids, int uid_count,
			 const struct container_watch_ops *ops)
{
	int n, ret;

	if (!w || !uids || !ops)
		return -EINVAL;

	if (uid_count < 0 || uid_count > LOTA_CONFIG_MAX_CONTAINER_LISTENERS)
		return -EINVAL;

	memset(w, 0, sizeof(*w));
	w->fd = -1;
	w->mnt_fd = -1;

	n = snprintf(w->root, sizeof(w->root), "%s",
		     root ? root : CONTAINER_WATCH_RUNTIME_ROOT);
	if (n < 0 || (size_t)n >= sizeof(w->root))
		return -ENAMETOOLONG;

	w->ops = *ops;
	for (int i = 0; i < uid_count; i++) {
		if (watch_slot_of_uid(w, uids[i]) >= 0)
			continue;
		w->uids[w->uid_count++] = uids[i];
	}

	/* watch before the scan: a login between the two is not lost */
	ret = watch_start(w);

	for (int i = 0; i < w->uid_count; i++)
		(void)watch_sync_uid(w, i);

	return ret;
}

bool container_watch_bind_pending(int err)
{
	return err == -ENOENT;
}

int container_watch_fd(const struct container_watch *w)
{
	if (!w)
		return -1;

	return w->fd;
}

int container_watch_mount_fd(const struct container_watch *w)
{
	if (!w)
		return -1;

	return w->mnt_fd;
}

int container_watch_process(struct container_watch *w)
{
	int bound = 0;

	if (!w)
		return -EINVAL;

	watch_drain_events(w);
	watch_drain_mounts(w);

	for (int i = 0; i < w->uid_count; i++)
		bound += watch_sync_uid(w, i);

	return bound;
}

void container_watch_cleanup(struct container_watch *w)
{
	if (!w)
		return;

	if (w->fd >= 0)
		close(w->fd);
	if (w->mnt_fd >= 0)
		close(w->mnt_fd);

	memset(w, 0, sizeof(*w));
	w->fd = -1;
	w->mnt_fd = -1;
}
