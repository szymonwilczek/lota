/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */

#include "container_watch.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * Events that can start or end a login: logind creates the runtime
 * directory when the user's first session opens and removes it when
 * the last one closes.
 */
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

/*
 * A runtime directory is the login's own tmpfs mount,
 * so nothing but a directory at that path is one.
 */
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
 * Reconcile one UID against what is on the filesystem.
 *
 * The events themselves are never read for their contents:
 * a rescan answers the same question without having to trust that every event
 * arrived, which the queue does not guarantee under IN_Q_OVERFLOW, and without
 * a second code path for the directory that appeared while the watch was being
 * installed.
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
	w->wd = wd;
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
	w->wd = -1;

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

	/*
	 * Watch first, scan second.
	 * A login that lands between the two is seen twice, which costs nothing;
	 * the other order loses it.
	 */
	ret = watch_start(w);

	for (int i = 0; i < w->uid_count; i++)
		(void)watch_sync_uid(w, i);

	return ret;
}

int container_watch_fd(const struct container_watch *w)
{
	if (!w)
		return -1;

	return w->fd;
}

int container_watch_process(struct container_watch *w)
{
	int bound = 0;

	if (!w)
		return -EINVAL;

	watch_drain_events(w);

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

	memset(w, 0, sizeof(*w));
	w->fd = -1;
	w->wd = -1;
}
