/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */

#include "container_watch.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

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

static void watch_bind_uid(struct container_watch *w, int slot)
{
	if (w->bound[slot] || !w->ops.bind)
		return;

	if (!runtime_dir_present(w, w->uids[slot]))
		return;

	if (w->ops.bind(w->uids[slot], w->ops.user) == 0)
		w->bound[slot] = true;
}

int container_watch_init(struct container_watch *w, const char *root,
			 const uint32_t *uids, int uid_count,
			 const struct container_watch_ops *ops)
{
	int n;

	if (!w || !uids || !ops)
		return -EINVAL;

	if (uid_count < 0 || uid_count > LOTA_CONFIG_MAX_CONTAINER_LISTENERS)
		return -EINVAL;

	memset(w, 0, sizeof(*w));

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

	for (int i = 0; i < w->uid_count; i++)
		watch_bind_uid(w, i);

	return 0;
}

int container_watch_fd(const struct container_watch *w)
{
	(void)w;

	return -1;
}

int container_watch_process(struct container_watch *w)
{
	if (!w)
		return -EINVAL;

	return 0;
}

void container_watch_cleanup(struct container_watch *w)
{
	if (!w)
		return;

	memset(w, 0, sizeof(*w));
}
