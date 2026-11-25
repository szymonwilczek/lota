/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Per-UID container listener tracking.
 *
 * A title in a container reaches the agent through a socket under the user's
 * runtime directory, which can appear after the daemon starts. This tracks
 * which configured UIDs have that directory and a listener.
 */

#ifndef LOTA_CONTAINER_WATCH_H
#define LOTA_CONTAINER_WATCH_H

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>

#include "config.h"

/* Parent of the per-user runtime directories */
#define CONTAINER_WATCH_RUNTIME_ROOT "/run/user"

/**
 * struct container_watch_ops - What the tracking asks of its caller.
 * @bind: Lay down the listener for the UID. Returns 0 or a negative errno; a
 *        failure leaves the UID unbound, so the next observation retries it.
 * @unbind: The runtime directory went away, drop the listener.
 * @user: Passed to both.
 */
struct container_watch_ops {
	int (*bind)(uint32_t uid, void *user);
	void (*unbind)(uint32_t uid, void *user);
	void *user;
};

struct container_watch {
	char root[PATH_MAX];
	uint32_t uids[LOTA_CONFIG_MAX_CONTAINER_LISTENERS];
	bool bound[LOTA_CONFIG_MAX_CONTAINER_LISTENERS];
	int uid_count;
	int fd; /* inotify on the root, -1 when unavailable */
	int mnt_fd; /* /proc/self/mountinfo, -1 when unavailable */
	struct container_watch_ops ops;
};

/**
 * container_watch_plan() - Pick the logins that get a watched listener.
 * @cfg_uids: UIDs the configuration names, or NULL.
 * @cfg_uid_count: How many of them.
 * @runtime_dir: The agent's own XDG_RUNTIME_DIR, or NULL when unset.
 * @out: Filled with the UIDs to watch.
 * @max_out: Capacity of @out.
 *
 * UIDs the configuration names are taken as they are. With none, the one
 * UID @runtime_dir names, if any.
 *
 * Return: the number of UIDs written to @out, or a negative errno.
 */
int container_watch_plan(const uint32_t *cfg_uids, int cfg_uid_count,
			 const char *runtime_dir, uint32_t *out, int max_out);

/**
 * container_watch_uid_of_runtime_dir() - The UID a path names.
 * @runtime_dir: A path such as /run/user/1000.
 * @uid: Receives the UID.
 *
 * Return: 0, or a negative errno when the path is not a per-user runtime
 * directory under CONTAINER_WATCH_RUNTIME_ROOT.
 */
int container_watch_uid_of_runtime_dir(const char *runtime_dir, uint32_t *uid);

/**
 * container_watch_init() - Watch @root for logins and bind what is there.
 * @w: The tracking state.
 * @root: Parent of the runtime directories, or NULL for
 *        CONTAINER_WATCH_RUNTIME_ROOT.
 * @uids: UIDs to track; a repeat is ignored.
 * @uid_count: How many.
 * @ops: The caller's operations.
 *
 * Starts watching before it scans. A UID whose bind fails stays unbound.
 *
 * Return: 0, or a negative errno when the arguments are unusable or the root
 * cannot be watched; what the scan bound then stays in place.
 */
int container_watch_init(struct container_watch *w, const char *root,
			 const uint32_t *uids, int uid_count,
			 const struct container_watch_ops *ops);

/**
 * container_watch_bind_pending() - Is a failed bind waiting for the login?
 * @err: The negative errno a bind returned.
 *
 * Return: true for -ENOENT.
 */
bool container_watch_bind_pending(int err);

/**
 * container_watch_fd() - Descriptor that reports a change under the root.
 * @w: The tracking state.
 *
 * Return: the descriptor, or -1 when the root could not be watched.
 */
int container_watch_fd(const struct container_watch *w);

/**
 * container_watch_mount_fd() - Descriptor that reports a mount change.
 * @w: The tracking state.
 *
 * A mount fires no inotify event on the directory it covers. Wait on this
 * for POLLPRI as well, so a bind that failed before the mount is retried.
 *
 * Return: the descriptor, or -1 when the mount table cannot be watched.
 */
int container_watch_mount_fd(const struct container_watch *w);

/**
 * container_watch_process() - Act on what happened under the root.
 * @w: The tracking state.
 *
 * Binds each tracked UID that has a runtime directory and no listener,
 * and unbinds each one that has lost the directory.
 * Call it when either descriptor above reports.
 *
 * Return: the number of UIDs bound by this call, or -EINVAL.
 */
int container_watch_process(struct container_watch *w);

void container_watch_cleanup(struct container_watch *w);

#endif /* LOTA_CONTAINER_WATCH_H */
