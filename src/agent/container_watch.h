/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * LOTA Agent - per-UID container listener tracking
 *
 * A title inside a Proton container reaches the agent through a socket
 * under the launching user's runtime directory. That directory is created
 * by systemd-logind at login, which is long after the agent starts,
 * so the set of UIDs that can carry a listener changes while the daemon runs.
 *
 * This module owns that set: which UIDs were configured, which of them currently
 * have a runtime directory, and which already carry a listener.
 *
 * Binding a socket is the caller's business -- the ops below keep the IPC layer
 * out of this file so the tracking can be tested without one.
 */

#ifndef LOTA_CONTAINER_WATCH_H
#define LOTA_CONTAINER_WATCH_H

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>

#include "config.h"

/* Parent of every per-user runtime directory, as systemd lays it out */
#define CONTAINER_WATCH_RUNTIME_ROOT "/run/user"

/*
 * @bind:   lay down the listener for @uid. Returns 0 on success and a negative
 *          errno otherwise; a failure leaves the UID unbound so the next
 *          observation retries it.
 * @unbind: the runtime directory went away, drop the listener.
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
	struct container_watch_ops ops;
};

/*
 * container_watch_init - track @uids under @root and bind what is there
 * @root: parent of the per-user runtime directories, or NULL for
 *        CONTAINER_WATCH_RUNTIME_ROOT.
 * 	  Overridable so a test can point the tracking at a directory it owns.
 *
 * Binds every configured UID whose runtime directory already exists,
 * which on a normal boot is none of them.
 *
 * Returns 0, or a negative errno when the arguments do not describe a usable set.
 * A UID whose bind fails is not an error here: it stays unbound and is retried.
 */
int container_watch_init(struct container_watch *w, const char *root,
			 const uint32_t *uids, int uid_count,
			 const struct container_watch_ops *ops);

/*
 * container_watch_fd - descriptor that reports a change under the root
 *
 * Returns a descriptor to poll, or -1 when nothing reports logins.
 * The agent has no such reporter today, so this is always -1.
 */
int container_watch_fd(const struct container_watch *w);

/*
 * container_watch_process - act on what happened under the root
 *
 * Returns the number of UIDs bound by this call, or a negative errno.
 * Nothing observes the root today, so this call has nothing to act on.
 */
int container_watch_process(struct container_watch *w);

void container_watch_cleanup(struct container_watch *w);

#endif /* LOTA_CONTAINER_WATCH_H */
