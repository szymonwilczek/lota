/* SPDX-License-Identifier: MIT */
/*
 * Which inotify events on the socket directory can concern the socket.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#ifndef LOTA_AGENT_SOCKET_WATCH_H
#define LOTA_AGENT_SOCKET_WATCH_H

#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <sys/inotify.h>

#define LOTA_IPC_SOCKET_NAME "lota.sock"

/* Fixed part of an event; the name follows it */
#define LOTA_INOTIFY_HDR offsetof(struct inotify_event, name)

/*
 * True when a batch of events names @name, touches the directory itself,
 * or lost events to an overflow. A truncated tail counts as named.
 */
static inline bool socket_events_name(const char *buf, size_t len,
				      const char *name)
{
	size_t off = 0;

	while (off < len) {
		struct inotify_event ev;

		if (len - off < LOTA_INOTIFY_HDR)
			return true;
		memcpy(&ev, buf + off, LOTA_INOTIFY_HDR);
		if (len - off - LOTA_INOTIFY_HDR < ev.len)
			return true;
		if ((ev.mask & IN_Q_OVERFLOW) || ev.len == 0 ||
		    strncmp(buf + off + LOTA_INOTIFY_HDR, name, ev.len) == 0)
			return true;
		off += LOTA_INOTIFY_HDR + ev.len;
	}
	return false;
}

#endif /* LOTA_AGENT_SOCKET_WATCH_H */
