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

#define LOTA_INOTIFY_HDR offsetof(struct inotify_event, name)

/**
 * socket_events_name() - Whether a batch of inotify events concerns @name.
 * @buf: events as read() returned them.
 * @len: bytes in @buf.
 * @name: file name in the watched directory.
 *
 * Return: true when an event names @name, concerns the directory itself
 * or reports an overflow, and when the batch ends in a cut event.
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
