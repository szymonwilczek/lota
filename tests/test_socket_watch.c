/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for the socket directory's event filter.
 *
 * The directory also holds the --bench file, rewritten each second; those
 * events must not cost a recheck, and no event on the socket may be missed.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#include <stdalign.h>
#include <stdio.h>
#include <string.h>

#include "../src/agent/socket_watch.h"

#include "test.h"

static alignas(struct inotify_event) char g_buf[1024];
static size_t g_len;

static void add(uint32_t mask, const char *name)
{
	struct inotify_event ev = { 0 };
	size_t n = name ? strlen(name) + 1 : 0;
	size_t pad = (n + 15) & ~(size_t)15;

	ev.mask = mask;
	ev.len = (uint32_t)pad;
	memset(g_buf + g_len, 0, LOTA_INOTIFY_HDR + pad);
	memcpy(g_buf + g_len, &ev, LOTA_INOTIFY_HDR);
	if (name)
		memcpy(g_buf + g_len + LOTA_INOTIFY_HDR, name, n);
	g_len += LOTA_INOTIFY_HDR + pad;
}

static bool named(void)
{
	return socket_events_name(g_buf, g_len, LOTA_IPC_SOCKET_NAME);
}

int main(void)
{
	test_begin("socket watch");

	g_len = 0;
	add(IN_CREATE, ".bench.tmp");
	add(IN_ATTRIB, ".bench.tmp");
	add(IN_MOVED_FROM, ".bench.tmp");
	add(IN_MOVED_TO, "bench.json");
	TEST("a bench write costs no recheck");
	if (named())
		FAIL("expected: !named()");

	add(IN_CREATE, "lota.sock");
	TEST("the socket among bench events is seen");
	if (!named())
		FAIL("expected: named()");

	g_len = 0;
	add(IN_DELETE, "lota.sock.old");
	add(IN_CREATE, "lota.soc");
	TEST("a name that only starts like the socket is not it");
	if (named())
		FAIL("expected: !named()");

	g_len = 0;
	add(IN_Q_OVERFLOW, NULL);
	TEST("lost events force a recheck");
	if (!named())
		FAIL("expected: named()");

	g_len = 0;
	add(IN_ATTRIB, NULL);
	TEST("an event on the directory itself forces a recheck");
	if (!named())
		FAIL("expected: named()");

	g_len = 0;
	add(IN_MOVED_TO, "bench.json");
	TEST("a truncated batch forces a recheck");
	if (!(named() == false &&
	      socket_events_name(g_buf, g_len - 1, LOTA_IPC_SOCKET_NAME)))
		FAIL("expected: named() == false && socket_events_name(g_buf, "
		     "g_len - 1, LOTA_IPC_SOCKET_NAME)");

	TEST("an empty read names nothing");
	if (socket_events_name(g_buf, 0, LOTA_IPC_SOCKET_NAME))
		FAIL("expected: !socket_events_name(g_buf, 0, "
		     "LOTA_IPC_SOCKET_NAME)");

	return test_end();
}
