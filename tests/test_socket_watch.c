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

static int g_failures;

#define CHECK(cond, msg)                                    \
	do {                                                \
		if (!(cond)) {                              \
			fprintf(stderr, "FAIL: %s\n", msg); \
			g_failures++;                       \
		} else {                                    \
			printf("PASS: %s\n", msg);          \
		}                                           \
	} while (0)

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
	printf("=== socket watch filter tests ===\n\n");

	g_len = 0;
	add(IN_CREATE, ".bench.tmp");
	add(IN_ATTRIB, ".bench.tmp");
	add(IN_MOVED_FROM, ".bench.tmp");
	add(IN_MOVED_TO, "bench.json");
	CHECK(!named(), "a bench write costs no recheck");

	add(IN_CREATE, "lota.sock");
	CHECK(named(), "the socket among bench events is seen");

	g_len = 0;
	add(IN_DELETE, "lota.sock.old");
	add(IN_CREATE, "lota.soc");
	CHECK(!named(), "a name that only starts like the socket is not it");

	g_len = 0;
	add(IN_Q_OVERFLOW, NULL);
	CHECK(named(), "lost events force a recheck");

	g_len = 0;
	add(IN_ATTRIB, NULL);
	CHECK(named(), "an event on the directory itself forces a recheck");

	g_len = 0;
	add(IN_MOVED_TO, "bench.json");
	CHECK(named() == false && socket_events_name(g_buf, g_len - 1,
						     LOTA_IPC_SOCKET_NAME),
	      "a truncated batch forces a recheck");

	CHECK(!socket_events_name(g_buf, 0, LOTA_IPC_SOCKET_NAME),
	      "an empty read names nothing");

	printf("\n%s: %d failure(s)\n", g_failures ? "FAILED" : "OK",
	       g_failures);
	return g_failures ? 1 : 0;
}
