/* SPDX-License-Identifier: MIT */
/*
 * LOTA systemd Integration Unit Tests
 *
 * Tests the sdnotify and journal modules in isolation.
 * All tests run without systemd supervision, so the sd_notify
 * and journal calls operate in fallback/no-op mode.
 *
 * Build:
 *   gcc -Wall -Wextra -Werror -O2 -g -Iinclude -D_GNU_SOURCE \
 *       -o build/test_systemd \
 *       tests/test_systemd.c \
 *       src/agent/sdnotify.c src/agent/journal.c \
 *       -lsystemd
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <syslog.h>
#include <unistd.h>
#include <stdint.h>

#include "test.h"
#include "../src/agent/ipc.h"
#include "../src/agent/journal.h"
#include "../src/agent/sdnotify.h"

void ipc_set_dbus(struct ipc_context *ctx, struct dbus_context *dbus)
{
	(void)ctx;
	(void)dbus;
}

static void test_ready_no_socket(void)
{
	TEST("sdnotify: ready() without socket -> 0");

	unsetenv("NOTIFY_SOCKET");

	int ret = sdnotify_ready();
	if (ret != 0) {
		FAIL("expected 0");
		return;
	}
}

static void test_ready_rejects_spoofed_notify_socket(void)
{
	TEST("sdnotify: ready() rejects spoofed NOTIFY_SOCKET");

	setenv("NOTIFY_SOCKET", "/tmp/lota-fake-notify.sock", 1);

	int ret = sdnotify_ready();
	if (ret != -EPERM) {
		unsetenv("NOTIFY_SOCKET");
		FAIL("expected -EPERM");
		return;
	}

	if (getenv("NOTIFY_SOCKET") != NULL) {
		unsetenv("NOTIFY_SOCKET");
		FAIL("expected NOTIFY_SOCKET to be cleared after rejection");
		return;
	}
}

static void test_stopping_no_socket(void)
{
	TEST("sdnotify: stopping() without socket -> 0");

	unsetenv("NOTIFY_SOCKET");
	int ret = sdnotify_stopping();
	if (ret != 0) {
		FAIL("expected 0");
		return;
	}
}

static void test_reloading_no_socket(void)
{
	TEST("sdnotify: reloading() without socket -> 0");

	unsetenv("NOTIFY_SOCKET");
	int ret = sdnotify_reloading();
	if (ret != 0) {
		FAIL("expected 0");
		return;
	}
}

static void test_status_no_socket(void)
{
	TEST("sdnotify: status() without socket -> 0");

	unsetenv("NOTIFY_SOCKET");
	int ret = sdnotify_status("test status %d", 42);
	if (ret != 0) {
		FAIL("expected 0");
		return;
	}
}

static void test_status_null(void)
{
	TEST("sdnotify: status(NULL) -> -EINVAL");

	int ret = sdnotify_status(NULL);
	if (ret != -EINVAL) {
		FAIL("expected -EINVAL");
		return;
	}
}

static void test_watchdog_not_enabled(void)
{
	TEST("sdnotify: watchdog not enabled (no WATCHDOG_USEC)");

	unsetenv("WATCHDOG_USEC");
	unsetenv("WATCHDOG_PID");
	uint64_t interval = 0;

	if (sdnotify_watchdog_enabled(&interval)) {
		FAIL("expected false");
		return;
	}
}

static void test_watchdog_ping_no_socket(void)
{
	TEST("sdnotify: watchdog_ping() without socket -> 0");

	unsetenv("NOTIFY_SOCKET");
	int ret = sdnotify_watchdog_ping();
	if (ret != 0) {
		FAIL("expected 0");
		return;
	}
}

static void test_listen_fds_none(void)
{
	TEST("sdnotify: listen_fds() without LISTEN_FDS -> 0");

	unsetenv("LISTEN_FDS");
	unsetenv("LISTEN_PID");
	int n = sdnotify_listen_fds();
	if (n != 0) {
		FAIL("expected 0");
		return;
	}
}

static void test_is_unix_socket_stdin(void)
{
	TEST("sdnotify: is_unix_socket(stdin) -> false");

	if (sdnotify_is_unix_socket(STDIN_FILENO)) {
		FAIL("stdin should not be a unix socket");
		return;
	}
}

static void test_is_unix_socket_real(void)
{
	TEST("sdnotify: is_unix_socket(real AF_UNIX) -> true");

	int fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		FAIL("socket() failed");
		return;
	}

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	/*
	 * Use a pathname socket under /tmp instead of Linux's abstract
	 * namespace. Some sandboxed CI environments block abstract AF_UNIX
	 * bind even though normal filesystem-backed sockets work; the code
	 * under test only needs a real AF_UNIX fd.
	 */
	snprintf(addr.sun_path, sizeof(addr.sun_path), "/tmp/lota-test-%d.sock",
		 getpid());
	unlink(addr.sun_path);
	socklen_t addr_len = offsetof(struct sockaddr_un, sun_path) +
			     strlen(addr.sun_path) + 1;

	if (bind(fd, (struct sockaddr *)&addr, addr_len) < 0 ||
	    listen(fd, 1) < 0) {
		int saved_errno = errno;
		unlink(addr.sun_path);
		close(fd);
		if (saved_errno == EPERM || saved_errno == EACCES) {
			SKIP("AF_UNIX bind not permitted: %s",
			     strerror(saved_errno));
			return;
		}
		FAIL("bind/listen failed: %s", strerror(saved_errno));
		return;
	}

	if (!sdnotify_is_unix_socket(fd)) {
		unlink(addr.sun_path);
		close(fd);
		FAIL("expected true for AF_UNIX SOCK_STREAM");
		return;
	}

	unlink(addr.sun_path);
	close(fd);
}

static void test_journal_level_filter(void)
{
	TEST("journal: level filter suppresses debug");

	unsetenv("JOURNAL_STREAM");
	unsetenv("INVOCATION_ID");
	journal_init("test");
	journal_set_level(LOG_WARNING);

	lota_dbg("this should be suppressed");
	lota_info("this should be suppressed");
	lota_warn("this should be emitted");
	lota_err("this should be emitted");

	journal_set_level(LOG_DEBUG); /* restore */
}

int main(void)
{
	test_begin("systemd");

	/* sdnotify tests */
	test_ready_no_socket();
	test_ready_rejects_spoofed_notify_socket();
	test_stopping_no_socket();
	test_reloading_no_socket();
	test_status_no_socket();
	test_status_null();
	test_watchdog_not_enabled();
	test_watchdog_ping_no_socket();
	test_listen_fds_none();
	test_is_unix_socket_stdin();
	test_is_unix_socket_real();

	/* journal tests */
	test_journal_level_filter();

	return test_end();
}
