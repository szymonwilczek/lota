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
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <syslog.h>
#include <unistd.h>

#include "../src/agent/journal.h"
#include "../src/agent/sdnotify.h"

struct ipc_context;
struct dbus_context;
void ipc_set_dbus(struct ipc_context *ctx, struct dbus_context *dbus) {
  (void)ctx;
  (void)dbus;
}

static int tests_run;
static int tests_passed;

#define TEST(name)                                                             \
  do {                                                                         \
    tests_run++;                                                               \
    printf("  [%d] %-55s ", tests_run, name);                                  \
  } while (0)

#define PASS()                                                                 \
  do {                                                                         \
    tests_passed++;                                                            \
    printf("PASS\n");                                                          \
  } while (0)

#define FAIL(msg)                                                              \
  do {                                                                         \
    printf("FAIL: %s\n", msg);                                                 \
  } while (0)

static void test_not_under_systemd(void) {
  TEST("sdnotify: not under systemd (no env vars)");

  /* ensure test isolation */
  unsetenv("NOTIFY_SOCKET");
  unsetenv("INVOCATION_ID");

  if (sdnotify_under_systemd()) {
    FAIL("expected false");
    return;
  }
  PASS();
}

static void test_detect_invocation_id(void) {
  TEST("sdnotify: detect INVOCATION_ID");

  unsetenv("NOTIFY_SOCKET");
  setenv("INVOCATION_ID", "test-id-1234", 1);

  if (!sdnotify_under_systemd()) {
    unsetenv("INVOCATION_ID");
    FAIL("expected true");
    return;
  }
  unsetenv("INVOCATION_ID");
  PASS();
}

static void test_detect_notify_socket(void) {
  TEST("sdnotify: detect NOTIFY_SOCKET");

  unsetenv("INVOCATION_ID");
  setenv("NOTIFY_SOCKET", "/run/systemd/notify", 1);

  if (!sdnotify_under_systemd()) {
    unsetenv("NOTIFY_SOCKET");
    FAIL("expected true");
    return;
  }
  unsetenv("NOTIFY_SOCKET");
  PASS();
}

static void test_ready_no_socket(void) {
  TEST("sdnotify: ready() without socket -> 0");

  unsetenv("NOTIFY_SOCKET");

  int ret = sdnotify_ready();
  if (ret != 0) {
    FAIL("expected 0");
    return;
  }
  PASS();
}

static void test_stopping_no_socket(void) {
  TEST("sdnotify: stopping() without socket -> 0");

  unsetenv("NOTIFY_SOCKET");
  int ret = sdnotify_stopping();
  if (ret != 0) {
    FAIL("expected 0");
    return;
  }
  PASS();
}

static void test_reloading_no_socket(void) {
  TEST("sdnotify: reloading() without socket -> 0");

  unsetenv("NOTIFY_SOCKET");
  int ret = sdnotify_reloading();
  if (ret != 0) {
    FAIL("expected 0");
    return;
  }
  PASS();
}

static void test_status_no_socket(void) {
  TEST("sdnotify: status() without socket -> 0");

  unsetenv("NOTIFY_SOCKET");
  int ret = sdnotify_status("test status %d", 42);
  if (ret != 0) {
    FAIL("expected 0");
    return;
  }
  PASS();
}

static void test_status_null(void) {
  TEST("sdnotify: status(NULL) -> -EINVAL");

  int ret = sdnotify_status(NULL);
  if (ret != -EINVAL) {
    FAIL("expected -EINVAL");
    return;
  }
  PASS();
}

static void test_watchdog_not_enabled(void) {
  TEST("sdnotify: watchdog not enabled (no WATCHDOG_USEC)");

  unsetenv("WATCHDOG_USEC");
  unsetenv("WATCHDOG_PID");
  uint64_t interval = 0;

  if (sdnotify_watchdog_enabled(&interval)) {
    FAIL("expected false");
    return;
  }
  PASS();
}

static void test_watchdog_ping_no_socket(void) {
  TEST("sdnotify: watchdog_ping() without socket -> 0");

  unsetenv("NOTIFY_SOCKET");
  int ret = sdnotify_watchdog_ping();
  if (ret != 0) {
    FAIL("expected 0");
    return;
  }
  PASS();
}

static void test_listen_fds_none(void) {
  TEST("sdnotify: listen_fds() without LISTEN_FDS -> 0");

  unsetenv("LISTEN_FDS");
  unsetenv("LISTEN_PID");
  int n = sdnotify_listen_fds();
  if (n != 0) {
    FAIL("expected 0");
    return;
  }
  PASS();
}

static void test_is_unix_socket_stdin(void) {
  TEST("sdnotify: is_unix_socket(stdin) -> false");

  if (sdnotify_is_unix_socket(STDIN_FILENO)) {
    FAIL("stdin should not be a unix socket");
    return;
  }
  PASS();
}

static void test_is_unix_socket_real(void) {
  TEST("sdnotify: is_unix_socket(real AF_UNIX) -> true");

  int fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) {
    FAIL("socket() failed");
    return;
  }

  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  /* abstract socket: first byte is NUL */
  snprintf(addr.sun_path + 1, sizeof(addr.sun_path) - 1, "lota-test-%d",
           getpid());
  socklen_t addr_len =
      offsetof(struct sockaddr_un, sun_path) + 1 + strlen(addr.sun_path + 1);

  if (bind(fd, (struct sockaddr *)&addr, addr_len) < 0 || listen(fd, 1) < 0) {
    close(fd);
    FAIL("bind/listen failed");
    return;
  }

  if (!sdnotify_is_unix_socket(fd)) {
    close(fd);
    FAIL("expected true for AF_UNIX SOCK_STREAM");
    return;
  }

  close(fd);
  PASS();
}

static void test_sd_listen_fds_start(void) {
  TEST("sdnotify: SD_LISTEN_FDS_START == 3");

  if (SD_LISTEN_FDS_START != 3) {
    FAIL("expected 3");
    return;
  }
  PASS();
}

static void test_journal_init_null(void) {
  TEST("journal: init(NULL) does not crash");
  journal_init(NULL);
  PASS();
}

static void test_journal_init_ident(void) {
  TEST("journal: init(\"test\") succeeds");
  journal_init("test");
  PASS();
}

static void test_journal_default_level(void) {
  TEST("journal: default level is LOG_DEBUG");

  journal_init("test");
  if (journal_get_level() != LOG_DEBUG) {
    FAIL("expected LOG_DEBUG");
    return;
  }
  PASS();
}

static void test_journal_set_level(void) {
  TEST("journal: set_level(LOG_WARNING) persists");

  journal_init("test");
  journal_set_level(LOG_WARNING);
  if (journal_get_level() != LOG_WARNING) {
    FAIL("level not set");
    journal_set_level(LOG_DEBUG);
    return;
  }
  journal_set_level(LOG_DEBUG);
  PASS();
}

static void test_journal_not_journal_mode(void) {
  TEST("journal: not in journal mode (no JOURNAL_STREAM)");

  unsetenv("JOURNAL_STREAM");
  unsetenv("INVOCATION_ID");
  journal_init("test");

  if (journal_use_journal()) {
    FAIL("expected false");
    return;
  }
  PASS();
}

static void test_journal_detect_stream(void) {
  TEST("journal: detect JOURNAL_STREAM");

  setenv("JOURNAL_STREAM", "8:12345", 1);
  journal_init("test");

  if (!journal_use_journal()) {
    unsetenv("JOURNAL_STREAM");
    FAIL("expected true");
    return;
  }
  unsetenv("JOURNAL_STREAM");
  /* reinit to clear */
  journal_init("test");
  PASS();
}

static void test_journal_macros_no_crash(void) {
  TEST("journal: lota_err/warn/info/dbg macros");

  unsetenv("JOURNAL_STREAM");
  unsetenv("INVOCATION_ID");
  journal_init("test");

  /* should emit to stderr in fallback mode */
  lota_err("test error %d", 1);
  lota_warn("test warning %s", "hello");
  lota_info("test info");
  lota_dbg("test debug");
  lota_notice("test notice");
  PASS();
}

static void test_journal_level_filter(void) {
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
  PASS();
}

int main(void) {
  printf("=== LOTA systemd Integration Tests ===\n\n");

  /* sdnotify tests */
  test_not_under_systemd();
  test_detect_invocation_id();
  test_detect_notify_socket();
  test_ready_no_socket();
  test_stopping_no_socket();
  test_reloading_no_socket();
  test_status_no_socket();
  test_status_null();
  test_watchdog_not_enabled();
  test_watchdog_ping_no_socket();
  test_listen_fds_none();
  test_is_unix_socket_stdin();
  test_is_unix_socket_real();
  test_sd_listen_fds_start();

  /* journal tests */
  test_journal_init_null();
  test_journal_init_ident();
  test_journal_default_level();
  test_journal_set_level();
  test_journal_not_journal_mode();
  test_journal_detect_stream();
  test_journal_macros_no_crash();
  test_journal_level_filter();

  printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
  return (tests_passed == tests_run) ? 0 : 1;
}
