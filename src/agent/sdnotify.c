/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - systemd Integration
 *
 * Implements sd_notify lifecycle, watchdog pings, and socket
 * activation fd inheritance. All functions are safe to call
 * when not running under systemd.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include "sdnotify.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <systemd/sd-daemon.h>

bool sdnotify_under_systemd(void) {
  /*
   * NOTIFY_SOCKET is set for Type=notify services.
   * INVOCATION_ID is set for all systemd-managed units.
   * Either one indicates systemd management.
   */
  return getenv("NOTIFY_SOCKET") != NULL || getenv("INVOCATION_ID") != NULL;
}

int sdnotify_ready(void) {
  int ret = sd_notify(0, "READY=1");
  return (ret < 0) ? ret : 0;
}

int sdnotify_reloading(void) {
  int ret = sd_notify(0, "RELOADING=1");
  return (ret < 0) ? ret : 0;
}

int sdnotify_stopping(void) {
  int ret = sd_notify(0, "STOPPING=1");
  return (ret < 0) ? ret : 0;
}

int sdnotify_status(const char *fmt, ...) {
  char buf[256];
  char msg[280]; /* STATUS= prefix + buf */
  va_list ap;
  int ret;

  if (!fmt)
    return -EINVAL;

  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);

  snprintf(msg, sizeof(msg), "STATUS=%s", buf);
  ret = sd_notify(0, msg);
  return (ret < 0) ? ret : 0;
}

bool sdnotify_watchdog_enabled(uint64_t *interval_usec) {
  uint64_t usec = 0;
  int ret;

  ret = sd_watchdog_enabled(0, &usec);
  if (ret <= 0 || usec == 0)
    return false;

  if (interval_usec)
    *interval_usec = usec;
  return true;
}

int sdnotify_watchdog_ping(void) {
  int ret = sd_notify(0, "WATCHDOG=1");
  return (ret < 0) ? ret : 0;
}

int sdnotify_listen_fds(void) {
  /*
   * sd_listen_fds(1) consumes LISTEN_FDS / LISTEN_PID so
   * subsequent calls return 0. This is the correct behavior:
   * the fds should only be claimed once.
   */
  return sd_listen_fds(1);
}

bool sdnotify_is_unix_socket(int fd) {
  return sd_is_socket_unix(fd, SOCK_STREAM, 1, NULL, 0) > 0;
}
