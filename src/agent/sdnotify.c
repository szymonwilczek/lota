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

static int validate_filesystem_notify_socket(const char *path, uid_t owner) {
  struct stat st;

  if (!path)
    return -EINVAL;

  if (stat(path, &st) < 0)
    return -EPERM;

  if (!S_ISSOCK(st.st_mode))
    return -EPERM;

  if (st.st_uid != owner)
    return -EPERM;

  if ((st.st_mode & S_IWOTH) != 0)
    return -EPERM;

  return 0;
}

static int validate_notify_socket_env(void) {
  const char *notify_socket = getenv("NOTIFY_SOCKET");
  char expected[64];

  if (!notify_socket || notify_socket[0] == '\0')
    return 0;

  if (strcmp(notify_socket, "/run/systemd/notify") == 0)
    return validate_filesystem_notify_socket(notify_socket, 0);

  snprintf(expected, sizeof(expected), "/run/user/%u/systemd/notify",
           (unsigned)geteuid());
  if (strcmp(notify_socket, expected) == 0)
    return validate_filesystem_notify_socket(notify_socket, geteuid());

  if (strcmp(notify_socket, "@org/freedesktop/systemd1/notify") == 0)
    return 0;

  return -EPERM;
}

static int sdnotify_send_checked(const char *message) {
  int ret;

  ret = validate_notify_socket_env();
  if (ret < 0) {
    unsetenv("NOTIFY_SOCKET");
    return ret;
  }

  ret = sd_notify(0, message);
  return (ret < 0) ? ret : 0;
}

bool sdnotify_under_systemd(void) {
  /*
   * NOTIFY_SOCKET is set for Type=notify services.
   * INVOCATION_ID is set for all systemd-managed units.
   * Either one indicates systemd management.
   */
  return getenv("NOTIFY_SOCKET") != NULL || getenv("INVOCATION_ID") != NULL;
}

int sdnotify_ready(void) { return sdnotify_send_checked("READY=1"); }

int sdnotify_reloading(void) { return sdnotify_send_checked("RELOADING=1"); }

int sdnotify_stopping(void) { return sdnotify_send_checked("STOPPING=1"); }

int sdnotify_status(const char *fmt, ...) {
  char buf[256];
  char msg[280]; /* STATUS= prefix + buf */
  va_list ap;

  if (!fmt)
    return -EINVAL;

  va_start(ap, fmt);
  vsnprintf(buf, sizeof(buf), fmt, ap);
  va_end(ap);

  snprintf(msg, sizeof(msg), "STATUS=%s", buf);
  return sdnotify_send_checked(msg);
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

int sdnotify_watchdog_ping(void) { return sdnotify_send_checked("WATCHDOG=1"); }

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
