/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - systemd Integration
 *
 * Each sender first checks NOTIFY_SOCKET: /run/systemd/notify and the euid's
 * /run/user/<uid>/systemd/notify must belong to root or that user, in a
 * directory only the owner writes, and the abstract
 * @org/freedesktop/systemd1/notify is taken as is. Any other value is refused
 * with -EPERM and unset, so later sends return 0 without sending.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_AGENT_SDNOTIFY_H
#define LOTA_AGENT_SDNOTIFY_H

#include <stdbool.h>
#include <stdint.h>

/**
 * sdnotify_ready() - Send READY=1.
 *
 * Return: 0, also without NOTIFY_SOCKET, or a negative errno.
 */
int sdnotify_ready(void);

/**
 * sdnotify_reloading() - Send RELOADING=1.
 *
 * Return: As sdnotify_ready().
 */
int sdnotify_reloading(void);

/**
 * sdnotify_stopping() - Send STOPPING=1.
 *
 * Return: As sdnotify_ready().
 */
int sdnotify_stopping(void);

/**
 * sdnotify_status() - Send STATUS= with a formatted text.
 * @fmt: printf format.
 *
 * The text is cut to 255 bytes.
 *
 * Return: -EINVAL for a NULL @fmt, else as sdnotify_ready().
 */
__attribute__((format(printf, 1, 2))) int sdnotify_status(const char *fmt, ...);

/**
 * sdnotify_watchdog_enabled() - Does systemd expect watchdog pings?
 * @interval_usec: Receives the interval when true; may be NULL.
 *
 * Return: true when sd_watchdog_enabled() reports a nonzero interval.
 */
bool sdnotify_watchdog_enabled(uint64_t *interval_usec);

/**
 * sdnotify_watchdog_ping() - Send WATCHDOG=1.
 *
 * Return: As sdnotify_ready().
 */
int sdnotify_watchdog_ping(void);

#define SD_LISTEN_FDS_START 3

/**
 * sdnotify_listen_fds() - Count the descriptors socket activation passed.
 *
 * They start at SD_LISTEN_FDS_START. LISTEN_FDS and LISTEN_PID are unset,
 * so a later call returns 0.
 *
 * Return: the count, or a negative errno.
 */
int sdnotify_listen_fds(void);

/**
 * sdnotify_is_unix_socket() - Check the type of an inherited descriptor.
 * @fd: Descriptor.
 *
 * Return: true for a listening AF_UNIX SOCK_STREAM socket.
 */
bool sdnotify_is_unix_socket(int fd);

#endif /* LOTA_AGENT_SDNOTIFY_H */
