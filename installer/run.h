/* SPDX-License-Identifier: MIT
 * Copyright (C) 2026 Szymon Wilczek
 *
 * lota-install - Child Process Runner
 */

#ifndef LOTA_INSTALL_RUN_H
#define LOTA_INSTALL_RUN_H

#include <stddef.h>

#include "ui.h"

/**
 * run_cmd() - Run a command with its output in the live region.
 * @ui:    UI the live region belongs to.
 * @label: live region label.
 * @argv:  NULL-terminated argv for execvp; no shell.
 *
 * stdout and stderr are merged; stdin is /dev/null.
 *
 * Return: the child's exit code (127 when exec fails), 128 + signal when
 * signalled, 128 + SIGTERM for a child the sink aborted that exited 0, or
 * -errno when the child cannot be started or waited for.
 */
int run_cmd(struct ui *ui, const char *label, const char *const argv[]);

/**
 * run_capture() - Run a command and capture its output.
 * @argv: NULL-terminated argv for execvp; no shell.
 * @out:  merged stdout and stderr, truncated to @cap - 1 bytes and
 *        NUL-terminated.
 * @cap:  size of @out.
 *
 * Return: as run_cmd(); -EINVAL for a NULL @out or zero @cap.
 */
int run_capture(const char *const argv[], char *out, size_t cap);

#endif /* LOTA_INSTALL_RUN_H */
