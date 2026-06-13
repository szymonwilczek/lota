/* SPDX-License-Identifier: MIT
 *
 * lota-install - Child Process Runner
 *
 * Stages that change system state shell out to the same tools the
 * documentation names (dracut, grubby, systemctl, lota-agent, ...).
 *
 * Commands are argv arrays passed straight to execvp - no shell, no
 * word splitting - with stdout+stderr merged into the UI's live
 * region so the player sees exactly what ran.
 */

#ifndef LOTA_INSTALL_RUN_H
#define LOTA_INSTALL_RUN_H

#include "ui.h"

/* Runs argv (NULL-terminated) with output streamed to the live
 * region under `label`.
 * Returns the child's exit code (0..255), 128+signal when signalled,
 * or -errno on spawn failure.
 * Live region is opened and closed by this call. */
int run_cmd(struct ui *ui, const char *label, const char *const argv[]);

/* Runs argv silently, capturing combined output into out (NUL
 * terminated, truncated to cap).
 * Same return contract as run_cmd. */
int run_capture(const char *const argv[], char *out, size_t cap);

#endif /* LOTA_INSTALL_RUN_H */
