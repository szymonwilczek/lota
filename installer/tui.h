/* SPDX-License-Identifier: MIT
 *
 * lota-install - Full-screen Interactive Frontend
 */

#ifndef LOTA_INSTALL_TUI_H
#define LOTA_INSTALL_TUI_H

#include "install.h"

/* Takes over the whole terminal (alternate screen, raw keys) and drives
 * the stage engine interactively.
 * Returns the process exit code (EXIT_INSTALL_*).
 * Terminal is restored and a short result summary is printed to the normal
 * screen before returning. */
int tui_run(struct install_ctx *ctx);

#endif /* LOTA_INSTALL_TUI_H */
