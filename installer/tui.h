/* SPDX-License-Identifier: MIT
 * Copyright (C) 2026 Szymon Wilczek
 *
 * lota-install - Full-screen Interactive Frontend
 */

#ifndef LOTA_INSTALL_TUI_H
#define LOTA_INSTALL_TUI_H

#include "install.h"

/**
 * tui_run() - Drive the stage table in a full-screen view.
 * @ctx: install context.
 *
 * The terminal is restored before returning.
 *
 * Return: an EXIT_INSTALL_* code, or -1 when the view cannot start
 * and the caller should run the plain flow.
 */
int tui_run(struct install_ctx *ctx);

#endif /* LOTA_INSTALL_TUI_H */
