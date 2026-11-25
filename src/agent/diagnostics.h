/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - Diagnostic and admin one-shot dispatch
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_AGENT_DIAGNOSTICS_H
#define LOTA_AGENT_DIAGNOSTICS_H

#include "cli.h"
#include "config.h"

/**
 * diagnostics_dispatch() - Run the one-shot the options name.
 * @opts: Parsed and finalized options.
 * @cfg: Loaded configuration, or NULL.
 *
 * Sets g_agent.tpm_ctx.allow_env_tpm_overrides as
 * attest_env_overrides_allowed() decides, and clears it when the daemon
 * follows.
 *
 * Return: the exit code of the one-shot, 1 where it failed with a negative
 * errno, or -1 when the options name none and the daemon follows.
 */
int diagnostics_dispatch(struct cli_options *opts, struct lota_config *cfg);

#endif /* LOTA_AGENT_DIAGNOSTICS_H */
