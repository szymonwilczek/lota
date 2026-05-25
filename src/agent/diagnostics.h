/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - Diagnostic and admin one-shot dispatch
 *
 * Collects every short-lived CLI mode (--shutdown, --dump-config,
 * --gen-signing-key, --sign-policy, --verify-policy, --test-tpm,
 * --test-iommu, --test-ipc, --test-signed, --export-policy, --attest)
 * behind one entry point so main() never sees the per-flag branching.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_AGENT_DIAGNOSTICS_H
#define LOTA_AGENT_DIAGNOSTICS_H

#include "cli.h"
#include "config.h"

/*
 * Run any diagnostic / admin mode requested by the CLI. Returns:
 *   - a non-negative program exit code when a diagnostic mode handled
 *     the invocation and main() should exit with that value;
 *   - -1 when no diagnostic flag fired, meaning main() must continue
 *     down the daemon path.
 */
int diagnostics_dispatch(struct cli_options *opts, struct lota_config *cfg);

#endif /* LOTA_AGENT_DIAGNOSTICS_H */
