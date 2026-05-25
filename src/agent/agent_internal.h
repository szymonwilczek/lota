/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - Internal Test Surface
 *
 * Single umbrella header that aggregates symbols intentionally exposed
 * to unit tests under tests/. Production agent translation units never
 * include this file; they include the per-module headers directly. The
 * LOTA_INTERNAL_TESTS gate keeps these declarations out of the agent
 * ABI and turns the set of test entry points into one auditable list.
 *
 * Adding a new test-only entry point: declare it inside the
 * LOTA_INTERNAL_TESTS block in the module's own header (or in this
 * file when the symbol is cross-module), and make tests/ include
 * "agent_internal.h" instead of redefining per-module testing macros.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_AGENT_INTERNAL_H
#define LOTA_AGENT_INTERNAL_H

#ifdef LOTA_INTERNAL_TESTS

/*
 * Activate per-module testing surfaces. Tests link the agent's own .c
 * files and call into normally-static helpers through these guards.
 */
#ifndef LOTA_TPM_TESTING
#define LOTA_TPM_TESTING 1
#endif

#include "tpm.h"

#endif /* LOTA_INTERNAL_TESTS */

#endif /* LOTA_AGENT_INTERNAL_H */
