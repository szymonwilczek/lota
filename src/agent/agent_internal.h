/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - test entry points under LOTA_INTERNAL_TESTS.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_AGENT_INTERNAL_H
#define LOTA_AGENT_INTERNAL_H

#ifdef LOTA_INTERNAL_TESTS

#ifndef LOTA_TPM_TESTING
#define LOTA_TPM_TESTING 1
#endif

#include "tpm.h"

#endif /* LOTA_INTERNAL_TESTS */

#endif /* LOTA_AGENT_INTERNAL_H */
