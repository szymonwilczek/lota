/* SPDX-License-Identifier: MIT */
/*
 * The enforcement bits of an attestation report, and what they are taken from.
 *
 * LOTA_REPORT_FLAG_ENFORCE and LOTA_REPORT_FLAG_BPF_ACTIVE are bound into the
 * quote's nonce, and a verifier that requires enforcement accepts a host on
 * ENFORCE alone. Both bits describe the process that holds the LSM.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#ifndef LOTA_AGENT_REPORT_FLAGS_H
#define LOTA_AGENT_REPORT_FLAGS_H

#include <stdbool.h>
#include <stdint.h>

#include "../../include/attestation.h"
#include "../../include/lota.h"
#include "../../include/lota_ipc.h"

/* The enforcing process as the reporter last saw it */
struct enforcement_view {
	bool answered; /* the process holding the LSM was reached */
	uint8_t mode; /* its enum lota_mode */
	uint32_t status_flags; /* its LOTA_STATUS_* word */
};

static inline uint32_t
report_enforcement_flags(const struct enforcement_view *v)
{
	uint32_t flags = 0;

	if (!v)
		return 0;

	if (v->mode == LOTA_MODE_ENFORCE)
		flags |= LOTA_REPORT_FLAG_ENFORCE;
	if (v->status_flags & LOTA_STATUS_BPF_LOADED)
		flags |= LOTA_REPORT_FLAG_BPF_ACTIVE;

	return flags;
}

#endif /* LOTA_AGENT_REPORT_FLAGS_H */
