/* SPDX-License-Identifier: MIT */
/*
 * The enforcement bits of an attestation report, and what they are taken from.
 *
 * LOTA_REPORT_FLAG_ENFORCE and LOTA_REPORT_FLAG_BPF_ACTIVE are bound into the
 * quote's nonce, and a verifier that requires enforcement accepts a host on
 * ENFORCE alone. Both bits describe the enforcement daemon, which holds the
 * LSM, not the process building the report: a daemon that does not answer
 * enforces nothing, and enforce mode with nothing loaded blocks nothing.
 * LOTA_REPORT_FLAG_BENCH, LOTA_REPORT_FLAG_EVENTS_LOST and the policy keys ride
 * along, as they too are the daemon's.
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

	if (!v || !v->answered)
		return 0;
	if (v->status_flags & LOTA_STATUS_BENCH)
		flags |= LOTA_REPORT_FLAG_BENCH;
	if (v->status_flags & LOTA_STATUS_EVENTS_LOST)
		flags |= LOTA_REPORT_FLAG_EVENTS_LOST;
	if (!(v->status_flags & LOTA_STATUS_BPF_LOADED))
		return flags;

	flags |= LOTA_REPORT_FLAG_BPF_ACTIVE;
	if (v->mode != LOTA_MODE_ENFORCE)
		return flags;

	flags |= LOTA_REPORT_FLAG_ENFORCE;
	if (v->status_flags & LOTA_STATUS_STRICT_MMAP)
		flags |= LOTA_REPORT_FLAG_STRICT_MMAP;
	if (v->status_flags & LOTA_STATUS_STRICT_EXEC)
		flags |= LOTA_REPORT_FLAG_STRICT_EXEC;
	if (v->status_flags & LOTA_STATUS_STRICT_MODULES)
		flags |= LOTA_REPORT_FLAG_STRICT_MODULES;
	if (v->status_flags & LOTA_STATUS_BLOCK_ANON_EXEC)
		flags |= LOTA_REPORT_FLAG_BLOCK_ANON_EXEC;
	if (v->status_flags & LOTA_STATUS_BLOCK_PTRACE)
		flags |= LOTA_REPORT_FLAG_BLOCK_PTRACE;

	return flags;
}

#endif /* LOTA_AGENT_REPORT_FLAGS_H */
