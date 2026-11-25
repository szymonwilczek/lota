/* SPDX-License-Identifier: MIT */
/*
 * The enforcement bits of an attestation report, taken from the daemon that
 * holds the LSM, not from the process building the report: a daemon that
 * does not answer gives none, BPF_ACTIVE needs the LSM loaded, and ENFORCE
 * and the policy keys need enforce mode too.
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

/**
 * struct enforcement_view - The enforcing daemon as the reporter last saw it.
 * @answered: the daemon was reached.
 * @mode: its enum lota_mode.
 * @status_flags: its LOTA_STATUS_* word.
 */
struct enforcement_view {
	bool answered;
	uint8_t mode;
	uint32_t status_flags;
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
