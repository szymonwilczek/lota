/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Zero-copy BPF decision-logic fuzzer: ring-buffer emission budget.
 *
 * 	include/lota_event_budget.h holds the rate-limit arithmetic the LSM
 * 	uses to stop an attacker-driven event flood from starving the ring buffer.
 * 	The header is user-space-includable, so this harness fuzzes the REAL
 * 	helpers against an independent reference whose budgets and window are
 * 	written from the documented spec rather than reusing the header's
 * 	constants -- so fat-fingered budget, wrong window, or flipped boundary
 * 	comparison (>= vs >, or a dropped backwards-clock branch) is caught.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "lota_event_budget.h"

/* Independent reference:
 * documented values (header doc + design), restated */
#define REF_WINDOW_NS 1000000000ULL
#define REF_ALLOW_PER_SEC 256u
#define REF_BLOCKED_PER_SEC 1024u

static unsigned int ref_limit(unsigned int enforce, int blocked)
{
	if (!enforce)
		return 0;
	return blocked ? REF_BLOCKED_PER_SEC : REF_ALLOW_PER_SEC;
}

static int ref_window_expired(unsigned long long now, unsigned long long start)
{
	if (now < start) /* clock moved backwards */
		return 1;
	return (now - start) >= REF_WINDOW_NS;
}

static int ref_exhausted(unsigned int count_before, unsigned int limit)
{
	return count_before >= limit;
}

#define FZ_CHECK(cond)           \
	do {                     \
		if (!(cond))     \
			abort(); \
	} while (0)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint32_t enforce = 0, blocked = 0, count = 0, limit = 0;
	uint64_t now = 0, start = 0;

	if (size >= 4)
		memcpy(&enforce, data + 0, 4);
	if (size >= 8)
		memcpy(&blocked, data + 4, 4);
	if (size >= 16)
		memcpy(&now, data + 8, 8);
	if (size >= 24)
		memcpy(&start, data + 16, 8);
	if (size >= 28)
		memcpy(&count, data + 24, 4);
	if (size >= 32)
		memcpy(&limit, data + 28, 4);

	FZ_CHECK(lota_event_budget_limit(enforce & 1u, (int)(blocked & 1u)) ==
		 ref_limit(enforce & 1u, (int)(blocked & 1u)));

	FZ_CHECK(!lota_event_budget_window_expired(now, start) ==
		 !ref_window_expired(now, start));

	FZ_CHECK(!lota_event_budget_exhausted(count, limit) ==
		 !ref_exhausted(count, limit));

	return 0;
}
