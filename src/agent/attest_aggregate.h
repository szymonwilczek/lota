/* SPDX-License-Identifier: MIT */
/*
 * The host-wide answer, folded from every publisher's verdict.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#ifndef LOTA_AGENT_ATTEST_AGGREGATE_H
#define LOTA_AGENT_ATTEST_AGGREGATE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "attest_targets.h"

struct attest_aggregate {
	/* every publisher currently reporting is satisfied */
	bool attested;
	/* earliest verdict expiry among them, 0 when not attested */
	uint64_t valid_until;
	/* publishers that contributed a verdict */
	size_t considered;
	/* publishers this host reports to at all, token-only ones excluded */
	size_t reporting;
};

/**
 * attest_aggregate_compute() - Fold @targets into the host-wide answer.
 * @targets: The target list.
 * @count: Its length.
 * @out: The answer.
 *
 * A session-gated publisher with no session and a token-only one hold no
 * verdict and count neither way. With no verdict at all the host is not
 * attested.
 */
static inline void attest_aggregate_compute(const struct attest_target *targets,
					    size_t count,
					    struct attest_aggregate *out)
{
	uint64_t valid_until = 0;
	bool all = true;

	if (!out)
		return;

	out->attested = false;
	out->valid_until = 0;
	out->considered = 0;
	out->reporting = 0;

	if (!targets)
		return;

	/*
	 * Counted apart from the verdict below,
	 * which stops at the first publisher that is not satisfied
	 */
	for (size_t i = 0; i < count; i++) {
		if (!targets[i].token_only)
			out->reporting++;
	}

	for (size_t i = 0; i < count; i++) {
		if (targets[i].session_gated && targets[i].sessions == 0)
			continue;

		if (targets[i].token_only)
			continue;

		out->considered++;
		if (!targets[i].attested) {
			all = false;
			break;
		}
		if (valid_until == 0 || targets[i].valid_until < valid_until)
			valid_until = targets[i].valid_until;
	}

	if (out->considered == 0)
		all = false;

	out->attested = all;
	out->valid_until = all ? valid_until : 0;
}

#endif /* LOTA_AGENT_ATTEST_AGGREGATE_H */
