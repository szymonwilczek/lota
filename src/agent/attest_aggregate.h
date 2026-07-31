/* SPDX-License-Identifier: MIT */
/*
 * The host-wide answer, folded from every publisher's verdict.
 *
 * Title that names no publisher asks "is this machine attested",
 * and a consumer host answers to several publishers at once, so the answer is
 * a fold rather than a flag.
 * Split out of the attestation loop because the process that computes it
 * and the process that answers with it are not the same one, and because the fold
 * has cases a live host is a slow way to reach.
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
};

/*
 * Fold @targets into the host-wide answer.
 *
 * A publisher nobody is playing for is not reporting, so it has no verdict to
 * contribute: counting its silence as a failure would leave a consumer host
 * permanently unattested, and counting it as success would assert something
 * nothing is checking.
 *
 * Host with nobody reporting is therefore not attested either
 * -- there is no live verdict to report.
 *
 * The expiry is the earliest of the contributing verdicts,
 * so the answer stops being true when the first publisher's does.
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

	if (!targets)
		return;

	for (size_t i = 0; i < count; i++) {
		if (targets[i].session_gated && targets[i].sessions == 0)
			continue;

		/*
		 * Publisher who verifies tokens in their own backend never reports
		 * here, so this host holds no verdict of theirs to fold in.
		 * Their titles read the token they fetched, not this bit.
		 */
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
