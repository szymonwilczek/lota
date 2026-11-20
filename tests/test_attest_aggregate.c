/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for the host-wide attestation fold.
 *
 * The process that computes a verdict and the process that answers title with it
 * are not the same one, so this fold has to mean the same thing on both sides.
 *
 * Its cases -- nobody playing, one publisher of several down, publisher that
 * never reports -- are all reachable on a live host and all slow to reach there.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#include <string.h>

#include "../src/agent/attest_aggregate.h"

#include "test.h"

int main(void)
{
	struct attest_target targets[3] = {};
	struct attest_aggregate agg;

	test_begin("attest aggregate");

	/* no publishers at all: nothing has judged this host */
	attest_aggregate_compute(targets, 0, &agg);
	TEST("a host with no publishers is not attested");
	if (!(!agg.attested && agg.considered == 0 && agg.valid_until == 0))
		FAIL("expected: !agg.attested && agg.considered == 0 && "
		     "agg.valid_until == 0");

	/* one continuous publisher, satisfied */
	memset(targets, 0, sizeof(targets));
	targets[0].attested = true;
	targets[0].valid_until = 1000;
	attest_aggregate_compute(targets, 1, &agg);
	TEST("one satisfied publisher attests the host");
	if (!(agg.attested && agg.considered == 1 && agg.valid_until == 1000))
		FAIL("expected: agg.attested && agg.considered == 1 && "
		     "agg.valid_until == 1000");

	/* two satisfied publishers: the answer lapses with the first of them */
	memset(targets, 0, sizeof(targets));
	targets[0].attested = true;
	targets[0].valid_until = 1000;
	targets[1].attested = true;
	targets[1].valid_until = 500;
	attest_aggregate_compute(targets, 2, &agg);
	TEST("the window closes at the earliest verdict");
	if (!(agg.attested && agg.valid_until == 500))
		FAIL("expected: agg.attested && agg.valid_until == 500");

	/* one publisher of several unsatisfied sinks the host-wide answer */
	memset(targets, 0, sizeof(targets));
	targets[0].attested = true;
	targets[0].valid_until = 1000;
	targets[1].attested = false;
	attest_aggregate_compute(targets, 2, &agg);
	TEST("one unsatisfied publisher is enough to answer no");
	if (!(!agg.attested && agg.valid_until == 0))
		FAIL("expected: !agg.attested && agg.valid_until == 0");

	/*
	 * Session-gated publisher nobody is playing for contributes nothing.
	 * Counting its silence as failure would leave a consumer host permanently
	 * unattested; counting it as success would assert something nothing
	 * is checking.
	 */
	memset(targets, 0, sizeof(targets));
	targets[0].attested = true;
	targets[0].valid_until = 1000;
	targets[1].session_gated = true;
	targets[1].sessions = 0;
	targets[1].attested = false;
	attest_aggregate_compute(targets, 2, &agg);
	TEST("a publisher with no session is not counted");
	if (!(agg.attested && agg.considered == 1 && agg.valid_until == 1000))
		FAIL("expected: agg.attested && agg.considered == 1 && "
		     "agg.valid_until == 1000");

	/* the same publisher, once a title of theirs is running */
	targets[1].sessions = 1;
	attest_aggregate_compute(targets, 2, &agg);
	TEST("a publisher with a live session is counted again");
	if (!(!agg.attested && agg.considered == 2))
		FAIL("expected: !agg.attested && agg.considered == 2");

	/* every publisher session-gated and idle: nothing reports */
	memset(targets, 0, sizeof(targets));
	targets[0].session_gated = true;
	targets[0].attested = true;
	targets[0].valid_until = 1000;
	targets[1].session_gated = true;
	targets[1].attested = true;
	targets[1].valid_until = 1000;
	attest_aggregate_compute(targets, 2, &agg);
	TEST("a host with no title running holds no live verdict");
	if (!(!agg.attested && agg.considered == 0))
		FAIL("expected: !agg.attested && agg.considered == 0");

	/*
	 * Publisher who verifies tokens in their own backend is never reported to,
	 * so this host holds no verdict of theirs to fold in.
	 */
	memset(targets, 0, sizeof(targets));
	targets[0].attested = true;
	targets[0].valid_until = 1000;
	targets[1].token_only = true;
	targets[1].attested = false;
	attest_aggregate_compute(targets, 2, &agg);
	TEST("a token-only publisher contributes no verdict");
	if (!(agg.attested && agg.considered == 1 && agg.reporting == 1))
		FAIL("expected: agg.attested && agg.considered == 1 && "
		     "agg.reporting == 1");

	/*
	 * Every publisher running light is different answer from failed one:
	 * the host reports to nobody, which is what the caller turns into
	 * TOKEN_ONLY rather than bare NOT ATTESTED.
	 */
	memset(targets, 0, sizeof(targets));
	targets[0].token_only = true;
	targets[1].token_only = true;
	attest_aggregate_compute(targets, 2, &agg);
	TEST("a host whose every publisher runs light reports to nobody");
	if (!(!agg.attested && agg.considered == 0 && agg.reporting == 0))
		FAIL("expected: !agg.attested && agg.considered == 0 && "
		     "agg.reporting == 0");

	/* stale verdict is still the caller's to time out, not this fold's */
	memset(targets, 0, sizeof(targets));
	targets[0].attested = true;
	targets[0].valid_until = 1;
	attest_aggregate_compute(targets, 1, &agg);
	TEST("expiry is reported, not enforced, by the fold");
	if (!(agg.attested && agg.valid_until == 1))
		FAIL("expected: agg.attested && agg.valid_until == 1");

	return test_end();
}
