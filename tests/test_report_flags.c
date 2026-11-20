/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for the enforcement bits of an attestation report.
 *
 * The report is built by the attestation loop, and the LSM is held by the
 * enforcement daemon. A verifier that requires enforcement accepts a host on
 * LOTA_REPORT_FLAG_ENFORCE alone, so the bit has to say that the daemon is
 * up, in enforce mode, with its LSM loaded -- not what the loop's own
 * config says.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include "../src/agent/report_flags.h"

#include "test.h"

#define ENF LOTA_REPORT_FLAG_ENFORCE
#define BPF LOTA_REPORT_FLAG_BPF_ACTIVE

static uint32_t flags_for(bool answered, uint8_t mode, uint32_t status)
{
	struct enforcement_view v = {
		.answered = answered,
		.mode = mode,
		.status_flags = status,
	};

	return report_enforcement_flags(&v);
}

int main(void)
{
	uint32_t f;

	test_begin("report flags");

	f = flags_for(true, LOTA_MODE_ENFORCE, LOTA_STATUS_BPF_LOADED);
	TEST("daemon enforcing with its LSM loaded: both");
	if (f != (ENF | BPF))
		FAIL("expected: f == (ENF | BPF)");

	f = flags_for(true, LOTA_MODE_MONITOR, LOTA_STATUS_BPF_LOADED);
	TEST("daemon in monitor mode: BPF_ACTIVE, no ENFORCE");
	if (f != BPF)
		FAIL("expected: f == BPF");

	/* a mode with nothing attached blocks nothing */
	f = flags_for(true, LOTA_MODE_ENFORCE, 0);
	TEST("enforce mode without the LSM loaded: neither");
	if (f != 0)
		FAIL("expected: f == 0");

	/* no answer is no daemon, whatever the reporter was configured with */
	f = flags_for(false, LOTA_MODE_ENFORCE, LOTA_STATUS_BPF_LOADED);
	TEST("daemon not reached: neither");
	if (f != 0)
		FAIL("expected: f == 0");

	f = flags_for(false, LOTA_MODE_ENFORCE, 0);
	TEST("daemon not reached, nothing known: neither");
	if (f != 0)
		FAIL("expected: f == 0");

	TEST("no view: neither");
	if (report_enforcement_flags(NULL) != 0)
		FAIL("expected: report_enforcement_flags(NULL) == 0");

	f = flags_for(true, LOTA_MODE_ENFORCE,
		      LOTA_STATUS_BPF_LOADED | LOTA_STATUS_BENCH);
	TEST("daemon on --bench: BENCH beside the enforcement bits");
	if (f != (ENF | BPF | LOTA_REPORT_FLAG_BENCH))
		FAIL("expected: f == (ENF | BPF | LOTA_REPORT_FLAG_BENCH)");

	f = flags_for(true, LOTA_MODE_MONITOR, LOTA_STATUS_BENCH);
	TEST("--bench without the LSM loaded: BENCH alone");
	if (f != LOTA_REPORT_FLAG_BENCH)
		FAIL("expected: f == LOTA_REPORT_FLAG_BENCH");

	f = flags_for(false, LOTA_MODE_ENFORCE, LOTA_STATUS_BENCH);
	TEST("daemon not reached: no BENCH");
	if (f != 0)
		FAIL("expected: f == 0");

	f = flags_for(true, LOTA_MODE_ENFORCE, LOTA_STATUS_BPF_LOADED);
	TEST("no --bench: no BENCH");
	if (f & LOTA_REPORT_FLAG_BENCH)
		FAIL("expected: !(f & LOTA_REPORT_FLAG_BENCH)");

	/* a daemon that lost its LSM after the loss still says so */
	f = flags_for(true, LOTA_MODE_ENFORCE,
		      LOTA_STATUS_BPF_LOADED | LOTA_STATUS_EVENTS_LOST);
	TEST("events lost: EVENTS_LOST beside the enforcement bits");
	if (f != (ENF | BPF | LOTA_REPORT_FLAG_EVENTS_LOST))
		FAIL("expected: f == (ENF | BPF | "
		     "LOTA_REPORT_FLAG_EVENTS_LOST)");

	f = flags_for(true, LOTA_MODE_MONITOR, LOTA_STATUS_EVENTS_LOST);
	TEST("events lost without the LSM loaded: EVENTS_LOST alone");
	if (f != LOTA_REPORT_FLAG_EVENTS_LOST)
		FAIL("expected: f == LOTA_REPORT_FLAG_EVENTS_LOST");

	f = flags_for(false, LOTA_MODE_ENFORCE, LOTA_STATUS_EVENTS_LOST);
	TEST("daemon not reached: no EVENTS_LOST");
	if (f != 0)
		FAIL("expected: f == 0");

	f = flags_for(true, LOTA_MODE_ENFORCE, LOTA_STATUS_BPF_LOADED);
	TEST("no loss: no EVENTS_LOST");
	if (f & LOTA_REPORT_FLAG_EVENTS_LOST)
		FAIL("expected: !(f & LOTA_REPORT_FLAG_EVENTS_LOST)");

	/* the daemon's policy keys reach the report under enforce only */
	f = flags_for(true, LOTA_MODE_ENFORCE,
		      LOTA_STATUS_BPF_LOADED | LOTA_STATUS_STRICT_MMAP |
			      LOTA_STATUS_BLOCK_PTRACE);
	TEST("enforcing daemon: its keys beside ENFORCE");
	if (f != (ENF | BPF | LOTA_REPORT_FLAG_STRICT_MMAP |
		  LOTA_REPORT_FLAG_BLOCK_PTRACE))
		FAIL("expected: f == (ENF | BPF | "
		     "LOTA_REPORT_FLAG_STRICT_MMAP | "
		     "LOTA_REPORT_FLAG_BLOCK_PTRACE)");

	f = flags_for(true, LOTA_MODE_ENFORCE,
		      LOTA_STATUS_BPF_LOADED | LOTA_STATUS_STRICT_EXEC |
			      LOTA_STATUS_STRICT_MODULES |
			      LOTA_STATUS_BLOCK_ANON_EXEC);
	TEST("enforcing daemon: the other three keys");
	if (f != (ENF | BPF | LOTA_REPORT_FLAG_STRICT_EXEC |
		  LOTA_REPORT_FLAG_STRICT_MODULES |
		  LOTA_REPORT_FLAG_BLOCK_ANON_EXEC))
		FAIL("expected: f == (ENF | BPF | "
		     "LOTA_REPORT_FLAG_STRICT_EXEC | "
		     "LOTA_REPORT_FLAG_STRICT_MODULES | "
		     "LOTA_REPORT_FLAG_BLOCK_ANON_EXEC)");

	f = flags_for(true, LOTA_MODE_MONITOR,
		      LOTA_STATUS_BPF_LOADED | LOTA_STATUS_STRICT_MMAP);
	TEST("monitor: no key, whatever the word says");
	if (f != BPF)
		FAIL("expected: f == BPF");

	f = flags_for(true, LOTA_MODE_ENFORCE, LOTA_STATUS_STRICT_MMAP);
	TEST("enforce without the LSM loaded: no key");
	if (f != 0)
		FAIL("expected: f == 0");

	return test_end();
}
