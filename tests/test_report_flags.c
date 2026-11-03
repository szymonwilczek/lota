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
#include <stdio.h>

#include "../src/agent/report_flags.h"

static int g_failures;

#define CHECK(cond, msg)                                    \
	do {                                                \
		if (!(cond)) {                              \
			fprintf(stderr, "FAIL: %s\n", msg); \
			g_failures++;                       \
		} else {                                    \
			printf("PASS: %s\n", msg);          \
		}                                           \
	} while (0)

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

	printf("=== report enforcement flag tests ===\n\n");

	f = flags_for(true, LOTA_MODE_ENFORCE, LOTA_STATUS_BPF_LOADED);
	CHECK(f == (ENF | BPF), "daemon enforcing with its LSM loaded: both");

	f = flags_for(true, LOTA_MODE_MONITOR, LOTA_STATUS_BPF_LOADED);
	CHECK(f == BPF, "daemon in monitor mode: BPF_ACTIVE, no ENFORCE");

	/* a mode with nothing attached blocks nothing */
	f = flags_for(true, LOTA_MODE_ENFORCE, 0);
	CHECK(f == 0, "enforce mode without the LSM loaded: neither");

	/* no answer is no daemon, whatever the reporter was configured with */
	f = flags_for(false, LOTA_MODE_ENFORCE, LOTA_STATUS_BPF_LOADED);
	CHECK(f == 0, "daemon not reached: neither");

	f = flags_for(false, LOTA_MODE_ENFORCE, 0);
	CHECK(f == 0, "daemon not reached, nothing known: neither");

	CHECK(report_enforcement_flags(NULL) == 0, "no view: neither");

	f = flags_for(true, LOTA_MODE_ENFORCE,
		      LOTA_STATUS_BPF_LOADED | LOTA_STATUS_BENCH);
	CHECK(f == (ENF | BPF | LOTA_REPORT_FLAG_BENCH),
	      "daemon on --bench: BENCH beside the enforcement bits");

	f = flags_for(true, LOTA_MODE_MONITOR, LOTA_STATUS_BENCH);
	CHECK(f == LOTA_REPORT_FLAG_BENCH,
	      "--bench without the LSM loaded: BENCH alone");

	f = flags_for(false, LOTA_MODE_ENFORCE, LOTA_STATUS_BENCH);
	CHECK(f == 0, "daemon not reached: no BENCH");

	f = flags_for(true, LOTA_MODE_ENFORCE, LOTA_STATUS_BPF_LOADED);
	CHECK(!(f & LOTA_REPORT_FLAG_BENCH), "no --bench: no BENCH");

	if (g_failures) {
		fprintf(stderr, "\n%d failure(s)\n", g_failures);
		return 1;
	}
	printf("\nAll tests passed\n");
	return 0;
}
