/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for net_result_str(), the sentence a host shows for
 * the verifier's verdict.
 *
 * The verdict is the only account the machine has of why it stopped attesting:
 * the verifier's own log is on somebody else's server, and a player has no route
 * to it at all. A code the agent cannot name is rendered as "Unknown error",
 * which is what a support call then starts from.
 *
 * The two an administrator causes on purpose -- a revoked AIK and a banned
 * hardware ID -- are the ones that matter most here, because a machine doing
 * exactly what it was told to do must not read as a fault of the machine.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../src/agent/net.h"

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

/* Every code the verifier can send, by the number it sends it as.
 * Written as literals rather than through the macros so a code the agent
 * has not learned yet is a failing test rather than a build error. */
#define FIRST_UNKNOWN_CODE 22

static const char *g_default;

static int is_named(uint32_t code)
{
	return strcmp(net_result_str(code), g_default) != 0;
}

int main(void)
{
	uint32_t code, other;

	printf("=== verifier verdict naming tests ===\n\n");

	/* whatever the default reads, it is what an unnamed code falls to */
	g_default = net_result_str(0xFFFFFFFFu);

	for (code = 0; code < FIRST_UNKNOWN_CODE; code++) {
		char msg[96];

		snprintf(msg, sizeof(msg),
			 "verdict %u is named rather than reported as unknown",
			 code);
		CHECK(is_named(code), msg);
	}

	/* two codes sharing a sentence is two states an operator cannot tell
	 * apart, which is the same defect the default has */
	for (code = 0; code < FIRST_UNKNOWN_CODE; code++) {
		for (other = code + 1; other < FIRST_UNKNOWN_CODE; other++) {
			char msg[96];

			if (!is_named(code) || !is_named(other))
				continue;
			snprintf(msg, sizeof(msg),
				 "verdicts %u and %u read differently", code,
				 other);
			CHECK(strcmp(net_result_str(code),
				     net_result_str(other)) != 0,
			      msg);
		}
	}

	/*
	 * Verdict 6 covers the agent binary, the PCR 14 boot commitment
	 * and the firmware/Secure Boot baseline, and the host cannot tell
	 * which, so the sentence must name all three.
	 */
	CHECK(strstr(net_result_str(6), "agent") != NULL &&
		      strstr(net_result_str(6), "PCR 14") != NULL &&
		      strstr(net_result_str(6), "firmware") != NULL,
	      "verdict 6 names every measurement it is sent for");

	/* the two an administrator causes on purpose say so,
	 * so the machine is not read as broken when it is obeying */
	CHECK(strstr(net_result_str(7), "revoked") != NULL,
	      "verdict 7 names the revocation");
	CHECK(strstr(net_result_str(8), "banned") != NULL,
	      "verdict 8 names the ban");

	/* each requirement has its own remedy, so its verdict names it */
	CHECK(strstr(net_result_str(13), "certificate") != NULL,
	      "verdict 13 names the missing certificate");
	CHECK(strstr(net_result_str(14), "Secure Boot") != NULL &&
		      strstr(net_result_str(14), "firmware") != NULL,
	      "verdict 14 names Secure Boot and where it is turned on");
	CHECK(strstr(net_result_str(15), "lockdown") != NULL,
	      "verdict 15 names kernel lockdown");
	CHECK(strstr(net_result_str(16), "module") != NULL,
	      "verdict 16 names module signature enforcement");
	CHECK(strstr(net_result_str(17), "enforc") != NULL,
	      "verdict 17 names the LSM enforce mode");
	CHECK(strstr(net_result_str(18), "IMA") != NULL,
	      "verdict 18 names IMA appraisal");
	CHECK(strstr(net_result_str(19), "kernel") != NULL,
	      "verdict 19 names the kernel image");
	CHECK(strstr(net_result_str(20), "command line") != NULL,
	      "verdict 20 names the kernel command line");

	/* an unreadable report is not an old wire: no upgrade advice */
	CHECK(strstr(net_result_str(5), "version") != NULL,
	      "verdict 5 names the protocol version");
	CHECK(strstr(net_result_str(21), "read") != NULL &&
		      strstr(net_result_str(21), "version") == NULL,
	      "verdict 21 says the report could not be read and does not advise an upgrade");

	/* the default still exists for a code from a newer verifier */
	CHECK(!is_named(FIRST_UNKNOWN_CODE),
	      "a code the agent does not know still falls to the default");

	printf("\n%s\n", g_failures ? "FAILURES" : "All tests passed");
	return g_failures ? 1 : 0;
}
