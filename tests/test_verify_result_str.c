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
#define FIRST_UNKNOWN_CODE 10

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

	/* the two an administrator causes on purpose say so,
	 * so the machine is not read as broken when it is obeying */
	CHECK(strstr(net_result_str(7), "revoked") != NULL,
	      "verdict 7 names the revocation");
	CHECK(strstr(net_result_str(8), "banned") != NULL,
	      "verdict 8 names the ban");

	/* the default still exists for a code from a newer verifier */
	CHECK(!is_named(FIRST_UNKNOWN_CODE),
	      "a code the agent does not know still falls to the default");

	printf("\n%s\n", g_failures ? "FAILURES" : "All tests passed");
	return g_failures ? 1 : 0;
}
