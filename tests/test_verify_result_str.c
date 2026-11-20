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

#include "../include/attestation.h"
#include "../src/agent/config.h"
#include "../src/agent/net.h"

#include "test.h"

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

	test_begin("verify result str");

	/* whatever the default reads, it is what an unnamed code falls to */
	g_default = net_result_str(0xFFFFFFFFu);

	for (code = 0; code < FIRST_UNKNOWN_CODE; code++) {
		char msg[96];

		snprintf(msg, sizeof(msg),
			 "verdict %u is named rather than reported as unknown",
			 code);
		TEST(msg);
		if (!is_named(code))
			FAIL("expected: is_named(code)");
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
			TEST(msg);
			if (strcmp(net_result_str(code),
				   net_result_str(other)) == 0)
				FAIL("expected: strcmp(net_result_str(code), "
				     "net_result_str(other)) != 0");
		}
	}

	/*
	 * Verdict 6 covers the agent binary, the PCR 14 boot commitment
	 * and the firmware/Secure Boot baseline, and the host cannot tell
	 * which, so the sentence must name all three.
	 */
	TEST("verdict 6 names every measurement it is sent for");
	if (!(strstr(net_result_str(6), "agent") != NULL &&
	      strstr(net_result_str(6), "PCR 14") != NULL &&
	      strstr(net_result_str(6), "firmware") != NULL))
		FAIL("expected: strstr(net_result_str(6), \"agent\") != NULL "
		     "&& strstr(net_result_str(6), \"PCR 14\") != NULL && "
		     "strstr(net_result_str(6), \"firmware\") != NULL");

	/* the two an administrator causes on purpose say so,
	 * so the machine is not read as broken when it is obeying */
	TEST("verdict 7 names the revocation");
	if (strstr(net_result_str(7), "revoked") == NULL)
		FAIL("expected: strstr(net_result_str(7), \"revoked\") != NULL");
	TEST("verdict 8 names the ban");
	if (strstr(net_result_str(8), "banned") == NULL)
		FAIL("expected: strstr(net_result_str(8), \"banned\") != NULL");

	/* each requirement has its own remedy, so its verdict names it */
	TEST("verdict 13 names the missing certificate");
	if (strstr(net_result_str(13), "certificate") == NULL)
		FAIL("expected: strstr(net_result_str(13), \"certificate\") "
		     "!= NULL");
	TEST("verdict 14 names Secure Boot and where it is turned on");
	if (!(strstr(net_result_str(14), "Secure Boot") != NULL &&
	      strstr(net_result_str(14), "firmware") != NULL))
		FAIL("expected: strstr(net_result_str(14), \"Secure Boot\") "
		     "!= NULL && strstr(net_result_str(14), \"firmware\") != "
		     "NULL");
	TEST("verdict 15 names kernel lockdown");
	if (strstr(net_result_str(15), "lockdown") == NULL)
		FAIL("expected: strstr(net_result_str(15), \"lockdown\") != "
		     "NULL");
	TEST("verdict 16 names module signature enforcement");
	if (strstr(net_result_str(16), "module") == NULL)
		FAIL("expected: strstr(net_result_str(16), \"module\") != NULL");
	TEST("verdict 17 names the LSM enforce mode");
	if (strstr(net_result_str(17), "enforc") == NULL)
		FAIL("expected: strstr(net_result_str(17), \"enforc\") != NULL");
	TEST("verdict 18 names IMA appraisal");
	if (strstr(net_result_str(18), "IMA") == NULL)
		FAIL("expected: strstr(net_result_str(18), \"IMA\") != NULL");
	TEST("verdict 19 names the kernel image");
	if (strstr(net_result_str(19), "kernel") == NULL)
		FAIL("expected: strstr(net_result_str(19), \"kernel\") != NULL");
	TEST("verdict 20 names the kernel command line");
	if (strstr(net_result_str(20), "command line") == NULL)
		FAIL("expected: strstr(net_result_str(20), \"command line\") "
		     "!= NULL");

	/* an unreadable report is not an old wire: no upgrade advice */
	TEST("verdict 5 names the protocol version");
	if (strstr(net_result_str(5), "version") == NULL)
		FAIL("expected: strstr(net_result_str(5), \"version\") != NULL");
	TEST("verdict 21 says the report could not be read and does not advise an upgrade");
	if (!(strstr(net_result_str(21), "read") != NULL &&
	      strstr(net_result_str(21), "version") == NULL))
		FAIL("expected: strstr(net_result_str(21), \"read\") != NULL "
		     "&& strstr(net_result_str(21), \"version\") == NULL");

	/*
	 * an enforce refusal tells the host what to write and where: the line
	 * the config parser takes, in the file the agent reads, and a reboot,
	 * since a restart spends the boot's attestation
	 */
	{
		static const uint32_t states[] = {
			0, LOTA_REPORT_FLAG_BPF_ACTIVE
		};
		size_t i;

		for (i = 0; i < sizeof(states) / sizeof(states[0]); i++) {
			const char *t = net_verdict_str(17, states[i]);
			char msg[128];

			snprintf(msg, sizeof(msg),
				 "verdict 17 (flags 0x%x) names mode = enforce "
				 "in " LOTA_CONFIG_DEFAULT_PATH " and a reboot",
				 states[i]);
			TEST(msg);
			if (!(strstr(t, "mode = enforce") != NULL &&
			      strstr(t, LOTA_CONFIG_DEFAULT_PATH) != NULL &&
			      strstr(t, "reboot") != NULL))
				FAIL("expected: strstr(t, \"mode = enforce\") != NULL && "
				     "strstr(t, LOTA_CONFIG_DEFAULT_PATH) != NULL && "
				     "strstr(t, \"reboot\") != NULL");

			snprintf(msg, sizeof(msg),
				 "verdict 17 (flags 0x%x) names no other file, "
				 "key or restart",
				 states[i]);
			TEST(msg);
			if (!(strstr(t, "agent.conf") == NULL &&
			      strstr(t, "enforce = true") == NULL &&
			      strstr(t, "restart lota-agent") == NULL))
				FAIL("expected: strstr(t, \"agent.conf\") == NULL && "
				     "strstr(t, \"enforce = true\") == NULL && strstr(t, "
				     "\"restart lota-agent\") == NULL");
		}
	}

	/* the report says whether the LSM was loaded; the sentence follows */
	TEST("verdict 17 on a report with the LSM loaded says it is not enforcing");
	if (strstr(net_verdict_str(17, LOTA_REPORT_FLAG_BPF_ACTIVE),
		   "not enforcing") == NULL)
		FAIL("expected: strstr(net_verdict_str(17, "
		     "LOTA_REPORT_FLAG_BPF_ACTIVE), \"not enforcing\") != NULL");
	TEST("verdict 17 on a report without the LSM says the daemon is not running");
	if (!(strstr(net_verdict_str(17, 0), "is loaded") == NULL &&
	      strstr(net_verdict_str(17, 0), "not running") != NULL))
		FAIL("expected: strstr(net_verdict_str(17, 0), \"is loaded\") "
		     "== NULL && strstr(net_verdict_str(17, 0), \"not "
		     "running\") != NULL");

	/* the default still exists for a code from a newer verifier */
	TEST("a code the agent does not know still falls to the default");
	if (is_named(FIRST_UNKNOWN_CODE))
		FAIL("expected: !is_named(FIRST_UNKNOWN_CODE)");

	return test_end();
}
