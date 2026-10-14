/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Unit tests for the guided installer's agent-service verdict.
 *
 * The stage that reports whether a host runs the agent is what a player is
 * told when they ask if their machine is protected. A host that is running the
 * agent but has not enabled its units enforces until it reboots and then does
 * not, so what is pinned here is that "running" alone is not the answer, and
 * that the note distinguishes a stopped host from an unenabled one.
 *
 * The verdict is a pure function of the probe answers: no systemd here.
 */

#include <stdio.h>
#include <string.h>

#include "../installer/install.h"
#include "../installer/probe.h"

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

static const struct probe_service_state all_good = {
	.agent_active = 1,
	.agent_enabled = 1,
	.socket_enabled = 1,
	.attest_enabled = 1,
};

/* A host that runs the agent and starts it again after a reboot is done. */
static void test_active_and_enabled_is_done(void)
{
	char note[256] = { 0 };

	CHECK(probe_agent_service_stage(&all_good, note, sizeof(note)) ==
		      STAGE_DONE,
	      "an active, enabled host is satisfied");
	CHECK(note[0] != '\0', "the satisfied verdict still carries a note");
}

/*
 * Running but not enabled is the state this stage used to call satisfied.
 * It is the one that loses enforcement silently, so it has to come back as work
 * to do, naming the unit that will not come up.
 */
static void test_active_but_not_enabled_is_pending(void)
{
	struct probe_service_state s;
	char note[256];

	s = all_good;
	s.agent_enabled = 0;
	note[0] = '\0';
	CHECK(probe_agent_service_stage(&s, note, sizeof(note)) ==
		      STAGE_PENDING,
	      "a running but unenabled agent is not satisfied");
	CHECK(strstr(note, "reboot") != NULL,
	      "the note says the agent will not survive a reboot");

	s = all_good;
	s.socket_enabled = 0;
	note[0] = '\0';
	CHECK(probe_agent_service_stage(&s, note, sizeof(note)) ==
		      STAGE_PENDING,
	      "an unenabled socket is not satisfied");

	s = all_good;
	s.attest_enabled = 0;
	note[0] = '\0';
	CHECK(probe_agent_service_stage(&s, note, sizeof(note)) ==
		      STAGE_PENDING,
	      "an unenabled attestation loop is not satisfied");
}

/*
 * A stopped host is a different problem from an unenabled one and gets
 * a different sentence: one needs starting, the other needs enabling.
 */
static void test_inactive_is_reported_apart(void)
{
	struct probe_service_state s = all_good;
	char stopped[256] = { 0 };
	char unenabled[256] = { 0 };

	s.agent_active = 0;
	CHECK(probe_agent_service_stage(&s, stopped, sizeof(stopped)) ==
		      STAGE_PENDING,
	      "a stopped agent is not satisfied");

	s = all_good;
	s.agent_enabled = 0;
	probe_agent_service_stage(&s, unenabled, sizeof(unenabled));

	CHECK(strcmp(stopped, unenabled) != 0,
	      "a stopped host and an unenabled one do not read alike");
}

int main(void)
{
	printf("=== installer agent-service verdict tests ===\n");
	test_active_and_enabled_is_done();
	test_active_but_not_enabled_is_pending();
	test_inactive_is_reported_apart();

	if (g_failures) {
		fprintf(stderr, "\n%d test(s) failed\n", g_failures);
		return 1;
	}
	printf("\nAll installer agent-service verdict tests passed\n");
	return 0;
}
