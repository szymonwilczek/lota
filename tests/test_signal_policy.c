/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for the signal-delivery decision (include/lota.h).
 *
 * They pin the mode contract: an agent in monitor mode observes and refuses
 * nothing, including a signal aimed at itself, because monitor is the mode
 * an operator evaluates LOTA in and an agent that cannot be stopped without
 * spending the boot commitment is the opposite of an evaluation posture.
 * Self-protection in enforce is the deliberate property and is pinned here
 * as well, so the two cannot be confused for one another later.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <signal.h>
#include <stdio.h>

#include "../include/lota.h"

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

#define DENIED(sig, lota_mode, is_agent, is_protected) \
	lota_signal_denied((sig), (lota_mode), (is_agent), (is_protected))

/*
 * Monitor is the mode that blocks nothing.
 * The kill hook was the one hook that ignored that, so a `timeout 20` around
 * a monitor-mode agent outlived its timeout, and every experiment in a sweep
 * had to end in a reboot.
 */
static void test_monitor_refuses_nothing(void)
{
	CHECK(!DENIED(SIGTERM, LOTA_MODE_MONITOR, 1, 0),
	      "monitor delivers SIGTERM to the agent");
	CHECK(!DENIED(SIGKILL, LOTA_MODE_MONITOR, 1, 0),
	      "monitor delivers SIGKILL to the agent");
	CHECK(!DENIED(SIGTERM, LOTA_MODE_MONITOR, 0, 1),
	      "monitor delivers SIGTERM to a protected task");
	CHECK(!DENIED(SIGINT, LOTA_MODE_MONITOR, 1, 0),
	      "monitor delivers an interactive interrupt to the agent");
}

/* Maintenance exists to lift the gates, and lifts this one too */
static void test_maintenance_refuses_nothing(void)
{
	CHECK(!DENIED(SIGTERM, LOTA_MODE_MAINTENANCE, 0, 1),
	      "maintenance delivers SIGTERM to a protected task");
	CHECK(!DENIED(SIGKILL, LOTA_MODE_MAINTENANCE, 1, 0),
	      "maintenance delivers SIGKILL to the agent");
}

/*
 * Enforce is where the refusal is the point: a local-root attacker must not be
 * able to kill the agent, drop the BPF coverage and swap a tampered binary in
 * before the next attestation
 */
static void test_enforce_refuses_what_can_end_the_target(void)
{
	CHECK(DENIED(SIGTERM, LOTA_MODE_ENFORCE, 1, 0),
	      "enforce refuses SIGTERM to the agent");
	CHECK(DENIED(SIGKILL, LOTA_MODE_ENFORCE, 1, 0),
	      "enforce refuses SIGKILL to the agent");
	CHECK(DENIED(SIGSTOP, LOTA_MODE_ENFORCE, 0, 1),
	      "enforce refuses SIGSTOP to a protected task");
}

/* A target nobody protects is nobody's business here, in any mode */
static void test_an_unprotected_target_is_never_refused(void)
{
	CHECK(!DENIED(SIGKILL, LOTA_MODE_ENFORCE, 0, 0),
	      "enforce delivers SIGKILL to a task nobody protects");
	CHECK(!DENIED(SIGTERM, LOTA_MODE_MONITOR, 0, 0),
	      "monitor delivers SIGTERM to a task nobody protects");
}

/*
 * The two signals that cannot end a target.
 * A probe is how a supervisor asks whether a process is still there,
 * and SIGHUP is the agent's own reload -- refusing either would break the thing
 * the refusal exists to protect.
 */
static void test_the_signals_that_are_always_delivered(void)
{
	CHECK(!DENIED(0, LOTA_MODE_ENFORCE, 1, 0),
	      "enforce delivers a probe aimed at the agent");
	CHECK(!DENIED(0, LOTA_MODE_ENFORCE, 0, 1),
	      "enforce delivers a probe aimed at a protected task");
	CHECK(!DENIED(SIGHUP, LOTA_MODE_ENFORCE, 1, 0),
	      "enforce delivers SIGHUP to the agent, which is its reload");
	CHECK(DENIED(SIGHUP, LOTA_MODE_ENFORCE, 0, 1),
	      "enforce refuses SIGHUP to a protected task that is not the agent");
}

/* Header mirrors the signal number because the object has no uapi */
static void test_the_mirrored_signal_number(void)
{
	CHECK(LOTA_SIG_HUP == SIGHUP,
	      "the mirrored SIGHUP matches the system's");
}

int main(void)
{
	printf("=== signal delivery policy tests ===\n\n");

	test_monitor_refuses_nothing();
	test_maintenance_refuses_nothing();
	test_enforce_refuses_what_can_end_the_target();
	test_an_unprotected_target_is_never_refused();
	test_the_signals_that_are_always_delivered();
	test_the_mirrored_signal_number();

	printf("\n%s\n", g_failures ? "FAILURES" : "All tests passed");
	return g_failures ? 1 : 0;
}
