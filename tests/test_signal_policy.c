/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for the signal-delivery decision (include/lota.h).
 *
 * The verdict takes no enforcement mode: the agent is guarded in every mode,
 * since the mode switches policy and not the integrity of the measurement.
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

#define DENIED(sig, is_agent) lota_signal_denied((sig), (is_agent))

#define RECORDS(sig, denied) lota_signal_event((sig), (denied))

/*
 * A local root must not be able to kill the agent, drop the BPF coverage and
 * swap a tampered binary in before the next attestation, in any mode.
 */
static void test_refuses_what_can_end_the_agent(void)
{
	CHECK(DENIED(SIGTERM, 1), "refuses SIGTERM to the agent");
	CHECK(DENIED(SIGKILL, 1), "refuses SIGKILL to the agent");
	CHECK(DENIED(SIGSTOP, 1), "refuses SIGSTOP to the agent");
	CHECK(DENIED(SIGINT, 1),
	      "refuses an interactive interrupt to the agent");
	CHECK(DENIED(SIGUSR1, 1), "refuses SIGUSR1 to the agent");
}

/* A probe asks whether the agent is there; SIGHUP is its own reload */
static void test_the_signals_the_agent_takes(void)
{
	CHECK(!DENIED(0, 1), "delivers a probe aimed at the agent");
	CHECK(!DENIED(SIGHUP, 1),
	      "delivers SIGHUP to the agent, which is its reload");
}

/*
 * Ending or stopping a protected process puts nothing into it, and the
 * wineserver drives every process it hosts with signals.
 */
static void test_any_other_target_takes_every_signal(void)
{
	CHECK(!DENIED(SIGKILL, 0), "delivers SIGKILL to any other task");
	CHECK(!DENIED(SIGSTOP, 0), "delivers SIGSTOP to any other task");
	CHECK(!DENIED(SIGTERM, 0), "delivers SIGTERM to any other task");
	CHECK(!DENIED(SIGUSR1, 0), "delivers SIGUSR1 to any other task");
	CHECK(!DENIED(0, 0), "delivers a probe to any other task");
}

/* Header mirrors the signal number because the object has no uapi */
static void test_the_mirrored_signal_number(void)
{
	CHECK(LOTA_SIG_HUP == SIGHUP,
	      "the mirrored SIGHUP matches the system's");
}

/* A refusal is recorded whatever the signal */
static void test_a_refusal_is_always_recorded(void)
{
	CHECK(RECORDS(SIGTERM, 1) == LOTA_EVENT_KILL_BLOCKED,
	      "a refused SIGTERM is recorded as a refusal");
	CHECK(RECORDS(SIGKILL, 1) == LOTA_EVENT_KILL_BLOCKED,
	      "a refused SIGKILL is recorded as a refusal");
	CHECK(RECORDS(SIGSTOP, 1) == LOTA_EVENT_KILL_BLOCKED,
	      "a refused SIGSTOP is recorded as a refusal");
	CHECK(RECORDS(SIGHUP, 1) == LOTA_EVENT_KILL_BLOCKED,
	      "a refused SIGHUP is recorded as a refusal");
}

/* Every delivered signal but a probe is still recorded */
static void test_a_delivered_signal_is_still_recorded(void)
{
	CHECK(RECORDS(SIGTERM, 0) == LOTA_EVENT_KILL,
	      "a delivered SIGTERM is recorded");
	CHECK(RECORDS(SIGKILL, 0) == LOTA_EVENT_KILL,
	      "a delivered SIGKILL is recorded");
	CHECK(RECORDS(SIGSTOP, 0) == LOTA_EVENT_KILL,
	      "a delivered SIGSTOP is recorded");
	CHECK(RECORDS(SIGINT, 0) == LOTA_EVENT_KILL,
	      "a delivered interactive interrupt is recorded");
	CHECK(RECORDS(SIGHUP, 0) == LOTA_EVENT_KILL,
	      "the agent's own reload signal is recorded");
	CHECK(RECORDS(SIGUSR1, 0) == LOTA_EVENT_KILL,
	      "a signal the policy has no opinion about is recorded");
}

/*
 * A delivered probe is not recorded: a launcher polls several times a second
 * and would bury the real events.
 */
static void test_a_permitted_probe_is_not_recorded(void)
{
	CHECK(RECORDS(0, 0) == 0, "a permitted probe records nothing");
}

/* Suppression follows the verdict: a refused probe is still recorded */
static void test_suppression_follows_the_verdict(void)
{
	CHECK(RECORDS(0, 1) == LOTA_EVENT_KILL_BLOCKED,
	      "a refused probe is still recorded");
}

/* Verdict, then the event it records, in the hook's order */
static void test_the_two_decisions_together(void)
{
	int sig;

	sig = 0;
	CHECK(RECORDS(sig, DENIED(sig, 1)) == 0,
	      "a probe at the agent is delivered and records nothing");

	sig = SIGKILL;
	CHECK(RECORDS(sig, DENIED(sig, 1)) == LOTA_EVENT_KILL_BLOCKED,
	      "SIGKILL at the agent is refused and recorded");

	sig = SIGHUP;
	CHECK(RECORDS(sig, DENIED(sig, 1)) == LOTA_EVENT_KILL,
	      "the agent's reload is delivered and recorded");

	sig = SIGKILL;
	CHECK(RECORDS(sig, DENIED(sig, 0)) == LOTA_EVENT_KILL,
	      "SIGKILL at a protected task is delivered and recorded");

	sig = 0;
	CHECK(RECORDS(sig, DENIED(sig, 0)) == 0,
	      "a probe at a protected task records nothing");
}

/* cgroup.kill ends the cgroup past the signal hook, so it is SIGKILL's twin */
static void test_the_cgroup_kill_guard(void)
{
	CHECK(lota_kill_guard_denied(1, 1, 0),
	      "a write open of a guarded cgroup.kill is refused");
	CHECK(!lota_kill_guard_denied(1, 1, 1),
	      "the agent and the admin identity may write it");
	CHECK(!lota_kill_guard_denied(0, 1, 0), "a read ends nobody");
	CHECK(!lota_kill_guard_denied(1, 0, 0),
	      "a cgroup.kill nobody guards is not refused");
}

int main(void)
{
	printf("=== signal delivery policy tests ===\n\n");

	test_refuses_what_can_end_the_agent();
	test_the_signals_the_agent_takes();
	test_any_other_target_takes_every_signal();
	test_the_mirrored_signal_number();
	test_a_refusal_is_always_recorded();
	test_a_delivered_signal_is_still_recorded();
	test_a_permitted_probe_is_not_recorded();
	test_suppression_follows_the_verdict();
	test_the_two_decisions_together();
	test_the_cgroup_kill_guard();

	printf("\n%s\n", g_failures ? "FAILURES" : "All tests passed");
	return g_failures ? 1 : 0;
}
