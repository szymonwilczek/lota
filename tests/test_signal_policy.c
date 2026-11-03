/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for the signal-delivery decision (include/lota.h).
 *
 * The verdict takes no enforcement mode: the agent and a protected process
 * are guarded in every mode, since the mode switches policy and not the
 * integrity of the measurement.
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

#define DENIED(sig, is_agent, is_protected) \
	lota_signal_denied((sig), (is_agent), (is_protected), 0)

/* as DENIED, for a target with a handler for @sig */
#define DENIED_HANDLED(sig, is_agent, is_protected) \
	lota_signal_denied((sig), (is_agent), (is_protected), 1)

#define RECORDS(sig, denied) lota_signal_event((sig), (denied))

/*
 * A local root must not be able to kill the agent, drop the BPF coverage and
 * swap a tampered binary in before the next attestation, in any mode.
 */
static void test_refuses_what_can_end_the_target(void)
{
	CHECK(DENIED(SIGTERM, 1, 0), "refuses SIGTERM to the agent");
	CHECK(DENIED(SIGKILL, 1, 0), "refuses SIGKILL to the agent");
	CHECK(DENIED(SIGINT, 1, 0),
	      "refuses an interactive interrupt to the agent");
	CHECK(DENIED(SIGTERM, 0, 1), "refuses SIGTERM to a protected task");
	CHECK(DENIED(SIGKILL, 0, 1), "refuses SIGKILL to a protected task");
	CHECK(DENIED(SIGSTOP, 0, 1), "refuses SIGSTOP to a protected task");
}

/* A target nobody protects is nobody's business here */
static void test_an_unprotected_target_is_never_refused(void)
{
	CHECK(!DENIED(SIGKILL, 0, 0),
	      "delivers SIGKILL to a task nobody protects");
	CHECK(!DENIED(SIGTERM, 0, 0),
	      "delivers SIGTERM to a task nobody protects");
}

/*
 * The two signals that cannot end a target.
 * A probe is how a supervisor asks whether a process is still there,
 * and SIGHUP is the agent's own reload -- refusing either would break the thing
 * the refusal exists to protect.
 */
static void test_the_signals_that_are_always_delivered(void)
{
	CHECK(!DENIED(0, 1, 0), "delivers a probe aimed at the agent");
	CHECK(!DENIED(0, 0, 1), "delivers a probe aimed at a protected task");
	CHECK(!DENIED(SIGHUP, 1, 0),
	      "delivers SIGHUP to the agent, which is its reload");
	CHECK(DENIED(SIGHUP, 0, 1),
	      "refuses SIGHUP to a protected task that is not the agent");
}

/*
 * A handled signal neither ends nor stops the target. The wineserver
 * suspends threads and delivers APCs with SIGUSR1 and ends threads with
 * SIGQUIT; a title under Wine refused them hangs.
 */
static void test_a_signal_the_target_handles_is_delivered(void)
{
	CHECK(!DENIED_HANDLED(SIGUSR1, 0, 1),
	      "delivers a handled SIGUSR1 to a protected task");
	CHECK(!DENIED_HANDLED(SIGQUIT, 0, 1),
	      "delivers a handled SIGQUIT to a protected task");
	CHECK(DENIED(SIGUSR1, 0, 1),
	      "refuses SIGUSR1 to a protected task with no handler");
	CHECK(DENIED(SIGQUIT, 0, 1),
	      "refuses SIGQUIT to a protected task with no handler");
}

/*
 * SIGKILL and SIGSTOP cannot be handled. SIGTERM, SIGINT and SIGHUP ask
 * a process to end, so a protected title still ends only through the agent.
 * The agent shuts down from its own handlers, so a handler opens nothing.
 */
static void test_a_handler_does_not_open_what_ends_the_target(void)
{
	CHECK(DENIED_HANDLED(SIGKILL, 0, 1),
	      "refuses SIGKILL to a protected task, handler or not");
	CHECK(DENIED_HANDLED(SIGSTOP, 0, 1),
	      "refuses SIGSTOP to a protected task, handler or not");
	CHECK(DENIED_HANDLED(SIGTERM, 0, 1),
	      "refuses a handled SIGTERM to a protected task");
	CHECK(DENIED_HANDLED(SIGINT, 0, 1),
	      "refuses a handled SIGINT to a protected task");
	CHECK(DENIED_HANDLED(SIGHUP, 0, 1),
	      "refuses a handled SIGHUP to a protected task");
	CHECK(DENIED_HANDLED(SIGTERM, 1, 0),
	      "refuses a handled SIGTERM to the agent");
	CHECK(DENIED_HANDLED(SIGUSR1, 1, 0),
	      "refuses a handled SIGUSR1 to the agent");
}

/* Header mirrors the signal number because the object has no uapi */
static void test_the_mirrored_signal_number(void)
{
	CHECK(LOTA_SIG_HUP == SIGHUP,
	      "the mirrored SIGHUP matches the system's");
	CHECK(LOTA_SIG_INT == SIGINT,
	      "the mirrored SIGINT matches the system's");
	CHECK(LOTA_SIG_KILL == SIGKILL,
	      "the mirrored SIGKILL matches the system's");
	CHECK(LOTA_SIG_TERM == SIGTERM,
	      "the mirrored SIGTERM matches the system's");
	CHECK(LOTA_SIG_STOP == SIGSTOP,
	      "the mirrored SIGSTOP matches the system's");
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
	CHECK(RECORDS(sig, DENIED(sig, 1, 0)) == 0,
	      "a probe at the agent is delivered and records nothing");

	sig = SIGKILL;
	CHECK(RECORDS(sig, DENIED(sig, 1, 0)) == LOTA_EVENT_KILL_BLOCKED,
	      "SIGKILL at the agent is refused and recorded");

	sig = 0;
	CHECK(RECORDS(sig, DENIED(sig, 0, 1)) == 0,
	      "a probe at a protected task records nothing");

	sig = SIGHUP;
	CHECK(RECORDS(sig, DENIED(sig, 1, 0)) == LOTA_EVENT_KILL,
	      "the agent's reload is delivered and recorded");

	sig = SIGHUP;
	CHECK(RECORDS(sig, DENIED(sig, 0, 1)) == LOTA_EVENT_KILL_BLOCKED,
	      "SIGHUP at a protected task is refused and recorded");
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

	test_refuses_what_can_end_the_target();
	test_an_unprotected_target_is_never_refused();
	test_the_signals_that_are_always_delivered();
	test_a_signal_the_target_handles_is_delivered();
	test_a_handler_does_not_open_what_ends_the_target();
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
