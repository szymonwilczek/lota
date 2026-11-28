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
#include <string.h>
#include <stdio.h>

#include "../include/lota.h"

#include "test.h"

#define DENIED(sig, is_agent) lota_signal_denied((sig), (is_agent), 0)

#define DENIED_INSIDE(sig) lota_signal_denied((sig), 0, 1)

#define RECORDS(sig, denied) lota_signal_event((sig), (denied))

/*
 * A local root must not be able to kill the agent, drop the BPF coverage and
 * swap a tampered binary in before the next attestation, in any mode.
 */
static void test_refuses_what_can_end_the_agent(void)
{
	TEST("refuses SIGTERM to the agent");
	if (!DENIED(SIGTERM, 1))
		FAIL("expected: DENIED(SIGTERM, 1)");
	TEST("refuses SIGKILL to the agent");
	if (!DENIED(SIGKILL, 1))
		FAIL("expected: DENIED(SIGKILL, 1)");
	TEST("refuses SIGSTOP to the agent");
	if (!DENIED(SIGSTOP, 1))
		FAIL("expected: DENIED(SIGSTOP, 1)");
	TEST("refuses an interactive interrupt to the agent");
	if (!DENIED(SIGINT, 1))
		FAIL("expected: DENIED(SIGINT, 1)");
	TEST("refuses SIGUSR1 to the agent");
	if (!DENIED(SIGUSR1, 1))
		FAIL("expected: DENIED(SIGUSR1, 1)");
}

/* A probe asks whether the agent is there; SIGHUP is its own reload */
static void test_the_signals_the_agent_takes(void)
{
	TEST("delivers a probe aimed at the agent");
	if (DENIED(0, 1))
		FAIL("expected: !DENIED(0, 1)");
	TEST("delivers SIGHUP to the agent, which is its reload");
	if (DENIED(SIGHUP, 1))
		FAIL("expected: !DENIED(SIGHUP, 1)");
}

/* A title that hung has to die from the terminal or the task manager */
static void test_a_protected_process_can_be_ended(void)
{
	TEST("delivers SIGKILL to a protected process");
	if (DENIED(SIGKILL, 0))
		FAIL("expected: !DENIED(SIGKILL, 0)");
	TEST("delivers SIGTERM to a protected process");
	if (DENIED(SIGTERM, 0))
		FAIL("expected: !DENIED(SIGTERM, 0)");
	TEST("delivers SIGINT to a protected process");
	if (DENIED(SIGINT, 0))
		FAIL("expected: !DENIED(SIGINT, 0)");
	TEST("delivers SIGHUP to a protected process");
	if (DENIED(SIGHUP, 0))
		FAIL("expected: !DENIED(SIGHUP, 0)");
	TEST("delivers SIGUSR1 to a protected process");
	if (DENIED(SIGUSR1, 0))
		FAIL("expected: !DENIED(SIGUSR1, 0)");
	TEST("delivers SIGCONT to a protected process");
	if (DENIED(SIGCONT, 0))
		FAIL("expected: !DENIED(SIGCONT, 0)");
	TEST("delivers a probe to a protected process");
	if (DENIED(0, 0))
		FAIL("expected: !DENIED(0, 0)");
}

/* Stopping the title or dumping its memory is what a cheat gains from */
static void test_a_protected_process_is_not_frozen_or_dumped(void)
{
	static const int refused[] = {
		SIGSTOP, SIGTSTP, SIGTTIN, SIGTTOU, SIGQUIT, SIGILL,  SIGTRAP,
		SIGABRT, SIGBUS,  SIGFPE,  SIGSEGV, SIGXCPU, SIGXFSZ, SIGSYS,
	};

	for (size_t i = 0; i < sizeof(refused) / sizeof(refused[0]); i++) {
		TEST(strsignal(refused[i]));
		if (!DENIED(refused[i], 0))
			FAIL("expected: DENIED(refused[i], 0)");
		TEST("the same signal passes inside the instance");
		if (DENIED_INSIDE(refused[i]))
			FAIL("expected: !DENIED_INSIDE(refused[i])");
	}
}

/* the sender is unknown there, so it counts as outside; 0 is the default SIGIO */
static void test_sigio_counts_as_outside(void)
{
	TEST("refuses SIGSTOP through F_SETOWN to a protected process");
	if (!lota_sigio_denied(SIGSTOP, 0))
		FAIL("expected: lota_sigio_denied(SIGSTOP, 0)");
	TEST("refuses SIGSEGV through F_SETOWN to a protected process");
	if (!lota_sigio_denied(SIGSEGV, 0))
		FAIL("expected: lota_sigio_denied(SIGSEGV, 0)");
	TEST("passes SIGIO to a protected process");
	if (lota_sigio_denied(0, 0))
		FAIL("expected: !lota_sigio_denied(0, 0)");
	TEST("passes a realtime signal to a protected process");
	if (lota_sigio_denied(SIGRTMIN, 0))
		FAIL("expected: !lota_sigio_denied(SIGRTMIN, 0)");
	TEST("refuses SIGIO to the agent");
	if (!lota_sigio_denied(0, 1))
		FAIL("expected: lota_sigio_denied(0, 1)");
	TEST("refuses SIGKILL through F_SETOWN to the agent");
	if (!lota_sigio_denied(SIGKILL, 1))
		FAIL("expected: lota_sigio_denied(SIGKILL, 1)");
}

/* Numbers outside the mask's range are never an index into it */
static void test_numbers_outside_the_mask(void)
{
	TEST("a negative number is not refused by the mask");
	if (DENIED(-1, 0))
		FAIL("expected: !DENIED(-1, 0)");
	TEST("a realtime signal is not in the mask");
	if (DENIED(SIGRTMIN, 0))
		FAIL("expected: !DENIED(SIGRTMIN, 0)");
	TEST("the last signal number is not in the mask");
	if (DENIED(64, 0))
		FAIL("expected: !DENIED(64, 0)");
}

/* Header mirrors the signal number because the object has no uapi */
static void test_the_mirrored_signal_number(void)
{
	TEST("the mirrored SIGHUP matches the system's");
	if (LOTA_SIG_HUP != SIGHUP)
		FAIL("expected: LOTA_SIG_HUP == SIGHUP");
	TEST("the mirrored SIGKILL matches the system's");
	if (LOTA_SIG_KILL != SIGKILL)
		FAIL("expected: LOTA_SIG_KILL == SIGKILL");
}

/* A refusal is recorded whatever the signal */
static void test_a_refusal_is_always_recorded(void)
{
	TEST("a refused SIGTERM is recorded as a refusal");
	if (RECORDS(SIGTERM, 1) != LOTA_EVENT_KILL_BLOCKED)
		FAIL("expected: RECORDS(SIGTERM, 1) == LOTA_EVENT_KILL_BLOCKED");
	TEST("a refused SIGKILL is recorded as a refusal");
	if (RECORDS(SIGKILL, 1) != LOTA_EVENT_KILL_BLOCKED)
		FAIL("expected: RECORDS(SIGKILL, 1) == LOTA_EVENT_KILL_BLOCKED");
	TEST("a refused SIGSTOP is recorded as a refusal");
	if (RECORDS(SIGSTOP, 1) != LOTA_EVENT_KILL_BLOCKED)
		FAIL("expected: RECORDS(SIGSTOP, 1) == LOTA_EVENT_KILL_BLOCKED");
	TEST("a refused SIGHUP is recorded as a refusal");
	if (RECORDS(SIGHUP, 1) != LOTA_EVENT_KILL_BLOCKED)
		FAIL("expected: RECORDS(SIGHUP, 1) == LOTA_EVENT_KILL_BLOCKED");
}

/* Every delivered signal but a probe is still recorded */
static void test_a_delivered_signal_is_still_recorded(void)
{
	TEST("a delivered SIGTERM is recorded");
	if (RECORDS(SIGTERM, 0) != LOTA_EVENT_KILL)
		FAIL("expected: RECORDS(SIGTERM, 0) == LOTA_EVENT_KILL");
	TEST("a delivered SIGKILL is recorded");
	if (RECORDS(SIGKILL, 0) != LOTA_EVENT_KILL)
		FAIL("expected: RECORDS(SIGKILL, 0) == LOTA_EVENT_KILL");
	TEST("a delivered SIGSTOP is recorded");
	if (RECORDS(SIGSTOP, 0) != LOTA_EVENT_KILL)
		FAIL("expected: RECORDS(SIGSTOP, 0) == LOTA_EVENT_KILL");
	TEST("a delivered interactive interrupt is recorded");
	if (RECORDS(SIGINT, 0) != LOTA_EVENT_KILL)
		FAIL("expected: RECORDS(SIGINT, 0) == LOTA_EVENT_KILL");
	TEST("the agent's own reload signal is recorded");
	if (RECORDS(SIGHUP, 0) != LOTA_EVENT_KILL)
		FAIL("expected: RECORDS(SIGHUP, 0) == LOTA_EVENT_KILL");
	TEST("a signal the policy has no opinion about is recorded");
	if (RECORDS(SIGUSR1, 0) != LOTA_EVENT_KILL)
		FAIL("expected: RECORDS(SIGUSR1, 0) == LOTA_EVENT_KILL");
}

/*
 * A delivered probe is not recorded: a launcher polls several times a second
 * and would bury the real events.
 */
static void test_a_permitted_probe_is_not_recorded(void)
{
	TEST("a permitted probe records nothing");
	if (RECORDS(0, 0) != 0)
		FAIL("expected: RECORDS(0, 0) == 0");
}

/* Suppression follows the verdict: a refused probe is still recorded */
static void test_suppression_follows_the_verdict(void)
{
	TEST("a refused probe is still recorded");
	if (RECORDS(0, 1) != LOTA_EVENT_KILL_BLOCKED)
		FAIL("expected: RECORDS(0, 1) == LOTA_EVENT_KILL_BLOCKED");
}

/* Verdict, then the event it records, in the hook's order */
static void test_the_two_decisions_together(void)
{
	int sig;

	sig = 0;
	TEST("a probe at the agent is delivered and records nothing");
	if (RECORDS(sig, DENIED(sig, 1)) != 0)
		FAIL("expected: RECORDS(sig, DENIED(sig, 1)) == 0");

	sig = SIGKILL;
	TEST("SIGKILL at the agent is refused and recorded");
	if (RECORDS(sig, DENIED(sig, 1)) != LOTA_EVENT_KILL_BLOCKED)
		FAIL("expected: RECORDS(sig, DENIED(sig, 1)) == "
		     "LOTA_EVENT_KILL_BLOCKED");

	sig = SIGHUP;
	TEST("the agent's reload is delivered and recorded");
	if (RECORDS(sig, DENIED(sig, 1)) != LOTA_EVENT_KILL)
		FAIL("expected: RECORDS(sig, DENIED(sig, 1)) == "
		     "LOTA_EVENT_KILL");

	sig = SIGKILL;
	TEST("SIGKILL at a protected task is delivered and recorded");
	if (RECORDS(sig, DENIED(sig, 0)) != LOTA_EVENT_KILL)
		FAIL("expected: RECORDS(sig, DENIED(sig, 0)) == "
		     "LOTA_EVENT_KILL");

	sig = 0;
	TEST("a probe at a protected task records nothing");
	if (RECORDS(sig, DENIED(sig, 0)) != 0)
		FAIL("expected: RECORDS(sig, DENIED(sig, 0)) == 0");
}

/* cgroup.kill ends the cgroup past the signal hook, so it is SIGKILL's twin */
static void test_the_cgroup_kill_guard(void)
{
	TEST("a write open of a guarded cgroup.kill is refused");
	if (!lota_kill_guard_denied(1, 1, 0))
		FAIL("expected: lota_kill_guard_denied(1, 1, 0)");
	TEST("the agent and the admin identity may write it");
	if (lota_kill_guard_denied(1, 1, 1))
		FAIL("expected: !lota_kill_guard_denied(1, 1, 1)");
	TEST("a read ends nobody");
	if (lota_kill_guard_denied(0, 1, 0))
		FAIL("expected: !lota_kill_guard_denied(0, 1, 0)");
	TEST("a cgroup.kill nobody guards is not refused");
	if (lota_kill_guard_denied(1, 0, 0))
		FAIL("expected: !lota_kill_guard_denied(1, 0, 0)");
}

/* the open period counts while a thread stands, and only then */
static void test_stopped_time(void)
{
	TEST("never stopped: nothing");
	if (lota_stopped_ns(0, 0, 0, 500) != 0)
		FAIL("expected: lota_stopped_ns(0, 0, 0, 500) == 0");
	TEST("none standing: the ended periods alone");
	if (lota_stopped_ns(70, 0, 100, 500) != 70)
		FAIL("expected: lota_stopped_ns(70, 0, 100, 500) == 70");
	TEST("one standing: its period counts");
	if (lota_stopped_ns(70, 1, 100, 500) != 470)
		FAIL("expected: lota_stopped_ns(70, 1, 100, 500) == 470");
	TEST("eight standing: the same period, not eight");
	if (lota_stopped_ns(70, 8, 100, 500) != 470)
		FAIL("expected: lota_stopped_ns(70, 8, 100, 500) == 470");
	TEST("clock behind the stop: no wrap");
	if (lota_stopped_ns(70, 1, 500, 100) != 70)
		FAIL("expected: lota_stopped_ns(70, 1, 500, 100) == 70");
}

int main(void)
{
	test_begin("signal policy");

	test_refuses_what_can_end_the_agent();
	test_the_signals_the_agent_takes();
	test_a_protected_process_can_be_ended();
	test_a_protected_process_is_not_frozen_or_dumped();
	test_sigio_counts_as_outside();
	test_numbers_outside_the_mask();
	test_the_mirrored_signal_number();
	test_a_refusal_is_always_recorded();
	test_a_delivered_signal_is_still_recorded();
	test_a_permitted_probe_is_not_recorded();
	test_suppression_follows_the_verdict();
	test_the_two_decisions_together();
	test_the_cgroup_kill_guard();
	test_stopped_time();

	return test_end();
}
