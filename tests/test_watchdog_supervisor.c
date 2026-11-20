/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * The agent's task_kill hook refuses systemd's watchdog SIGABRT/SIGKILL,
 * but delivers a signal to the task's own thread group.
 * The supervisor must read a stalled main loop as a wedge, stop pinging
 * and kill the process itself.
 */

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../src/agent/watchdog.h"

#include "test.h"

#define NSEC_PER_USEC 1000ULL
#define NSEC_PER_MSEC 1000000ULL

static void sleep_ms(unsigned int ms)
{
	struct timespec ts = { .tv_sec = ms / 1000,
			       .tv_nsec = (long)(ms % 1000) * 1000000L };

	while (nanosleep(&ts, &ts) < 0 && errno == EINTR)
		;
}

/* WATCHDOG_USEC as systemd passes it; the cases derive the ns deadline */
static const uint64_t WD_USEC = 60ULL * 1000000ULL;

static void test_verdicts(void)
{
	uint64_t deadline = WD_USEC * NSEC_PER_USEC;
	uint64_t now = 1000ULL * NSEC_PER_MSEC * 1000ULL;

	TEST("a loop that advanced just now pings the watchdog");
	if (watchdog_verdict_for(now, now, deadline) != WATCHDOG_PING)
		FAIL("expected: watchdog_verdict_for(now, now, deadline) == "
		     "WATCHDOG_PING");

	TEST("a loop inside the ping contract still pings");
	if (watchdog_verdict_for(now, now - (deadline / 2 - 1), deadline) !=
	    WATCHDOG_PING)
		FAIL("expected: watchdog_verdict_for(now, now - (deadline / 2 "
		     "- 1), deadline) == WATCHDOG_PING");

	TEST("a loop that missed its ping contract holds the ping");
	if (watchdog_verdict_for(now, now - deadline / 2, deadline) !=
	    WATCHDOG_HOLD)
		FAIL("expected: watchdog_verdict_for(now, now - deadline / 2, "
		     "deadline) == WATCHDOG_HOLD");

	TEST("a loop stalled for the whole interval ends the process");
	if (watchdog_verdict_for(now, now - deadline, deadline) !=
	    WATCHDOG_TERMINATE)
		FAIL("expected: watchdog_verdict_for(now, now - deadline, "
		     "deadline) == WATCHDOG_TERMINATE");

	TEST("a loop stalled well past the interval ends the process");
	if (watchdog_verdict_for(now, now - deadline * 4, deadline) !=
	    WATCHDOG_TERMINATE)
		FAIL("expected: watchdog_verdict_for(now, now - deadline * 4, "
		     "deadline) == WATCHDOG_TERMINATE");

	/* beats are read unlocked: a torn read must not kill a live agent */
	TEST("a beat from the future is not a wedge");
	if (watchdog_verdict_for(now, now + deadline, deadline) !=
	    WATCHDOG_PING)
		FAIL("expected: watchdog_verdict_for(now, now + deadline, "
		     "deadline) == WATCHDOG_PING");

	TEST("no deadline configured is never a wedge");
	if (watchdog_verdict_for(now, now - deadline, 0) != WATCHDOG_PING)
		FAIL("expected: watchdog_verdict_for(now, now - deadline, 0) "
		     "== WATCHDOG_PING");
}

/*
 * Must end as a kill, not a clean exit: the shutdown path spends PCR 14,
 * and a watchdog restart has to keep the boot commitment.
 */
static void test_wedged_process_ends_itself(void)
{
	pid_t pid = fork();
	int status = 0;

	if (pid == 0) {
		if (watchdog_start(200000ULL) < 0)
			_exit(70);
		/* the wedge: the main loop never advances again */
		for (;;)
			sleep_ms(50);
	}

	TEST("the wedged-agent child forked");
	if (pid <= 0)
		FAIL("expected: pid > 0");
	if (pid <= 0)
		return;

	TEST("the wedged agent did not outlive its watchdog interval");
	if (waitpid(pid, &status, 0) != pid)
		FAIL("expected: waitpid(pid, &status, 0) == pid");
	TEST("the wedged agent was ended by a signal, not a clean exit");
	if (!WIFSIGNALED(status))
		FAIL("expected: WIFSIGNALED(status)");
	TEST("the signal the supervisor sent is SIGKILL");
	if (!(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL))
		FAIL("expected: WIFSIGNALED(status) && WTERMSIG(status) == "
		     "SIGKILL");
}

/* A loop that keeps advancing is left alone for several intervals. */
static void test_live_process_is_left_alone(void)
{
	pid_t pid = fork();
	int status = 0;

	if (pid == 0) {
		if (watchdog_start(200000ULL) < 0)
			_exit(70);
		for (int i = 0; i < 40; i++) {
			watchdog_beat();
			sleep_ms(25);
		}
		watchdog_stop();
		_exit(0);
	}

	TEST("the live-agent child forked");
	if (pid <= 0)
		FAIL("expected: pid > 0");
	if (pid <= 0)
		return;

	TEST("the live agent was reaped");
	if (waitpid(pid, &status, 0) != pid)
		FAIL("expected: waitpid(pid, &status, 0) == pid");
	TEST("an agent whose loop advances is not ended by its supervisor");
	if (!(WIFEXITED(status) && WEXITSTATUS(status) == 0))
		FAIL("expected: WIFEXITED(status) && WEXITSTATUS(status) == 0");
}

int main(void)
{
	test_begin("watchdog supervisor");

	test_verdicts();
	test_wedged_process_ends_itself();
	test_live_process_is_left_alone();

	return test_end();
}
