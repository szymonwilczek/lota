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
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "../src/agent/watchdog.h"

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

	CHECK(watchdog_verdict_for(now, now, deadline) == WATCHDOG_PING,
	      "a loop that advanced just now pings the watchdog");

	CHECK(watchdog_verdict_for(now, now - (deadline / 2 - 1), deadline) ==
		      WATCHDOG_PING,
	      "a loop inside the ping contract still pings");

	CHECK(watchdog_verdict_for(now, now - deadline / 2, deadline) ==
		      WATCHDOG_HOLD,
	      "a loop that missed its ping contract holds the ping");

	CHECK(watchdog_verdict_for(now, now - deadline, deadline) ==
		      WATCHDOG_TERMINATE,
	      "a loop stalled for the whole interval ends the process");

	CHECK(watchdog_verdict_for(now, now - deadline * 4, deadline) ==
		      WATCHDOG_TERMINATE,
	      "a loop stalled well past the interval ends the process");

	/* beats are read unlocked: a torn read must not kill a live agent */
	CHECK(watchdog_verdict_for(now, now + deadline, deadline) ==
		      WATCHDOG_PING,
	      "a beat from the future is not a wedge");

	CHECK(watchdog_verdict_for(now, now - deadline, 0) == WATCHDOG_PING,
	      "no deadline configured is never a wedge");
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

	CHECK(pid > 0, "the wedged-agent child forked");
	if (pid <= 0)
		return;

	CHECK(waitpid(pid, &status, 0) == pid,
	      "the wedged agent did not outlive its watchdog interval");
	CHECK(WIFSIGNALED(status),
	      "the wedged agent was ended by a signal, not a clean exit");
	CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL,
	      "the signal the supervisor sent is SIGKILL");
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

	CHECK(pid > 0, "the live-agent child forked");
	if (pid <= 0)
		return;

	CHECK(waitpid(pid, &status, 0) == pid, "the live agent was reaped");
	CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	      "an agent whose loop advances is not ended by its supervisor");
}

int main(void)
{
	printf("=== watchdog supervisor tests ===\n");

	test_verdicts();
	test_wedged_process_ends_itself();
	test_live_process_is_left_alone();

	if (g_failures) {
		fprintf(stderr, "\n%d test(s) failed\n", g_failures);
		return 1;
	}

	printf("\nAll watchdog supervisor tests passed\n");
	return 0;
}
