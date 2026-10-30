/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for the watchdog ping pace: replay early wakes, slow rounds
 * and both, and check no gap between pings reaches the deadline.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <stdio.h>
#include <string.h>

#include "../src/agent/watchdog_pace.h"

static int tests_run;
static int tests_passed;

static void check(const char *name, int ok, const char *why)
{
	tests_run++;
	printf("  [%2d] %-58s ", tests_run, name);
	if (ok) {
		tests_passed++;
		printf("PASS\n");
	} else {
		printf("FAIL: %s\n", why);
	}
}

#define DEADLINE 60000

/* One wake of the loop: when after the sleep began, and the work after it */
struct loop_event {
	uint64_t woke_after_ms; /* 0: at once */
	uint64_t work_ms;
};

/* Ping when owed, sleep no longer than allowed; returns the widest gap */
static uint64_t widest_gap(const struct loop_event *events, size_t count,
			   uint64_t interval_ms)
{
	struct watchdog_pace pace;
	uint64_t now = 0;
	uint64_t widest = 0;
	size_t i;

	watchdog_pace_init(&pace, DEADLINE, now);

	for (i = 0; i < count; i++) {
		uint64_t allowed;

		/* before the sleep */
		if (watchdog_pace_due(&pace, now)) {
			if (now - pace.last_ping_ms > widest)
				widest = now - pace.last_ping_ms;
			watchdog_pace_mark(&pace, now);
		}

		allowed = watchdog_pace_sleep_ms(&pace, now, interval_ms);
		now += events[i].woke_after_ms < allowed ?
			       events[i].woke_after_ms :
			       allowed;

		/* after the wake, before the work */
		if (watchdog_pace_due(&pace, now)) {
			if (now - pace.last_ping_ms > widest)
				widest = now - pace.last_ping_ms;
			watchdog_pace_mark(&pace, now);
		}

		now += events[i].work_ms;
	}

	if (now - pace.last_ping_ms > widest)
		widest = now - pace.last_ping_ms;

	return widest;
}

static void test_owing(void)
{
	struct watchdog_pace pace;

	watchdog_pace_init(&pace, DEADLINE, 1000);

	check("a loop that has just pinged owes nothing",
	      !watchdog_pace_due(&pace, 1000),
	      "it asked to ping twice running");

	check("it still owes nothing a moment later",
	      !watchdog_pace_due(&pace, 1100),
	      "it pings far more than it need");

	/* half, so a slightly late ping still lands in time */
	check("it owes one once half the deadline has gone",
	      watchdog_pace_due(&pace, 1000 + DEADLINE / 2),
	      "it waits out the whole deadline before pinging");

	check("an unwatched loop never owes one",
	      (watchdog_pace_init(&pace, 0, 0),
	       !watchdog_pace_due(&pace, DEADLINE * 10)),
	      "it pings a supervisor that is not there");
}

static void test_sleep_bound(void)
{
	struct watchdog_pace pace;

	watchdog_pace_init(&pace, DEADLINE, 0);

	check("a sleep never runs past the point a ping is owed",
	      watchdog_pace_sleep_ms(&pace, 0, DEADLINE * 2) <= DEADLINE / 2,
	      "the loop sleeps through its own deadline");

	check("a shorter wait is left alone",
	      watchdog_pace_sleep_ms(&pace, 0, 5) == 5,
	      "the rule lengthened a wait it was only asked to cap");

	check("a loop that already owes a ping does not sleep first",
	      watchdog_pace_sleep_ms(&pace, DEADLINE, DEADLINE) == 0,
	      "it sleeps while a ping is overdue");

	check("an unwatched loop waits for what it asked",
	      (watchdog_pace_init(&pace, 0, 0),
	       watchdog_pace_sleep_ms(&pace, 0, DEADLINE * 2) == DEADLINE * 2),
	      "an absent supervisor shortened the wait");
}

static void test_quiet_loop(void)
{
	/* nothing wakes it early */
	const struct loop_event quiet[] = {
		{ 30000, 2000 }, { 30000, 2000 }, { 30000, 2000 },
		{ 30000, 2000 }, { 30000, 2000 }, { 30000, 2000 },
	};

	check("a loop nothing interrupts stays inside the deadline",
	      widest_gap(quiet, sizeof(quiet) / sizeof(quiet[0]), 30000) <
		      DEADLINE,
	      "even the undisturbed loop misses its deadline");
}

static void test_early_wakes(void)
{
	/* a busy host: each session opening or closing wakes the loop */
	struct loop_event busy[30];
	size_t i;

	for (i = 0; i < sizeof(busy) / sizeof(busy[0]); i++) {
		busy[i].woke_after_ms = 0;
		busy[i].work_ms = 3000;
	}

	check("a loop woken early keeps pinging",
	      widest_gap(busy, sizeof(busy) / sizeof(busy[0]), 30000) <
		      DEADLINE,
	      "sessions opening and closing let the deadline pass");
}

static void test_slow_round(void)
{
	/* a round longer than the target gap: the pings around it must fit */
	const struct loop_event slow[] = {
		{ 30000, 2000 },
		{ 0, 35000 },
		{ 30000, 2000 },
	};

	check("a round slower than the target gap is survived",
	      widest_gap(slow, sizeof(slow) / sizeof(slow[0]), 30000) <
		      DEADLINE,
	      "one slow round is enough to be killed");
}

static void test_mixed(void)
{
	/* both, as on the failing host */
	const struct loop_event mixed[] = {
		{ 0, 3000 },	 { 0, 3000 }, { 30000, 2000 },	{ 0, 20000 },
		{ 0, 3000 },	 { 0, 3000 }, { 12000, 30000 }, { 0, 3000 },
		{ 30000, 2000 }, { 0, 3000 }, { 5000, 25000 },	{ 0, 3000 },
	};

	check("early wakes and slow rounds together stay inside the deadline",
	      widest_gap(mixed, sizeof(mixed) / sizeof(mixed[0]), 30000) <
		      DEADLINE,
	      "the loop is killed on the path that made this worth writing");
}

int main(void)
{
	printf("\n=== watchdog pacing tests ===\n\n");

	test_owing();
	test_sleep_bound();
	test_quiet_loop();
	test_early_wakes();
	test_slow_round();
	test_mixed();

	printf("\n%d/%d passed\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
