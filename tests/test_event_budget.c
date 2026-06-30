/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for the ring-buffer emission budget helpers
 * (include/lota_event_budget.h).
 *
 * They pin the policy the BPF LSM enforces under ring-buffer pressure:
 * both allowed and blocked events are bounded per one-second window in ENFORCE
 * mode so neither class can flood the ring buffer and starve the other, while
 * outside ENFORCE nothing is gated.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <stdio.h>

#include "../include/lota_event_budget.h"

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

/*
 * Blocked events are security-relevant, so a flood of self-induced denials
 * must not be free to monopolise the ring buffer:
 * in ENFORCE mode the blocked class carries a finite, non-zero budget of its
 * own, larger than the allowed budget but still bounded.
 */
static void test_blocked_is_bounded_under_enforce(void)
{
	CHECK(lota_event_budget_limit(1, 1) != 0,
	      "blocked events are budgeted (not unbounded) in ENFORCE mode");
	CHECK(lota_event_budget_limit(1, 1) ==
		      LOTA_BLOCKED_EVENT_BUDGET_PER_SEC,
	      "blocked budget is the blocked per-second cap");
	CHECK(lota_event_budget_limit(1, 1) > lota_event_budget_limit(1, 0),
	      "blocked budget is larger than the allowed budget");
}

static void test_allowed_budget_and_unbounded_modes(void)
{
	CHECK(lota_event_budget_limit(1, 0) == LOTA_ALLOW_EVENT_BUDGET_PER_SEC,
	      "allowed events keep the allowed per-second cap in ENFORCE mode");
	CHECK(lota_event_budget_limit(0, 0) == 0,
	      "allowed events are unbounded outside ENFORCE mode");
	CHECK(lota_event_budget_limit(0, 1) == 0,
	      "blocked events are unbounded outside ENFORCE mode");
}

static void test_window_expiry(void)
{
	CHECK(!lota_event_budget_window_expired(1000, 1000),
	      "same instant is within the window");
	CHECK(!lota_event_budget_window_expired(
		      1000 + LOTA_EVENT_BUDGET_WINDOW_NS - 1, 1000),
	      "one nanosecond before the boundary is within the window");
	CHECK(lota_event_budget_window_expired(
		      1000 + LOTA_EVENT_BUDGET_WINDOW_NS, 1000),
	      "exactly the window length has elapsed");
	CHECK(lota_event_budget_window_expired(500, 1000),
	      "a backwards clock rotates the window");
}

static void test_exhaustion_boundary(void)
{
	CHECK(!lota_event_budget_exhausted(0, 256),
	      "an empty window is not exhausted");
	CHECK(!lota_event_budget_exhausted(255, 256),
	      "the last in-budget slot is not exhausted");
	CHECK(lota_event_budget_exhausted(256, 256),
	      "the slot at the cap is exhausted");
	CHECK(lota_event_budget_exhausted(1000, 256),
	      "past the cap stays exhausted");
}

int main(void)
{
	printf("=== event budget tests ===\n");
	test_blocked_is_bounded_under_enforce();
	test_allowed_budget_and_unbounded_modes();
	test_window_expiry();
	test_exhaustion_boundary();

	if (g_failures) {
		fprintf(stderr, "\n%d test(s) failed\n", g_failures);
		return 1;
	}
	printf("\nAll event budget tests passed\n");
	return 0;
}
