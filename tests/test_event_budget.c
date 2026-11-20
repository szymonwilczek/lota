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
 * A budget bounds rate, not ring space; under ring pressure a loud event
 * type must yield room to a quiet one.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include "../include/lota_event_budget.h"

#include "test.h"

/*
 * Blocked events are security-relevant, so a flood of self-induced denials
 * must not be free to monopolise the ring buffer:
 * in ENFORCE mode the blocked class carries a finite, non-zero budget of its
 * own, larger than the allowed budget but still bounded.
 */
static void test_blocked_is_bounded_under_enforce(void)
{
	TEST("blocked events are budgeted (not unbounded) in ENFORCE mode");
	if (lota_event_budget_limit(1, 1) == 0)
		FAIL("expected: lota_event_budget_limit(1, 1) != 0");
	TEST("blocked budget is the blocked per-second cap");
	if (lota_event_budget_limit(1, 1) != LOTA_BLOCKED_EVENT_BUDGET_PER_SEC)
		FAIL("expected: lota_event_budget_limit(1, 1) == "
		     "LOTA_BLOCKED_EVENT_BUDGET_PER_SEC");
	TEST("blocked budget is larger than the allowed budget");
	if (lota_event_budget_limit(1, 1) <= lota_event_budget_limit(1, 0))
		FAIL("expected: lota_event_budget_limit(1, 1) > "
		     "lota_event_budget_limit(1, 0)");
}

static void test_allowed_budget_and_unbounded_modes(void)
{
	TEST("allowed events keep the allowed per-second cap in ENFORCE mode");
	if (lota_event_budget_limit(1, 0) != LOTA_ALLOW_EVENT_BUDGET_PER_SEC)
		FAIL("expected: lota_event_budget_limit(1, 0) == "
		     "LOTA_ALLOW_EVENT_BUDGET_PER_SEC");
	TEST("allowed events are unbounded outside ENFORCE mode");
	if (lota_event_budget_limit(0, 0) != 0)
		FAIL("expected: lota_event_budget_limit(0, 0) == 0");
	TEST("blocked events are unbounded outside ENFORCE mode");
	if (lota_event_budget_limit(0, 1) != 0)
		FAIL("expected: lota_event_budget_limit(0, 1) == 0");
}

static void test_window_expiry(void)
{
	TEST("same instant is within the window");
	if (lota_event_budget_window_expired(1000, 1000))
		FAIL("expected: !lota_event_budget_window_expired(1000, 1000)");
	TEST("one nanosecond before the boundary is within the window");
	if (lota_event_budget_window_expired(
		    1000 + LOTA_EVENT_BUDGET_WINDOW_NS - 1, 1000))
		FAIL("expected: !lota_event_budget_window_expired( 1000 + "
		     "LOTA_EVENT_BUDGET_WINDOW_NS - 1, 1000)");
	TEST("exactly the window length has elapsed");
	if (!lota_event_budget_window_expired(
		    1000 + LOTA_EVENT_BUDGET_WINDOW_NS, 1000))
		FAIL("expected: lota_event_budget_window_expired( 1000 + "
		     "LOTA_EVENT_BUDGET_WINDOW_NS, 1000)");
	TEST("a backwards clock rotates the window");
	if (!lota_event_budget_window_expired(500, 1000))
		FAIL("expected: lota_event_budget_window_expired(500, 1000)");
}

static void test_exhaustion_boundary(void)
{
	TEST("an empty window is not exhausted");
	if (lota_event_budget_exhausted(0, 256))
		FAIL("expected: !lota_event_budget_exhausted(0, 256)");
	TEST("the last in-budget slot is not exhausted");
	if (lota_event_budget_exhausted(255, 256))
		FAIL("expected: !lota_event_budget_exhausted(255, 256)");
	TEST("the slot at the cap is exhausted");
	if (!lota_event_budget_exhausted(256, 256))
		FAIL("expected: lota_event_budget_exhausted(256, 256)");
	TEST("past the cap stays exhausted");
	if (!lota_event_budget_exhausted(1000, 256))
		FAIL("expected: lota_event_budget_exhausted(1000, 256)");
}

/* pressure comes from ring occupancy, not the class counters */
static void test_pressure_is_read_from_the_ring(void)
{
	const unsigned long long ring = 256ULL * 1024ULL;

	TEST("an empty ring is not under pressure");
	if (lota_event_ring_under_pressure(0, ring))
		FAIL("expected: !lota_event_ring_under_pressure(0, ring)");
	TEST("one byte below the watermark is not under pressure");
	if (lota_event_ring_under_pressure(
		    ring * LOTA_EVENT_RING_PRESSURE_PCT / 100 - 1, ring))
		FAIL("expected: !lota_event_ring_under_pressure( ring * "
		     "LOTA_EVENT_RING_PRESSURE_PCT / 100 - 1, ring)");
	TEST("the watermark itself is under pressure");
	if (!lota_event_ring_under_pressure(
		    ring * LOTA_EVENT_RING_PRESSURE_PCT / 100, ring))
		FAIL("expected: lota_event_ring_under_pressure( ring * "
		     "LOTA_EVENT_RING_PRESSURE_PCT / 100, ring)");
	TEST("a full ring is under pressure");
	if (!lota_event_ring_under_pressure(ring, ring))
		FAIL("expected: lota_event_ring_under_pressure(ring, ring)");
	TEST("an unknown ring size reports no pressure");
	if (lota_event_ring_under_pressure(0, 0))
		FAIL("expected: !lota_event_ring_under_pressure(0, 0)");
}

/*
 * Under pressure a type that already spoke this window yields; one that has
 * not keeps its detail, e.g. a lone mmap block amid refused signals.
 */
static void test_a_quiet_type_keeps_its_detail_under_a_flood(void)
{
	const unsigned long long ring = 256ULL * 1024ULL;
	const unsigned long long full = ring;

	TEST("a type's first event of the window survives a full ring");
	if (lota_event_type_yields(0, full, ring))
		FAIL("expected: !lota_event_type_yields(0, full, ring)");
	TEST("a quiet type keeps its detail up to its share");
	if (lota_event_type_yields(LOTA_EVENT_PRESSURE_SHARE - 1, full, ring))
		FAIL("expected: !lota_event_type_yields(LOTA_EVENT_PRESSURE_SHARE "
		     "- 1, full, ring)");
	TEST("a type past its share yields the ring under pressure");
	if (!lota_event_type_yields(LOTA_EVENT_PRESSURE_SHARE, full, ring))
		FAIL("expected: lota_event_type_yields(LOTA_EVENT_PRESSURE_SHARE, "
		     "full, ring)");
	TEST("a flooding type keeps yielding");
	if (!lota_event_type_yields(100000, full, ring))
		FAIL("expected: lota_event_type_yields(100000, full, ring)");
	TEST("with room in the ring no type yields, however loud");
	if (lota_event_type_yields(100000, 0, ring))
		FAIL("expected: !lota_event_type_yields(100000, 0, ring)");
	TEST("an unknown ring size gates nothing");
	if (lota_event_type_yields(100000, 0, 0))
		FAIL("expected: !lota_event_type_yields(100000, 0, 0)");
}

int main(void)
{
	test_begin("event budget");
	test_blocked_is_bounded_under_enforce();
	test_allowed_budget_and_unbounded_modes();
	test_window_expiry();
	test_exhaustion_boundary();
	test_pressure_is_read_from_the_ring();
	test_a_quiet_type_keeps_its_detail_under_a_flood();

	return test_end();
}
