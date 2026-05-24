/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for daemon event-loop helpers.
 *
 * Pins the contract of agent_ringbuf_drop_delta(): the function is
 * the source of truth for what counts as an alertable BPF ringbuf
 * drop. A daemon that does not call it from the loop, or that calls
 * it with a stale baseline, would either over-alert on every loop
 * iteration or miss the forensic gap entirely. The flood-style
 * scenario at the bottom of this file feeds a synthetic drop counter
 * across two windows and verifies the alerting delta matches the
 * number of newly dropped events exactly.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <stdio.h>
#include <stdlib.h>

#include "../src/agent/daemon_loop.h"

static int tests_run;
static int tests_passed;

#define TEST(name)                                                             \
  do {                                                                         \
    tests_run++;                                                               \
    printf("  [%2d] %-55s ", tests_run, name);                                 \
  } while (0)

#define PASS()                                                                 \
  do {                                                                         \
    tests_passed++;                                                            \
    printf("PASS\n");                                                          \
  } while (0)

#define FAIL(fmt, ...)                                                         \
  do {                                                                         \
    printf("FAIL: " fmt "\n", ##__VA_ARGS__);                                  \
  } while (0)

static void test_drop_delta_first_observation_reports_total(void) {
  TEST("drop_delta: first observation reports full counter");
  uint64_t last = 0;
  uint64_t delta = agent_ringbuf_drop_delta(7, &last);
  if (delta != 7) {
    FAIL("expected delta=7 on first non-zero current, got %lu",
         (unsigned long)delta);
    return;
  }
  if (last != 7) {
    FAIL("baseline not updated, last=%lu", (unsigned long)last);
    return;
  }
  PASS();
}

static void test_drop_delta_quiet_when_unchanged(void) {
  TEST("drop_delta: quiet when counter unchanged");
  uint64_t last = 42;
  uint64_t delta = agent_ringbuf_drop_delta(42, &last);
  if (delta != 0 || last != 42) {
    FAIL("expected delta=0 last=42, got delta=%lu last=%lu",
         (unsigned long)delta, (unsigned long)last);
    return;
  }
  PASS();
}

static void test_drop_delta_reports_only_increment(void) {
  TEST("drop_delta: reports only the increment");
  uint64_t last = 10;
  uint64_t delta = agent_ringbuf_drop_delta(13, &last);
  if (delta != 3 || last != 13) {
    FAIL("expected delta=3 last=13, got delta=%lu last=%lu",
         (unsigned long)delta, (unsigned long)last);
    return;
  }
  PASS();
}

static void test_drop_delta_resets_on_counter_rollback(void) {
  TEST("drop_delta: counter rollback rebases without alert");
  uint64_t last = 1000;
  uint64_t delta = agent_ringbuf_drop_delta(5, &last);
  if (delta != 0) {
    FAIL("expected delta=0 on rollback, got %lu", (unsigned long)delta);
    return;
  }
  if (last != 5) {
    FAIL("baseline not rebased on rollback, last=%lu", (unsigned long)last);
    return;
  }
  delta = agent_ringbuf_drop_delta(8, &last);
  if (delta != 3 || last != 8) {
    FAIL("post-rollback increment incorrect: delta=%lu last=%lu",
         (unsigned long)delta, (unsigned long)last);
    return;
  }
  PASS();
}

static void test_drop_delta_null_last_returns_zero(void) {
  TEST("drop_delta: NULL last pointer is rejected");
  if (agent_ringbuf_drop_delta(100, NULL) != 0) {
    FAIL("expected 0 on NULL last");
    return;
  }
  PASS();
}

/*
 * Synthesises a flood: 10 000 events queued, ring buffer absorbs the
 * first 8 192 and drops the rest. The helper must report 1 808 drops
 * on the first poll, then zero on a steady-state second poll where no
 * additional events were dropped. A regression that resets last_drops
 * incorrectly would re-fire 1 808 on every iteration; a regression
 * that fails to update last_drops would report 1 808 once and then
 * miss future drops.
 */
static void test_drop_delta_flood_scenario(void) {
  TEST("drop_delta: 10k flood -> first poll 1808, steady second 0");
  uint64_t last = 0;
  uint64_t flood = 1808; /* 10000 emitted, 8192 absorbed */
  uint64_t delta = agent_ringbuf_drop_delta(flood, &last);
  if (delta != 1808) {
    FAIL("flood window 1: expected 1808, got %lu", (unsigned long)delta);
    return;
  }
  delta = agent_ringbuf_drop_delta(flood, &last);
  if (delta != 0) {
    FAIL("flood window 2 (no new drops): expected 0, got %lu",
         (unsigned long)delta);
    return;
  }
  delta = agent_ringbuf_drop_delta(flood + 250, &last);
  if (delta != 250) {
    FAIL("flood window 3 (250 new drops): expected 250, got %lu",
         (unsigned long)delta);
    return;
  }
  PASS();
}

int main(void) {
  printf("=== LOTA daemon_loop unit tests ===\n\n");

  test_drop_delta_first_observation_reports_total();
  test_drop_delta_quiet_when_unchanged();
  test_drop_delta_reports_only_increment();
  test_drop_delta_resets_on_counter_rollback();
  test_drop_delta_null_last_returns_zero();
  test_drop_delta_flood_scenario();

  printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
  return (tests_passed == tests_run) ? 0 : 1;
}
