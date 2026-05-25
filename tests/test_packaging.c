/* SPDX-License-Identifier: MIT */
/*
 * LOTA packaging invariants.
 *
 * These tests validate files shipped by the repository rather than a
 * runtime integration layer. Keep package, unit, udev, D-Bus, and SELinux
 * layout checks here so module-specific test runners stay focused.
 *
 * Copyright (C) 2026 Szymon Wilczek
 *
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tests_run;
static int tests_passed;

#define TEST(name)                                                             \
  do {                                                                         \
    tests_run++;                                                               \
    printf("  [%d] %-55s ", tests_run, name);                                  \
  } while (0)

#define PASS()                                                                 \
  do {                                                                         \
    tests_passed++;                                                            \
    printf("PASS\n");                                                          \
  } while (0)

#define FAIL(msg)                                                              \
  do {                                                                         \
    printf("FAIL: %s\n", msg);                                                 \
  } while (0)

/*
 * The packaged unit must not pass a --mode flag on ExecStart. The agent
 * picks cfg.mode (default enforce) and refuses to weaken that without
 * --insecure-allow-mode-downgrade. A unit that re-introduces e.g.
 * --mode monitor silently demotes the daemon below the configured
 * policy, so guard the regression here.
 */
static void test_packaged_unit_does_not_set_mode(void) {
  TEST("packaged unit: ExecStart has no --mode override");

  FILE *fp = fopen("systemd/lota-agent.service", "re");
  if (!fp) {
    fp = fopen("../systemd/lota-agent.service", "re");
  }
  if (!fp) {
    FAIL("could not open lota-agent.service");
    return;
  }

  char line[1024];
  bool saw_exec_start = false;
  bool saw_mode_flag = false;
  while (fgets(line, sizeof(line), fp)) {
    if (strncmp(line, "ExecStart=", 10) != 0)
      continue;
    saw_exec_start = true;
    if (strstr(line, " --mode") || strstr(line, "\t--mode") ||
        strstr(line, " -m ") || strstr(line, "\t-m ")) {
      saw_mode_flag = true;
      break;
    }
  }
  fclose(fp);

  if (!saw_exec_start) {
    FAIL("ExecStart= not found");
    return;
  }
  if (saw_mode_flag) {
    FAIL("ExecStart must not pass --mode (would override cfg.mode)");
    return;
  }
  PASS();
}

int main(void) {
  printf("=== LOTA Packaging Tests ===\n\n");

  test_packaged_unit_does_not_set_mode();

  printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
  return (tests_passed == tests_run) ? 0 : 1;
}
