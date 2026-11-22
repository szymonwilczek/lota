/* SPDX-License-Identifier: MIT */
/*
 * Shared unit test reporting.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_TEST_H
#define LOTA_TEST_H

#include <stdio.h>

static int tests_run;
static int tests_passed;

#define TEST(name)                                         \
	do {                                               \
		tests_run++;                               \
		printf("  [%2d] %-58s ", tests_run, name); \
	} while (0)

#define PASS()                    \
	do {                      \
		tests_passed++;   \
		printf("PASS\n"); \
	} while (0)

#define FAIL(msg)                          \
	do {                               \
		printf("FAIL: %s\n", msg); \
	} while (0)

#endif /* LOTA_TEST_H */
