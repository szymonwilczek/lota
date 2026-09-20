/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for the --terminate-protected report line.
 *
 * The count is what else stays protected and must not include the signalled
 * process, or a player goes looking for a second protected title.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <stdio.h>
#include <string.h>

#include "../src/agent/terminate_report.h"

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

int main(void)
{
	char buf[256];

	printf("=== what --terminate-protected reports ===\n\n");

	TEST("ending the only protected process claims no other");
	terminate_sent_message(14418, false, 0, buf, sizeof(buf));
	if (strstr(buf, "SIGTERM") && strstr(buf, "14418") &&
	    strstr(buf, "no other process is protected"))
		PASS();
	else
		FAIL(buf);

	TEST("every count says it is of other processes");
	terminate_sent_message(14418, false, 2, buf, sizeof(buf));
	if (strstr(buf, "other") && !strstr(buf, "2 processes still protected"))
		PASS();
	else
		FAIL(buf);

	TEST("one other protected process is reported as another");
	terminate_sent_message(14418, false, 1, buf, sizeof(buf));
	if (strstr(buf, "1 other process is still protected"))
		PASS();
	else
		FAIL(buf);

	TEST("several others are counted in the plural");
	terminate_sent_message(14418, false, 3, buf, sizeof(buf));
	if (strstr(buf, "3 other processes are still protected"))
		PASS();
	else
		FAIL(buf);

	TEST("the signal that was sent is named");
	terminate_sent_message(2, true, 0, buf, sizeof(buf));
	if (strstr(buf, "SIGKILL") && !strstr(buf, "SIGTERM"))
		PASS();
	else
		FAIL(buf);

	TEST("a caller without a buffer is not written to");
	terminate_sent_message(1, false, 0, NULL, 0);
	PASS();

	printf("\n=== %d/%d passed ===\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
