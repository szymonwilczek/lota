/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for what an operator is told when the daemon will not start.
 *
 * --protect-pid sits in the help beside --terminate-protected, which is a runtime
 * verb that talks to the running daemon and works. It is not one: it is a startup
 * option that seeds the protected set of the instance it starts, so on any normal
 * host -- where a daemon is already up -- it does nothing and says only that
 * an instance is running. Nothing points at the call that does protect a live
 * process.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <stdio.h>
#include <string.h>

#include "../src/agent/startup_hint.h"

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
	char buf[512];

	printf("=== daemon startup refusal ===\n\n");

	TEST("a plain refusal names the PID file lock");
	startup_busy_message(false, buf, sizeof(buf));
	if (!strstr(buf, "PID file"))
		FAIL("the refusal does not say why");
	else if (strstr(buf, "--protect-pid"))
		FAIL("a caller that asked for nothing is told about a flag");
	else
		PASS();

	TEST("--protect-pid is named as a startup option that did nothing");
	startup_busy_message(true, buf, sizeof(buf));
	if (!strstr(buf, "--protect-pid"))
		FAIL("the flag the operator passed is not mentioned");
	else if (!strstr(buf, "startup option"))
		FAIL("nothing says it is not a request to the running daemon");
	else if (!strstr(buf, "did nothing"))
		FAIL("nothing says the flag had no effect");
	else
		PASS();

	TEST("the way to protect a running process is named");
	startup_busy_message(true, buf, sizeof(buf));
	if (!strstr(buf, "lota_protect_self"))
		FAIL("the SDK call that protects a live process is missing");
	else
		PASS();

	TEST("a short buffer is still terminated");
	{
		/* volatile so the truncation is a run-time fact */
		volatile size_t small = 24;

		memset(buf, 'x', sizeof(buf));
		startup_busy_message(true, buf, small);
		if (strlen(buf) >= small)
			FAIL("the message overran the buffer");
		else
			PASS();
	}

	printf("\n=== %d/%d passed ===\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
