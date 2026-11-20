/* SPDX-License-Identifier: MIT */
/*
 * Tests for the kill event log line, the only record of a signal aimed
 * at a protected process.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <signal.h>
#include <string.h>

#include "../src/agent/kill_report.h"

#include "test.h"

static char g_line[256];

static void line(int blocked, const char *comm, uint32_t target, uint32_t sig)
{
	kill_report_line(g_line, sizeof(g_line), blocked, comm, target, sig,
			 4242, 1000);
}

static int says(const char *needle)
{
	return strstr(g_line, needle) != NULL;
}

/* Sender, target and verdict stay in the line */
static void test_the_line_still_names_everyone(void)
{
	line(0, "gameoverlayui", 15553, SIGTERM);
	TEST("a delivered signal is labelled KILL");
	if (!says("KILL "))
		FAIL("expected: says(\"KILL \")");
	TEST("the sender is named");
	if (!says("gameoverlayui"))
		FAIL("expected: says(\"gameoverlayui\")");
	TEST("the target is named");
	if (!says("pid=15553"))
		FAIL("expected: says(\"pid=15553\")");
	TEST("the sending thread is named");
	if (!says("pid=4242"))
		FAIL("expected: says(\"pid=4242\")");
	TEST("the sender's uid is named");
	if (!says("uid=1000"))
		FAIL("expected: says(\"uid=1000\")");

	line(1, "attacker", 1061, SIGKILL);
	TEST("a refusal is labelled KILL_BLOCKED");
	if (!says("KILL_BLOCKED"))
		FAIL("expected: says(\"KILL_BLOCKED\")");
	TEST("the refused sender is named");
	if (!says("attacker"))
		FAIL("expected: says(\"attacker\")");
	TEST("the protected target is named");
	if (!says("pid=1061"))
		FAIL("expected: says(\"pid=1061\")");
}

/* Without the signal a delivered SIGTERM and a probe read the same */
static void test_the_line_names_the_signal(void)
{
	line(0, "steam", 15553, SIGTERM);
	TEST("a delivered SIGTERM names its number");
	if (!says("sig=15"))
		FAIL("expected: says(\"sig=15\")");

	line(1, "attacker", 1061, SIGKILL);
	TEST("a refused SIGKILL names its number");
	if (!says("sig=9"))
		FAIL("expected: says(\"sig=9\")");

	line(1, "supervisor", 1061, SIGHUP);
	TEST("a refused reload names its number");
	if (!says("sig=1"))
		FAIL("expected: says(\"sig=1\")");

	line(0, "probe", 1061, 0);
	TEST("a probe that is recorded names its number");
	if (!says("sig=0"))
		FAIL("expected: says(\"sig=0\")");
}

/* No buffer or no sender name is not a crash */
static void test_the_caller_owns_the_buffer(void)
{
	kill_report_line(NULL, 0, 0, "x", 1, SIGTERM, 2, 3);
	TEST("no buffer is not a crash");
	if (!1)
		FAIL("expected: 1");

	g_line[0] = 'x';
	kill_report_line(g_line, sizeof(g_line), 0, NULL, 1, SIGTERM, 2, 3);
	TEST("a sender with no name still produces a line");
	if (strstr(g_line, "pid=1") == NULL)
		FAIL("expected: strstr(g_line, \"pid=1\") != NULL");
}

int main(void)
{
	test_begin("kill report");

	test_the_line_still_names_everyone();
	test_the_line_names_the_signal();
	test_the_caller_owns_the_buffer();

	return test_end();
}
