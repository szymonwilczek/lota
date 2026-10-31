/* SPDX-License-Identifier: MIT */
/*
 * Tests for the kill event log line, the only record of a signal aimed
 * at a protected process.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <signal.h>
#include <stdio.h>
#include <string.h>

#include "../src/agent/kill_report.h"

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
	CHECK(says("KILL "), "a delivered signal is labelled KILL");
	CHECK(says("gameoverlayui"), "the sender is named");
	CHECK(says("pid=15553"), "the target is named");
	CHECK(says("pid=4242"), "the sending thread is named");
	CHECK(says("uid=1000"), "the sender's uid is named");

	line(1, "attacker", 1061, SIGKILL);
	CHECK(says("KILL_BLOCKED"), "a refusal is labelled KILL_BLOCKED");
	CHECK(says("attacker"), "the refused sender is named");
	CHECK(says("pid=1061"), "the protected target is named");
}

/* Without the signal a delivered SIGTERM and a probe read the same */
static void test_the_line_names_the_signal(void)
{
	line(0, "steam", 15553, SIGTERM);
	CHECK(says("sig=15"), "a delivered SIGTERM names its number");

	line(1, "attacker", 1061, SIGKILL);
	CHECK(says("sig=9"), "a refused SIGKILL names its number");

	line(1, "supervisor", 1061, SIGHUP);
	CHECK(says("sig=1"), "a refused reload names its number");

	line(0, "probe", 1061, 0);
	CHECK(says("sig=0"), "a probe that is recorded names its number");
}

/* No buffer or no sender name is not a crash */
static void test_the_caller_owns_the_buffer(void)
{
	kill_report_line(NULL, 0, 0, "x", 1, SIGTERM, 2, 3);
	CHECK(1, "no buffer is not a crash");

	g_line[0] = 'x';
	kill_report_line(g_line, sizeof(g_line), 0, NULL, 1, SIGTERM, 2, 3);
	CHECK(strstr(g_line, "pid=1") != NULL,
	      "a sender with no name still produces a line");
}

int main(void)
{
	printf("=== what the log says about a signal ===\n\n");

	test_the_line_still_names_everyone();
	test_the_line_names_the_signal();
	test_the_caller_owns_the_buffer();

	printf("\n%s\n", g_failures ? "FAILURES" : "All tests passed");
	return g_failures ? 1 : 0;
}
