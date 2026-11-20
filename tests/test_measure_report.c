/* SPDX-License-Identifier: MIT */
/*
 * Tests for which measurement answers reach the log: every changed answer,
 * no repeat. Suppressing too much hides why a token was refused.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <string.h>

#include "../src/agent/measure_report.h"

#include "test.h"

static struct measure_report_table g_table;
static char g_line[MEASURE_REPORT_STATEMENT_MAX];

/* Forget answers as the agent does; a memset would clear ~140 KiB */
static void reset(void)
{
	measure_report_retain(&g_table, NULL, 0);
	g_table.suppressed = 0;
	g_table.unremembered = 0;
}

/* Render the line as the agent does, then ask whether to write it */
static bool round_for(uint32_t pid, int answer, const char *reason,
		      uint64_t *held)
{
	measure_report_line(g_line, sizeof(g_line), answer, pid, 4242, 3, 1,
			    reason);
	return measure_report_note(&g_table, pid, answer, g_line, held);
}

static bool says(const char *needle)
{
	return strstr(g_line, needle) != NULL;
}

/* Which process, whether it was the caller, and why */
static void test_the_line_names_what_happened(void)
{
	measure_report_line(
		g_line, sizeof(g_line), MEASURE_ANSWER_REFUSED, 6134, 6134, 0,
		1, "the process's own executable /games/cs2 carries no digest");
	TEST("a refusal names the process");
	if (!says("pid=6134"))
		FAIL("expected: says(\"pid=6134\")");
	TEST("a refusal says the process was the caller");
	if (!says("requesting"))
		FAIL("expected: says(\"requesting\")");
	TEST("a refusal names the reason");
	if (!says("the process's own executable /games/cs2 carries no digest"))
		FAIL("expected: says(\"the process's own executable "
		     "/games/cs2 carries no digest\")");

	measure_report_line(g_line, sizeof(g_line), MEASURE_ANSWER_ABSENT, 900,
			    4242, 0, 1, "no digest");
	TEST("an absent process is named");
	if (!says("pid=900"))
		FAIL("expected: says(\"pid=900\")");
	TEST("the caller it is not is named");
	if (!says("pid=4242"))
		FAIL("expected: says(\"pid=4242\")");
	TEST("the token's answer is named");
	if (!says("partial coverage"))
		FAIL("expected: says(\"partial coverage\")");

	measure_report_line(g_line, sizeof(g_line), MEASURE_ANSWER_PARTIAL, 901,
			    4242, 7, 2, "libsteam_api.so carries no digest");
	TEST("partial coverage counts what it has");
	if (!says("covers 7 objects"))
		FAIL("expected: says(\"covers 7 objects\")");
	TEST("partial coverage counts what it lacks");
	if (!says("misses 2"))
		FAIL("expected: says(\"misses 2\")");

	measure_report_line(g_line, sizeof(g_line), MEASURE_ANSWER_MEASURED,
			    902, 4242, 9, 0, NULL);
	TEST("a full measurement names the process");
	if (!says("pid=902"))
		FAIL("expected: says(\"pid=902\")");
	TEST("a full measurement is not a failure");
	if (says("failed"))
		FAIL("expected: !says(\"failed\")");
}

/* The first answer about a process cannot be a repeat */
static void test_the_first_answer_is_always_stated(void)
{
	uint64_t held = 99;

	reset();
	TEST("a first refusal is stated");
	if (!round_for(6134, MEASURE_ANSWER_REFUSED, "no digest", &held))
		FAIL("expected: round_for(6134, MEASURE_ANSWER_REFUSED, \"no "
		     "digest\", &held)");
	TEST("a first answer replaces nothing");
	if (held != 0)
		FAIL("expected: held == 0");

	reset();
	TEST("a first absent process is stated");
	if (!round_for(900, MEASURE_ANSWER_ABSENT, "no digest", NULL))
		FAIL("expected: round_for(900, MEASURE_ANSWER_ABSENT, \"no "
		     "digest\", NULL)");

	reset();
	TEST("a first partial coverage is stated");
	if (!round_for(901, MEASURE_ANSWER_PARTIAL, "no digest", NULL))
		FAIL("expected: round_for(901, MEASURE_ANSWER_PARTIAL, \"no "
		     "digest\", NULL)");
}

/* A clean measurement is not news */
static void test_a_healthy_process_says_nothing(void)
{
	reset();
	TEST("a process that measures cleanly writes no line");
	if (round_for(902, MEASURE_ANSWER_MEASURED, NULL, NULL))
		FAIL("expected: !round_for(902, MEASURE_ANSWER_MEASURED, "
		     "NULL, NULL)");
	TEST("and writes none on the round after either");
	if (round_for(902, MEASURE_ANSWER_MEASURED, NULL, NULL))
		FAIL("expected: !round_for(902, MEASURE_ANSWER_MEASURED, "
		     "NULL, NULL)");
}

/* The same answer every round is stated once */
static void test_the_same_answer_is_stated_once(void)
{
	uint64_t held = 99;
	int i;

	reset();
	TEST("the answer is stated when it is new");
	if (!round_for(6134, MEASURE_ANSWER_REFUSED, "no digest", NULL))
		FAIL("expected: round_for(6134, MEASURE_ANSWER_REFUSED, \"no "
		     "digest\", NULL)");

	for (i = 0; i < 200; i++) {
		if (round_for(6134, MEASURE_ANSWER_REFUSED, "no digest",
			      &held)) {
			TEST("the same answer is not stated again");
			if (!false)
				FAIL("expected: false");
			break;
		}
	}
	if (i == 200) {
		TEST("the same answer is not stated again");
		if (!true)
			FAIL("expected: true");
	}

	TEST("every round that said the same thing is counted");
	if (g_table.suppressed != 200)
		FAIL("expected: g_table.suppressed == 200");
}

/* A new mapping changes the reason, so the sentence is compared */
static void test_a_changed_answer_is_stated(void)
{
	uint64_t held = 0;

	reset();
	TEST("the first partial answer is stated");
	if (!round_for(901, MEASURE_ANSWER_PARTIAL, "libA has no digest", NULL))
		FAIL("expected: round_for(901, MEASURE_ANSWER_PARTIAL, \"libA "
		     "has no digest\", NULL)");
	TEST("repeating it is not");
	if (round_for(901, MEASURE_ANSWER_PARTIAL, "libA has no digest", NULL))
		FAIL("expected: !round_for(901, MEASURE_ANSWER_PARTIAL, "
		     "\"libA has no digest\", NULL)");
	TEST("a different reason is stated");
	if (!round_for(901, MEASURE_ANSWER_PARTIAL, "libB has no digest",
		       &held))
		FAIL("expected: round_for(901, MEASURE_ANSWER_PARTIAL, \"libB "
		     "has no digest\", &held)");
	TEST("a different verdict is stated");
	if (!round_for(901, MEASURE_ANSWER_REFUSED, "libB has no digest", NULL))
		FAIL("expected: round_for(901, MEASURE_ANSWER_REFUSED, \"libB "
		     "has no digest\", NULL)");
}

/* Recovery is news too */
static void test_the_return_to_measurable_is_stated(void)
{
	reset();
	TEST("the failure is stated");
	if (!round_for(901, MEASURE_ANSWER_PARTIAL, "libA has no digest", NULL))
		FAIL("expected: round_for(901, MEASURE_ANSWER_PARTIAL, \"libA "
		     "has no digest\", NULL)");
	TEST("the recovery is stated");
	if (!round_for(901, MEASURE_ANSWER_MEASURED, NULL, NULL))
		FAIL("expected: round_for(901, MEASURE_ANSWER_MEASURED, NULL, "
		     "NULL)");
	TEST("and is then quiet again");
	if (round_for(901, MEASURE_ANSWER_MEASURED, NULL, NULL))
		FAIL("expected: !round_for(901, MEASURE_ANSWER_MEASURED, "
		     "NULL, NULL)");
}

/* The line ending a run says how long the old answer held */
static void test_the_new_line_says_how_long_the_old_one_held(void)
{
	uint64_t held = 99;
	int i;

	reset();
	round_for(6134, MEASURE_ANSWER_REFUSED, "no digest", NULL);
	for (i = 0; i < 42; i++)
		round_for(6134, MEASURE_ANSWER_REFUSED, "no digest", NULL);

	TEST("the recovery is stated");
	if (!round_for(6134, MEASURE_ANSWER_MEASURED, NULL, &held))
		FAIL("expected: round_for(6134, MEASURE_ANSWER_MEASURED, "
		     "NULL, &held)");
	TEST("and says how many rounds the refusal held");
	if (held != 42)
		FAIL("expected: held == 42");

	held = 99;
	TEST("the round after it is quiet");
	if (round_for(6134, MEASURE_ANSWER_MEASURED, NULL, &held))
		FAIL("expected: !round_for(6134, MEASURE_ANSWER_MEASURED, "
		     "NULL, &held)");
	TEST("a suppressed round replaces nothing");
	if (held != 0)
		FAIL("expected: held == 0");
}

/* The held count is a separate clause, or no statement would ever repeat */
static void test_the_held_clause_hangs_off_the_line(void)
{
	char clause[128];

	measure_report_held_clause(clause, sizeof(clause), 0);
	TEST("an answer that replaces nothing says nothing");
	if (clause[0] != '\0')
		FAIL("expected: clause[0] == '\\0'");

	measure_report_held_clause(clause, sizeof(clause), 1);
	TEST("a single held round reads as one");
	if (strstr(clause, "1 further round") == NULL)
		FAIL("expected: strstr(clause, \"1 further round\") != NULL");

	measure_report_held_clause(clause, sizeof(clause), 923);
	TEST("a long run reads as many");
	if (strstr(clause, "923 further rounds") == NULL)
		FAIL("expected: strstr(clause, \"923 further rounds\") != NULL");

	measure_report_held_clause(NULL, 0, 5);
	TEST("no buffer for the clause is not a crash");
	if (!true)
		FAIL("expected: true");
}

/* A reused PID is a different image with a different sentence */
static void test_pid_reuse_cannot_suppress_a_new_statement(void)
{
	uint32_t alive[] = { 6134 };

	reset();
	TEST("the first process is stated");
	if (!round_for(6134, MEASURE_ANSWER_REFUSED, "cs2 has no digest", NULL))
		FAIL("expected: round_for(6134, MEASURE_ANSWER_REFUSED, \"cs2 "
		     "has no digest\", NULL)");
	TEST("its repeats are not");
	if (round_for(6134, MEASURE_ANSWER_REFUSED, "cs2 has no digest", NULL))
		FAIL("expected: !round_for(6134, MEASURE_ANSWER_REFUSED, "
		     "\"cs2 has no digest\", NULL)");
	TEST("a different image under the same PID is stated");
	if (!round_for(6134, MEASURE_ANSWER_REFUSED, "hl2 has no digest", NULL))
		FAIL("expected: round_for(6134, MEASURE_ANSWER_REFUSED, \"hl2 "
		     "has no digest\", NULL)");

	/* a PID that left the protected set is forgotten */
	measure_report_retain(&g_table, alive, 1);
	TEST("a PID still protected keeps its answer");
	if (round_for(6134, MEASURE_ANSWER_REFUSED, "hl2 has no digest", NULL))
		FAIL("expected: !round_for(6134, MEASURE_ANSWER_REFUSED, "
		     "\"hl2 has no digest\", NULL)");
	measure_report_retain(&g_table, NULL, 0);
	TEST("a PID that left the protected set is news again");
	if (!round_for(6134, MEASURE_ANSWER_REFUSED, "hl2 has no digest", NULL))
		FAIL("expected: round_for(6134, MEASURE_ANSWER_REFUSED, \"hl2 "
		     "has no digest\", NULL)");
}

/* Not remembered cannot be known as a repeat, so it is stated */
static void test_what_cannot_be_remembered_is_stated(void)
{
	uint32_t pid;

	reset();
	for (pid = 1; pid <= MEASURE_REPORT_MAX_PIDS; pid++)
		round_for(pid, MEASURE_ANSWER_REFUSED, "no digest", NULL);

	TEST("a full table remembered every PID");
	if (g_table.unremembered != 0)
		FAIL("expected: g_table.unremembered == 0");
	TEST("a PID with no room left is stated");
	if (!round_for(9000, MEASURE_ANSWER_REFUSED, "no digest", NULL))
		FAIL("expected: round_for(9000, MEASURE_ANSWER_REFUSED, \"no "
		     "digest\", NULL)");
	TEST("and stated again, because nothing recorded the first");
	if (!round_for(9000, MEASURE_ANSWER_REFUSED, "no digest", NULL))
		FAIL("expected: round_for(9000, MEASURE_ANSWER_REFUSED, \"no "
		     "digest\", NULL)");
	TEST("what could not be remembered is counted");
	if (g_table.unremembered != 2)
		FAIL("expected: g_table.unremembered == 2");
}

/* No buffer is not a crash */
static void test_the_caller_owns_the_buffer(void)
{
	uint64_t held = 99;

	measure_report_line(NULL, 0, MEASURE_ANSWER_REFUSED, 1, 2, 0, 0, "x");
	TEST("no buffer is not a crash");
	if (!true)
		FAIL("expected: true");

	TEST("no table states everything");
	if (!measure_report_note(NULL, 1, MEASURE_ANSWER_REFUSED, "x", &held))
		FAIL("expected: measure_report_note(NULL, 1, "
		     "MEASURE_ANSWER_REFUSED, \"x\", &held)");
	measure_report_retain(NULL, NULL, 0);
	TEST("sweeping no table is not a crash");
	if (!true)
		FAIL("expected: true");
}

int main(void)
{
	test_begin("measure report");

	test_the_line_names_what_happened();
	test_the_first_answer_is_always_stated();
	test_a_healthy_process_says_nothing();
	test_the_same_answer_is_stated_once();
	test_a_changed_answer_is_stated();
	test_the_return_to_measurable_is_stated();
	test_the_new_line_says_how_long_the_old_one_held();
	test_the_held_clause_hangs_off_the_line();
	test_pid_reuse_cannot_suppress_a_new_statement();
	test_what_cannot_be_remembered_is_stated();
	test_the_caller_owns_the_buffer();

	return test_end();
}
