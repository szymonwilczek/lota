/* SPDX-License-Identifier: MIT */
/*
 * Tests for which measurement answers reach the log: every changed answer,
 * no repeat. Suppressing too much hides why a token was refused.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <stdio.h>
#include <string.h>

#include "../src/agent/measure_report.h"

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
	CHECK(says("pid=6134"), "a refusal names the process");
	CHECK(says("requesting"), "a refusal says the process was the caller");
	CHECK(says("the process's own executable /games/cs2 carries no digest"),
	      "a refusal names the reason");

	measure_report_line(g_line, sizeof(g_line), MEASURE_ANSWER_ABSENT, 900,
			    4242, 0, 1, "no digest");
	CHECK(says("pid=900"), "an absent process is named");
	CHECK(says("pid=4242"), "the caller it is not is named");
	CHECK(says("partial coverage"), "the token's answer is named");

	measure_report_line(g_line, sizeof(g_line), MEASURE_ANSWER_PARTIAL, 901,
			    4242, 7, 2, "libsteam_api.so carries no digest");
	CHECK(says("covers 7 objects"), "partial coverage counts what it has");
	CHECK(says("misses 2"), "partial coverage counts what it lacks");

	measure_report_line(g_line, sizeof(g_line), MEASURE_ANSWER_MEASURED,
			    902, 4242, 9, 0, NULL);
	CHECK(says("pid=902"), "a full measurement names the process");
	CHECK(!says("failed"), "a full measurement is not a failure");
}

/* The first answer about a process cannot be a repeat */
static void test_the_first_answer_is_always_stated(void)
{
	uint64_t held = 99;

	reset();
	CHECK(round_for(6134, MEASURE_ANSWER_REFUSED, "no digest", &held),
	      "a first refusal is stated");
	CHECK(held == 0, "a first answer replaces nothing");

	reset();
	CHECK(round_for(900, MEASURE_ANSWER_ABSENT, "no digest", NULL),
	      "a first absent process is stated");

	reset();
	CHECK(round_for(901, MEASURE_ANSWER_PARTIAL, "no digest", NULL),
	      "a first partial coverage is stated");
}

/* A clean measurement is not news */
static void test_a_healthy_process_says_nothing(void)
{
	reset();
	CHECK(!round_for(902, MEASURE_ANSWER_MEASURED, NULL, NULL),
	      "a process that measures cleanly writes no line");
	CHECK(!round_for(902, MEASURE_ANSWER_MEASURED, NULL, NULL),
	      "and writes none on the round after either");
}

/* The same answer every round is stated once */
static void test_the_same_answer_is_stated_once(void)
{
	uint64_t held = 99;
	int i;

	reset();
	CHECK(round_for(6134, MEASURE_ANSWER_REFUSED, "no digest", NULL),
	      "the answer is stated when it is new");

	for (i = 0; i < 200; i++) {
		if (round_for(6134, MEASURE_ANSWER_REFUSED, "no digest",
			      &held)) {
			CHECK(false, "the same answer is not stated again");
			break;
		}
	}
	if (i == 200)
		CHECK(true, "the same answer is not stated again");

	CHECK(g_table.suppressed == 200,
	      "every round that said the same thing is counted");
}

/* A new mapping changes the reason, so the sentence is compared */
static void test_a_changed_answer_is_stated(void)
{
	uint64_t held = 0;

	reset();
	CHECK(round_for(901, MEASURE_ANSWER_PARTIAL, "libA has no digest",
			NULL),
	      "the first partial answer is stated");
	CHECK(!round_for(901, MEASURE_ANSWER_PARTIAL, "libA has no digest",
			 NULL),
	      "repeating it is not");
	CHECK(round_for(901, MEASURE_ANSWER_PARTIAL, "libB has no digest",
			&held),
	      "a different reason is stated");
	CHECK(round_for(901, MEASURE_ANSWER_REFUSED, "libB has no digest",
			NULL),
	      "a different verdict is stated");
}

/* Recovery is news too */
static void test_the_return_to_measurable_is_stated(void)
{
	reset();
	CHECK(round_for(901, MEASURE_ANSWER_PARTIAL, "libA has no digest",
			NULL),
	      "the failure is stated");
	CHECK(round_for(901, MEASURE_ANSWER_MEASURED, NULL, NULL),
	      "the recovery is stated");
	CHECK(!round_for(901, MEASURE_ANSWER_MEASURED, NULL, NULL),
	      "and is then quiet again");
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

	CHECK(round_for(6134, MEASURE_ANSWER_MEASURED, NULL, &held),
	      "the recovery is stated");
	CHECK(held == 42, "and says how many rounds the refusal held");

	held = 99;
	CHECK(!round_for(6134, MEASURE_ANSWER_MEASURED, NULL, &held),
	      "the round after it is quiet");
	CHECK(held == 0, "a suppressed round replaces nothing");
}

/* The held count is a separate clause, or no statement would ever repeat */
static void test_the_held_clause_hangs_off_the_line(void)
{
	char clause[128];

	measure_report_held_clause(clause, sizeof(clause), 0);
	CHECK(clause[0] == '\0',
	      "an answer that replaces nothing says nothing");

	measure_report_held_clause(clause, sizeof(clause), 1);
	CHECK(strstr(clause, "1 further round") != NULL,
	      "a single held round reads as one");

	measure_report_held_clause(clause, sizeof(clause), 923);
	CHECK(strstr(clause, "923 further rounds") != NULL,
	      "a long run reads as many");

	measure_report_held_clause(NULL, 0, 5);
	CHECK(true, "no buffer for the clause is not a crash");
}

/* A reused PID is a different image with a different sentence */
static void test_pid_reuse_cannot_suppress_a_new_statement(void)
{
	uint32_t alive[] = { 6134 };

	reset();
	CHECK(round_for(6134, MEASURE_ANSWER_REFUSED, "cs2 has no digest",
			NULL),
	      "the first process is stated");
	CHECK(!round_for(6134, MEASURE_ANSWER_REFUSED, "cs2 has no digest",
			 NULL),
	      "its repeats are not");
	CHECK(round_for(6134, MEASURE_ANSWER_REFUSED, "hl2 has no digest",
			NULL),
	      "a different image under the same PID is stated");

	/* a PID that left the protected set is forgotten */
	measure_report_retain(&g_table, alive, 1);
	CHECK(!round_for(6134, MEASURE_ANSWER_REFUSED, "hl2 has no digest",
			 NULL),
	      "a PID still protected keeps its answer");
	measure_report_retain(&g_table, NULL, 0);
	CHECK(round_for(6134, MEASURE_ANSWER_REFUSED, "hl2 has no digest",
			NULL),
	      "a PID that left the protected set is news again");
}

/* Not remembered cannot be known as a repeat, so it is stated */
static void test_what_cannot_be_remembered_is_stated(void)
{
	uint32_t pid;

	reset();
	for (pid = 1; pid <= MEASURE_REPORT_MAX_PIDS; pid++)
		round_for(pid, MEASURE_ANSWER_REFUSED, "no digest", NULL);

	CHECK(g_table.unremembered == 0, "a full table remembered every PID");
	CHECK(round_for(9000, MEASURE_ANSWER_REFUSED, "no digest", NULL),
	      "a PID with no room left is stated");
	CHECK(round_for(9000, MEASURE_ANSWER_REFUSED, "no digest", NULL),
	      "and stated again, because nothing recorded the first");
	CHECK(g_table.unremembered == 2,
	      "what could not be remembered is counted");
}

/* No buffer is not a crash */
static void test_the_caller_owns_the_buffer(void)
{
	uint64_t held = 99;

	measure_report_line(NULL, 0, MEASURE_ANSWER_REFUSED, 1, 2, 0, 0, "x");
	CHECK(true, "no buffer is not a crash");

	CHECK(measure_report_note(NULL, 1, MEASURE_ANSWER_REFUSED, "x", &held),
	      "no table states everything");
	measure_report_retain(NULL, NULL, 0);
	CHECK(true, "sweeping no table is not a crash");
}

int main(void)
{
	printf("=== what the log says about measuring a protected process ===\n\n");

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

	printf("\n%s\n", g_failures ? "FAILURES" : "All tests passed");
	return g_failures ? 1 : 0;
}
