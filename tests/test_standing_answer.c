/* SPDX-License-Identifier: MIT */
/*
 * Tests for which standing answers reach the log: every changed answer,
 * no repeat.
 * Suppressing too much hides a refusal as surely as noise buries it.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <stdio.h>
#include <string.h>

#include "../src/agent/standing_answer.h"

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

/* two answers other than NOTHING_WRONG */
#define ANSWER_REFUSED 7
#define ANSWER_NO_TPM 9

static struct standing_answer g_answer;

static void reset(void)
{
	memset(&g_answer, 0, sizeof(g_answer));
}

/* A first answer cannot be a repeat */
static void test_the_first_answer_is_stated(void)
{
	uint64_t held = 99;

	reset();
	CHECK(standing_answer_note(&g_answer, ANSWER_REFUSED, NULL, &held),
	      "a first answer is stated");
	CHECK(held == 0, "a first answer replaces nothing");
}

/* The same answer every round is stated once */
static void test_the_same_answer_is_stated_once(void)
{
	int i;

	reset();
	CHECK(standing_answer_note(&g_answer, ANSWER_REFUSED, NULL, NULL),
	      "the answer is stated when it is new");

	for (i = 0; i < 200; i++) {
		if (standing_answer_note(&g_answer, ANSWER_REFUSED, NULL,
					 NULL)) {
			CHECK(false, "the same answer is not stated again");
			break;
		}
	}
	if (i == 200)
		CHECK(true, "the same answer is not stated again");

	CHECK(g_answer.repeats == 200,
	      "every round that said the same thing is counted");
}

/* One unhealthy answer can replace another */
static void test_a_changed_answer_is_stated(void)
{
	uint64_t held = 0;

	reset();
	CHECK(standing_answer_note(&g_answer, ANSWER_REFUSED, NULL, NULL),
	      "the first answer is stated");
	CHECK(!standing_answer_note(&g_answer, ANSWER_REFUSED, NULL, NULL),
	      "repeating it is not");
	CHECK(standing_answer_note(&g_answer, ANSWER_NO_TPM, NULL, &held),
	      "a different answer is stated");
}

/* A moved reason under the same verdict is news */
static void test_the_statement_is_what_is_compared(void)
{
	reset();
	CHECK(standing_answer_note(&g_answer, ANSWER_REFUSED,
				   "libA has no digest", NULL),
	      "the first statement is stated");
	CHECK(!standing_answer_note(&g_answer, ANSWER_REFUSED,
				    "libA has no digest", NULL),
	      "repeating it is not");
	CHECK(standing_answer_note(&g_answer, ANSWER_REFUSED,
				   "libB has no digest", NULL),
	      "a different reason under one verdict is stated");
	CHECK(strcmp(g_answer.statement, "libB has no digest") == 0,
	      "and the statement that now stands is the new one");
}

/* A healthy subject is not news by itself */
static void test_a_healthy_subject_says_nothing(void)
{
	reset();
	CHECK(!standing_answer_note(&g_answer, STANDING_ANSWER_NOTHING_WRONG,
				    NULL, NULL),
	      "a healthy first answer writes no line");
	CHECK(!standing_answer_note(&g_answer, STANDING_ANSWER_NOTHING_WRONG,
				    NULL, NULL),
	      "and writes none on the round after either");
}

/* Recovery is news too */
static void test_the_return_to_healthy_is_stated(void)
{
	uint64_t held = 0;
	int i;

	reset();
	CHECK(standing_answer_note(&g_answer, ANSWER_NO_TPM, NULL, NULL),
	      "the failure is stated");
	for (i = 0; i < 42; i++)
		standing_answer_note(&g_answer, ANSWER_NO_TPM, NULL, NULL);

	CHECK(standing_answer_note(&g_answer, STANDING_ANSWER_NOTHING_WRONG,
				   NULL, &held),
	      "the recovery is stated");
	CHECK(held == 42, "and says how many rounds the failure held");
	CHECK(!standing_answer_note(&g_answer, STANDING_ANSWER_NOTHING_WRONG,
				    NULL, NULL),
	      "the round after it is quiet");
}

/* The held count is a separate clause, or no statement would ever repeat */
static void test_the_held_clause_hangs_off_the_line(void)
{
	char clause[128];

	standing_answer_held_clause(clause, sizeof(clause), 0);
	CHECK(clause[0] == '\0',
	      "an answer that replaces nothing says nothing");

	standing_answer_held_clause(clause, sizeof(clause), 1);
	CHECK(strstr(clause, "1 further round") != NULL,
	      "a single held round reads as one");

	standing_answer_held_clause(clause, sizeof(clause), 923);
	CHECK(strstr(clause, "923 further rounds") != NULL,
	      "a long run reads as many");

	standing_answer_held_clause(NULL, 0, 5);
	CHECK(true, "no buffer for the clause is not a crash");
}

/* A forgotten subject is news again */
static void test_a_forgotten_subject_is_news_again(void)
{
	reset();
	standing_answer_note(&g_answer, ANSWER_REFUSED, NULL, NULL);
	CHECK(!standing_answer_note(&g_answer, ANSWER_REFUSED, NULL, NULL),
	      "its repeats are not stated");
	standing_answer_forget(&g_answer);
	CHECK(standing_answer_note(&g_answer, ANSWER_REFUSED, NULL, NULL),
	      "the same answer after forgetting is stated");
	standing_answer_forget(NULL);
	CHECK(true, "forgetting nothing is not a crash");
}

/* No record states everything */
static void test_no_record_states_everything(void)
{
	uint64_t held = 99;

	CHECK(standing_answer_note(NULL, ANSWER_NO_TPM, NULL, &held),
	      "no record states the answer");
	CHECK(held == 0, "and replaces nothing");
	CHECK(standing_answer_note(NULL, ANSWER_NO_TPM, NULL, NULL),
	      "and states it again, because nothing recorded the first");
}

int main(void)
{
	printf("=== when a standing answer is news ===\n\n");

	test_the_first_answer_is_stated();
	test_the_same_answer_is_stated_once();
	test_a_changed_answer_is_stated();
	test_the_statement_is_what_is_compared();
	test_a_healthy_subject_says_nothing();
	test_the_return_to_healthy_is_stated();
	test_the_held_clause_hangs_off_the_line();
	test_a_forgotten_subject_is_news_again();
	test_no_record_states_everything();

	printf("\n%s\n", g_failures ? "FAILURES" : "All tests passed");
	return g_failures ? 1 : 0;
}
