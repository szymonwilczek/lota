/* SPDX-License-Identifier: MIT */
/*
 * Tests for which standing answers reach the log: every changed answer,
 * no repeat.
 * Suppressing too much hides a refusal as surely as noise buries it.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <string.h>

#include "../src/agent/standing_answer.h"

#include "test.h"

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
	TEST("a first answer is stated");
	if (!standing_answer_note(&g_answer, ANSWER_REFUSED, NULL, &held))
		FAIL("expected: standing_answer_note(&g_answer, "
		     "ANSWER_REFUSED, NULL, &held)");
	TEST("a first answer replaces nothing");
	if (held != 0)
		FAIL("expected: held == 0");
}

/* The same answer every round is stated once */
static void test_the_same_answer_is_stated_once(void)
{
	int i;

	reset();
	TEST("the answer is stated when it is new");
	if (!standing_answer_note(&g_answer, ANSWER_REFUSED, NULL, NULL))
		FAIL("expected: standing_answer_note(&g_answer, "
		     "ANSWER_REFUSED, NULL, NULL)");

	for (i = 0; i < 200; i++) {
		if (standing_answer_note(&g_answer, ANSWER_REFUSED, NULL,
					 NULL)) {
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
	if (g_answer.repeats != 200)
		FAIL("expected: g_answer.repeats == 200");
}

/* One unhealthy answer can replace another */
static void test_a_changed_answer_is_stated(void)
{
	uint64_t held = 0;

	reset();
	TEST("the first answer is stated");
	if (!standing_answer_note(&g_answer, ANSWER_REFUSED, NULL, NULL))
		FAIL("expected: standing_answer_note(&g_answer, "
		     "ANSWER_REFUSED, NULL, NULL)");
	TEST("repeating it is not");
	if (standing_answer_note(&g_answer, ANSWER_REFUSED, NULL, NULL))
		FAIL("expected: !standing_answer_note(&g_answer, "
		     "ANSWER_REFUSED, NULL, NULL)");
	TEST("a different answer is stated");
	if (!standing_answer_note(&g_answer, ANSWER_NO_TPM, NULL, &held))
		FAIL("expected: standing_answer_note(&g_answer, "
		     "ANSWER_NO_TPM, NULL, &held)");
}

/* A moved reason under the same verdict is news */
static void test_the_statement_is_what_is_compared(void)
{
	reset();
	TEST("the first statement is stated");
	if (!standing_answer_note(&g_answer, ANSWER_REFUSED,
				  "libA has no digest", NULL))
		FAIL("expected: standing_answer_note(&g_answer, "
		     "ANSWER_REFUSED, \"libA has no digest\", NULL)");
	TEST("repeating it is not");
	if (standing_answer_note(&g_answer, ANSWER_REFUSED,
				 "libA has no digest", NULL))
		FAIL("expected: !standing_answer_note(&g_answer, "
		     "ANSWER_REFUSED, \"libA has no digest\", NULL)");
	TEST("a different reason under one verdict is stated");
	if (!standing_answer_note(&g_answer, ANSWER_REFUSED,
				  "libB has no digest", NULL))
		FAIL("expected: standing_answer_note(&g_answer, "
		     "ANSWER_REFUSED, \"libB has no digest\", NULL)");
	TEST("and the statement that now stands is the new one");
	if (strcmp(g_answer.statement, "libB has no digest") != 0)
		FAIL("expected: strcmp(g_answer.statement, \"libB has no "
		     "digest\") == 0");
}

/* A healthy subject is not news by itself */
static void test_a_healthy_subject_says_nothing(void)
{
	reset();
	TEST("a healthy first answer writes no line");
	if (standing_answer_note(&g_answer, STANDING_ANSWER_NOTHING_WRONG, NULL,
				 NULL))
		FAIL("expected: !standing_answer_note(&g_answer, "
		     "STANDING_ANSWER_NOTHING_WRONG, NULL, NULL)");
	TEST("and writes none on the round after either");
	if (standing_answer_note(&g_answer, STANDING_ANSWER_NOTHING_WRONG, NULL,
				 NULL))
		FAIL("expected: !standing_answer_note(&g_answer, "
		     "STANDING_ANSWER_NOTHING_WRONG, NULL, NULL)");
}

/* Recovery is news too */
static void test_the_return_to_healthy_is_stated(void)
{
	uint64_t held = 0;
	int i;

	reset();
	TEST("the failure is stated");
	if (!standing_answer_note(&g_answer, ANSWER_NO_TPM, NULL, NULL))
		FAIL("expected: standing_answer_note(&g_answer, "
		     "ANSWER_NO_TPM, NULL, NULL)");
	for (i = 0; i < 42; i++)
		standing_answer_note(&g_answer, ANSWER_NO_TPM, NULL, NULL);

	TEST("the recovery is stated");
	if (!standing_answer_note(&g_answer, STANDING_ANSWER_NOTHING_WRONG,
				  NULL, &held))
		FAIL("expected: standing_answer_note(&g_answer, "
		     "STANDING_ANSWER_NOTHING_WRONG, NULL, &held)");
	TEST("and says how many rounds the failure held");
	if (held != 42)
		FAIL("expected: held == 42");
	TEST("the round after it is quiet");
	if (standing_answer_note(&g_answer, STANDING_ANSWER_NOTHING_WRONG, NULL,
				 NULL))
		FAIL("expected: !standing_answer_note(&g_answer, "
		     "STANDING_ANSWER_NOTHING_WRONG, NULL, NULL)");
}

/* The held count is a separate clause, or no statement would ever repeat */
static void test_the_held_clause_hangs_off_the_line(void)
{
	char clause[128];

	standing_answer_held_clause(clause, sizeof(clause), 0);
	TEST("an answer that replaces nothing says nothing");
	if (clause[0] != '\0')
		FAIL("expected: clause[0] == '\\0'");

	standing_answer_held_clause(clause, sizeof(clause), 1);
	TEST("a single held round reads as one");
	if (strstr(clause, "1 further round") == NULL)
		FAIL("expected: strstr(clause, \"1 further round\") != NULL");

	standing_answer_held_clause(clause, sizeof(clause), 923);
	TEST("a long run reads as many");
	if (strstr(clause, "923 further rounds") == NULL)
		FAIL("expected: strstr(clause, \"923 further rounds\") != NULL");
}

/* A forgotten subject is news again */
static void test_a_forgotten_subject_is_news_again(void)
{
	reset();
	standing_answer_note(&g_answer, ANSWER_REFUSED, NULL, NULL);
	TEST("its repeats are not stated");
	if (standing_answer_note(&g_answer, ANSWER_REFUSED, NULL, NULL))
		FAIL("expected: !standing_answer_note(&g_answer, "
		     "ANSWER_REFUSED, NULL, NULL)");
	standing_answer_forget(&g_answer);
	TEST("the same answer after forgetting is stated");
	if (!standing_answer_note(&g_answer, ANSWER_REFUSED, NULL, NULL))
		FAIL("expected: standing_answer_note(&g_answer, "
		     "ANSWER_REFUSED, NULL, NULL)");
}

/* No record states everything */
static void test_no_record_states_everything(void)
{
	uint64_t held = 99;

	TEST("no record states the answer");
	if (!standing_answer_note(NULL, ANSWER_NO_TPM, NULL, &held))
		FAIL("expected: standing_answer_note(NULL, ANSWER_NO_TPM, "
		     "NULL, &held)");
	TEST("and replaces nothing");
	if (held != 0)
		FAIL("expected: held == 0");
	TEST("and states it again, because nothing recorded the first");
	if (!standing_answer_note(NULL, ANSWER_NO_TPM, NULL, NULL))
		FAIL("expected: standing_answer_note(NULL, ANSWER_NO_TPM, "
		     "NULL, NULL)");
}

int main(void)
{
	test_begin("standing answer");

	test_the_first_answer_is_stated();
	test_the_same_answer_is_stated_once();
	test_a_changed_answer_is_stated();
	test_the_statement_is_what_is_compared();
	test_a_healthy_subject_says_nothing();
	test_the_return_to_healthy_is_stated();
	test_the_held_clause_hangs_off_the_line();
	test_a_forgotten_subject_is_news_again();
	test_no_record_states_everything();

	return test_end();
}
