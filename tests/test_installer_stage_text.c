/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * What lota-install says before it changes anything.
 *
 * Each explanation is adjacent string literals, one per source line.
 * A literal that carries no space at its edge runs two sentences together
 * ("lockdown.This step"), which neither the compiler nor a reader of the
 * source sees, so the check runs on the joined text.
 */

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include "../installer/install.h"

static int tests_run;
static int tests_passed;

#define TEST(name)                                         \
	do {                                               \
		tests_run++;                               \
		printf("  [%2d] %-55s ", tests_run, name); \
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

/*
 * First place in s where closing punctuation runs straight into a capital,
 * or NULL. A dotted name ("lota.conf") is not caught.
 */
static const char *run_together(const char *s)
{
	for (; s && s[0] && s[1]; s++) {
		if (!strchr(".:;?!)", s[0]))
			continue;
		if (isupper((unsigned char)s[1]))
			return s;
	}
	return NULL;
}

static void test_the_detector(void)
{
	TEST("the check catches two sentences run together");
	if (run_together("kernel lockdown.This step appends") &&
	    run_together("the socket).The agent loads") &&
	    !run_together("kernel lockdown. This step appends") &&
	    !run_together("in /etc/lota/lota.conf and reloads") &&
	    !run_together("See lota-install --resume."))
		PASS();
	else
		FAIL("the detector itself is wrong");
}

static void test_every_explanation_is_spaced(void)
{
	char msg[64];
	int bad = 0;

	TEST("no stage explanation runs two sentences together");
	for (int i = 0; i < install_stage_count; i++) {
		const char *text = install_stages[i].explain;
		const char *at = run_together(text);

		if (!at)
			continue;
		/* enough either side of the join to find it in the source */
		if (at - text > 12)
			at -= 12;
		printf("\n       stage %d: ...%.30s...", i + 1, at);
		bad++;
	}
	if (!bad) {
		PASS();
		return;
	}
	snprintf(msg, sizeof(msg), "%d explanation(s) above", bad);
	printf("\n      ");
	FAIL(msg);
}

static void test_every_title_is_spaced(void)
{
	TEST("no stage title runs two sentences together");
	for (int i = 0; i < install_stage_count; i++) {
		if (run_together(install_stages[i].title)) {
			FAIL(install_stages[i].title);
			return;
		}
	}
	PASS();
}

int main(void)
{
	printf("\n=== lota-install: the text a stage prints ===\n");

	test_the_detector();
	test_every_explanation_is_spaced();
	test_every_title_is_spaced();

	printf("\nPassed: %d / %d\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
