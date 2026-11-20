/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Unit tests for ui_confirm(), the installer's yes/no question.
 *
 * Two callers cannot be undone for the rest of the boot, so every spelling
 * of no must decline and an unrecognised answer must never proceed.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../installer/ui.h"

#include "test.h"

/*
 * Feed @input to ui_confirm() with default @def; its prompt lands in @out.
 * stdin is a file, so end of input arrives as in a scripted run.
 */
static int ask_def(const char *input, enum ui_default def, char *out,
		   size_t outsz)
{
	char in_path[] = "/tmp/lota-confirm-in-XXXXXX";
	char out_path[] = "/tmp/lota-confirm-out-XXXXXX";
	int in_fd, out_fd, saved, rc;
	struct ui ui;
	FILE *f;
	size_t n;

	out[0] = '\0';
	in_fd = mkstemp(in_path);
	out_fd = mkstemp(out_path);
	if (in_fd < 0 || out_fd < 0) {
		perror("mkstemp");
		exit(1);
	}
	close(out_fd);
	if (write(in_fd, input, strlen(input)) != (ssize_t)strlen(input)) {
		perror("write");
		exit(1);
	}
	close(in_fd);

	if (!freopen(in_path, "r", stdin)) {
		perror("freopen stdin");
		exit(1);
	}
	fflush(stdout);
	saved = dup(STDOUT_FILENO);
	if (saved < 0 || !freopen(out_path, "w", stdout)) {
		perror("freopen stdout");
		exit(1);
	}

	ui_init(&ui, 1);
	rc = ui_confirm(&ui, "Apply this stage?", 0, def);

	fflush(stdout);
	if (dup2(saved, STDOUT_FILENO) < 0) {
		perror("dup2");
		exit(1);
	}
	close(saved);
	clearerr(stdout);

	f = fopen(out_path, "r");
	if (f) {
		n = fread(out, 1, outsz - 1, f);
		out[n] = '\0';
		fclose(f);
	}
	unlink(in_path);
	unlink(out_path);
	return rc;
}

/* Default yes, as for a stage. */
static int ask(const char *input, char *out, size_t outsz)
{
	return ask_def(input, UI_DEFAULT_YES, out, outsz);
}

/* Every spelling of no declines. */
static void test_no_declines(void)
{
	char seen[1024];

	TEST("\"n\" declines");
	if (ask("n\n", seen, sizeof(seen)) != 0)
		FAIL("expected: ask(\"n\\n\", seen, sizeof(seen)) == 0");
	TEST("\"N\" declines");
	if (ask("N\n", seen, sizeof(seen)) != 0)
		FAIL("expected: ask(\"N\\n\", seen, sizeof(seen)) == 0");
	TEST("\"no\" declines");
	if (ask("no\n", seen, sizeof(seen)) != 0)
		FAIL("expected: ask(\"no\\n\", seen, sizeof(seen)) == 0");
	TEST("\"No\" declines");
	if (ask("No\n", seen, sizeof(seen)) != 0)
		FAIL("expected: ask(\"No\\n\", seen, sizeof(seen)) == 0");
	TEST("\"n\" declines with spaces around it");
	if (ask("  n \n", seen, sizeof(seen)) != 0)
		FAIL("expected: ask(\"  n \\n\", seen, sizeof(seen)) == 0");
}

/* Quitting keeps the meaning it always had. */
static void test_quit_declines(void)
{
	char seen[1024];

	TEST("\"q\" declines");
	if (ask("q\n", seen, sizeof(seen)) != 0)
		FAIL("expected: ask(\"q\\n\", seen, sizeof(seen)) == 0");
	TEST("\"Q\" declines");
	if (ask("Q\n", seen, sizeof(seen)) != 0)
		FAIL("expected: ask(\"Q\\n\", seen, sizeof(seen)) == 0");
	TEST("\"quit\" declines");
	if (ask("quit\n", seen, sizeof(seen)) != 0)
		FAIL("expected: ask(\"quit\\n\", seen, sizeof(seen)) == 0");
	TEST("end of input declines");
	if (ask("", seen, sizeof(seen)) != 0)
		FAIL("expected: ask(\"\", seen, sizeof(seen)) == 0");
}

/* Yes proceeds, spelled either way. */
static void test_yes_proceeds(void)
{
	char seen[1024];

	TEST("\"y\" proceeds");
	if (ask("y\n", seen, sizeof(seen)) != 1)
		FAIL("expected: ask(\"y\\n\", seen, sizeof(seen)) == 1");
	TEST("\"Y\" proceeds");
	if (ask("Y\n", seen, sizeof(seen)) != 1)
		FAIL("expected: ask(\"Y\\n\", seen, sizeof(seen)) == 1");
	TEST("\"yes\" proceeds");
	if (ask("yes\n", seen, sizeof(seen)) != 1)
		FAIL("expected: ask(\"yes\\n\", seen, sizeof(seen)) == 1");
}

/* An unrecognised answer is asked again; running out of input declines. */
static void test_unknown_never_proceeds(void)
{
	char seen[1024];

	TEST("an unrecognised answer does not proceed");
	if (ask("maybe\n", seen, sizeof(seen)) != 0)
		FAIL("expected: ask(\"maybe\\n\", seen, sizeof(seen)) == 0");
	TEST("repeated unrecognised answers do not proceed");
	if (ask("maybe\nmaybe\nmaybe\nmaybe\n", seen, sizeof(seen)) != 0)
		FAIL("expected: ask(\"maybe\\nmaybe\\nmaybe\\nmaybe\\n\", "
		     "seen, sizeof(seen)) == 0");
	TEST("an unrecognised answer is asked again, and yes then proceeds");
	if (ask("maybe\ny\n", seen, sizeof(seen)) != 1)
		FAIL("expected: ask(\"maybe\\ny\\n\", seen, sizeof(seen)) == 1");
	TEST("an unrecognised answer is asked again, and no then declines");
	if (ask("maybe\nn\n", seen, sizeof(seen)) != 0)
		FAIL("expected: ask(\"maybe\\nn\\n\", seen, sizeof(seen)) == 0");
}

/* Enter takes the caller's default; under UI_DEFAULT_NO it declines. */
static void test_enter_takes_the_default(void)
{
	char seen[1024];

	TEST("Enter proceeds where the default is yes");
	if (ask_def("\n", UI_DEFAULT_YES, seen, sizeof(seen)) != 1)
		FAIL("expected: ask_def(\"\\n\", UI_DEFAULT_YES, seen, "
		     "sizeof(seen)) == 1");
	TEST("Enter declines where the default is no");
	if (ask_def("\n", UI_DEFAULT_NO, seen, sizeof(seen)) != 0)
		FAIL("expected: ask_def(\"\\n\", UI_DEFAULT_NO, seen, "
		     "sizeof(seen)) == 0");
	TEST("yes still proceeds where the default is no");
	if (ask_def("y\n", UI_DEFAULT_NO, seen, sizeof(seen)) != 1)
		FAIL("expected: ask_def(\"y\\n\", UI_DEFAULT_NO, seen, "
		     "sizeof(seen)) == 1");
	TEST("no still declines where the default is yes");
	if (ask_def("n\n", UI_DEFAULT_YES, seen, sizeof(seen)) != 0)
		FAIL("expected: ask_def(\"n\\n\", UI_DEFAULT_YES, seen, "
		     "sizeof(seen)) == 0");
}

static void test_prompt_names_the_answers(void)
{
	char seen[1024];

	(void)ask_def("y\n", UI_DEFAULT_YES, seen, sizeof(seen));
	TEST("the prompt is printed");
	if (strstr(seen, "Apply this stage?") == NULL)
		FAIL("expected: strstr(seen, \"Apply this stage?\") != NULL");
	TEST("the bracket names yes and no, and which one Enter takes");
	if (strstr(seen, "Y/n") == NULL)
		FAIL("expected: strstr(seen, \"Y/n\") != NULL");
	TEST("the bracket still names quit");
	if (strstr(seen, "q") == NULL)
		FAIL("expected: strstr(seen, \"q\") != NULL");

	(void)ask_def("y\n", UI_DEFAULT_NO, seen, sizeof(seen));
	TEST("a question that defaults to no says so in the bracket");
	if (strstr(seen, "y/N") == NULL)
		FAIL("expected: strstr(seen, \"y/N\") != NULL");
}

int main(void)
{
	test_begin("installer confirm");
	test_no_declines();
	test_quit_declines();
	test_yes_proceeds();
	test_unknown_never_proceeds();
	test_enter_takes_the_default();
	test_prompt_names_the_answers();

	return test_end();
}
