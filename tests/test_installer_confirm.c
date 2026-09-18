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

static int g_failures;

#define CHECK(cond, msg)                                    \
	do {                                                \
		if (!(cond)) {                              \
			fprintf(stderr, "FAIL: %s\n", msg); \
			g_failures++;                       \
		} else {                                    \
			printf("PASS: %s\n", msg);          \
		}                                           \
		fflush(stdout);                             \
	} while (0)

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

	CHECK(ask("n\n", seen, sizeof(seen)) == 0, "\"n\" declines");
	CHECK(ask("N\n", seen, sizeof(seen)) == 0, "\"N\" declines");
	CHECK(ask("no\n", seen, sizeof(seen)) == 0, "\"no\" declines");
	CHECK(ask("No\n", seen, sizeof(seen)) == 0, "\"No\" declines");
	CHECK(ask("  n \n", seen, sizeof(seen)) == 0,
	      "\"n\" declines with spaces around it");
}

/* Quitting keeps the meaning it always had. */
static void test_quit_declines(void)
{
	char seen[1024];

	CHECK(ask("q\n", seen, sizeof(seen)) == 0, "\"q\" declines");
	CHECK(ask("Q\n", seen, sizeof(seen)) == 0, "\"Q\" declines");
	CHECK(ask("quit\n", seen, sizeof(seen)) == 0, "\"quit\" declines");
	CHECK(ask("", seen, sizeof(seen)) == 0, "end of input declines");
}

/* Yes proceeds, spelled either way. */
static void test_yes_proceeds(void)
{
	char seen[1024];

	CHECK(ask("y\n", seen, sizeof(seen)) == 1, "\"y\" proceeds");
	CHECK(ask("Y\n", seen, sizeof(seen)) == 1, "\"Y\" proceeds");
	CHECK(ask("yes\n", seen, sizeof(seen)) == 1, "\"yes\" proceeds");
}

/* An unrecognised answer is asked again; running out of input declines. */
static void test_unknown_never_proceeds(void)
{
	char seen[1024];

	CHECK(ask("maybe\n", seen, sizeof(seen)) == 0,
	      "an unrecognised answer does not proceed");
	CHECK(ask("maybe\nmaybe\nmaybe\nmaybe\n", seen, sizeof(seen)) == 0,
	      "repeated unrecognised answers do not proceed");
	CHECK(ask("maybe\ny\n", seen, sizeof(seen)) == 1,
	      "an unrecognised answer is asked again, and yes then proceeds");
	CHECK(ask("maybe\nn\n", seen, sizeof(seen)) == 0,
	      "an unrecognised answer is asked again, and no then declines");
}

/* Enter takes the caller's default; under UI_DEFAULT_NO it declines. */
static void test_enter_takes_the_default(void)
{
	char seen[1024];

	CHECK(ask_def("\n", UI_DEFAULT_YES, seen, sizeof(seen)) == 1,
	      "Enter proceeds where the default is yes");
	CHECK(ask_def("\n", UI_DEFAULT_NO, seen, sizeof(seen)) == 0,
	      "Enter declines where the default is no");
	CHECK(ask_def("y\n", UI_DEFAULT_NO, seen, sizeof(seen)) == 1,
	      "yes still proceeds where the default is no");
	CHECK(ask_def("n\n", UI_DEFAULT_YES, seen, sizeof(seen)) == 0,
	      "no still declines where the default is yes");
}

static void test_prompt_names_the_answers(void)
{
	char seen[1024];

	(void)ask_def("y\n", UI_DEFAULT_YES, seen, sizeof(seen));
	CHECK(strstr(seen, "Apply this stage?") != NULL,
	      "the prompt is printed");
	CHECK(strstr(seen, "Y/n") != NULL,
	      "the bracket names yes and no, and which one Enter takes");
	CHECK(strstr(seen, "q") != NULL, "the bracket still names quit");

	(void)ask_def("y\n", UI_DEFAULT_NO, seen, sizeof(seen));
	CHECK(strstr(seen, "y/N") != NULL,
	      "a question that defaults to no says so in the bracket");
}

int main(void)
{
	test_no_declines();
	test_quit_declines();
	test_yes_proceeds();
	test_unknown_never_proceeds();
	test_enter_takes_the_default();
	test_prompt_names_the_answers();

	if (g_failures) {
		fprintf(stderr, "\n%d check(s) failed\n", g_failures);
		return 1;
	}
	printf("\nAll installer confirm tests passed\n");
	return 0;
}
