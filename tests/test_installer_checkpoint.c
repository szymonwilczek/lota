/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * What an unattended lota-install says where it stops.
 *
 * A package hook runs the installer unattended, and that run leaves the stages
 * that change how the machine boots to a person, then stops at the reboot
 * checkpoint. What it prints there is the operator's only list of the work
 * left, so it names the stages that were left and no others: a host where one
 * of them deferred and the rest reported themselves satisfied in the same run
 * must not be sent back for all of them.
 *
 * The exit code says the same thing: a run that left work to a person has not
 * finished the install, and a caller that reads only the code must see that.
 */

#include <stdio.h>
#include <stdlib.h>
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

static char note[4096];

static int stage_named(const char *title)
{
	int i;

	for (i = 0; i < install_stage_count; i++)
		if (strcmp(install_stages[i].title, title) == 0)
			return i;
	fprintf(stderr, "no stage titled '%s'\n", title);
	exit(1);
}

static int says(const char *what)
{
	return strstr(note, what) != NULL;
}

/* Every boot-path stage and the stages the old sentence also named. */
static int names_only(const int *deferred, int n)
{
	int i, j;

	for (i = 0; i < install_stage_count; i++) {
		int left = 0;

		for (j = 0; j < n; j++)
			left |= deferred[j] == i;
		if (says(install_stages[i].title) != left) {
			FAIL(note);
			return 0;
		}
	}
	if (!says("sudo lota-install") || !says(PATH_AUTO_BRINGUP)) {
		FAIL("the command that finishes the job is missing");
		return 0;
	}
	return 1;
}

static void test_one_deferred_stage_is_named_alone(void)
{
	int d[1];

	TEST("one deferred stage is the only one named");
	d[0] = stage_named("Kernel integrity floor on the cmdline");
	install_unattended_checkpoint(note, sizeof(note), d, 1);
	if (says("initramfs") || says("IMA")) {
		FAIL(note);
		return;
	}
	if (names_only(d, 1))
		PASS();
}

static void test_the_initramfs_stage_alone(void)
{
	int d[1];

	TEST("the initramfs stage alone");
	d[0] = stage_named("Boot-time PCR14 lock in the initramfs");
	install_unattended_checkpoint(note, sizeof(note), d, 1);
	if (says("integrity floor") || says("IMA")) {
		FAIL(note);
		return;
	}
	if (names_only(d, 1))
		PASS();
}

static void test_two_deferred_stages_are_both_named(void)
{
	int d[2];

	TEST("two deferred stages are both named");
	d[0] = stage_named("Boot-time PCR14 lock in the initramfs");
	d[1] = stage_named("Kernel integrity floor on the cmdline");
	install_unattended_checkpoint(note, sizeof(note), d, 2);
	if (says("IMA")) {
		FAIL(note);
		return;
	}
	if (names_only(d, 2))
		PASS();
}

/*
 * The deferral has a code of its own: 0 is what --status answers on a host
 * with nothing left, and an automated caller has only the code to go on.
 */
static void test_a_deferral_is_not_success(void)
{
	int d[1];
	int rc;

	TEST("a deferral exits with its own code, not 0");
	d[0] = stage_named("Kernel integrity floor on the cmdline");
	rc = install_unattended_checkpoint(note, sizeof(note), d, 1);
	if (rc != EXIT_INSTALL_DEFERRED) {
		char msg[64];

		snprintf(msg, sizeof(msg), "exit %d, want %d", rc,
			 EXIT_INSTALL_DEFERRED);
		FAIL(msg);
		return;
	}
	PASS();
}

static void test_the_codes_are_distinct(void)
{
	static const int codes[] = { EXIT_INSTALL_OK, EXIT_INSTALL_FAIL,
				     EXIT_INSTALL_USAGE, EXIT_INSTALL_REBOOT,
				     EXIT_INSTALL_DEFERRED };
	size_t i, j;

	TEST("every exit code means one outcome");
	for (i = 0; i < sizeof(codes) / sizeof(codes[0]); i++)
		for (j = 0; j < i; j++)
			if (codes[i] == codes[j]) {
				FAIL("two outcomes share a code");
				return;
			}
	PASS();
}

int main(void)
{
	printf("\n=== lota-install: the unattended checkpoint ===\n");

	test_one_deferred_stage_is_named_alone();
	test_the_initramfs_stage_alone();
	test_two_deferred_stages_are_both_named();
	test_a_deferral_is_not_success();
	test_the_codes_are_distinct();

	printf("\nPassed: %d / %d\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
