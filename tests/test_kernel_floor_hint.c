/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Unit tests for the kernel floor refusal.
 *
 * Under Secure Boot the firmware, not the cmdline, raises lockdown and module
 * signatures. The refusal names Secure Boot when it is off, and the
 * parameters only when it is on and the floor is still unmet.
 *
 * "Correct the policy" must not follow a floor refusal: its only actionable
 * reading drops the requirement.
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "../src/agent/kernel_floor_hint.h"

static int tests_run;
static int tests_passed;

#define TEST(name)                                         \
	do {                                               \
		tests_run++;                               \
		printf("  [%2d] %-58s ", tests_run, name); \
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

static char buf[1024];

static void test_lockdown_off_secureboot_names_the_firmware(void)
{
	TEST("lockdown refused with Secure Boot off names Secure Boot");

	kernel_floor_message(LOTA_KERNEL_FLOOR_LOCKDOWN, false, buf,
			     sizeof(buf));

	if (!strstr(buf, "Secure Boot"))
		FAIL("the switch that decides the floor is not named");
	else
		PASS();

	TEST("and says it is a firmware setting");

	if (!strstr(buf, "firmware"))
		FAIL("the player is not told where the setting lives");
	else
		PASS();

	TEST("and does not send the player to the kernel command line");

	if (strstr(buf, "lockdown=") || strstr(buf, "command line"))
		FAIL("a lever this host does not carry was named anyway");
	else
		PASS();
}

static void test_lockdown_on_secureboot_names_the_cmdline(void)
{
	TEST("lockdown refused with Secure Boot on names the parameter");

	kernel_floor_message(LOTA_KERNEL_FLOOR_LOCKDOWN, true, buf,
			     sizeof(buf));

	if (!strstr(buf, "lockdown="))
		FAIL("the lever this host does have was not named");
	else
		PASS();
}

static void test_module_sig_reads_the_host_the_same_way(void)
{
	TEST("module signatures refused with Secure Boot off names it");

	kernel_floor_message(LOTA_KERNEL_FLOOR_MODULE_SIG, false, buf,
			     sizeof(buf));

	if (!strstr(buf, "Secure Boot") || strstr(buf, "module.sig_enforce="))
		FAIL("the same host was given a different answer");
	else
		PASS();

	TEST("module signatures refused with Secure Boot on names the "
	     "parameter");

	kernel_floor_message(LOTA_KERNEL_FLOOR_MODULE_SIG, true, buf,
			     sizeof(buf));

	if (!strstr(buf, "module.sig_enforce"))
		FAIL("the lever this host does have was not named");
	else
		PASS();
}

static void test_every_message_says_what_is_missing(void)
{
	static const struct {
		enum lota_kernel_floor which;
		const char *what;
	} cases[] = {
		{ LOTA_KERNEL_FLOOR_LOCKDOWN, "lockdown" },
		{ LOTA_KERNEL_FLOOR_MODULE_SIG, "signature" },
	};
	size_t i;
	int sb;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		for (sb = 0; sb < 2; sb++) {
			TEST("the refusal still names the missing state");
			kernel_floor_message(cases[i].which, sb != 0, buf,
					     sizeof(buf));
			if (!strstr(buf, cases[i].what))
				FAIL("the reason was traded for the remedy");
			else
				PASS();
		}
	}
}

/*
 * -ENOTSUP: the host is below the floor. Any other startup refusal is the
 * command line or the config file, which an edit repairs.
 */
static void test_advice_matches_what_an_edit_can_repair(void)
{
	TEST("a host below the kernel floor is not sent to edit a policy");

	if (strstr(startup_refusal_advice(-ENOTSUP), "Correct the policy"))
		FAIL("the one action a player can take removes the property");
	else
		PASS();

	TEST("and is told the refusal is the host's state");

	if (!strstr(startup_refusal_advice(-ENOTSUP), "host"))
		FAIL("nothing says why editing will not help");
	else
		PASS();

	TEST("a policy that cannot be applied still says to correct it");

	if (!strstr(startup_refusal_advice(-EINVAL), "Correct the policy"))
		FAIL("the refusal an edit does repair lost its advice");
	else
		PASS();
}

int main(void)
{
	printf("=== kernel floor hint tests ===\n\n");

	test_lockdown_off_secureboot_names_the_firmware();
	test_lockdown_on_secureboot_names_the_cmdline();
	test_module_sig_reads_the_host_the_same_way();
	test_every_message_says_what_is_missing();
	test_advice_matches_what_an_edit_can_repair();

	printf("\n=== %d/%d passed ===\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
