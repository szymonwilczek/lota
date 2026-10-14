// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
/*
 * Unit tests for ipc_privilege_granted(), the rule that decides who may
 * issue a privileged IPC command - the command set that includes the only
 * supported way to stop a running agent.
 *
 * The rule has to satisfy two things at once. A stock host, where the operator
 * has configured no fs-verity allowlist, must still be able to stop its own
 * agent, because the unit's ExecStop is the route systemd takes and nothing
 * else can end the process: the agent's own LSM hook refuses SIGKILL.
 * And an operator who has configured an allowlist must get the narrower rule
 * they asked for, on top of the uid check rather than instead of it.
 */

#define LOTA_INTERNAL_TESTS 1

#include <stdio.h>

#include "../src/agent/ipc_privilege.h"

static int g_failures;
static const char *g_current_test;

#define TEST(name)                                 \
	do {                                       \
		g_current_test = name;             \
		printf("[ RUN      ] %s\n", name); \
	} while (0)

#define PASS()                                               \
	do {                                                 \
		printf("[       OK ] %s\n", g_current_test); \
	} while (0)

#define FAIL(fmt, ...)                                                        \
	do {                                                                  \
		fprintf(stderr, "[  FAILED  ] %s: " fmt "\n", g_current_test, \
			##__VA_ARGS__);                                       \
		g_failures++;                                                 \
		return;                                                       \
	} while (0)

/*
 * On a default install the allowlist is empty, so a rule that requires membership
 * in it can never pass and the service cannot be stopped by any route.
 */
static void test_default_install_can_stop_the_agent(void)
{
	TEST("the agent's own uid may stop it on a host with no allowlist");

	if (!ipc_privilege_granted(true, true, 0, false))
		FAIL("a stock host cannot stop its own agent");
	PASS();
}

/*
 * The uid check is the boundary and is not softened by the allowlist being empty.
 */
static void test_other_uid_is_refused(void)
{
	TEST("another uid is refused whether or not an allowlist exists");

	if (ipc_privilege_granted(false, true, 0, false))
		FAIL("a foreign uid was granted on an empty allowlist");
	if (ipc_privilege_granted(false, true, 2, true))
		FAIL("a foreign uid was granted on a populated allowlist");
	PASS();
}

/*
 * A pid whose start time no longer matches is a different process that inherited
 * the number, so the connection's authority does not carry.
 */
static void test_recycled_pid_is_refused(void)
{
	TEST("a pid that no longer matches its start time is refused");

	if (ipc_privilege_granted(true, false, 0, false))
		FAIL("a recycled pid was granted on an empty allowlist");
	if (ipc_privilege_granted(true, false, 2, true))
		FAIL("a recycled pid was granted on a populated allowlist");
	PASS();
}

/*
 * Where an operator has configured an allowlist, it narrows the uid check:
 * an executable that is not on the list is refused even though the uid is right.
 */
static void test_allowlist_narrows_when_configured(void)
{
	TEST("a configured allowlist still refuses an unlisted executable");

	if (ipc_privilege_granted(true, true, 2, false))
		FAIL("an unlisted executable was granted");
	if (!ipc_privilege_granted(true, true, 2, true))
		FAIL("a listed executable was refused");
	PASS();
}

int main(void)
{
	test_default_install_can_stop_the_agent();
	test_other_uid_is_refused();
	test_recycled_pid_is_refused();
	test_allowlist_narrows_when_configured();

	if (g_failures == 0) {
		printf("\nAll tests passed.\n");
		return 0;
	}
	fprintf(stderr, "\n%d test(s) failed.\n", g_failures);
	return 1;
}
