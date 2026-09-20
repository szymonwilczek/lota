/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * A kernel floor refusal (lockdown, module signatures, appraisal scope)
 * is a state of the host, so it must leave as -ENOTSUP, the status
 * RestartPreventExitStatus stops on; a bare -EPERM restarts the unit every
 * five seconds. The floor is wrapped, so no result depends on the host.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "../src/agent/agent.h"
#include "../src/agent/main_utils.h"
#include "../src/agent/startup_policy.h"

struct agent_globals g_agent;

/* What the wrapped floor answers, and how often it was asked. */
static int floor_answer;
static int floor_calls;

int __wrap_bpf_loader_verify_kernel_runtime_hardening(bool allow_mutable_rootfs);

int __wrap_bpf_loader_verify_kernel_runtime_hardening(bool allow_mutable_rootfs)
{
	(void)allow_mutable_rootfs;
	floor_calls++;
	return floor_answer;
}

/* named by the apply path, which a refused floor never reaches past */
const char *mode_to_string(int mode)
{
	(void)mode;
	return "monitor";
}

/* No socket owner here, so no verdict to drop */
void ipc_runtime_coverage_forget(void)
{
}

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

/* Secure Boot off: no lockdown, the floor answers -EPERM */
static void test_validator_refuses_the_host_and_not_the_run(void)
{
	struct agent_startup_policy policy = {
		.mode = LOTA_MODE_MONITOR,
	};
	int ret;

	TEST("a kernel out of lockdown is a host the agent refuses");

	floor_answer = -EPERM;
	floor_calls = 0;
	ret = agent_validate_startup_policy(&policy);

	if (floor_calls != 1)
		FAIL("the validator never asked the kernel floor");
	else if (ret == 0)
		FAIL("a host below the floor was accepted");
	else if (ret != -ENOTSUP)
		FAIL("the refusal is one systemd restarts into every five seconds");
	else
		PASS();
}

/* appraisal scope reaches no executable: -ENOENT, as a missing file */
static void test_a_scope_refusal_is_not_a_missing_file(void)
{
	struct agent_startup_policy policy = {
		.mode = LOTA_MODE_MONITOR,
	};
	int ret;

	TEST("an appraisal scope refusal is told from a missing file");

	floor_answer = -ENOENT;
	floor_calls = 0;
	ret = agent_validate_startup_policy(&policy);

	if (ret != -ENOTSUP)
		FAIL("the refusal keeps an errno that says try again");
	else
		PASS();
}

/* the apply path asks the floor again, after the commitment is spent */
static void test_the_apply_path_refuses_the_same_way(void)
{
	struct agent_startup_policy policy = {
		.mode = LOTA_MODE_MONITOR,
	};
	int ret;

	TEST("the apply path's floor refusal carries the same status");

	floor_answer = -EPERM;
	floor_calls = 0;
	ret = agent_apply_startup_policy(&policy);

	if (floor_calls != 1)
		FAIL("the apply path never asked the kernel floor");
	else if (ret != -ENOTSUP)
		FAIL("the same refusal means something else in the apply path");
	else
		PASS();
}

/* A host that meets the floor is not refused for it. */
static void test_a_host_that_meets_the_floor_passes(void)
{
	struct agent_startup_policy policy = {
		.mode = LOTA_MODE_MONITOR,
	};
	int ret;

	TEST("a host that meets the floor is not refused");

	floor_answer = 0;
	floor_calls = 0;
	ret = agent_validate_startup_policy(&policy);

	if (ret != 0)
		FAIL("a policy with nothing else in it was refused");
	else if (floor_calls != 1)
		FAIL("the validator never asked the kernel floor");
	else
		PASS();
}

int main(void)
{
	printf("=== What a refused kernel floor tells the supervisor ===\n\n");

	test_validator_refuses_the_host_and_not_the_run();
	test_a_scope_refusal_is_not_a_missing_file();
	test_the_apply_path_refuses_the_same_way();
	test_a_host_that_meets_the_floor_passes();

	printf("\n=== %d/%d passed ===\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
