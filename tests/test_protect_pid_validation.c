/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * What --protect-pid costs when it names nothing.
 *
 * The protected set is seeded from pids that are already up, so a pid that is
 * not running is a mistake in the command line. The agent finds out by reading
 * /proc/<pid>/stat, and it reads it from inside the apply path -- after
 * self_measure() has extended PCR 14. The boot commitment can be spent once
 * per boot, so a mistyped pid costs the host its attestation until it reboots,
 * and the operator is told only that a file could not be found.
 *
 * Every other list the startup policy carries is already answered before
 * the extend: agent_validate_startup_policy() measures each fs-verity path
 * and resolves each trusted library.
 * The protected pids are checked for capacity there and for nothing else.
 *
 * These tests ask for the same treatment: the same read the apply path makes,
 * made early enough that a refusal costs a failed start rather than the boot.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../src/agent/agent.h"
#include "../src/agent/bpf_loader.h"
#include "../src/agent/main_utils.h"
#include "../src/agent/startup_policy.h"

struct agent_globals g_agent;

/*
 * The kernel prerequisites are the first thing the validator asks about that
 * this test cannot answer for itself, and reaching them is the evidence that
 * the pid check let the policy through.
 */
static int hardening_calls;

int __wrap_bpf_loader_verify_kernel_runtime_hardening(bool allow_mutable_rootfs);

int __wrap_bpf_loader_verify_kernel_runtime_hardening(bool allow_mutable_rootfs)
{
	(void)allow_mutable_rootfs;
	hardening_calls++;
	return 0;
}

/* named by the apply path, which nothing here reaches */
const char *mode_to_string(int mode)
{
	(void)mode;
	return "monitor";
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

/*
 * A pid nothing holds. The child is reaped before it is used, so the number
 * is free at the moment it is asked about -- which is exactly the state
 * an operator's stale pid is in.
 */
static uint32_t reaped_pid(void)
{
	pid_t pid = fork();
	int status;

	if (pid == 0)
		_exit(0);
	if (pid < 0)
		return 0;

	waitpid(pid, &status, 0);
	return (uint32_t)pid;
}

static void test_probe_accepts_a_live_pid(void)
{
	TEST("a running process passes the protected-pid probe");

	if (bpf_loader_probe_protect_pid((uint32_t)getpid()) != 0) {
		FAIL("the probe refuses a process that is running");
		return;
	}

	PASS();
}

static void test_probe_refuses_a_pid_that_is_gone(void)
{
	uint32_t gone = reaped_pid();
	int ret;

	TEST("a pid nothing holds is refused, and named as missing");

	if (gone == 0) {
		FAIL("cannot fork a victim");
		return;
	}

	ret = bpf_loader_probe_protect_pid(gone);
	if (ret == 0) {
		FAIL("the probe accepts a pid that names no process");
		return;
	}
	if (ret != -ENOENT) {
		FAIL("the refusal does not say the process is not there");
		return;
	}

	PASS();
}

/* refusal has to land before anything is spent */
static void test_validator_refuses_before_the_commitment(void)
{
	uint32_t gone = reaped_pid();
	struct agent_startup_policy policy = {
		.mode = LOTA_MODE_MONITOR,
		.protect_pids = &gone,
		.protect_pid_count = 1,
	};
	int ret;

	TEST("a dead pid is refused before the policy is checked further");

	if (gone == 0) {
		FAIL("cannot fork a victim");
		return;
	}

	hardening_calls = 0;
	ret = agent_validate_startup_policy(&policy);
	if (ret == 0) {
		FAIL("the policy is accepted with a pid that is not running");
		return;
	}
	if (ret != -ENOENT) {
		FAIL("the refusal does not say the process is not there");
		return;
	}
	if (hardening_calls != 0) {
		FAIL("the validator carried on past a pid it cannot protect");
		return;
	}

	PASS();
}

/* and that a policy naming a live process is not refused for its pids */
static void test_validator_accepts_a_live_pid(void)
{
	uint32_t live = (uint32_t)getpid();
	struct agent_startup_policy policy = {
		.mode = LOTA_MODE_MONITOR,
		.protect_pids = &live,
		.protect_pid_count = 1,
	};
	int ret;

	TEST("a policy naming a running process is not refused");

	hardening_calls = 0;
	ret = agent_validate_startup_policy(&policy);
	if (ret != 0) {
		FAIL("the policy is refused with a pid that is running");
		return;
	}
	if (hardening_calls != 1) {
		FAIL("the validator never reached the kernel prerequisites");
		return;
	}

	PASS();
}

int main(void)
{
	printf("=== --protect-pid before the boot commitment ===\n\n");

	test_probe_accepts_a_live_pid();
	test_probe_refuses_a_pid_that_is_gone();
	test_validator_refuses_before_the_commitment();
	test_validator_accepts_a_live_pid();

	printf("\n=== %d/%d passed ===\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
