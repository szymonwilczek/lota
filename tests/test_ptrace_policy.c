/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for the ptrace access decision (include/lota.h).
 *
 * They pin what the block_ptrace configuration key covers: an attach, which is
 * what the key's help text and the documentation promise, and not a read of
 * another process's /proc, which the kernel's own permission model already
 * answers. A process that asked for protection is the separate case, and it
 * refuses both.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <stdio.h>

#include "../include/lota.h"

/* PTRACE_MODE_READ from include/linux/ptrace.h, the other half of the pair */
#define PTRACE_MODE_READ 0x01

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

#define DENIED(ptrace_mode, lota_mode, block, is_agent, is_protected)       \
	lota_ptrace_denied((ptrace_mode), (lota_mode), (block), (is_agent), \
			   (is_protected))

/*
 * The shipped default is block_ptrace on, in enforce, with nothing protected.
 * On that host an ordinary task must still be able to read another task's /proc:
 * lsof, ps with per-process detail, a crash handler and a profiler all take
 * PTRACE_MODE_READ, and same-uid /proc access is not a boundary this project
 * owns -- denying it breaks the desktop.
 */
static void test_read_is_allowed_on_the_shipped_default(void)
{
	CHECK(!DENIED(PTRACE_MODE_READ, LOTA_MODE_ENFORCE, 1, 0, 0),
	      "a read of an unprotected task is allowed with block_ptrace on");
	CHECK(!DENIED(0, LOTA_MODE_ENFORCE, 1, 0, 0),
	      "an access asking for neither flag is not an attach");
}

/* The half the key is named for, and the reason it defaults to on */
static void test_attach_is_refused_on_the_shipped_default(void)
{
	CHECK(DENIED(LOTA_PTRACE_MODE_ATTACH, LOTA_MODE_ENFORCE, 1, 0, 0),
	      "an attach on an unprotected task is refused with block_ptrace on");
	CHECK(DENIED(LOTA_PTRACE_MODE_ATTACH | PTRACE_MODE_READ,
		     LOTA_MODE_ENFORCE, 1, 0, 0),
	      "an attach that also asks to read is still an attach");
}

/* Turning the key off leaves both modes to the kernel */
static void test_the_key_off_refuses_nothing(void)
{
	CHECK(!DENIED(LOTA_PTRACE_MODE_ATTACH, LOTA_MODE_ENFORCE, 0, 0, 0),
	      "an attach is allowed with block_ptrace off");
	CHECK(!DENIED(PTRACE_MODE_READ, LOTA_MODE_ENFORCE, 0, 0, 0),
	      "a read is allowed with block_ptrace off");
}

/*
 * The global rule is enforce-only, so a monitor-mode host observes and refuses
 * nothing -- including the attach it would refuse in enforce
 */
static void test_the_global_rule_is_enforce_only(void)
{
	CHECK(!DENIED(LOTA_PTRACE_MODE_ATTACH, LOTA_MODE_MONITOR, 1, 0, 0),
	      "monitor mode refuses no attach on an unprotected task");
	CHECK(!DENIED(PTRACE_MODE_READ, LOTA_MODE_MONITOR, 1, 0, 0),
	      "monitor mode refuses no read on an unprotected task");
}

/*
 * A process that asked for protection is the case this hook exists for.
 * It is a set the operator opts into rather than every task on the machine,
 * so it refuses both modes, and it does so whether or not block_ptrace is on.
 */
static void test_a_protected_target_refuses_both_modes(void)
{
	CHECK(DENIED(PTRACE_MODE_READ, LOTA_MODE_ENFORCE, 1, 0, 1),
	      "a read of a protected task is refused");
	CHECK(DENIED(LOTA_PTRACE_MODE_ATTACH, LOTA_MODE_ENFORCE, 1, 0, 1),
	      "an attach on a protected task is refused");
	CHECK(DENIED(PTRACE_MODE_READ, LOTA_MODE_ENFORCE, 0, 0, 1),
	      "a protected task is refused with block_ptrace off");
	CHECK(DENIED(PTRACE_MODE_READ, LOTA_MODE_MONITOR, 0, 0, 1),
	      "a protected task is refused in monitor mode");
}

/* Maintenance is the mode that exists to lift the gates */
static void test_maintenance_lifts_the_protected_rule(void)
{
	CHECK(!DENIED(PTRACE_MODE_READ, LOTA_MODE_MAINTENANCE, 1, 0, 1),
	      "maintenance allows a read of a protected task");
	CHECK(!DENIED(LOTA_PTRACE_MODE_ATTACH, LOTA_MODE_MAINTENANCE, 1, 0, 1),
	      "maintenance allows an attach on a protected task");
}

/* The agent is never a target, in any mode, whatever the key says */
static void test_the_agent_is_never_a_target(void)
{
	CHECK(DENIED(PTRACE_MODE_READ, LOTA_MODE_ENFORCE, 0, 1, 0),
	      "a read of the agent is refused with block_ptrace off");
	CHECK(DENIED(LOTA_PTRACE_MODE_ATTACH, LOTA_MODE_MAINTENANCE, 0, 1, 0),
	      "an attach on the agent is refused in maintenance");
	CHECK(DENIED(PTRACE_MODE_READ, LOTA_MODE_MONITOR, 0, 1, 0),
	      "a read of the agent is refused in monitor mode");
}

/*
 * The agent's own exemption is the read half only: it measures a protected
 * process's live code through /proc, and it must not gain a debugger onto one.
 */
static void test_the_agent_read_exemption(void)
{
	CHECK(lota_ptrace_agent_read_exempt(PTRACE_MODE_READ, 1),
	      "the agent is exempt for a read");
	CHECK(!lota_ptrace_agent_read_exempt(LOTA_PTRACE_MODE_ATTACH, 1),
	      "the agent is not exempt for an attach");
	CHECK(!lota_ptrace_agent_read_exempt(PTRACE_MODE_READ, 0),
	      "a task that is not the agent gets no exemption");
}

static void test_attach_is_recognised_by_its_flag(void)
{
	CHECK(lota_ptrace_is_attach(LOTA_PTRACE_MODE_ATTACH),
	      "the attach flag is an attach");
	CHECK(!lota_ptrace_is_attach(PTRACE_MODE_READ),
	      "the read flag is not an attach");
	CHECK(lota_ptrace_is_attach(LOTA_PTRACE_MODE_ATTACH | PTRACE_MODE_READ),
	      "an access carrying both flags is an attach");
}

int main(void)
{
	printf("=== ptrace policy tests ===\n");
	test_read_is_allowed_on_the_shipped_default();
	test_attach_is_refused_on_the_shipped_default();
	test_the_key_off_refuses_nothing();
	test_the_global_rule_is_enforce_only();
	test_a_protected_target_refuses_both_modes();
	test_maintenance_lifts_the_protected_rule();
	test_the_agent_is_never_a_target();
	test_the_agent_read_exemption();
	test_attach_is_recognised_by_its_flag();

	if (g_failures) {
		fprintf(stderr, "\n%d test(s) failed\n", g_failures);
		return 1;
	}
	printf("\nAll ptrace policy tests passed\n");
	return 0;
}
