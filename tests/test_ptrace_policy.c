/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for the ptrace access decision (include/lota.h).
 *
 * They pin what the block_ptrace configuration key covers: an attach, which is
 * what the key's help text and the documentation promise, and not a read of
 * another process's /proc, which the kernel's own permission model already
 * answers. A process that asked for protection is the separate case, and it
 * refuses both, as does every process it starts.
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
 * With block_ptrace on, in enforce, and nothing protected, an ordinary task
 * must still be able to read another task's /proc: lsof, ps with per-process detail, a crash handler and a profiler all take
 * PTRACE_MODE_READ, and same-uid /proc access is not a boundary this project
 * owns -- denying it breaks the desktop.
 */
static void test_read_is_allowed_with_the_key_on(void)
{
	CHECK(!DENIED(PTRACE_MODE_READ, LOTA_MODE_ENFORCE, 1, 0, 0),
	      "a read of an unprotected task is allowed with block_ptrace on");
	CHECK(!DENIED(0, LOTA_MODE_ENFORCE, 1, 0, 0),
	      "an access asking for neither flag is not an attach");
}

/* The half the key is named for */
static void test_attach_is_refused_with_the_key_on(void)
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

/* Monitor lifts policy, and isolation of a protected task is not policy */
static void test_monitor_keeps_the_protected_rule(void)
{
	CHECK(DENIED(PTRACE_MODE_READ, LOTA_MODE_MONITOR, 1, 0, 1),
	      "monitor refuses a read of a protected task");
	CHECK(DENIED(LOTA_PTRACE_MODE_ATTACH, LOTA_MODE_MONITOR, 0, 0, 1),
	      "monitor refuses an attach on a protected task");
}

/* The agent is never a target, in any mode, whatever the key says */
static void test_the_agent_is_never_a_target(void)
{
	CHECK(DENIED(PTRACE_MODE_READ, LOTA_MODE_ENFORCE, 0, 1, 0),
	      "a read of the agent is refused with block_ptrace off");
	CHECK(DENIED(LOTA_PTRACE_MODE_ATTACH, LOTA_MODE_MONITOR, 0, 1, 0),
	      "an attach on the agent is refused in monitor mode");
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

/* CLONE_VM | CLONE_VFORK, what posix_spawn() passes */
#define SPAWN_FLAGS 0x00004100UL
/* CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND, what a thread adds to */
#define THREAD_SHARE_FLAGS 0x00000f00UL

/*
 * A protected process passes its protection to the processes it creates,
 * however it creates them, and to nothing a process nobody protects creates.
 */
static void test_a_child_inherits_protection(void)
{
	CHECK(lota_clone_inherits_protection(0, 1),
	      "a fork of a protected process is protected");
	CHECK(lota_clone_inherits_protection(SPAWN_FLAGS, 1),
	      "a posix_spawn() child of a protected process is protected");
	CHECK(!lota_clone_inherits_protection(0, 0),
	      "a fork of an unprotected process is not protected");
	CHECK(!lota_clone_inherits_protection(SPAWN_FLAGS, 0),
	      "a spawn of an unprotected process is not protected");
}

/* A thread is covered through its leader and takes no mark of its own */
static void test_a_thread_takes_no_mark(void)
{
	CHECK(!lota_clone_inherits_protection(
		      THREAD_SHARE_FLAGS | LOTA_CLONE_THREAD, 1),
	      "a thread of a protected process takes no mark");
}

/*
 * A tracer attached before the protection would follow a protected process
 * into its children, so a process held from outside the set creates nothing
 */
static void test_a_tracer_from_outside_stops_creation(void)
{
	CHECK(lota_clone_refused(1, 1, 0),
	      "a protected process traced from outside creates nothing");
	CHECK(!lota_clone_refused(1, 1, 1),
	      "a protected process traced from inside its instance creates");
	CHECK(!lota_clone_refused(1, 0, 0),
	      "an untraced protected process creates");
	CHECK(!lota_clone_refused(0, 1, 0),
	      "a traced unprotected process is not this rule's business");
}

static void test_access_inside_an_instance(void)
{
	CHECK(lota_inside_instance(1, 100, 5000, 1, 100, 5000),
	      "two processes of one instance are inside it");
	CHECK(!lota_inside_instance(1, 100, 5000, 1, 200, 5000),
	      "another instance's process is outside");
	CHECK(!lota_inside_instance(1, 100, 5000, 1, 100, 6000),
	      "a recycled root tgid names another instance");
	CHECK(!lota_inside_instance(0, 100, 5000, 1, 100, 5000),
	      "an unprotected actor is outside every instance");
	CHECK(!lota_inside_instance(1, 100, 5000, 0, 100, 5000),
	      "an unprotected target is in no instance");
}

/* the hook passes a target inside the actor's instance as unprotected */
static void test_an_attach_inside_the_instance_is_allowed(void)
{
	int inside = lota_inside_instance(1, 100, 5000, 1, 100, 5000);

	CHECK(!lota_ptrace_denied(LOTA_PTRACE_MODE_ATTACH, LOTA_MODE_MONITOR, 0,
				  0, !inside),
	      "an attach inside the instance is not refused");
	CHECK(lota_ptrace_denied(LOTA_PTRACE_MODE_ATTACH, LOTA_MODE_MONITOR, 0,
				 1, !inside),
	      "the agent stays refused to every instance");
}

int main(void)
{
	printf("=== ptrace policy tests ===\n");
	test_read_is_allowed_with_the_key_on();
	test_attach_is_refused_with_the_key_on();
	test_the_key_off_refuses_nothing();
	test_the_global_rule_is_enforce_only();
	test_a_protected_target_refuses_both_modes();
	test_monitor_keeps_the_protected_rule();
	test_the_agent_is_never_a_target();
	test_the_agent_read_exemption();
	test_attach_is_recognised_by_its_flag();
	test_a_child_inherits_protection();
	test_a_thread_takes_no_mark();
	test_a_tracer_from_outside_stops_creation();
	test_access_inside_an_instance();
	test_an_attach_inside_the_instance_is_allowed();

	if (g_failures) {
		fprintf(stderr, "\n%d test(s) failed\n", g_failures);
		return 1;
	}
	printf("\nAll ptrace policy tests passed\n");
	return 0;
}
