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

#include "../include/lota.h"

#include "test.h"

/* PTRACE_MODE_READ from include/linux/ptrace.h, the other half of the pair */
#define PTRACE_MODE_READ 0x01

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
	TEST("a read of an unprotected task is allowed with block_ptrace on");
	if (DENIED(PTRACE_MODE_READ, LOTA_MODE_ENFORCE, 1, 0, 0))
		FAIL("expected: !DENIED(PTRACE_MODE_READ, LOTA_MODE_ENFORCE, "
		     "1, 0, 0)");
	TEST("an access asking for neither flag is not an attach");
	if (DENIED(0, LOTA_MODE_ENFORCE, 1, 0, 0))
		FAIL("expected: !DENIED(0, LOTA_MODE_ENFORCE, 1, 0, 0)");
}

/* The half the key is named for */
static void test_attach_is_refused_with_the_key_on(void)
{
	TEST("an attach to an unprotected task is refused under block_ptrace");
	if (!DENIED(LOTA_PTRACE_MODE_ATTACH, LOTA_MODE_ENFORCE, 1, 0, 0))
		FAIL("expected: DENIED(LOTA_PTRACE_MODE_ATTACH, "
		     "LOTA_MODE_ENFORCE, 1, 0, 0)");
	TEST("an attach that also asks to read is still an attach");
	if (!DENIED(LOTA_PTRACE_MODE_ATTACH | PTRACE_MODE_READ,
		    LOTA_MODE_ENFORCE, 1, 0, 0))
		FAIL("expected: DENIED(LOTA_PTRACE_MODE_ATTACH | "
		     "PTRACE_MODE_READ, LOTA_MODE_ENFORCE, 1, 0, 0)");
}

/* Turning the key off leaves both modes to the kernel */
static void test_the_key_off_refuses_nothing(void)
{
	TEST("an attach is allowed with block_ptrace off");
	if (DENIED(LOTA_PTRACE_MODE_ATTACH, LOTA_MODE_ENFORCE, 0, 0, 0))
		FAIL("expected: !DENIED(LOTA_PTRACE_MODE_ATTACH, "
		     "LOTA_MODE_ENFORCE, 0, 0, 0)");
	TEST("a read is allowed with block_ptrace off");
	if (DENIED(PTRACE_MODE_READ, LOTA_MODE_ENFORCE, 0, 0, 0))
		FAIL("expected: !DENIED(PTRACE_MODE_READ, LOTA_MODE_ENFORCE, "
		     "0, 0, 0)");
}

/*
 * The global rule is enforce-only, so a monitor-mode host observes and refuses
 * nothing -- including the attach it would refuse in enforce
 */
static void test_the_global_rule_is_enforce_only(void)
{
	TEST("monitor mode refuses no attach on an unprotected task");
	if (DENIED(LOTA_PTRACE_MODE_ATTACH, LOTA_MODE_MONITOR, 1, 0, 0))
		FAIL("expected: !DENIED(LOTA_PTRACE_MODE_ATTACH, "
		     "LOTA_MODE_MONITOR, 1, 0, 0)");
	TEST("monitor mode refuses no read on an unprotected task");
	if (DENIED(PTRACE_MODE_READ, LOTA_MODE_MONITOR, 1, 0, 0))
		FAIL("expected: !DENIED(PTRACE_MODE_READ, LOTA_MODE_MONITOR, "
		     "1, 0, 0)");
}

/*
 * A process that asked for protection is the case this hook exists for.
 * It is a set the operator opts into rather than every task on the machine,
 * so it refuses both modes, and it does so whether or not block_ptrace is on.
 */
static void test_a_protected_target_refuses_both_modes(void)
{
	TEST("a read of a protected task is refused");
	if (!DENIED(PTRACE_MODE_READ, LOTA_MODE_ENFORCE, 1, 0, 1))
		FAIL("expected: DENIED(PTRACE_MODE_READ, LOTA_MODE_ENFORCE, "
		     "1, 0, 1)");
	TEST("an attach on a protected task is refused");
	if (!DENIED(LOTA_PTRACE_MODE_ATTACH, LOTA_MODE_ENFORCE, 1, 0, 1))
		FAIL("expected: DENIED(LOTA_PTRACE_MODE_ATTACH, "
		     "LOTA_MODE_ENFORCE, 1, 0, 1)");
	TEST("a protected task is refused with block_ptrace off");
	if (!DENIED(PTRACE_MODE_READ, LOTA_MODE_ENFORCE, 0, 0, 1))
		FAIL("expected: DENIED(PTRACE_MODE_READ, LOTA_MODE_ENFORCE, "
		     "0, 0, 1)");
	TEST("a protected task is refused in monitor mode");
	if (!DENIED(PTRACE_MODE_READ, LOTA_MODE_MONITOR, 0, 0, 1))
		FAIL("expected: DENIED(PTRACE_MODE_READ, LOTA_MODE_MONITOR, "
		     "0, 0, 1)");
}

/* Monitor lifts policy, and isolation of a protected task is not policy */
static void test_monitor_keeps_the_protected_rule(void)
{
	TEST("monitor refuses a read of a protected task");
	if (!DENIED(PTRACE_MODE_READ, LOTA_MODE_MONITOR, 1, 0, 1))
		FAIL("expected: DENIED(PTRACE_MODE_READ, LOTA_MODE_MONITOR, "
		     "1, 0, 1)");
	TEST("monitor refuses an attach on a protected task");
	if (!DENIED(LOTA_PTRACE_MODE_ATTACH, LOTA_MODE_MONITOR, 0, 0, 1))
		FAIL("expected: DENIED(LOTA_PTRACE_MODE_ATTACH, "
		     "LOTA_MODE_MONITOR, 0, 0, 1)");
}

/* The agent is never a target, in any mode, whatever the key says */
static void test_the_agent_is_never_a_target(void)
{
	TEST("a read of the agent is refused with block_ptrace off");
	if (!DENIED(PTRACE_MODE_READ, LOTA_MODE_ENFORCE, 0, 1, 0))
		FAIL("expected: DENIED(PTRACE_MODE_READ, LOTA_MODE_ENFORCE, "
		     "0, 1, 0)");
	TEST("an attach on the agent is refused in monitor mode");
	if (!DENIED(LOTA_PTRACE_MODE_ATTACH, LOTA_MODE_MONITOR, 0, 1, 0))
		FAIL("expected: DENIED(LOTA_PTRACE_MODE_ATTACH, "
		     "LOTA_MODE_MONITOR, 0, 1, 0)");
	TEST("a read of the agent is refused in monitor mode");
	if (!DENIED(PTRACE_MODE_READ, LOTA_MODE_MONITOR, 0, 1, 0))
		FAIL("expected: DENIED(PTRACE_MODE_READ, LOTA_MODE_MONITOR, "
		     "0, 1, 0)");
}

/*
 * The agent's own exemption is the read half only: it measures a protected
 * process's live code through /proc, and it must not gain a debugger onto one.
 */
static void test_the_agent_read_exemption(void)
{
	TEST("the agent is exempt for a read");
	if (!lota_ptrace_agent_read_exempt(PTRACE_MODE_READ, 1))
		FAIL("expected: lota_ptrace_agent_read_exempt(PTRACE_MODE_READ, "
		     "1)");
	TEST("the agent is not exempt for an attach");
	if (lota_ptrace_agent_read_exempt(LOTA_PTRACE_MODE_ATTACH, 1))
		FAIL("expected: !lota_ptrace_agent_read_exempt(LOTA_PTRACE_MODE_ATTACH, "
		     "1)");
	TEST("a task that is not the agent gets no exemption");
	if (lota_ptrace_agent_read_exempt(PTRACE_MODE_READ, 0))
		FAIL("expected: !lota_ptrace_agent_read_exempt(PTRACE_MODE_READ, "
		     "0)");
}

static void test_attach_is_recognised_by_its_flag(void)
{
	TEST("the attach flag is an attach");
	if (!lota_ptrace_is_attach(LOTA_PTRACE_MODE_ATTACH))
		FAIL("expected: lota_ptrace_is_attach(LOTA_PTRACE_MODE_ATTACH)");
	TEST("the read flag is not an attach");
	if (lota_ptrace_is_attach(PTRACE_MODE_READ))
		FAIL("expected: !lota_ptrace_is_attach(PTRACE_MODE_READ)");
	TEST("an access carrying both flags is an attach");
	if (!lota_ptrace_is_attach(LOTA_PTRACE_MODE_ATTACH | PTRACE_MODE_READ))
		FAIL("expected: lota_ptrace_is_attach(LOTA_PTRACE_MODE_ATTACH "
		     "| PTRACE_MODE_READ)");
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
	TEST("a fork of a protected process is protected");
	if (!lota_clone_inherits_protection(0, 1))
		FAIL("expected: lota_clone_inherits_protection(0, 1)");
	TEST("a posix_spawn() child of a protected process is protected");
	if (!lota_clone_inherits_protection(SPAWN_FLAGS, 1))
		FAIL("expected: lota_clone_inherits_protection(SPAWN_FLAGS, 1)");
	TEST("a fork of an unprotected process is not protected");
	if (lota_clone_inherits_protection(0, 0))
		FAIL("expected: !lota_clone_inherits_protection(0, 0)");
	TEST("a spawn of an unprotected process is not protected");
	if (lota_clone_inherits_protection(SPAWN_FLAGS, 0))
		FAIL("expected: !lota_clone_inherits_protection(SPAWN_FLAGS, "
		     "0)");
}

/* A thread is covered through its leader and takes no mark of its own */
static void test_a_thread_takes_no_mark(void)
{
	TEST("a thread of a protected process takes no mark");
	if (lota_clone_inherits_protection(
		    THREAD_SHARE_FLAGS | LOTA_CLONE_THREAD, 1))
		FAIL("expected: !lota_clone_inherits_protection( "
		     "THREAD_SHARE_FLAGS | LOTA_CLONE_THREAD, 1)");
}

/*
 * A tracer attached before the protection would follow a protected process
 * into its children, so a process held from outside the set creates nothing
 */
static void test_a_tracer_from_outside_stops_creation(void)
{
	TEST("a protected process traced from outside creates nothing");
	if (!lota_clone_refused(1, 1, 0))
		FAIL("expected: lota_clone_refused(1, 1, 0)");
	TEST("a protected process traced from inside its instance creates");
	if (lota_clone_refused(1, 1, 1))
		FAIL("expected: !lota_clone_refused(1, 1, 1)");
	TEST("an untraced protected process creates");
	if (lota_clone_refused(1, 0, 0))
		FAIL("expected: !lota_clone_refused(1, 0, 0)");
	TEST("a traced unprotected process is not this rule's business");
	if (lota_clone_refused(0, 1, 0))
		FAIL("expected: !lota_clone_refused(0, 1, 0)");
}

static void test_access_inside_an_instance(void)
{
	TEST("two processes of one instance are inside it");
	if (!lota_inside_instance(1, 100, 5000, 1, 100, 5000))
		FAIL("expected: lota_inside_instance(1, 100, 5000, 1, 100, "
		     "5000)");
	TEST("another instance's process is outside");
	if (lota_inside_instance(1, 100, 5000, 1, 200, 5000))
		FAIL("expected: !lota_inside_instance(1, 100, 5000, 1, 200, "
		     "5000)");
	TEST("a recycled root tgid names another instance");
	if (lota_inside_instance(1, 100, 5000, 1, 100, 6000))
		FAIL("expected: !lota_inside_instance(1, 100, 5000, 1, 100, "
		     "6000)");
	TEST("an unprotected actor is outside every instance");
	if (lota_inside_instance(0, 100, 5000, 1, 100, 5000))
		FAIL("expected: !lota_inside_instance(0, 100, 5000, 1, 100, "
		     "5000)");
	TEST("an unprotected target is in no instance");
	if (lota_inside_instance(1, 100, 5000, 0, 100, 5000))
		FAIL("expected: !lota_inside_instance(1, 100, 5000, 0, 100, "
		     "5000)");
}

/* the hook passes a target inside the actor's instance as unprotected */
static void test_an_attach_inside_the_instance_is_allowed(void)
{
	int inside = lota_inside_instance(1, 100, 5000, 1, 100, 5000);

	TEST("an attach inside the instance is not refused");
	if (lota_ptrace_denied(LOTA_PTRACE_MODE_ATTACH, LOTA_MODE_MONITOR, 0, 0,
			       !inside))
		FAIL("expected: !lota_ptrace_denied(LOTA_PTRACE_MODE_ATTACH, "
		     "LOTA_MODE_MONITOR, 0, 0, !inside)");
	TEST("the agent stays refused to every instance");
	if (!lota_ptrace_denied(LOTA_PTRACE_MODE_ATTACH, LOTA_MODE_MONITOR, 0,
				1, !inside))
		FAIL("expected: lota_ptrace_denied(LOTA_PTRACE_MODE_ATTACH, "
		     "LOTA_MODE_MONITOR, 0, 1, !inside)");
}

#define PROC_NAME(s) (s), (unsigned int)(sizeof(s) - 1)

/* /proc entries a CAP_PERFMON reader would get past the ptrace verdict */
static void test_proc_entries_that_read_memory(void)
{
	TEST("maps reads memory");
	if (!lota_proc_entry_reads_mm(PROC_NAME("maps")))
		FAIL("expected: lota_proc_entry_reads_mm(PROC_NAME(\"maps\"))");
	TEST("smaps_rollup reads memory");
	if (!lota_proc_entry_reads_mm(PROC_NAME("smaps_rollup")))
		FAIL("expected: lota_proc_entry_reads_mm(PROC_NAME(\"smaps_rollup\"))");
	TEST("pagemap reads memory");
	if (!lota_proc_entry_reads_mm(PROC_NAME("pagemap")))
		FAIL("expected: lota_proc_entry_reads_mm(PROC_NAME(\"pagemap\"))");
	TEST("environ reads memory");
	if (!lota_proc_entry_reads_mm(PROC_NAME("environ")))
		FAIL("expected: lota_proc_entry_reads_mm(PROC_NAME(\"environ\"))");
	TEST("auxv reads memory");
	if (!lota_proc_entry_reads_mm(PROC_NAME("auxv")))
		FAIL("expected: lota_proc_entry_reads_mm(PROC_NAME(\"auxv\"))");
	TEST("map_files lists the mappings");
	if (!lota_proc_entry_reads_mm(PROC_NAME("map_files")))
		FAIL("expected: lota_proc_entry_reads_mm(PROC_NAME(\"map_files\"))");
	TEST("status only names the process");
	if (lota_proc_entry_reads_mm(PROC_NAME("status")))
		FAIL("expected: !lota_proc_entry_reads_mm(PROC_NAME(\"status\"))");
	TEST("cmdline stays readable for ps");
	if (lota_proc_entry_reads_mm(PROC_NAME("cmdline")))
		FAIL("expected: !lota_proc_entry_reads_mm(PROC_NAME(\"cmdline\"))");
	TEST("cgroup stays readable for systemd");
	if (lota_proc_entry_reads_mm(PROC_NAME("cgroup")))
		FAIL("expected: !lota_proc_entry_reads_mm(PROC_NAME(\"cgroup\"))");
	TEST("a longer name is another entry");
	if (lota_proc_entry_reads_mm("mapsx", 4 + 1))
		FAIL("expected: !lota_proc_entry_reads_mm(\"mapsx\", 4 + 1)");
	TEST("a prefix is another entry");
	if (lota_proc_entry_reads_mm("map", 3))
		FAIL("expected: !lota_proc_entry_reads_mm(\"map\", 3)");
}

int main(void)
{
	test_begin("ptrace policy");
	test_proc_entries_that_read_memory();
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

	return test_end();
}
