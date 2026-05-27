/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for src/agent/hardening.c
 *
 * Runs in a forked child for every coverage scenario so the parent test
 * driver keeps an unrestricted process state (seccomp is one-way, prctl
 * dumpable/no-new-privs are inherited across fork but not erased).
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include "../src/agent/hardening.h"

#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static int tests_run;
static int tests_passed;

#define TEST(name)                                                             \
	do {                                                                   \
		tests_run++;                                                   \
		printf("  [%2d] %-55s ", tests_run, name);                     \
	} while (0)

#define PASS()                                                                 \
	do {                                                                   \
		tests_passed++;                                                \
		printf("PASS\n");                                              \
	} while (0)

#define FAIL(msg)                                                              \
	do {                                                                   \
		printf("FAIL: %s\n", msg);                                     \
	} while (0)

/*
 * hardening_parse_tracer_pid_buf lives in hardening.c without a public
 * prototype; tests link the symbol directly so the parser branches can
 * be exercised without spinning up a real ptracer.
 */
int hardening_parse_tracer_pid_buf(const char *buf, long *out_tracer);

static void test_tracer_pid_parser_accepts_zero(void)
{
	TEST("parse_tracer_pid: well-formed status with TracerPid: 0");
	static const char buf[] = "Name:\tlota-agent\n"
				  "Umask:\t0022\n"
				  "State:\tR (running)\n"
				  "Tgid:\t12345\n"
				  "TracerPid:\t0\n"
				  "Uid:\t0\t0\t0\t0\n";
	long tracer = 0xDEAD;
	int ret = hardening_parse_tracer_pid_buf(buf, &tracer);
	if (ret != 0 || tracer != 0) {
		FAIL("expected ret=0 tracer=0");
		return;
	}
	PASS();
}

static void test_tracer_pid_parser_returns_pid_on_attach(void)
{
	TEST("parse_tracer_pid: non-zero pid -> -EPERM with the pid");
	static const char buf[] = "Name:\tagent\n"
				  "TracerPid:\t98765\n";
	long tracer = 0;
	int ret = hardening_parse_tracer_pid_buf(buf, &tracer);
	if (ret != -EPERM) {
		FAIL("expected -EPERM");
		return;
	}
	if (tracer != 98765) {
		FAIL("expected tracer=98765");
		return;
	}
	PASS();
}

static void test_tracer_pid_parser_rejects_garbage_suffix(void)
{
	TEST("parse_tracer_pid: '0XYZ' must NOT silently parse as 0");
	static const char buf[] = "Name:\tagent\n"
				  "TracerPid:\t0XYZ\n";
	long tracer = 0;
	int ret = hardening_parse_tracer_pid_buf(buf, &tracer);
	if (ret != -EINVAL) {
		char msg[64];
		snprintf(msg, sizeof(msg), "expected -EINVAL, got %d", ret);
		FAIL(msg);
		return;
	}
	PASS();
}

static void test_tracer_pid_parser_rejects_missing_field(void)
{
	TEST("parse_tracer_pid: kernel without TracerPid: -> -ENOTSUP");
	static const char buf[] = "Name:\tagent\n"
				  "Umask:\t0022\n"
				  "State:\tR\n";
	long tracer = 0;
	int ret = hardening_parse_tracer_pid_buf(buf, &tracer);
	if (ret != -ENOTSUP) {
		FAIL("expected -ENOTSUP");
		return;
	}
	PASS();
}

static void test_tracer_pid_parser_rejects_no_digits(void)
{
	TEST("parse_tracer_pid: 'TracerPid:\\t\\n' (no digits) -> -EINVAL");
	static const char buf[] = "Name:\tagent\n"
				  "TracerPid:\t\n";
	long tracer = 0;
	int ret = hardening_parse_tracer_pid_buf(buf, &tracer);
	if (ret != -EINVAL) {
		FAIL("expected -EINVAL");
		return;
	}
	PASS();
}

static void test_tracer_pid_parser_rejects_overflow(void)
{
	TEST("parse_tracer_pid: pid above INT32_MAX -> -ERANGE");
	static const char buf[] = "Name:\tagent\n"
				  "TracerPid:\t9999999999\n";
	long tracer = 0;
	int ret = hardening_parse_tracer_pid_buf(buf, &tracer);
	if (ret != -ERANGE) {
		FAIL("expected -ERANGE");
		return;
	}
	PASS();
}

static void test_tracer_pid_parser_finds_field_after_dense_prefix(void)
{
	TEST("parse_tracer_pid: long prefix before TracerPid: still parses");
	/*
	 * Synthesise a dense /proc/self/status-like prefix to verify the
	 * parser does not depend on TracerPid: landing in the first 200
	 * bytes. The prefix mirrors what a host with many supplementary
	 * groups + dense Cpus_allowed bitmap would emit.
	 */
	char buf[16 * 1024];
	size_t off = 0;
	off += (size_t)snprintf(buf + off, sizeof(buf) - off, "Name:\tagent\n");
	while (off < sizeof(buf) - 256) {
		off += (size_t)snprintf(
		    buf + off, sizeof(buf) - off,
		    "Cpus_allowed:\tffffffff,ffffffff,ffffffff\n");
	}
	off +=
	    (size_t)snprintf(buf + off, sizeof(buf) - off, "TracerPid:\t0\n");
	long tracer = 0xDEAD;
	int ret = hardening_parse_tracer_pid_buf(buf, &tracer);
	if (ret != 0 || tracer != 0) {
		FAIL("expected ret=0 tracer=0 across the dense prefix");
		return;
	}
	PASS();
}

/* run @body in a forked child, exit code 0 == success, non-zero == failure */
static int run_in_child(int (*body)(void))
{
	pid_t pid = fork();
	if (pid < 0)
		return -errno;

	if (pid == 0) {
		int rc = body();
		_exit(rc == 0 ? 0 : 1);
	}

	int status = 0;
	if (waitpid(pid, &status, 0) < 0)
		return -errno;

	if (!WIFEXITED(status))
		return -EIO;

	return WEXITSTATUS(status);
}

static int child_refuse_if_traced_untraced(void)
{
	return hardening_refuse_if_traced() == 0 ? 0 : 1;
}

static int child_no_new_privs_sets_flag(void)
{
	if (hardening_apply_no_new_privs() != 0)
		return 1;

	int v = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
	return v == 1 ? 0 : 1;
}

static int child_no_dumpable_sets_flag(void)
{
	if (hardening_apply_no_dumpable() != 0)
		return 1;

	int v = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
	return v == 0 ? 0 : 1;
}

/*
 * Each denied-syscall child runs in its own fork because
 * SCMP_ACT_KILL_PROCESS terminates the calling process; a single
 * fork that probed multiple denied syscalls in sequence would only
 * exercise the first. The body installs no_new_privs + seccomp,
 * issues exactly one denied syscall, and never returns: a parent
 * observing WIFEXITED means the kernel let the syscall through
 * (test failure), WIFSIGNALED with WTERMSIG == SIGSYS means the
 * filter killed as designed.
 */
static int child_seccomp_kills_on_mount(void)
{
	if (hardening_apply_no_new_privs() != 0)
		return 1;
	if (hardening_apply_seccomp() != 0)
		return 1;
	syscall(SYS_mount, "none", "/tmp/lota_should_never_mount", "tmpfs", 0,
		"");
	return 0; /* unreachable when SCMP_ACT_KILL_PROCESS fires */
}

static int child_seccomp_kills_on_ptrace_self(void)
{
	if (hardening_apply_no_new_privs() != 0)
		return 1;
	if (hardening_apply_seccomp() != 0)
		return 1;
	syscall(SYS_ptrace, 0 /* PTRACE_TRACEME */, 0, 0, 0);
	return 0;
}

static int child_seccomp_kills_on_io_uring_setup(void)
{
	if (hardening_apply_no_new_privs() != 0)
		return 1;
	if (hardening_apply_seccomp() != 0)
		return 1;
	syscall(SYS_io_uring_setup, 1, 0);
	return 0;
}

static int child_seccomp_kills_on_userfaultfd(void)
{
	if (hardening_apply_no_new_privs() != 0)
		return 1;
	if (hardening_apply_seccomp() != 0)
		return 1;
	syscall(SYS_userfaultfd, 0);
	return 0;
}

static int child_seccomp_kills_on_pidfd_send_signal(void)
{
	if (hardening_apply_no_new_privs() != 0)
		return 1;
	if (hardening_apply_seccomp() != 0)
		return 1;
	syscall(SYS_pidfd_send_signal, -1, 0, 0, 0);
	return 0;
}

#ifdef SYS_modify_ldt
static int child_seccomp_kills_on_modify_ldt(void)
{
	if (hardening_apply_no_new_privs() != 0)
		return 1;
	if (hardening_apply_seccomp() != 0)
		return 1;
	syscall(SYS_modify_ldt, 0, 0, 0);
	return 0;
}
#endif

/*
 * TSYNC propagation: after hardening_apply_seccomp() installs the
 * filter with SCMP_FLTATR_CTL_TSYNC enabled, a thread spawned later
 * inherits the filter. Issuing a denied syscall from that thread
 * therefore must terminate the whole process via SIGSYS; without
 * TSYNC the thread would start unfiltered and the call would return
 * to userspace, the thread exit, and the parent observe WIFEXITED.
 */
static void *tsync_thread_denied_syscall(void *arg)
{
	(void)arg;
	syscall(SYS_mount, "none", "/tmp/lota_tsync_should_never_mount",
		"tmpfs", 0, "");
	return NULL;
}

static int child_seccomp_tsync_kills_spawned_thread(void)
{
	if (hardening_apply_basics() != 0)
		return 1;
	if (hardening_apply_daemon() != 0)
		return 1;

	pthread_t t;
	if (pthread_create(&t, NULL, tsync_thread_denied_syscall, NULL) != 0)
		return 1;
	pthread_join(t, NULL);
	return 0; /* unreachable: SCMP_ACT_KILL_PROCESS terminates the group */
}

static int child_seccomp_kills_on_personality(void)
{
	if (hardening_apply_no_new_privs() != 0)
		return 1;
	if (hardening_apply_seccomp() != 0)
		return 1;
	syscall(SYS_personality, (long)0xFFFFFFFF);
	return 0;
}

static int child_seccomp_allows_benign_syscalls(void)
{
	if (hardening_apply_no_new_privs() != 0)
		return 1;
	if (hardening_apply_seccomp() != 0)
		return 1;

	/* getpid + write should remain allowed by the blocklist policy */
	pid_t p = getpid();
	if (p <= 0)
		return 1;

	const char msg[] = "ok\n";
	ssize_t n = write(STDOUT_FILENO, msg, sizeof(msg) - 1);
	if (n != (ssize_t)(sizeof(msg) - 1))
		return 1;

	return 0;
}

static int child_apply_all_succeeds(void)
{
	return hardening_apply_all() == 0 ? 0 : 1;
}

/*
 * hardening_apply_basics must enable the prctl guards but leave the
 * seccomp blocklist uninstalled, so a diagnostic CLI mode invoked
 * after this step can still issue calls (e.g. mount, ptrace) the
 * daemon path would refuse.
 */
static int child_apply_basics_no_seccomp(void)
{
	if (hardening_apply_basics() != 0)
		return 1;
	if (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1)
		return 1;
	if (prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) != 0)
		return 1;

	/*
	 * Seccomp blocklist must still be absent. Calling mount() requires
	 * CAP_SYS_ADMIN, which the test process generally lacks: a
	 * non-EPERM errno (typically EPERM from the capability check
	 * itself, ENOENT for the target, EACCES from the source) tells
	 * us the syscall reached the kernel rather than being filtered
	 * back at SCMP_ACT_ERRNO. The actual signal we need is "errno
	 * is not EPERM caused by seccomp"; we detect that by issuing a
	 * call that fails with EFAULT when the kernel reads the source
	 * path. seccomp would have returned EPERM before the kernel
	 * dereferenced any argument.
	 */
	errno = 0;
	long ret = syscall(SYS_mount, (void *)0x1, (void *)0x1, (void *)0x1,
			   (unsigned long)0, (void *)0x1);
	if (ret == 0)
		return 1; /* mount must never succeed in the test process */
	if (errno == EPERM) {
		/*
		 * EPERM could be either the capability check or seccomp. To
		 * disambiguate, call prctl(PR_GET_SECCOMP) which returns 2
		 * (SECCOMP_MODE_FILTER) only when a filter is installed.
		 */
		int mode = prctl(PR_GET_SECCOMP, 0, 0, 0, 0);
		if (mode == 2)
			return 1; /* filter was installed -> basics did too much
				   */
	}
	return 0;
}

/*
 * hardening_apply_daemon, run after basics, completes the lockdown:
 * seccomp is installed (PR_GET_SECCOMP returns SECCOMP_MODE_FILTER).
 * The kill-case tests above prove the filter actually fires on a
 * denied syscall; this body is non-fatal because issuing a denied
 * syscall here would terminate the child via SIGSYS and the
 * run_child_case driver only inspects WIFEXITED status.
 */
static int child_apply_daemon_installs_seccomp(void)
{
	if (hardening_apply_basics() != 0)
		return 1;
	if (hardening_apply_daemon() != 0)
		return 1;
	if (prctl(PR_GET_SECCOMP, 0, 0, 0, 0) != 2)
		return 1; /* expected SECCOMP_MODE_FILTER */
	return 0;
}

static void run_child_case(const char *name, int (*body)(void))
{
	TEST(name);

	int rc = run_in_child(body);
	if (rc != 0) {
		char buf[64];
		snprintf(buf, sizeof(buf), "child exit=%d", rc);
		FAIL(buf);
		return;
	}
	PASS();
}

/*
 * run_kill_case forks, runs body (which is expected to never
 * return because SCMP_ACT_KILL_PROCESS fires), and asserts the
 * child terminated via SIGSYS. A normal exit means seccomp let
 * the denied syscall through, which is a test failure.
 */
static void run_kill_case(const char *name, int (*body)(void))
{
	TEST(name);

	pid_t pid = fork();
	if (pid < 0) {
		FAIL("fork");
		return;
	}
	if (pid == 0) {
		body();
		_exit(
		    77); /* sentinel: reached only when seccomp did NOT kill */
	}

	int status = 0;
	if (waitpid(pid, &status, 0) < 0) {
		FAIL("waitpid");
		return;
	}
	if (WIFSIGNALED(status) && WTERMSIG(status) == SIGSYS) {
		PASS();
		return;
	}
	if (WIFEXITED(status)) {
		char buf[80];
		snprintf(
		    buf, sizeof(buf),
		    "seccomp did NOT kill on denied syscall (child exit=%d)",
		    WEXITSTATUS(status));
		FAIL(buf);
		return;
	}
	FAIL("unexpected child termination");
}

int main(void)
{
	printf("\n=== Hardening Tests ===\n\n");

	test_tracer_pid_parser_accepts_zero();
	test_tracer_pid_parser_rejects_garbage_suffix();
	test_tracer_pid_parser_rejects_missing_field();
	test_tracer_pid_parser_returns_pid_on_attach();
	test_tracer_pid_parser_rejects_no_digits();
	test_tracer_pid_parser_rejects_overflow();
	test_tracer_pid_parser_finds_field_after_dense_prefix();

	run_child_case("refuse_if_traced: clean process returns 0",
		       child_refuse_if_traced_untraced);
	run_child_case("apply_no_new_privs: PR_GET_NO_NEW_PRIVS == 1",
		       child_no_new_privs_sets_flag);
	run_child_case("apply_no_dumpable: PR_GET_DUMPABLE == 0",
		       child_no_dumpable_sets_flag);
	run_kill_case("seccomp kills on mount() with SIGSYS",
		      child_seccomp_kills_on_mount);
	run_kill_case("seccomp kills on ptrace() with SIGSYS",
		      child_seccomp_kills_on_ptrace_self);
	run_kill_case("seccomp kills on io_uring_setup with SIGSYS",
		      child_seccomp_kills_on_io_uring_setup);
	run_kill_case("seccomp kills on userfaultfd with SIGSYS",
		      child_seccomp_kills_on_userfaultfd);
	run_kill_case("seccomp kills on pidfd_send_signal with SIGSYS",
		      child_seccomp_kills_on_pidfd_send_signal);
#ifdef SYS_modify_ldt
	run_kill_case("seccomp kills on modify_ldt with SIGSYS",
		      child_seccomp_kills_on_modify_ldt);
#endif
	run_kill_case("seccomp kills on personality with SIGSYS",
		      child_seccomp_kills_on_personality);
	run_kill_case("seccomp TSYNC kills denied syscall in spawned thread",
		      child_seccomp_tsync_kills_spawned_thread);
	run_child_case("seccomp keeps getpid/write available",
		       child_seccomp_allows_benign_syscalls);
	run_child_case("apply_all returns 0 in a clean child",
		       child_apply_all_succeeds);
	run_child_case("apply_basics: prctl guards set, seccomp filter absent",
		       child_apply_basics_no_seccomp);
	run_child_case("apply_daemon after basics installs seccomp filter",
		       child_apply_daemon_installs_seccomp);

	printf("\n  Result: %d/%d passed\n\n", tests_passed, tests_run);
	return (tests_passed == tests_run) ? 0 : 1;
}
