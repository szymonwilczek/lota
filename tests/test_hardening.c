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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static int tests_run;
static int tests_passed;

#define TEST(name)                                                             \
  do {                                                                         \
    tests_run++;                                                               \
    printf("  [%2d] %-55s ", tests_run, name);                                 \
  } while (0)

#define PASS()                                                                 \
  do {                                                                         \
    tests_passed++;                                                            \
    printf("PASS\n");                                                          \
  } while (0)

#define FAIL(msg)                                                              \
  do {                                                                         \
    printf("FAIL: %s\n", msg);                                                 \
  } while (0)

/*
 * hardening_parse_tracer_pid_buf lives in hardening.c without a public
 * prototype; tests link the symbol directly so the parser branches can
 * be exercised without spinning up a real ptracer.
 */
int hardening_parse_tracer_pid_buf(const char *buf, long *out_tracer);

static void test_tracer_pid_parser_accepts_zero(void) {
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

static void test_tracer_pid_parser_returns_pid_on_attach(void) {
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

static void test_tracer_pid_parser_rejects_garbage_suffix(void) {
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

static void test_tracer_pid_parser_rejects_missing_field(void) {
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

static void test_tracer_pid_parser_rejects_no_digits(void) {
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

static void test_tracer_pid_parser_rejects_overflow(void) {
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

static void test_tracer_pid_parser_finds_field_after_dense_prefix(void) {
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
    off += (size_t)snprintf(buf + off, sizeof(buf) - off,
                            "Cpus_allowed:\tffffffff,ffffffff,ffffffff\n");
  }
  off += (size_t)snprintf(buf + off, sizeof(buf) - off, "TracerPid:\t0\n");
  long tracer = 0xDEAD;
  int ret = hardening_parse_tracer_pid_buf(buf, &tracer);
  if (ret != 0 || tracer != 0) {
    FAIL("expected ret=0 tracer=0 across the dense prefix");
    return;
  }
  PASS();
}

/* run @body in a forked child, exit code 0 == success, non-zero == failure */
static int run_in_child(int (*body)(void)) {
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

static int child_refuse_if_traced_untraced(void) {
  return hardening_refuse_if_traced() == 0 ? 0 : 1;
}

static int child_no_new_privs_sets_flag(void) {
  if (hardening_apply_no_new_privs() != 0)
    return 1;

  int v = prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
  return v == 1 ? 0 : 1;
}

static int child_no_dumpable_sets_flag(void) {
  if (hardening_apply_no_dumpable() != 0)
    return 1;

  int v = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
  return v == 0 ? 0 : 1;
}

static int child_seccomp_blocks_mount(void) {
  if (hardening_apply_no_new_privs() != 0)
    return 1;
  if (hardening_apply_seccomp() != 0)
    return 1;

  errno = 0;
  long ret = syscall(SYS_mount, "none", "/tmp/lota_should_never_mount", "tmpfs",
                     0, "");
  if (ret == 0)
    return 1; /* mount must not succeed */
  if (errno != EPERM)
    return 1;

  return 0;
}

static int child_seccomp_blocks_ptrace_self(void) {
  if (hardening_apply_no_new_privs() != 0)
    return 1;
  if (hardening_apply_seccomp() != 0)
    return 1;

  errno = 0;
  long ret = syscall(SYS_ptrace, 0 /* PTRACE_TRACEME */, 0, 0, 0);
  if (ret == 0)
    return 1;
  if (errno != EPERM)
    return 1;

  return 0;
}

/*
 * Each must fail with EPERM after the seccomp filter is loaded. The probe
 * values are chosen so the syscall never makes a successful kernel-side effect
 * even if seccomp somehow let the call through.
 */
static int child_seccomp_blocks_new_denials(void) {
  if (hardening_apply_no_new_privs() != 0)
    return 1;
  if (hardening_apply_seccomp() != 0)
    return 1;

  struct {
    long nr;
    long arg0;
    long arg1;
  } probes[] = {
      /* SYS_io_uring_setup(entries=1, params=NULL) -> EFAULT without seccomp */
      {SYS_io_uring_setup, 1, 0},
      /* SYS_userfaultfd(flags=0) -> usually EPERM/EACCES from kernel,
       * but seccomp intercepts first. */
      {SYS_userfaultfd, 0, 0},
      /* SYS_pidfd_send_signal(pidfd=-1, sig=0, info=NULL, flags=0) ->
       * EBADF without seccomp; seccomp returns EPERM. */
      {SYS_pidfd_send_signal, -1, 0},
  /* SYS_modify_ldt(func=0, ptr=NULL, count=0) -> ENOSYS on
   * non-x86 builds where the syscall is absent, otherwise EINVAL
   * from the kernel. seccomp returns EPERM if installed. */
#ifdef SYS_modify_ldt
      {SYS_modify_ldt, 0, 0},
#endif
      /* SYS_personality(persona=0xFFFFFFFF) -> returns previous
       * persona on success; the call has a real side effect, so we
       * MUST see EPERM here. */
      {SYS_personality, (long)0xFFFFFFFF, 0},
  };

  for (size_t i = 0; i < sizeof(probes) / sizeof(probes[0]); i++) {
    errno = 0;
    long ret =
        syscall(probes[i].nr, probes[i].arg0, probes[i].arg1, 0, 0, 0, 0);
    if (ret >= 0 && probes[i].nr == SYS_personality) {
      /* personality() returns the previous mask on success; the only
       * acceptable outcome is an EPERM error. */
      return 1;
    }
    if (errno != EPERM)
      return 1;
  }
  return 0;
}

static int child_seccomp_allows_benign_syscalls(void) {
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

static int child_apply_all_succeeds(void) {
  return hardening_apply_all() == 0 ? 0 : 1;
}

/*
 * hardening_apply_basics must enable the prctl guards but leave the
 * seccomp blocklist uninstalled, so a diagnostic CLI mode invoked
 * after this step can still issue calls (e.g. mount, ptrace) the
 * daemon path would refuse.
 */
static int child_apply_basics_no_seccomp(void) {
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
      return 1; /* filter was installed -> basics did too much */
  }
  return 0;
}

/*
 * hardening_apply_daemon, run after basics, completes the lockdown:
 * seccomp is installed and mount() is refused with EPERM.
 */
static int child_apply_daemon_installs_seccomp(void) {
  if (hardening_apply_basics() != 0)
    return 1;
  if (hardening_apply_daemon() != 0)
    return 1;

  if (prctl(PR_GET_SECCOMP, 0, 0, 0, 0) != 2)
    return 1; /* expected SECCOMP_MODE_FILTER */

  errno = 0;
  long ret = syscall(SYS_mount, "none", "/tmp/lota_should_never_mount", "tmpfs",
                     0, "");
  if (ret == 0)
    return 1;
  if (errno != EPERM)
    return 1;
  return 0;
}

static void run_child_case(const char *name, int (*body)(void)) {
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

int main(void) {
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
  run_child_case("seccomp blocks mount() with EPERM",
                 child_seccomp_blocks_mount);
  run_child_case("seccomp blocks ptrace() with EPERM",
                 child_seccomp_blocks_ptrace_self);
  run_child_case(
      "seccomp blocks io_uring/userfaultfd/pidfd/modify_ldt/personality",
      child_seccomp_blocks_new_denials);
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
