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
