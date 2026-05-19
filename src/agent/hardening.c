/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - Process self-hardening helpers
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include "hardening.h"
#include "journal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>

#include <seccomp.h>

int hardening_refuse_if_traced(void) {
  int fd = open("/proc/self/status", O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    return -errno;

  char buf[4096];
  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  int saved_errno = errno;
  close(fd);

  if (n < 0)
    return -saved_errno;
  if (n == 0)
    return -EIO;

  buf[n] = '\0';

  const char *p = strstr(buf, "TracerPid:");
  if (!p) {
    /* /proc/self/status without TracerPid is an unsupported kernel. */
    return -ENOTSUP;
  }
  p += sizeof("TracerPid:") - 1;
  while (*p == ' ' || *p == '\t')
    p++;

  /* parse a non-negative decimal up to the newline */
  long tracer = 0;
  while (*p >= '0' && *p <= '9') {
    tracer = tracer * 10 + (*p - '0');
    p++;
    if (tracer > 0x7fffffff)
      return -ERANGE;
  }

  if (tracer != 0) {
    lota_err("hardening: refusing to start under tracer pid %ld", tracer);
    return -EPERM;
  }
  return 0;
}

int hardening_apply_no_new_privs(void) {
  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
    return -errno;
  return 0;
}

int hardening_apply_no_dumpable(void) {
  if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0)
    return -errno;
  return 0;
}

/*
 * Syscalls the agent must never invoke. EPERM keeps the agent alive on
 * an accidental hit and matches the systemd unit's SystemCallErrorNumber
 * so observed behavior is consistent across launch paths.
 */
static const int hardening_denied_syscalls[] = {
    SCMP_SYS(ptrace),
    SCMP_SYS(process_vm_readv),
    SCMP_SYS(process_vm_writev),
    SCMP_SYS(kexec_load),
    SCMP_SYS(kexec_file_load),
    SCMP_SYS(init_module),
    SCMP_SYS(finit_module),
    SCMP_SYS(delete_module),
    SCMP_SYS(create_module),
    SCMP_SYS(query_module),
    SCMP_SYS(get_kernel_syms),
    SCMP_SYS(pivot_root),
    SCMP_SYS(swapon),
    SCMP_SYS(swapoff),
    SCMP_SYS(reboot),
    SCMP_SYS(mount),
    SCMP_SYS(umount2),
    SCMP_SYS(name_to_handle_at),
    SCMP_SYS(open_by_handle_at),
    SCMP_SYS(setns),
    SCMP_SYS(unshare),
};

int hardening_apply_seccomp(void) {
  scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
  if (!ctx)
    return -ENOMEM;

  int rc = 0;
  for (size_t i = 0; i < sizeof(hardening_denied_syscalls) / sizeof(int); i++) {
    int sc = hardening_denied_syscalls[i];
    if (sc < 0)
      continue; /* libseccomp returns __NR_SCMP_ERROR (negative) on unknown */

    rc = seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), sc, 0);
    if (rc < 0) {
      /*
       * EOPNOTSUPP/EDOM may indicate a syscall absent on this arch
       * (e.g. create_module on aarch64). Tolerate that to keep the
       * filter loadable; the underlying syscall is unreachable anyway.
       */
      if (rc == -EOPNOTSUPP || rc == -EDOM || rc == -EINVAL)
        continue;
      seccomp_release(ctx);
      return rc;
    }
  }

  rc = seccomp_load(ctx);
  seccomp_release(ctx);
  if (rc < 0)
    return rc;

  return 0;
}

int hardening_apply_all(void) {
  int ret;

  ret = hardening_refuse_if_traced();
  if (ret < 0)
    return ret;

  ret = hardening_apply_no_new_privs();
  if (ret < 0) {
    lota_err("hardening: PR_SET_NO_NEW_PRIVS failed: %s", strerror(-ret));
    return ret;
  }

  ret = hardening_apply_no_dumpable();
  if (ret < 0) {
    lota_err("hardening: PR_SET_DUMPABLE failed: %s", strerror(-ret));
    return ret;
  }

  ret = hardening_apply_seccomp();
  if (ret < 0) {
    lota_err("hardening: seccomp filter load failed: %s", strerror(-ret));
    return ret;
  }

  lota_info("hardening: applied no_new_privs, dumpable=0, seccomp blocklist");
  return 0;
}
