/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - Process self-hardening helpers
 *
 * Apply prctl / seccomp / tracer-detection guards from inside the agent binary.
 * Required because the agent may be launched outside systemd (recovery shells,
 * sysadmin dry-runs, integration tests) and must still refuse to expose secrets
 * to root-attached debuggers or to issue privileged syscalls it never
 * legitimately needs.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_AGENT_HARDENING_H
#define LOTA_AGENT_HARDENING_H

#include <stdbool.h>

/*
 * hardening_refuse_if_traced - Refuse to start under a debugger
 *
 * Reads /proc/self/status and inspects the TracerPid field. Any non-zero
 * tracer indicates an attached ptracer (gdb, strace, frida-server, ...).
 *
 * Ordering note: hardening_apply_basics() drops PR_SET_DUMPABLE to 0
 * before this function runs (see hardening_apply_all() and
 * hardening_apply_daemon()). PR_SET_DUMPABLE=0 makes the process
 * non-attachable via PTRACE_ATTACH for any process without
 * CAP_SYS_PTRACE, which closes the TOCTOU window between reading
 * TracerPid and finishing startup: an unprivileged attacker cannot
 * attach in that interval because the kernel-side dumpable check
 * fires first.
 *
 * Returns: 0 if not traced, -EPERM if traced, -EINVAL on a malformed
 * TracerPid line, -ENOTSUP on a kernel that omits the field, -ERANGE
 * on a tracer pid that overflows int32, negative errno on I/O error.
 */
int hardening_refuse_if_traced(void);

/*
 * hardening_apply_no_new_privs - prctl(PR_SET_NO_NEW_PRIVS, 1)
 *
 * Once set, execve() cannot grant additional privileges (no setuid/sgid,
 * no file capabilities, no LSM transitions that elevate). Required before
 * installing a seccomp BPF filter that uses SECCOMP_RET_ERRNO.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int hardening_apply_no_new_privs(void);

/*
 * hardening_apply_no_dumpable - prctl(PR_SET_DUMPABLE, 0)
 *
 * Disables core dumps and forces /proc/self/{mem,maps,environ} to root
 * ownership while preventing read access by other users. Defeats memory
 * harvesting via /proc when the agent crashes or when an unprivileged
 * subshell inherits the same UID.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int hardening_apply_no_dumpable(void);

/*
 * hardening_apply_seccomp - Install in-process seccomp BPF blocklist
 *
 * Default policy: SCMP_ACT_ALLOW. The agent denies (with -EPERM) every
 * syscall that has no legitimate use in attestation or BPF management:
 *
 *   ptrace, process_vm_readv, process_vm_writev, kexec_load,
 *   kexec_file_load, init_module, finit_module, delete_module,
 *   create_module, query_module, get_kernel_syms, pivot_root,
 *   swapon, swapoff, reboot, mount, umount2, name_to_handle_at,
 *   open_by_handle_at, setns, unshare, io_uring_setup,
 *   io_uring_enter, io_uring_register, userfaultfd,
 *   pidfd_send_signal, modify_ldt, personality.
 *
 * Requires PR_SET_NO_NEW_PRIVS to be set beforehand.
 *
 * Returns: 0 on success, negative errno on filter build/load failure.
 */
int hardening_apply_seccomp(void);

/*
 * hardening_apply_basics - Pre-CLI defenses safe under any launch path
 *
 * Applies PR_SET_NO_NEW_PRIVS and PR_SET_DUMPABLE=0. Neither call blocks
 * a sysadmin running ./lota-agent --shutdown or --test-tpm under strace,
 * so the binary remains diagnosable in recovery shells while still
 * refusing to expose secrets via /proc/<pid>/{mem,maps,environ} or to
 * gain privileges through an unexpected execve.
 *
 * Must be invoked unconditionally at process start (before getopt and
 * before any TPM/IPC/BPF interaction).
 *
 * Returns: 0 on success, negative errno on the first failing step.
 */
int hardening_apply_basics(void);

/*
 * hardening_apply_daemon - Daemon-mode defenses (tracer refusal + seccomp)
 *
 * Refuses startup under a ptracer and installs the seccomp blocklist
 * documented on hardening_apply_seccomp(). Invoked only by long-running
 * entry points (run_daemon, do_continuous_attest, do_attest); diagnostic
 * one-shots (--shutdown, --test-tpm, --export-policy, --gen-signing-key,
 * --sign-policy, --verify-policy) skip this step so an admin debugging a
 * misconfiguration with strace/gdb is not blocked by -EPERM.
 *
 * Requires hardening_apply_basics() to have completed first (seccomp
 * needs PR_SET_NO_NEW_PRIVS).
 *
 * Returns: 0 on success, negative errno on the first failing step.
 */
int hardening_apply_daemon(void);

/*
 * hardening_apply_all - Convenience wrapper invoking the helpers above
 *
 * Equivalent to hardening_apply_basics() followed by
 * hardening_apply_daemon(). Retained for test harnesses that exercise
 * the full sequence in a single forked child.
 *
 * Returns: 0 on success, negative errno on the first failing step.
 */
int hardening_apply_all(void);

#endif /* LOTA_AGENT_HARDENING_H */
