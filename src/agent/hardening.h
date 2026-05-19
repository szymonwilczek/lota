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
 * Returns: 0 if not traced, -EPERM if traced, negative errno on I/O error.
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
 *   swapon, swapoff, reboot, mount, umount, umount2,
 *   name_to_handle_at, open_by_handle_at, setns, unshare.
 *
 * Requires PR_SET_NO_NEW_PRIVS to be set beforehand.
 *
 * Returns: 0 on success, negative errno on filter build/load failure.
 */
int hardening_apply_seccomp(void);

/*
 * hardening_apply_all - Convenience wrapper invoking the helpers above
 *
 * Order is significant: tracer-pid -> NO_NEW_PRIVS -> NOT-dumpable ->
 * seccomp. The first hard failure short-circuits with its errno; the
 * caller is expected to abort startup on a non-zero return so the agent
 * never runs in a half-hardened state.
 *
 * Returns: 0 on success, negative errno on the first failing step.
 */
int hardening_apply_all(void);

#endif /* LOTA_AGENT_HARDENING_H */
