/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - process self-hardening
 *
 * The agent applies these itself, so they hold outside systemd too.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_AGENT_HARDENING_H
#define LOTA_AGENT_HARDENING_H

#include <stdbool.h>
#include <sys/types.h>

/**
 * hardening_read_tracer_pid() - Read the TracerPid of a process.
 * @pid: The process; 0 or below for the caller.
 * @out_tracer: The tracer's pid on -EPERM, else 0.
 *
 * Return: as hardening_parse_tracer_pid_buf() on /proc/<pid>/status,
 * -EIO for an empty file, or a negative errno from reading it: -ENOENT when
 * the process is gone before the open, -ESRCH when it goes before the read.
 */
int hardening_read_tracer_pid(pid_t pid, long *out_tracer);

/**
 * hardening_refuse_if_traced() - Refuse to start under a tracer.
 *
 * Logs the tracer it finds. After hardening_apply_basics() the process is not
 * dumpable, so a tracer without CAP_SYS_PTRACE cannot attach after the check.
 *
 * Return: as hardening_read_tracer_pid() for the caller.
 */
int hardening_refuse_if_traced(void);

/**
 * hardening_apply_no_new_privs() - Set PR_SET_NO_NEW_PRIVS.
 *
 * Return: 0 or a negative errno.
 */
int hardening_apply_no_new_privs(void);

/**
 * hardening_apply_no_dumpable() - Set PR_SET_DUMPABLE to 0.
 *
 * Return: 0 or a negative errno.
 */
int hardening_apply_no_dumpable(void);

/**
 * hardening_apply_seccomp() - Load the syscall blocklist.
 *
 * A syscall in hardening_denied_syscalls kills the process with SIGSYS; every
 * other one passes. SCMP_FLTATR_CTL_TSYNC binds the filter to the threads
 * already running; a build of libseccomp without it fails the call.
 *
 * Return: 0, or a negative errno when the filter cannot be built or loaded.
 */
int hardening_apply_seccomp(void);

/**
 * hardening_apply_basics() - Set PR_SET_NO_NEW_PRIVS and PR_SET_DUMPABLE=0.
 *
 * Return: 0, or the negative errno of the first step that fails.
 */
int hardening_apply_basics(void);

/**
 * hardening_apply_daemon() - Refuse a tracer, then load the blocklist.
 *
 * Called by run_daemon(), do_attest() and continuous_attest_run();
 * other commands start under a tracer.
 *
 * Return: 0, or the negative errno of the first step that fails.
 */
int hardening_apply_daemon(void);

/**
 * hardening_parse_tracer_pid_buf() - Parse the TracerPid line of a status text.
 * @buf: NUL-terminated /proc/<pid>/status text.
 * @out_tracer: The tracer's pid on -EPERM, else 0.
 *
 * Return: 0 for TracerPid 0, -EPERM for another pid, -ENOTSUP without the
 * field at the start of a line, -EINVAL for a NULL argument or a value other
 * than digits up to a newline or the end, -ERANGE above INT32_MAX.
 */
int hardening_parse_tracer_pid_buf(const char *buf, long *out_tracer);

#endif /* LOTA_AGENT_HARDENING_H */
