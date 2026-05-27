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

/*
 * hardening_parse_tracer_pid - inspect a /proc/<pid>/status payload
 *                              for the TracerPid: field
 * @buf: NUL-terminated copy of the /proc payload (the function does
 *       not read past the first NUL; truncation past the TracerPid
 *       line is therefore safe).
 * @out_tracer: caller-owned output; on -EPERM holds the offending
 *              pid, otherwise zero.
 *
 * Returns:
 *    0       - field present, tracer is pid 0 (not traced);
 *   -EPERM   - field present, tracer is a non-zero pid;
 *   -ENOTSUP - field absent (procfs without TracerPid);
 *   -EINVAL  - field present but malformed (no digits, trailing
 *              garbage such as "0XYZ", ...);
 *   -ERANGE  - tracer pid exceeds INT32_MAX.
 *
 * Exposed via hardening.c rather than hardening.h so the surface
 * stays internal; tests link it through LOTA_HARDENING_TESTING.
 */
int hardening_parse_tracer_pid_buf(const char *buf, long *out_tracer)
{
	if (!buf || !out_tracer)
		return -EINVAL;
	*out_tracer = 0;

	/*
	 * Match "TracerPid:" at the start of a line. /proc emits the field
	 * once with a leading newline (or as the first line in pathological
	 * cases); searching for the "\n" prefix prevents a future field
	 * whose value happens to contain "TracerPid:" from being mistaken
	 * for the real one.
	 */
	const char *p = (buf[0] == 'T' && strncmp(buf, "TracerPid:", 10) == 0)
			    ? buf
			    : strstr(buf, "\nTracerPid:");
	if (!p)
		return -ENOTSUP;
	if (*p == '\n')
		p++;
	p += sizeof("TracerPid:") - 1;
	while (*p == ' ' || *p == '\t')
		p++;

	/*
	 * Parse a non-negative decimal up to the newline. Two contracts:
	 *   - at least one digit must be present;
	 *   - the digit run must be terminated by '\n' (or by the end of
	 *     the buffer when /proc truncated the trailing newline). Any
	 *     other trailing character means the value is malformed -
	 *     e.g. "0XYZ" - and must NOT be silently coerced to
	 *     tracer == 0 the way the original parser did.
	 */
	long tracer = 0;
	const char *digit_start = p;
	while (*p >= '0' && *p <= '9') {
		tracer = tracer * 10 + (*p - '0');
		if (tracer > 0x7fffffff)
			return -ERANGE;
		p++;
	}
	if (p == digit_start)
		return -EINVAL;
	if (*p != '\n' && *p != '\0')
		return -EINVAL;

	*out_tracer = tracer;
	return tracer == 0 ? 0 : -EPERM;
}

int hardening_refuse_if_traced(void)
{
	int fd = open("/proc/self/status", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;

	/*
	 * /proc/<pid>/status can exceed 4 KiB on hosts with dense cgroup
	 * namespaces, many supplementary groups, or large Cpus_allowed_list
	 * / Mems_allowed_list bitmaps. TracerPid: lands in the first ~200
	 * bytes in practice but the parser must not rely on that, so the
	 * read is done in a loop that drains the file up to a generous
	 * 32 KiB cap. The cap exists only to bound resident memory; a
	 * status file larger than that on a non-malicious kernel is
	 * unheard of, and partial truncation past the TracerPid: line
	 * cannot hide a tracer because that field appears near the top.
	 */
	char buf[32 * 1024];
	size_t off = 0;
	while (off < sizeof(buf) - 1) {
		ssize_t n = read(fd, buf + off, sizeof(buf) - 1 - off);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			int err = -errno;
			close(fd);
			return err;
		}
		if (n == 0)
			break;
		off += (size_t)n;
	}
	close(fd);

	if (off == 0)
		return -EIO;
	buf[off] = '\0';

	long tracer = 0;
	int ret = hardening_parse_tracer_pid_buf(buf, &tracer);
	if (ret == -EPERM)
		lota_err("hardening: refusing to start under tracer pid %ld",
			 tracer);
	return ret;
}

int hardening_apply_no_new_privs(void)
{
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
		return -errno;
	return 0;
}

int hardening_apply_no_dumpable(void)
{
	if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0)
		return -errno;
	return 0;
}

/*
 * Syscalls the agent must never invoke. The filter answers any hit
 * with SECCOMP_RET_KILL_PROCESS (SIGSYS, no handler runs, no rollback):
 * a denied syscall reaching this point means either (a) an agent
 * regression that started calling something it has no business in,
 * (b) attacker-induced state mid-process, or (c) a dependency
 * stepping outside its documented surface. In none of those cases is
 * "return EPERM and keep going" a safe outcome - the in-process
 * filter is the fail-deep layer, distinct from the systemd unit's
 * SystemCallErrorNumber=EPERM which exists only to catch
 * non-daemon paths. systemd restarts the agent and the journal
 * carries the SIGSYS+si_code=SYS_SECCOMP audit line so the
 * responder can attribute the kill to the responsible syscall.
 *
 * Coverage rationale:
 *   - ptrace, process_vm_readv/writev: cross-process memory inspection.
 *   - kexec_load/file_load, init_module/finit/delete/create_module,
 *     query_module, get_kernel_syms: kernel-image and module surface.
 *   - pivot_root, mount, umount2, name_to_handle_at, open_by_handle_at,
 *     setns, unshare: namespace and filesystem-handle manipulation.
 *   - swapon/swapoff, reboot: system-wide state changes.
 *   - io_uring_setup, io_uring_enter, io_uring_register: ring-based
 *     async I/O is unused by the agent and is the entry point for
 *     several historical sandbox escapes (CVE-2022-2602 and follow-ons).
 *   - userfaultfd: classic UAF / heap-spray primitive (CVE-2016-3070
 *     class). The agent does not register a userfault region.
 *   - pidfd_send_signal: delivers signals without kill()/permission
 *     checks via process file descriptors; the agent only signals
 *     itself via signalfd.
 *   - modify_ldt: x86 LDT manipulation, recurring local-priv vector.
 *   - personality: ABI-switching primitive abused to weaken ASLR
 *     (READ_IMPLIES_EXEC) on x86.
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
    SCMP_SYS(io_uring_setup),
    SCMP_SYS(io_uring_enter),
    SCMP_SYS(io_uring_register),
    SCMP_SYS(userfaultfd),
    SCMP_SYS(pidfd_send_signal),
    SCMP_SYS(modify_ldt),
    SCMP_SYS(personality),
};

int hardening_apply_seccomp(void)
{
	scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
	if (!ctx)
		return -ENOMEM;

	int rc = 0;
	for (size_t i = 0; i < sizeof(hardening_denied_syscalls) / sizeof(int);
	     i++) {
		int sc = hardening_denied_syscalls[i];
		if (sc < 0)
			continue; /* libseccomp returns __NR_SCMP_ERROR
				     (negative) on unknown */

		rc = seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, sc, 0);
		if (rc < 0) {
			/*
			 * EOPNOTSUPP/EDOM may indicate a syscall absent on this
			 * arch (e.g. create_module on aarch64). Tolerate that
			 * to keep the filter loadable; the underlying syscall
			 * is unreachable anyway.
			 */
			if (rc == -EOPNOTSUPP || rc == -EDOM || rc == -EINVAL)
				continue;
			seccomp_release(ctx);
			return rc;
		}
	}

	/*
	 * SCMP_FLTATR_CTL_TSYNC installs the filter on every thread of the
	 * caller's thread group (SECCOMP_FILTER_FLAG_TSYNC at the syscall
	 * level). The agent is single-threaded today but several near-term
	 * paths (libtss2 ESYS background worker, libbpf ring-buffer reader,
	 * future epoll worker pool) may legitimately spawn threads after
	 * this point. Without TSYNC any such thread starts unfiltered,
	 * silently reopening the deny-list. Failing the load when TSYNC
	 * cannot be enforced is the correct production behaviour: a
	 * libseccomp build that lacks TSYNC support is not a configuration
	 * the agent should run in.
	 */
	rc = seccomp_attr_set(ctx, SCMP_FLTATR_CTL_TSYNC, 1);
	if (rc < 0) {
		seccomp_release(ctx);
		return rc;
	}

	rc = seccomp_load(ctx);
	seccomp_release(ctx);
	if (rc < 0)
		return rc;

	return 0;
}

int hardening_apply_basics(void)
{
	int ret;

	ret = hardening_apply_no_new_privs();
	if (ret < 0) {
		lota_err("hardening: PR_SET_NO_NEW_PRIVS failed: %s",
			 strerror(-ret));
		return ret;
	}

	ret = hardening_apply_no_dumpable();
	if (ret < 0) {
		lota_err("hardening: PR_SET_DUMPABLE failed: %s",
			 strerror(-ret));
		return ret;
	}

	lota_info("hardening: applied no_new_privs, dumpable=0");
	return 0;
}

int hardening_apply_daemon(void)
{
	int ret;

	ret = hardening_refuse_if_traced();
	if (ret < 0)
		return ret;

	ret = hardening_apply_seccomp();
	if (ret < 0) {
		lota_err("hardening: seccomp filter load failed: %s",
			 strerror(-ret));
		return ret;
	}

	lota_info("hardening: applied tracer refusal and seccomp blocklist");
	return 0;
}

int hardening_apply_all(void)
{
	int ret = hardening_apply_basics();
	if (ret < 0)
		return ret;
	return hardening_apply_daemon();
}
