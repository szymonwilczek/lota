/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - Process self-hardening helpers
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include "hardening.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <unistd.h>
#include <seccomp.h>
#include <sys/types.h>

#include "journal.h"

int hardening_parse_tracer_pid_buf(const char *buf, long *out_tracer)
{
	if (!buf || !out_tracer)
		return -EINVAL;
	*out_tracer = 0;

	/* only at a line start */
	const char *p = (buf[0] == 'T' && strncmp(buf, "TracerPid:", 10) == 0) ?
				buf :
				strstr(buf, "\nTracerPid:");
	if (!p)
		return -ENOTSUP;
	if (*p == '\n')
		p++;
	p += sizeof("TracerPid:") - 1;
	while (*p == ' ' || *p == '\t')
		p++;

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

int hardening_read_tracer_pid(pid_t pid, long *out_tracer)
{
	char path[64];
	int fd;

	if (!out_tracer)
		return -EINVAL;
	*out_tracer = 0;

	if (pid > 0)
		snprintf(path, sizeof(path), "/proc/%d/status", (int)pid);
	else
		snprintf(path, sizeof(path), "/proc/self/status");

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;

	/* the file can pass 4 KiB; TracerPid comes before the cap */
	const size_t cap = 32 * 1024;
	char *buf = malloc(cap);
	size_t off = 0;

	if (!buf) {
		close(fd);
		return -ENOMEM;
	}

	while (off < cap - 1) {
		ssize_t n = read(fd, buf + off, cap - 1 - off);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			int err = -errno;
			close(fd);
			free(buf);
			return err;
		}
		if (n == 0)
			break;
		off += (size_t)n;
	}
	close(fd);

	if (off == 0) {
		free(buf);
		return -EIO;
	}
	buf[off] = '\0';

	int ret = hardening_parse_tracer_pid_buf(buf, out_tracer);
	free(buf);
	return ret;
}

int hardening_refuse_if_traced(void)
{
	long tracer = 0;
	int ret = hardening_read_tracer_pid(0, &tracer);

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
 * A hit kills the process: a listed syscall from the agent is a fault or a
 * compromise, and an EPERM it carries on past would hide it.
 * name_to_handle_at and open_by_handle_at stay off: under socket activation
 * libsystemd calls the first inside sd_listen_fds().
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
	SCMP_SYS(setns),
	SCMP_SYS(unshare),
	SCMP_SYS(io_uring_setup),
	SCMP_SYS(io_uring_enter),
	SCMP_SYS(io_uring_register),
	SCMP_SYS(userfaultfd),
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
			continue; /* SCMP_SYS() of a syscall this arch lacks */

		rc = seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, sc, 0);
		if (rc < 0) {
			seccomp_release(ctx);
			return rc;
		}
	}

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
