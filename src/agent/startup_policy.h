/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
#ifndef LOTA_STARTUP_POLICY_H
#define LOTA_STARTUP_POLICY_H

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>

struct agent_startup_policy {
	int mode;
	bool strict_mmap;
	bool strict_exec;
	bool block_ptrace;
	bool strict_modules;
	bool block_anon_exec;
	uint32_t *protect_pids;
	int protect_pid_count;
	char (*trust_libs)[PATH_MAX];
	int trust_lib_count;

	char (*allow_verity)[PATH_MAX];
	int allow_verity_count;

	/*
	 * When true, skip the agent-binary immutability check inside
	 * bpf_loader_verify_kernel_runtime_hardening().
	 * It is for a host that can offer neither proof
	 * -- no fs-verity (XFS and ZFS have none) and no signed security.ima xattr.
	 * --insecure-allow-mutable-rootfs CLI flag is the only path that flips
	 *  this on, and operators are warned that the dirty-shutdown coverage
	 *  gap stays open on that host.
	 */
	bool allow_mutable_rootfs;
};

int agent_apply_startup_policy(const struct agent_startup_policy *policy);

int agent_compute_policy_digest_for_protect_pids(const uint32_t *protect_pids,
						 int protect_pid_count,
						 uint8_t out_digest[32]);

#endif /* LOTA_STARTUP_POLICY_H */
