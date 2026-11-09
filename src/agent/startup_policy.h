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
	 * Set by --insecure-allow-mutable-rootfs. Turns the refusal of a TPM
	 * device without its SELinux label into a warning.
	 */
	bool allow_mutable_rootfs;
};

/**
 * agent_validate_startup_policy() - Refuse a policy before the boot commitment.
 * @policy: The policy agent_apply_startup_policy() will get.
 *
 * Checks the protected-PID capacity and that each PID names a process, the kernel
 * floor, strict_exec or strict_modules without allow_verity, that each fs-verity
 * path can be measured, and probes each trusted library. The boot commitment is
 * made once per boot, so a refusal after it leaves the host without an agent
 * until reboot. Needs no loaded BPF object.
 *
 * Return: 0 or a negative errno, -ENOTSUP for a kernel floor refusal.
 */
int agent_validate_startup_policy(const struct agent_startup_policy *policy);

int agent_apply_startup_policy(const struct agent_startup_policy *policy);

#endif /* LOTA_STARTUP_POLICY_H */
