/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Advice for a host below the kernel floor: restrictive lockdown and enforced
 * module signatures. Pure, so a test pins the sentence and both daemon
 * refusals share it.
 */

#ifndef LOTA_AGENT_KERNEL_FLOOR_HINT_H
#define LOTA_AGENT_KERNEL_FLOOR_HINT_H

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

/* Which half of the floor is missing */
enum lota_kernel_floor {
	LOTA_KERNEL_FLOOR_LOCKDOWN,
	LOTA_KERNEL_FLOOR_MODULE_SIG,
};

/* Name the missing state and the lever that raises it; always NUL-terminated */
static inline void kernel_floor_message(enum lota_kernel_floor which,
					bool secureboot, char *out, size_t cap)
{
	if (!out || cap == 0)
		return;

	/* not read yet: both sentences name a kernel parameter */
	(void)secureboot;

	if (which == LOTA_KERNEL_FLOOR_LOCKDOWN)
		snprintf(out, cap,
			 "Kernel lockdown is not in restrictive mode "
			 "(integrity/confidentiality required)");
	else
		snprintf(out, cap,
			 "Kernel module signature enforcement is not active "
			 "(module.sig_enforce=1 required to close the boot -> "
			 "agent module-load window)");
}

/* Advice under a startup refusal @err: fix the policy, or the host */
static inline const char *startup_refusal_advice(int err)
{
	(void)err;

	return "Correct the policy and start again.";
}

#endif /* LOTA_AGENT_KERNEL_FLOOR_HINT_H */
