/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - advice for a host below the kernel floor.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_AGENT_KERNEL_FLOOR_HINT_H
#define LOTA_AGENT_KERNEL_FLOOR_HINT_H

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

/**
 * enum lota_kernel_floor - The part of the kernel floor that is missing.
 * @LOTA_KERNEL_FLOOR_LOCKDOWN: restrictive lockdown.
 * @LOTA_KERNEL_FLOOR_MODULE_SIG: enforced module signatures.
 */
enum lota_kernel_floor {
	LOTA_KERNEL_FLOOR_LOCKDOWN,
	LOTA_KERNEL_FLOOR_MODULE_SIG,
};

/**
 * kernel_floor_message() - Name the missing state and how to raise it.
 * @which: the missing part.
 * @secureboot: Secure Boot is on.
 * @out: the message; NUL-terminated when @cap is not 0.
 * @cap: size of @out.
 */
static inline void kernel_floor_message(enum lota_kernel_floor which,
					bool secureboot, char *out, size_t cap)
{
	if (!out || cap == 0)
		return;

	if (which == LOTA_KERNEL_FLOOR_LOCKDOWN) {
		if (secureboot)
			snprintf(
				out, cap,
				"Kernel lockdown is not in restrictive mode "
				"(integrity/confidentiality required). Secure "
				"Boot is on, so the kernel did not take itself "
				"there: boot with lockdown=integrity on the "
				"kernel command line.");
		else
			snprintf(out, cap,
				 "Kernel lockdown is not in restrictive mode "
				 "(integrity/confidentiality required), and "
				 "Secure Boot is off on this host, which is "
				 "what puts the kernel there. It is a firmware "
				 "setting, so the agent cannot turn it on; "
				 "'lota-install --status' names this machine "
				 "and the way into its setup screen.");
		return;
	}

	if (secureboot)
		snprintf(out, cap,
			 "Kernel module signature enforcement is not active "
			 "(module.sig_enforce=1 closes the window between the "
			 "boot and the agent). Secure Boot is on, so boot with "
			 "that parameter on the kernel command line.");
	else
		snprintf(out, cap,
			 "Kernel module signature enforcement is not active, "
			 "so an unsigned module can be loaded in the window "
			 "between the boot and the agent. Secure Boot is off "
			 "on this host, which is what makes the kernel enforce "
			 "signatures. It is a firmware setting, so the agent "
			 "cannot turn it on; 'lota-install --status' names "
			 "this machine and the way into its setup screen.");
}

/**
 * startup_refusal_advice() - Advice under a startup policy refusal.
 * @err: the refusal.
 *
 * Return: for -ENOTSUP, a sentence naming the host; otherwise the policy.
 */
static inline const char *startup_refusal_advice(int err)
{
	if (err == -ENOTSUP)
		return "The line above names a state of this host: raise it "
		       "and start again.";

	return "Correct the policy and start again.";
}

#endif /* LOTA_AGENT_KERNEL_FLOOR_HINT_H */
