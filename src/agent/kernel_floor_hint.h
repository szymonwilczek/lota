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

	/* Secure Boot off: enable it. On: the cmdline parameter is missing. */
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

/* Advice under a startup refusal @err: fix the policy, or the host */
static inline const char *startup_refusal_advice(int err)
{
	/*
	 * -ENOTSUP is the floor, a state of the host: the only policy edit
	 * that passes it drops the requirement. An edit repairs the rest.
	 */
	if (err == -ENOTSUP)
		return "The line above is a state of this host, not of this "
		       "configuration: raise it and start again.";

	return "Correct the policy and start again.";
}

#endif /* LOTA_AGENT_KERNEL_FLOOR_HINT_H */
