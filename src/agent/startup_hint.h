/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Header-only, so a test pins what an operator reads without starting a second
 * daemon.
 */

#ifndef LOTA_AGENT_STARTUP_HINT_H
#define LOTA_AGENT_STARTUP_HINT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

/**
 * startup_busy_message() - Why the daemon does not start beside another one.
 * @asked_protect_pid: Add the part on --protect-pid.
 * @out: Receives a NUL-terminated message.
 * @cap: Size of @out.
 *
 * With @asked_protect_pid the message also says the flag did nothing
 * and how a running process gets protected.
 */
static inline void startup_busy_message(bool asked_protect_pid, char *out,
					size_t cap)
{
	if (!out || cap == 0)
		return;

	if (!asked_protect_pid) {
		snprintf(out, cap,
			 "Another instance is already running (PID file "
			 "locked).");
		return;
	}

	snprintf(out, cap,
		 "Another instance is already running (PID file locked), so "
		 "--protect-pid did nothing.\n"
		 "It is read only at startup: it seeds the protected set of "
		 "the instance it starts.\n"
		 "A process that is already running protects itself through "
		 "the SDK, with lota_protect_self(), or starts under "
		 "lota-protect.");
}

#endif /* LOTA_AGENT_STARTUP_HINT_H */
