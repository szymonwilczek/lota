/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * What to say when the daemon will not start because one is already running.
 *
 * Header-only and pure: the caller owns the buffer and the printing, so what an
 * operator reads can be pinned by a test rather than reproduced by starting a
 * second daemon.
 *
 * Flags only the daemon reads do nothing when another instance holds the PID
 * file.
 * --protect-pid is the one passed expecting an effect on the running instance,
 * so a refusal that carried it says the flag was ignored and names what protects
 * a live process instead; any other refusal stays one line.
 */

#ifndef LOTA_AGENT_STARTUP_HINT_H
#define LOTA_AGENT_STARTUP_HINT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

/*
 * @asked_protect_pid: the command line carried --protect-pid.
 *
 * Always writes a NUL-terminated sentence naming the refusal; adds what
 * the flag would have done, and the way to protect a process that is
 * already running, when that is what the caller asked for.
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
		 "It is a startup option of the daemon, not a request to the "
		 "one that is running: it seeds the protected set of the "
		 "instance it starts.\n"
		 "A process that is already running protects itself through "
		 "the SDK, with lota_protect_self(); ending one that did is "
		 "lota-agent --terminate-protected PID.");
}

#endif /* LOTA_AGENT_STARTUP_HINT_H */
