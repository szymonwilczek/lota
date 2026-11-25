/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/* Log line for a KILL or KILL_BLOCKED event. */

#ifndef LOTA_AGENT_KILL_REPORT_H
#define LOTA_AGENT_KILL_REPORT_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/**
 * kill_report_line() - Format the log line for one event.
 * @out: Caller's buffer.
 * @cap: Its size.
 * @blocked: The event is KILL_BLOCKED.
 * @comm: Name of the task the hook ran in, already sanitized.
 * @target_pid: Target's tgid.
 * @sig: Signal number; 0 for a refused rlimit change or a default SIGIO.
 * @pid: That task's thread id.
 * @uid: That task's uid.
 *
 * That task is not always the sender: at the delivery of a dump signal it is
 * the receiver.
 */
static inline void kill_report_line(char *out, size_t cap, int blocked,
				    const char *comm, uint32_t target_pid,
				    uint32_t sig, uint32_t pid, uint32_t uid)
{
	if (!out || cap == 0)
		return;

	snprintf(out, cap, "%s %s -> pid=%u sig=%u (pid=%u, uid=%u)",
		 blocked ? "KILL_BLOCKED" : "KILL", comm ? comm : "",
		 target_pid, sig, pid, uid);
}

#endif /* LOTA_AGENT_KILL_REPORT_H */
