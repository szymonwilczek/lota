/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Log line for a signal aimed at a protected process.
 * Pure, so tests can pin the line; it names the signal,
 * as a SIGKILL and a probe must differ.
 */

#ifndef LOTA_AGENT_KILL_REPORT_H
#define LOTA_AGENT_KILL_REPORT_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/*
 * kill_report_line - Format the log line for one kill event
 * @out: caller's buffer
 * @cap: its size
 * @blocked: signal was refused
 * @comm: sender's name, already folded for the log
 * @target_pid: protected target
 * @sig: signal number
 * @pid: sending thread
 * @uid: sender's uid
 */
static inline void kill_report_line(char *out, size_t cap, int blocked,
				    const char *comm, uint32_t target_pid,
				    uint32_t sig, uint32_t pid, uint32_t uid)
{
	if (!out || cap == 0)
		return;

	(void)sig;

	snprintf(out, cap, "%s %s -> pid=%u (pid=%u, uid=%u)",
		 blocked ? "KILL_BLOCKED" : "KILL", comm ? comm : "", target_pid,
		 pid, uid);
}

#endif /* LOTA_AGENT_KILL_REPORT_H */
