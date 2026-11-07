/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/* The --terminate-protected report line. */

#ifndef LOTA_AGENT_TERMINATE_REPORT_H
#define LOTA_AGENT_TERMINATE_REPORT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/**
 * terminate_others_protected() - Count the protected PIDs other than @target.
 * @pids: The set.
 * @count: Its size.
 * @target: The signalled process.
 *
 * Return: the count.
 */
static inline uint32_t terminate_others_protected(const uint32_t *pids,
						  int count, uint32_t target)
{
	uint32_t others = 0;
	int i;

	if (!pids || count <= 0)
		return 0;

	for (i = 0; i < count; i++) {
		if (pids[i] != target)
			others++;
	}

	return others;
}

/**
 * terminate_sent_message() - Format the report after the signal went out.
 * @pid: Signalled process.
 * @force: SIGKILL when true, SIGTERM when false.
 * @others: Rest of the protected set, as the agent reported it.
 * @out: Receives a NUL-terminated sentence without a newline.
 * @cap: Size of @out.
 */
static inline void terminate_sent_message(uint32_t pid, bool force,
					  uint32_t others, char *out,
					  size_t cap)
{
	const char *sig = force ? "SIGKILL" : "SIGTERM";

	if (!out || cap == 0)
		return;

	if (others == 0) {
		snprintf(out, cap,
			 "Sent %s to protected PID %u; no other process is "
			 "protected.",
			 sig, pid);
		return;
	}

	snprintf(out, cap,
		 "Sent %s to protected PID %u; %u other process%s "
		 "still protected.",
		 sig, pid, others, others == 1 ? " is" : "es are");
}

#endif /* LOTA_AGENT_TERMINATE_REPORT_H */
