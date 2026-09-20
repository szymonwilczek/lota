/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * --terminate-protected report line.
 * Header-only and pure, so a test can pin it without ending a protected process.
 */

#ifndef LOTA_AGENT_TERMINATE_REPORT_H
#define LOTA_AGENT_TERMINATE_REPORT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/*
 * terminate_sent_message - format the report after the signal went out
 * @pid:   signalled process
 * @force: SIGKILL rather than SIGTERM
 * @count: protected-set size the agent reported
 *
 * Writes a NUL-terminated sentence without a trailing newline.
 */
static inline void terminate_sent_message(uint32_t pid, bool force,
					  uint32_t count, char *out, size_t cap)
{
	if (!out || cap == 0)
		return;

	snprintf(out, cap,
		 "Sent %s to protected PID %u; %u process%s still protected.",
		 force ? "SIGKILL" : "SIGTERM", pid, count,
		 count == 1 ? "" : "es");
}

#endif /* LOTA_AGENT_TERMINATE_REPORT_H */
