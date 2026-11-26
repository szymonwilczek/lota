/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/* The --terminate-protected report line. */

#ifndef LOTA_AGENT_TERMINATE_REPORT_H
#define LOTA_AGENT_TERMINATE_REPORT_H

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "../../include/lota_ipc.h"

/**
 * terminate_result_errno() - The errno a TERMINATE_PROTECTED refusal maps to.
 * @result: The result code of the response, not LOTA_IPC_OK.
 *
 * diagnostics.c words its message from the errno.
 *
 * Return: -EINVAL not protected, -EPERM a target the verb does not end,
 * -ESRCH no such process, -EACCES not the caller's to end or a caller
 * outside the agent's PID namespace, -EIO the signal failed in the agent,
 * -EPROTO any other code.
 */
static inline int terminate_result_errno(uint32_t result)
{
	switch (result) {
	case LOTA_IPC_ERR_NOT_PROTECTED:
		return -EINVAL;
	case LOTA_IPC_ERR_TARGET_REFUSED:
		return -EPERM;
	case LOTA_IPC_ERR_BAD_REQUEST:
		return -ESRCH;
	case LOTA_IPC_ERR_ACCESS_DENIED:
		return -EACCES;
	case LOTA_IPC_ERR_INTERNAL:
		return -EIO;
	default:
		return -EPROTO;
	}
}

/**
 * terminate_sent_message() - Format the report after the signal went out.
 * @pid: Signalled process.
 * @force: SIGKILL when true, SIGTERM when false.
 * @others: Number of the other protected processes of @pid's instance, as
 *          the agent reported it.
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
			 "Sent %s to protected PID %u; no other process in "
			 "its process tree is protected.",
			 sig, pid);
		return;
	}

	snprintf(out, cap,
		 "Sent %s to protected PID %u; %u other process%s in "
		 "its process tree %s still protected.",
		 sig, pid, others, others == 1 ? "" : "es",
		 others == 1 ? "is" : "are");
}

#endif /* LOTA_AGENT_TERMINATE_REPORT_H */
