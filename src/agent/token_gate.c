/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */

#include "token_gate.h"

#include "../../include/lota_ipc.h"

bool token_gate_needs_attested(uint32_t view_flags)
{
	return (view_flags & LOTA_STATUS_TOKEN_ONLY) == 0;
}

bool token_gate_failure_is_fatal(pid_t failing_pid, pid_t requesting_pid)
{
	return failing_pid == requesting_pid;
}
