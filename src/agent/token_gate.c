/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */

#include "token_gate.h"

bool token_gate_needs_attested(uint32_t view_flags)
{
	(void)view_flags;

	return true;
}

bool token_gate_failure_is_fatal(pid_t failing_pid, pid_t requesting_pid)
{
	(void)failing_pid;
	(void)requesting_pid;

	return true;
}
