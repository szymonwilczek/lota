/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */

#include "token_gate.h"

#include "../../include/lota_ipc.h"

bool token_gate_needs_attested(uint32_t view_flags)
{
	/*
	 * The flag says this connection's publisher runs no verifier,
	 * so the host holds no verdict of theirs and never will.
	 * Everything else a token needs stays in handle_get_token():
	 * the DA lockout reject, the session and uid rate limits,
	 * tpm_bind_profile() loading the publisher's enrolled AIK,
	 * and tpm_quote() itself.
	 */
	return (view_flags & LOTA_STATUS_TOKEN_ONLY) == 0;
}

bool token_gate_failure_is_fatal(pid_t failing_pid, pid_t requesting_pid)
{
	/*
	 * The caller's own executable is the part its publisher packages,
	 * so an unmeasurable one is theirs to answer for.
	 * Every other protected process belongs to somebody else and is reported
	 * through the coverage flag instead: a token that cannot be issued
	 * because a third program protected itself from a binary with no fs-verity
	 * is a denial of service any local program can cause.
	 */
	return failing_pid == requesting_pid;
}
