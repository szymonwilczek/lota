/* SPDX-License-Identifier: MIT */
/*
 * Who may end a protected process through the agent: root, or the process's
 * owner. Only SIGTERM and SIGKILL are relayed.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#ifndef LOTA_AGENT_TERMINATE_POLICY_H
#define LOTA_AGENT_TERMINATE_POLICY_H

#include <signal.h>
#include <stdbool.h>
#include <stdint.h>

#include "../../include/lota_ipc.h"

enum terminate_decision {
	TERMINATE_ALLOW = 0,
	/* no request, pid 0 or PID 1 */
	TERMINATE_DENY_TARGET,
	TERMINATE_DENY_NOT_PROTECTED,
	TERMINATE_DENY_SIGNAL,
	TERMINATE_DENY_OWNER,
	TERMINATE_DENY_AGENT,
};

struct terminate_request {
	uint32_t target_pid;
	uint32_t target_uid; /* real uid of the target, read from /proc */
	uint32_t caller_uid; /* SO_PEERCRED of the connection */
	uint32_t agent_pid; /* the daemon serving this request */
	int signal;
	bool target_is_protected;
};

/**
 * terminate_policy_decide() - Decide a termination request.
 * @req: The request.
 *
 * Return: TERMINATE_ALLOW, or the boundary that refused it.
 */
static inline enum terminate_decision
terminate_policy_decide(const struct terminate_request *req)
{
	if (!req || req->target_pid == 0)
		return TERMINATE_DENY_TARGET;

	if (req->target_pid == 1)
		return TERMINATE_DENY_TARGET;

	if (req->agent_pid != 0 && req->target_pid == req->agent_pid)
		return TERMINATE_DENY_AGENT;

	if (!req->target_is_protected)
		return TERMINATE_DENY_NOT_PROTECTED;

	if (req->signal != SIGTERM && req->signal != SIGKILL)
		return TERMINATE_DENY_SIGNAL;

	if (req->caller_uid != 0 && req->caller_uid != req->target_uid)
		return TERMINATE_DENY_OWNER;

	return TERMINATE_ALLOW;
}

/**
 * terminate_decision_result() - The wire code a denial answers with.
 * @d: The decision.
 *
 * diagnostics.c words its message from this code.
 *
 * Return: the code, LOTA_IPC_OK for TERMINATE_ALLOW.
 */
static inline enum lota_ipc_result
terminate_decision_result(enum terminate_decision d)
{
	switch (d) {
	case TERMINATE_DENY_NOT_PROTECTED:
		return LOTA_IPC_ERR_NOT_PROTECTED;
	case TERMINATE_DENY_TARGET:
	case TERMINATE_DENY_AGENT:
		return LOTA_IPC_ERR_TARGET_REFUSED;
	case TERMINATE_DENY_SIGNAL:
	case TERMINATE_DENY_OWNER:
		return LOTA_IPC_ERR_ACCESS_DENIED;
	case TERMINATE_ALLOW:
		break;
	}
	return LOTA_IPC_OK;
}

/**
 * terminate_decision_reason() - One sentence per decision, for the journal.
 * @d: The decision.
 *
 * Return: a static string.
 */
static inline const char *terminate_decision_reason(enum terminate_decision d)
{
	switch (d) {
	case TERMINATE_ALLOW:
		return "allowed";
	case TERMINATE_DENY_TARGET:
		return "not a process this verb can end";
	case TERMINATE_DENY_NOT_PROTECTED:
		return "not a protected process";
	case TERMINATE_DENY_SIGNAL:
		return "only SIGTERM and SIGKILL are relayed";
	case TERMINATE_DENY_OWNER:
		return "the caller does not own that process";
	case TERMINATE_DENY_AGENT:
		return "the agent stops with --shutdown, not with this";
	}
	return "refused";
}

#endif /* LOTA_AGENT_TERMINATE_POLICY_H */
