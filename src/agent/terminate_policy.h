/* SPDX-License-Identifier: MIT */
/*
 * Who may end a protected process, and on what terms.
 *
 * Protected task takes no signal from anything but itself, the agent, holder of
 * LOTA_TASK_AUTH_ADMIN or the kernel, and the admin identity lives on the agent's
 * own PID in a frozen map.
 * That is what stops a cheat from killing the process being measured, and it is
 * also what leaves a player with a hung title and no remedy short of a reboot.
 *
 * The agent can deliver the signal, so the boundary is who it delivers for.
 * The rule below is kill(2)'s own: the owner of the process, or root.
 * The verb hands back what the machine had before the LSM intervened and widens
 * nothing, which is why it needs no operator privilege gate -- demanding
 * verity-allowlisted caller would reproduce the dead end it exists to end.
 *
 * What the rule does not hand back is the ability to drive a protected process:
 * only a termination is relayed, so nothing a process survives can be sent through
 * the agent's privilege while that process stays in the measured set.
 *
 * Every allowed termination is recorded, and the host reports for the rest of
 * the boot that one happened, so the publisher sees a session ended locally
 * rather than a process that merely vanished.
 *
 * Split out of ipc.c so the boundary is exercised as a table of cases rather
 * than by spawning processes a test would then have to protect and kill.
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
	/* the target is not a process this verb speaks for */
	TERMINATE_DENY_TARGET,
	/* nobody protected it, so kill(2) already reaches it */
	TERMINATE_DENY_NOT_PROTECTED,
	/* not a termination */
	TERMINATE_DENY_SIGNAL,
	/* kill(2) would have refused this caller */
	TERMINATE_DENY_OWNER,
	/* the agent stops through --shutdown and a reboot, not through this */
	TERMINATE_DENY_AGENT,
};

struct terminate_request {
	uint32_t target_pid;
	uint32_t target_uid; /* real uid of the target, read from /proc */
	uint32_t caller_uid; /* SO_PEERCRED of the connection */
	uint32_t caller_pid;
	uint32_t agent_pid; /* the daemon serving this request */
	int signal;
	bool target_is_protected;
};

/*
 * Whether @req may be relayed, and when it may not, which boundary refused it.
 * The caller reports the reason, so the cases stay distinguishable rather than
 * collapsing into one denial a player cannot act on.
 */
static inline enum terminate_decision
terminate_policy_decide(const struct terminate_request *req)
{
	if (!req || req->target_pid == 0)
		return TERMINATE_DENY_TARGET;

	/*
	 * PID 1 is refused to everyone.
	 * No title is init, and a machine that loses init is a machine that
	 * reboots -- which is the outcome the verb exists to avoid.
	 */
	if (req->target_pid == 1)
		return TERMINATE_DENY_TARGET;

	if (req->agent_pid != 0 && req->target_pid == req->agent_pid)
		return TERMINATE_DENY_AGENT;

	if (!req->target_is_protected)
		return TERMINATE_DENY_NOT_PROTECTED;

	/*
	 * SIGTERM asks, SIGKILL insists, and both end the process.
	 * Anything else -- handled signal, stop, or the sig == 0 existence probe
	 * kill(2) answers on its own -- would make the agent a signal relay for
	 * process the machine is still measuring.
	 */
	if (req->signal != SIGTERM && req->signal != SIGKILL)
		return TERMINATE_DENY_SIGNAL;

	if (req->caller_uid != 0 && req->caller_uid != req->target_uid)
		return TERMINATE_DENY_OWNER;

	return TERMINATE_ALLOW;
}

/*
 * The wire code a denial answers with.
 *
 * The caller sees this and not the sentence below, so the families a player can
 * act on stay apart:
 * a process nobody protected is one an ordinary kill reaches,
 * a target the verb does not speak for is one no caller can end this way,
 * and the rest is the request not being theirs to make.
 *
 * Collapsing them makes the message wrong -- with one code, ending the agent's
 * own PID reads as a permission problem with someone else's process.
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

/* One sentence per denial, for the journal and for the caller's stderr */
static inline const char *terminate_decision_reason(enum terminate_decision d)
{
	switch (d) {
	case TERMINATE_ALLOW:
		return "allowed";
	case TERMINATE_DENY_TARGET:
		return "not a process this verb can end";
	case TERMINATE_DENY_NOT_PROTECTED:
		return "not a protected process (ordinary kill reaches it)";
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
