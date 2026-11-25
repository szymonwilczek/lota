/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */

#ifndef LOTA_IPC_PRIVILEGE_H
#define LOTA_IPC_PRIVILEGE_H

#include <stdbool.h>

/**
 * ipc_privilege_granted() - Whether a peer may issue a privileged IPC command.
 * @uid_is_agent: Peer uid equals the agent's own, from SO_PEERCRED.
 * @pid_identity_ok: The peer's pid still has the start time it had at accept,
 *                   so a recycled pid does not inherit the connection's
 *                   authority.
 * @verity_allowlist_count: Executables on the operator's fs-verity allowlist.
 * @exe_on_allowlist: The peer's executable is one of them.
 *
 * Return: true when granted.
 */
static inline bool ipc_privilege_granted(bool uid_is_agent,
					 bool pid_identity_ok,
					 int verity_allowlist_count,
					 bool exe_on_allowlist)
{
	if (!uid_is_agent || !pid_identity_ok)
		return false;

	/*
	 * An empty allowlist does not narrow the rule: requiring membership
	 * would deny the unit's ExecStop, and the LSM refuses SIGKILL to the
	 * agent.
	 *
	 * The uid check keeps out the lota group, which reaches the socket.
	 */
	if (verity_allowlist_count > 0)
		return exe_on_allowlist;

	return true;
}

#endif /* LOTA_IPC_PRIVILEGE_H */
