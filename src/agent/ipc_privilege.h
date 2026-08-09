/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */

#ifndef LOTA_IPC_PRIVILEGE_H
#define LOTA_IPC_PRIVILEGE_H

#include <stdbool.h>

/*
 * Who may issue a privileged IPC command.
 *
 * The rule is kept apart from the code that gathers its inputs so it can
 * be read and tested on its own: everything here is a decision, nothing
 * here reads /proc, a map or a socket.
 *
 * @uid_is_agent:     peer uid equals the agent's own, authenticated by
 *                    the kernel through SO_PEERCRED
 * @pid_identity_ok:  the peer's pid still carries the start time it had
 *                    when the connection was accepted, so a recycled pid
 *                    cannot inherit the connection's authority
 * @verity_allowlist_count: how many executables the operator put on the
 *                    fs-verity allowlist
 * @exe_on_allowlist: whether the peer's executable is one of them
 */
static inline bool ipc_privilege_granted(bool uid_is_agent,
					 bool pid_identity_ok,
					 int verity_allowlist_count,
					 bool exe_on_allowlist)
{
	(void)verity_allowlist_count;

	if (!uid_is_agent || !pid_identity_ok)
		return false;

	return exe_on_allowlist;
}

#endif /* LOTA_IPC_PRIVILEGE_H */
