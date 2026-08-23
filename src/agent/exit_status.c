/* SPDX-License-Identifier: MIT */
/*
 * LOTA - what a refused daemon start tells its supervisor.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <errno.h>

#include "exit_status.h"
#include "tpm.h"

int lota_daemon_exit_status(int rc, enum tpm_pcr14_state commitment)
{
	(void)commitment;

	if (rc >= 0)
		return rc;

	/*
	 * -ENOTSUP is the daemon's "this host is configured in a way I refuse":
	 * a legacy firmware interface, or a publisher key that predates
	 * per-publisher derivation.
	 * Both need someone to act; neither is fixed by trying again.
	 */
	if (rc == -ENOTSUP)
		return LOTA_EXIT_OPERATOR_ACTION;

	return rc;
}
