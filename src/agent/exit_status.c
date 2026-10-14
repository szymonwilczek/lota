/* SPDX-License-Identifier: MIT */
/*
 * LOTA - what a refused daemon start tells its supervisor.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <errno.h>
#include <stdbool.h>

#include "exit_status.h"
#include "tpm.h"

/*
 * Did the PCR 14 verdict refuse the boot commitment?
 *
 * PCR 14 cannot be reset from userspace, so a refused extend stays refused
 * until reboot and restarting the daemon cannot change it.
 * Only AWAITING_EXTEND and ALREADY_COMMITTED let the extend proceed.
 * A run that never reached the register leaves AWAITING_EXTEND, the zero value.
 */
static bool commitment_refused(enum tpm_pcr14_state state)
{
	switch (state) {
	case TPM_PCR14_AWAITING_EXTEND:
	case TPM_PCR14_ALREADY_COMMITTED:
		return false;
	case TPM_PCR14_LOCK_MISSING:
	case TPM_PCR14_SPENT_BY_SHUTDOWN:
	case TPM_PCR14_BINARY_CHANGED:
	case TPM_PCR14_TAMPERED_BEFORE_START:
	case TPM_PCR14_MUTATED_IN_SESSION:
	case TPM_PCR14_UNATTRIBUTABLE:
	case TPM_PCR14_STATE_ROLLBACK:
		return true;
	}

	/*
	 * A verdict this file has no case for is the one that must not be
	 * restarted into: an unrecognised state is not evidence that trying
	 * again is free.
	 */
	return true;
}

int lota_daemon_exit_status(int rc, enum tpm_pcr14_state commitment)
{
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

	/*
	 * The refusal every restart pays for: a spent, mis-chained or mutated
	 * PCR 14 stands until the host reboots, and each attempt still opens
	 * the TPM, provisions the AIK and lays the container socket down before
	 * finding that out.
	 */
	if (commitment_refused(commitment))
		return LOTA_EXIT_OPERATOR_ACTION;

	return rc;
}
