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
 * PCR 14 cannot be reset from userspace, so a restart of the same binary meets
 * the same refusal until reboot. A run that never reached the register leaves
 * AWAITING_EXTEND, the zero value.
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
	case TPM_PCR14_HANDOFF_CHANGED:
	case TPM_PCR14_UNATTRIBUTABLE:
	case TPM_PCR14_STATE_ROLLBACK:
		return true;
	}

	/* an unknown state is no evidence that a restart is free */
	return true;
}

int lota_daemon_exit_status(int rc, enum tpm_pcr14_state commitment)
{
	if (rc >= 0)
		return rc;

	/* a host configuration the daemon refuses, such as the kernel floor */
	if (rc == -ENOTSUP)
		return LOTA_EXIT_OPERATOR_ACTION;

	/* an AIK record missing or blank on disk: a restart reads the same */
	if (rc == -EKEYREVOKED)
		return LOTA_EXIT_OPERATOR_ACTION;

	/* each restart would set up IPC, the TPM and the AIK again first */
	if (commitment_refused(commitment))
		return LOTA_EXIT_OPERATOR_ACTION;

	return 1;
}

int lota_startup_check_exit_status(int err)
{
	switch (err) {
	case -EIO:
	case -EMFILE:
	case -ENFILE:
	case -ENOMEM:
	case -EAGAIN:
	case -EINTR:
	case -EBUSY:
		return 1;
	}
	return LOTA_EXIT_OPERATOR_ACTION;
}
