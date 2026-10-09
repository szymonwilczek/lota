/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
#ifndef LOTA_EXIT_STATUS_H
#define LOTA_EXIT_STATUS_H

#include "tpm.h"

/*
 * Exit status for a state only an operator can clear: the host is configured
 * in a way the agent refuses, and starting it again changes nothing.
 * The packaged unit lists it in RestartPreventExitStatus, so systemd leaves
 * the unit failed with the reason in the journal.
 *
 * 78 is sysexits.h EX_CONFIG, which is what this is.
 */
#define LOTA_EXIT_OPERATOR_ACTION 78

/*
 * What the daemon's return value becomes as a process exit status.
 *
 * @rc:         what run_daemon() returned: 0 or a negative errno.
 * @commitment: the PCR 14 verdict the same run reached, read from
 *              the TPM context this process used.
 *
 * The unit file's behaviour stands on this answer, so it has one producer:
 * a refusal routed anywhere but LOTA_EXIT_OPERATOR_ACTION is one systemd
 * restarts into for the rest of the boot.
 */
int lota_daemon_exit_status(int rc, enum tpm_pcr14_state commitment);

#endif /* LOTA_EXIT_STATUS_H */
