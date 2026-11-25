/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
#ifndef LOTA_EXIT_STATUS_H
#define LOTA_EXIT_STATUS_H

#include "tpm.h"

/*
 * A state only an operator can clear. Both packaged units list it in
 * RestartPreventExitStatus. 78 is EX_CONFIG of sysexits.h.
 */
#define LOTA_EXIT_OPERATOR_ACTION 78

/*
 * Another instance holds the PID file. lota-agent.service lists it in
 * RestartPreventExitStatus.
 */
#define LOTA_EXIT_ALREADY_RUNNING 3

/**
 * lota_daemon_exit_status() - Map the daemon's result to its exit status.
 * @rc: What run_daemon() returned: 0 or a negative errno.
 * @commitment: The PCR 14 verdict of the same run.
 *
 * Return: LOTA_EXIT_OPERATOR_ACTION for -ENOTSUP or a refused boot commitment,
 * else @rc.
 */
int lota_daemon_exit_status(int rc, enum tpm_pcr14_state commitment);

#endif /* LOTA_EXIT_STATUS_H */
