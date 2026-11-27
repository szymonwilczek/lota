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
 * @rc: What run_daemon() returned: an exit status or a negative errno.
 * @commitment: The PCR 14 verdict of the same run.
 *
 * Return: @rc when it is not negative, LOTA_EXIT_OPERATOR_ACTION for -ENOTSUP,
 * -EKEYREVOKED or a refused boot commitment, else 1.
 */
int lota_daemon_exit_status(int rc, enum tpm_pcr14_state commitment);

/**
 * lota_startup_check_exit_status() - Exit status of a failed startup check.
 * @err: The negative errno of a check run before the boot commitment.
 *
 * Return: 1 for -EIO, -EMFILE, -ENFILE, -ENOMEM, -EAGAIN, -EINTR or -EBUSY,
 * which a restart may clear, else LOTA_EXIT_OPERATOR_ACTION.
 */
int lota_startup_check_exit_status(int err);

/**
 * lota_bpf_load_refusal() - Classify a failed load of the enforcement object.
 * @err: The negative errno bpf_loader_load() returned.
 *
 * A restart does not change the object or the kernel the load failed on.
 *
 * Return: @err for an errno lota_startup_check_exit_status() retries,
 * else -ENOTSUP.
 */
int lota_bpf_load_refusal(int err);

#endif /* LOTA_EXIT_STATUS_H */
