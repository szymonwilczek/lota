/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/* LOTA Agent - the two decisions token issuance turns on */

#ifndef LOTA_AGENT_TOKEN_GATE_H
#define LOTA_AGENT_TOKEN_GATE_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

/**
 * token_gate_needs_attested() - Must this connection hold a verdict?
 * @view_flags: The flags this connection's publisher sees, as
 *              client_attestation_view() built them.
 *
 * A publisher who runs no verifier is not reported to, so holds no verdict on
 * this host.
 *
 * Return: false for such a publisher, true for any other.
 */
bool token_gate_needs_attested(uint32_t view_flags);

/**
 * token_gate_failure_is_fatal() - Does this failure decide the request?
 * @failing_pid: The protected process that could not be measured.
 * @requesting_pid: The process asking for the token.
 *
 * The round measures every protected process on the host, so refusing over
 * another process's failure would let a local program stop token issuance for
 * other titles by protecting itself from an unmeasurable binary.
 *
 * Return: true when the process that cannot be measured is the one asking.
 */
bool token_gate_failure_is_fatal(pid_t failing_pid, pid_t requesting_pid);

#endif /* LOTA_AGENT_TOKEN_GATE_H */
