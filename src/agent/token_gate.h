/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * LOTA Agent - the two decisions token issuance turns on
 *
 * Both are one-line rules with consequences that reach every title on
 * the host, and both were wrong in a way no single-title test could show.
 * They live here so they can be exercised without a TPM, an IPC connection
 * or a second process.
 */

#ifndef LOTA_AGENT_TOKEN_GATE_H
#define LOTA_AGENT_TOKEN_GATE_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

/*
 * token_gate_needs_attested - must this connection hold a verdict
 * @view_flags: the flags this connection's publisher sees,
 *              as client_attestation_view() built them
 *
 * A publisher who runs a verifier is answered with that verifier's
 * verdict, and a token before there is one would claim it.
 * A publisher who runs none is never reported to, so no verdict of theirs
 * can ever exist: for them the token is the evidence, and requiring a verdict
 * first is requiring something that cannot happen.
 */
bool token_gate_needs_attested(uint32_t view_flags);

/*
 * token_gate_failure_is_fatal - does one process's measurement failure decide
 *                               this request
 * @failing_pid:    the protected process that could not be measured
 * @requesting_pid: the process asking for the token
 *
 * The token's runtime digest covers every protected process on the host,
 * so a process nobody asked about can make the fold fail.  Folding that into
 * a refusal hands any local program a way to stop token issuance for every
 * title on the machine by protecting itself from an unmeasurable binary.
 *
 * A publisher controls its own executable and nobody else's, so the refusal
 * is theirs alone: the request fails when the process that cannot be measured
 * is the one asking, and otherwise the process is reported through the coverage
 * flag instead.
 */
bool token_gate_failure_is_fatal(pid_t failing_pid, pid_t requesting_pid);

#endif /* LOTA_AGENT_TOKEN_GATE_H */
