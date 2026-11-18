/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
#ifndef LOTA_SHUTDOWN_H
#define LOTA_SHUTDOWN_H

#include <stdbool.h>

#include "bpf_loader.h"
#include "tpm.h"

/**
 * poison_runtime_pcr() - Spend this boot's PCR 14 commitment.
 * @ctx: an initialized TPM context.
 * @requested: true for a requested stop, false for a failed run.
 *
 * Extends PCR 14 with a random digest, or with 0xDE bytes when
 * getrandom() fails. Then, best effort, records the new value in the
 * clock-state snapshot with LOTA_CLOCK_STATE_FLAG_SHUTDOWN_POISON when
 * @requested, else LOTA_CLOCK_STATE_FLAG_ERROR_POISON, so a later start of
 * this boot reports TPM_PCR14_SPENT_BY_SHUTDOWN or TPM_PCR14_SPENT_BY_ERROR.
 *
 * Return: 0 once the extend succeeded, -EINVAL without an initialized
 * @ctx, or the error of the extend.
 */
int poison_runtime_pcr(struct tpm_context *ctx, bool requested);

/**
 * agent_poison_runtime_pcr_before_bpf_unload() - Poison on the way out.
 * @tpm: the agent's TPM context.
 * @bpf: the agent's BPF loader context.
 * @current_ret: the result so far, 0 or a negative errno.
 *
 * Poisons only when @tpm is initialized and @bpf is loaded.
 * A @current_ret of 0 is a requested stop, a negative one a failed run.
 *
 * Return: @current_ret, or the poison error when @current_ret is 0.
 */
int agent_poison_runtime_pcr_before_bpf_unload(struct tpm_context *tpm,
					       const struct bpf_loader_ctx *bpf,
					       int current_ret);

#endif /* LOTA_SHUTDOWN_H */
