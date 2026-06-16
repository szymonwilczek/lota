/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
#ifndef LOTA_SHUTDOWN_H
#define LOTA_SHUTDOWN_H

#include "bpf_loader.h"
#include "tpm.h"

int poison_runtime_pcr(struct tpm_context *ctx);
int agent_poison_runtime_pcr_before_bpf_unload(struct tpm_context *tpm,
					       const struct bpf_loader_ctx *bpf,
					       int current_ret);

#endif /* LOTA_SHUTDOWN_H */
