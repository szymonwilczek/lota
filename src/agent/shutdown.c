/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */

#include "shutdown.h"

#include <errno.h>
#include <string.h>
#include <sys/random.h>
#include <stdint.h>
#include <sys/types.h>

#include "../../include/lota.h"
#include "agent.h"
#include "journal.h"

int poison_runtime_pcr(struct tpm_context *ctx)
{
	uint8_t poison_digest[LOTA_HASH_SIZE];
	size_t off = 0;
	int use_fallback = 0;

	if (!ctx || !ctx->initialized)
		return -EINVAL;

	while (off < sizeof(poison_digest)) {
		ssize_t got = getrandom(poison_digest + off,
					sizeof(poison_digest) - off, 0);
		if (got < 0) {
			if (errno == EINTR)
				continue;
			use_fallback = 1;
			break;
		}
		if (got == 0) {
			use_fallback = 1;
			break;
		}
		off += (size_t)got;
	}

	if (use_fallback)
		memset(poison_digest, 0xDE, sizeof(poison_digest));

	return tpm_pcr_extend(ctx, LOTA_PCR_SELF, poison_digest);
}

int agent_poison_runtime_pcr_before_bpf_unload(struct tpm_context *tpm,
					       const struct bpf_loader_ctx *bpf,
					       int current_ret)
{
	int poison_ret;

	if (!tpm || !bpf || !tpm->initialized || !bpf->loaded)
		return current_ret;

	poison_ret = poison_runtime_pcr(tpm);
	if (poison_ret < 0) {
		lota_err("Failed to poison runtime PCR before BPF unload: %s",
			 strerror(-poison_ret));
		if (current_ret == 0)
			current_ret = poison_ret;
	} else {
		lota_notice("Runtime PCR poisoned before BPF unload");
	}

	return current_ret;
}
