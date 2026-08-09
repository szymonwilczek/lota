/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */

#include "shutdown.h"

#include <errno.h>
#include <string.h>
#include <sys/random.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

#include "../../include/lota.h"
#include "agent.h"
#include "journal.h"

int poison_runtime_pcr(struct tpm_context *ctx)
{
	uint8_t poison_digest[LOTA_HASH_SIZE];
	size_t off = 0;
	int use_fallback = 0;
	int ret;

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

	ret = tpm_pcr_extend(ctx, LOTA_PCR_SELF, poison_digest);
	if (ret < 0)
		return ret;

	/*
	 * Record that this host spent its own commitment, so the next start
	 * reports a paused agent.
	 * Best effort: losing the note costs the wording of a refusal that
	 * happens either way.
	 */
	{
		struct lota_clock_state snap = { 0 };

		/*
		 * Keep the counters the successful extend recorded;
		 * only the register value and the reason change
		 */
		if (tpm_clock_state_load(ctx, &snap) < 0)
			memset(&snap, 0, sizeof(snap));

		if (tpm_read_pcr(ctx, LOTA_PCR_SELF, TPM_HASH_ALG,
				 snap.pcr14) == 0) {
			snap.saved_at = (int64_t)time(NULL);
			snap.flags |= LOTA_CLOCK_STATE_FLAG_SHUTDOWN_POISON;
			(void)tpm_clock_state_save(ctx, &snap);
		}
	}

	return 0;
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
