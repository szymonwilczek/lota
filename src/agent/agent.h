/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - daemon state shared across modules.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_AGENT_H
#define LOTA_AGENT_H

#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>

#include "../../include/lota.h"
#include "bpf_loader.h"
#include "container_watch.h"
#include "dbus.h"
#include "hash_verify.h"
#include "ipc.h"
#include "tpm.h"

#define LOTA_PCR_SELF 14

/* VerifyBootEvidence() in sdk/server needs PCR 7 in the token quote */
#define LOTA_TOKEN_QUOTE_PCR_MASK \
	((1U << 0) | (1U << 1) | (1U << 7) | (1U << LOTA_PCR_SELF))

struct agent_globals {
	volatile sig_atomic_t running;
	struct tpm_context tpm_ctx;
	struct bpf_loader_ctx bpf_ctx;
	struct ipc_context ipc_ctx;
	struct hash_verify_ctx hash_ctx;
	struct dbus_context *dbus_ctx;
	struct container_watch container_watch;
	int mode;

	uint8_t policy_digest[32];
	int policy_digest_set;

	int policy_snapshot_set;

	struct lota_verity_digest_key *policy_verity_digests;
	int policy_verity_digest_count;

	uint32_t *policy_protect_pids;
	int policy_protect_pid_count;
	/* 0 for the startup set, bumped on each runtime change */
	uint64_t policy_protect_epoch;

	/* lockout state reconcile_tpm_lockout() last saw */
	bool tpm_lockout_last_known;
};

extern struct agent_globals g_agent;

/* Mark a write to agent_globals; no-ops with one event loop thread */
static inline void agent_globals_lock(struct agent_globals *agent)
{
	(void)agent;
}

static inline void agent_globals_unlock(struct agent_globals *agent)
{
	(void)agent;
}

int self_measure(struct tpm_context *ctx);
struct lota_config;
void setup_container_listener(struct ipc_context *ctx,
			      const struct lota_config *cfg);
void setup_dbus(struct ipc_context *ctx);
int ipc_init_or_activate(struct ipc_context *ctx);

#endif /* LOTA_AGENT_H */
