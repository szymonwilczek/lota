/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - Internal shared declarations
 *
 * Globals and helpers used across agent modules.
 * Not part of the public API.
 */

#ifndef LOTA_AGENT_H
#define LOTA_AGENT_H

#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>

#include "../../include/lota.h"
#include "bpf_loader.h"
#include "dbus.h"
#include "hash_verify.h"
#include "ipc.h"
#include "tpm.h"

/* PCR index for LOTA agent self-measurement */
#define LOTA_PCR_SELF 14

/*
 * PCR mask covered by the agent quote that backs every signed IPC
 * token: firmware (PCR0), platform configuration (PCR1), Secure
 * Boot policy (PCR7), and the LOTA self-measurement (PCR14). The
 * mask MUST match the verifier-side PCRPolicy.GetRequiredMask()
 * default so a token signed for a local SDK consumer carries the
 * same firmware-baseline evidence as a remote attestation.
 * Without PCR7 the SDK server cannot reproduce the verifier's
 * Secure Boot gate against the same digest.
 */
#define LOTA_TOKEN_QUOTE_PCR_MASK                                              \
  ((1U << 0) | (1U << 1) | (1U << 7) | (1U << LOTA_PCR_SELF))

/*
 * Agent global runtime state.
 */
struct agent_globals {
  volatile sig_atomic_t running;
  struct tpm_context tpm_ctx;
  struct bpf_loader_ctx bpf_ctx;
  struct ipc_context ipc_ctx;
  struct hash_verify_ctx hash_ctx;
  struct dbus_context *dbus_ctx;
  int mode;

  /*
   * SHA-256 over enforcement-relevant startup policy state (includes allowlist)
   */
  uint8_t policy_digest[32];
  int policy_digest_set;

  /* Canonical snapshot of the current enforcement policy used for digest
   * recompute */
  int policy_snapshot_set;
  int policy_mode;
  bool policy_strict_mmap;
  bool policy_strict_exec;
  bool policy_block_ptrace;
  bool policy_strict_modules;
  bool policy_block_anon_exec;

  struct lota_verity_digest_key *policy_verity_digests;
  int policy_verity_digest_count;

  uint32_t *policy_protect_pids; /* sorted unique */
  int policy_protect_pid_count;
  uint64_t policy_protect_epoch; /* monotonic runtime PID set mutation id */

  char (*policy_trust_libs)[PATH_MAX]; /* sorted unique */
  int policy_trust_lib_count;

  /*
   * Edge-trigger cache for the TPM DA-lockout transition logger.
   * reconcile_tpm_lockout() inspects this to decide whether the
   * current observation crosses the cleared->locked or
   * locked->cleared boundary. Lives on the globals struct (rather
   * than as a function-static) so test harnesses can drive
   * deterministic state and a hypothetical second reconciliation
   * thread shares the same view; the existing single-threaded
   * epoll loop is the only writer today.
   */
  bool tpm_lockout_last_known;
};

extern struct agent_globals g_agent;

int self_measure(struct tpm_context *ctx);
void setup_container_listener(struct ipc_context *ctx);
void setup_dbus(struct ipc_context *ctx);
int ipc_init_or_activate(struct ipc_context *ctx);

#endif /* LOTA_AGENT_H */
