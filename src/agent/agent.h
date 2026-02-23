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

#include "bpf_loader.h"
#include "dbus.h"
#include "hash_verify.h"
#include "ipc.h"
#include "tpm.h"

/* PCR index for LOTA agent self-measurement */
#define LOTA_PCR_SELF 14

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

  uint8_t *policy_verity_digests;
  int policy_verity_digest_count;

  uint32_t *policy_protect_pids; /* sorted unique */
  int policy_protect_pid_count;

  char (*policy_trust_libs)[PATH_MAX]; /* sorted unique */
  int policy_trust_lib_count;
};

extern struct agent_globals g_agent;

int self_measure(struct tpm_context *ctx);
void setup_container_listener(struct ipc_context *ctx);
void setup_dbus(struct ipc_context *ctx);
int ipc_init_or_activate(struct ipc_context *ctx);

#endif /* LOTA_AGENT_H */
