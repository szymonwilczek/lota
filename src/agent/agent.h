/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - Internal shared declarations
 *
 * Globals and helpers used across agent modules.
 * Not part of the public API.
 */

#ifndef LOTA_AGENT_H
#define LOTA_AGENT_H

#include <signal.h>
#include <stdint.h>

#include "bpf_loader.h"
#include "hash_verify.h"
#include "ipc.h"
#include "tpm.h"

/* PCR index for LOTA agent self-measurement */
#define LOTA_PCR_SELF 14

struct dbus_context;

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
};

extern struct agent_globals g_agent;

int self_measure(struct tpm_context *ctx);
void setup_container_listener(struct ipc_context *ctx);
void setup_dbus(struct ipc_context *ctx);
int ipc_init_or_activate(struct ipc_context *ctx);

#endif /* LOTA_AGENT_H */
