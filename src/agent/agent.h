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

/* PCR index for LOTA agent self-measurement */
#define LOTA_PCR_SELF 14

struct tpm_context;
struct bpf_loader_ctx;
struct ipc_context;
struct dbus_context;
struct hash_verify_ctx;

extern volatile sig_atomic_t g_running;
extern struct tpm_context g_tpm_ctx;
extern struct bpf_loader_ctx g_bpf_ctx;
extern struct ipc_context g_ipc_ctx;
extern struct hash_verify_ctx g_hash_ctx;
extern struct dbus_context *g_dbus_ctx;
extern int g_mode;

int self_measure(struct tpm_context *ctx);
void setup_container_listener(struct ipc_context *ctx);
void setup_dbus(struct ipc_context *ctx);
int ipc_init_or_activate(struct ipc_context *ctx);

#endif /* LOTA_AGENT_H */
