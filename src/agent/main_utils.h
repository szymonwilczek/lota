/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
#ifndef LOTA_MAIN_UTILS_H
#define LOTA_MAIN_UTILS_H

#include <stdbool.h>
#include <stdint.h>

#include "config.h"
#include "ipc.h"
#include "shutdown.h"
#include "tpm.h"

const char *mode_to_string(int mode);
int parse_mode(const char *mode_str);
void print_usage(const char *prog, const char *default_bpf_path,
		 int default_verifier_port);

struct policy_ops_args {
	const char *gen_signing_key_prefix;
	const char *sign_policy_file;
	const char *verify_policy_file;
	const char *signing_key_path;
	const char *policy_pubkey_path;
};

int handle_policy_ops(const struct policy_ops_args *args);
void setup_dbus(struct ipc_context *ctx);
/**
 * setup_container_listener() - Serve the socket a containerized title reaches.
 * @ctx: The IPC context.
 * @cfg: The config, or NULL.
 *
 * Each container_listener_uid in @cfg gets /run/user/<uid>/lota/lota.sock
 * while that user is logged in. Without them, an XDG_RUNTIME_DIR of the form
 * /run/user/<uid> is watched the same way, and any other one gets a listener
 * in it, bound once. Failures are logged.
 */
void setup_container_listener(struct ipc_context *ctx,
			      const struct lota_config *cfg);
int ipc_init_or_activate(struct ipc_context *ctx);

/**
 * self_measure() - Commit the running binary into PCR 14.
 * @ctx: An initialized TPM context.
 *
 * Return: TPM_BOOT_COMMITMENT_EXTENDED when this call extended PCR 14,
 * TPM_BOOT_COMMITMENT_ALREADY_HELD when the register already held this boot's
 * commitment, or a negative errno; -EBADMSG for a refused commitment,
 * with the reason in ctx->boot_commitment_state.
 */
int self_measure(struct tpm_context *ctx);

#endif /* LOTA_MAIN_UTILS_H */
