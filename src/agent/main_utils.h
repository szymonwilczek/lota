/* SPDX-License-Identifier: MIT */
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
/*
 * @cfg: when non-NULL and container_listener_uid_count > 0, lay down
 *       one /run/user/<uid>/lota/lota.sock listener per configured UID.
 *       Otherwise fall back to the legacy XDG_RUNTIME_DIR-driven path
 *       (single secondary listener for the agent's own runtime dir,
 *       pinned by the systemd drop-in on single-operator hosts).
 */
void setup_container_listener(struct ipc_context *ctx,
			      const struct lota_config *cfg);
int ipc_init_or_activate(struct ipc_context *ctx);
int self_measure(struct tpm_context *ctx);

#endif /* LOTA_MAIN_UTILS_H */
