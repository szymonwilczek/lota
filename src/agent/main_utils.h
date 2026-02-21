/* SPDX-License-Identifier: MIT */
#ifndef LOTA_MAIN_UTILS_H
#define LOTA_MAIN_UTILS_H

#include <stdbool.h>
#include <stdint.h>

#include "ipc.h"
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
void setup_container_listener(struct ipc_context *ctx);
int ipc_init_or_activate(struct ipc_context *ctx);
int self_measure(struct tpm_context *ctx);
int poison_runtime_pcr(struct tpm_context *ctx);

#endif /* LOTA_MAIN_UTILS_H */
