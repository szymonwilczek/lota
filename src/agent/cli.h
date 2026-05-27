/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - CLI argument parsing
 *
 * Encapsulates getopt_long, defaults sourced from the on-disk config,
 * and the per-flag validation.
 * main() consumes the resulting struct cli_options and dispatches into
 * the diagnostic or daemon path; it never touches the option table or
 * the per-option case bodies directly.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_AGENT_CLI_H
#define LOTA_AGENT_CLI_H

#include <linux/limits.h>
#include <stdbool.h>
#include <stdint.h>

#include "config.h"
#include "net.h"

#define LOTA_CLI_DEFAULT_BPF_PATH "/usr/lib/lota/lota_lsm.bpf.o"
#define LOTA_CLI_DEFAULT_VERIFIER_PORT 8443
#define LOTA_CLI_DEFAULT_AIK_TTL 0 /* 0 -> use TPM_AIK_DEFAULT_TTL_SEC */

struct cli_options {
	/* diagnostic / admin one-shots */
	int test_tpm_flag;
	int test_iommu_flag;
	int test_ipc_flag;
	int test_signed_flag;
	int shutdown_flag;
	int dump_config_flag;
	int export_policy_flag;
	int attest_flag;
	const char *gen_signing_key_prefix;
	const char *sign_policy_file;
	const char *verify_policy_file;

	/* shared inputs */
	const char *signing_key_path;
	const char *policy_pubkey_path;
	const char *config_path;
	int attest_interval;
	uint32_t aik_ttl;

	/* enforcement toggles */
	bool strict_mmap;
	bool strict_exec;
	bool block_ptrace;
	bool strict_modules;
	bool block_anon_exec;

	/* daemon lifecycle */
	int daemon_flag;
	const char *pid_file_path;

	/* networking */
	const char *bpf_path;
	const char *server_addr;
	bool server_overridden;
	int server_port;
	const char *ca_cert_path;
	int no_verify_tls;
	int insecure_allow_no_verify_tls;
	int insecure_allow_mode_downgrade;
	int insecure_allow_mutable_rootfs;
	const char *pin_sha256_hex;
	uint8_t pin_sha256_bin[NET_PIN_SHA256_LEN];
	int has_pin;

	/* mode tracking */
	bool cli_mode_set;
	int config_file_mode;
};

/*
 * Parse argv into a fully-resolved cli_options. The function loads the
 * on-disk config (via --config or the default path), seeds defaults from
 * it, then layers the CLI overrides on top. Side effects:
 *
 *   - mutates g_agent.mode and g_agent.tpm_ctx.aik_handle while parsing
 *     the config, mirroring the behavior of the previous inline parser;
 *   - populates the module-local runtime lists exposed via the
 *     cli_runtime_* accessors below.
 *
 * Returns 0 on success, a positive program exit code on a parse error
 * that the binary should report and exit with.
 */
int cli_parse(int argc, char **argv, struct cli_options *out,
	      struct lota_config *cfg);

/*
 * Emit the merged CLI+config view of struct lota_config on stdout, as
 * driven by --dump-config. Returns the program exit code.
 */
int cli_dump_config(struct cli_options *opts, struct lota_config *cfg);

/*
 * Validate parsed pin/no-verify-tls combinations once parsing is done.
 * Returns 0 on success, a non-zero program exit code on error.
 */
int cli_finalize_pin(struct cli_options *opts);

/* Runtime lists populated by cli_parse(), shared with run_daemon(). */
uint32_t **cli_runtime_protect_pids(void);
int *cli_runtime_protect_pid_count(void);
char (*cli_runtime_trust_libs(void))[PATH_MAX];
int *cli_runtime_trust_lib_count(void);
char (*cli_runtime_allow_verity(void))[PATH_MAX];
int *cli_runtime_allow_verity_count(void);

#endif /* LOTA_AGENT_CLI_H */
