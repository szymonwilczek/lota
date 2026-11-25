/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - CLI argument parsing
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_AGENT_CLI_H
#define LOTA_AGENT_CLI_H

#include <linux/limits.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>

#include "config.h"
#include "net.h"
#include "pin.h"

#define LOTA_CLI_DEFAULT_BPF_PATH "/usr/lib/lota/lota_lsm.bpf.o"
#define LOTA_CLI_DEFAULT_AIK_TTL 0 /* 0 -> use TPM_AIK_DEFAULT_TTL_SEC */

struct cli_options {
	/* diagnostic / admin one-shots */
	int test_tpm_flag;
	int test_iommu_flag;
	int test_ipc_flag;
	int test_signed_flag;
	int shutdown_flag;
	int status_flag;
	/* --terminate-protected PID: SIGTERM, or SIGKILL with --force */
	uint32_t terminate_protected_pid;
	int terminate_protected_flag;
	int force_flag;
	int dump_config_flag;
	int export_policy_flag;
	int attest_flag;
	int enroll_flag;
	int reenroll_flag; /* --reenroll: reuse the saved endpoint */
	int seal_flag;
	int unseal_flag;
	int seal_aik_auth_migrate_flag; /* --seal-aik-auth: adopt sealing */
	int reprovision_aik_flag; /* --reprovision-aik: strict recovery */
	int seal_persist_primary_flag;
	int seal_evict_primary_flag;
	const char *seal_pcrs; /* PCR mask string for --seal; NULL = default */
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

	bool bench;

	/* daemon lifecycle */
	int daemon_flag;
	const char *pid_file_path;

	const char *bpf_path;
	const char *server_addr;
	bool server_overridden;
	int server_port;
	const char *ca_cert_path;

	/* attestation-CA enrollment endpoint (--enroll) */
	const char *ca_server;
	int ca_port;
	bool ca_port_given; /* --ca-port given, not the default */
	const char *enroll_token_file; /* --enroll-token-file: tenant token */
	/* --allow-publisher: record consent to answer to one publisher,
	 * named by the hex SHA-256 of its CA anchor's SPKI */
	const char *allow_publisher;

	/*
	 * --add-publisher writes a [profile] section into lota.conf.
	 * It records no consent: --allow-publisher does.
	 */
	const char *add_publisher;
	const char *publisher_name; /* --publisher-name, the section label */
	bool reporting_continuous; /* --reporting continuous */
	int list_publishers_flag;
	/* --forget-publisher: destroy one publisher's key and stored state */
	const char *forget_publisher;
	int no_verify_tls;
	int insecure_allow_no_verify_tls;
	int insecure_allow_mode_downgrade;
	int insecure_allow_mutable_rootfs;
	const char *pin_sha256_hex;
	uint8_t pin_sha256_bin[LOTA_PIN_SHA256_LEN];
	int has_pin;

	/* mode tracking */
	bool cli_mode_set;
	int config_file_mode;
};

/**
 * cli_parse() - Parse argv over the config file's values.
 * @argc: Argument count.
 * @argv: The arguments.
 * @out: Receives the options.
 * @cfg: Receives the config file; @out points into it.
 *
 * Loads --config or the default path, then layers the flags on top. Also sets
 * g_agent.mode and the AIK handle, sealing flags and kernel path in
 * g_agent.tpm_ctx, and fills the lists behind the accessors below.
 *
 * Return: 0 on success, -1 after printing help for --help, or a positive
 * program exit code on a parse error.
 */
int cli_parse(int argc, char **argv, struct cli_options *out,
	      struct lota_config *cfg);

/**
 * cli_dump_config() - Print the merged config for --dump-config.
 * @opts: The parsed options.
 * @cfg: The config; the merge overwrites it.
 *
 * Return: the program exit code.
 */
int cli_dump_config(struct cli_options *opts, struct lota_config *cfg);

/**
 * cli_finalize_pin() - Parse the pin from the flag or the file into @opts.
 * @opts: The options; receives pin_sha256_bin and has_pin.
 *
 * Warns when the pin is combined with --no-verify-tls.
 *
 * Return: 0, or 1 for a malformed pin.
 */
int cli_finalize_pin(struct cli_options *opts);

/* The lists cli_parse() builds from the file and the flags. */
uint32_t **cli_runtime_protect_pids(void);
int *cli_runtime_protect_pid_count(void);
char (*cli_runtime_trust_libs(void))[PATH_MAX];
int *cli_runtime_trust_lib_count(void);
char (*cli_runtime_allow_verity(void))[PATH_MAX];
int *cli_runtime_allow_verity_count(void);

/*
 * Which enforcement switches the command line turned on, so that a reload keeps
 * them.
 */
#define LOTA_CLI_SWITCH_STRICT_MMAP (1U << 0)
#define LOTA_CLI_SWITCH_STRICT_EXEC (1U << 1)
#define LOTA_CLI_SWITCH_BLOCK_PTRACE (1U << 2)
#define LOTA_CLI_SWITCH_STRICT_MODULES (1U << 3)
#define LOTA_CLI_SWITCH_BLOCK_ANON_EXEC (1U << 4)

uint32_t cli_startup_switch_mask(void);

/*
 * The --trust-lib and --protect-pid entries alone, so that a reload keeps them;
 * the lists above also hold the file's. Empty without those flags.
 */
const char (*cli_startup_trust_libs(void))[PATH_MAX];
int cli_startup_trust_lib_count(void);
const uint32_t *cli_startup_protect_pids(void);
int cli_startup_protect_pid_count(void);

#endif /* LOTA_AGENT_CLI_H */
