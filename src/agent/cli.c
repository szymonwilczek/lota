/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - CLI argument parsing implementation
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include "cli.h"

#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../include/lota.h"
#include "agent.h"
#include "config.h"
#include "main_utils.h"
#include "net.h"
#include "parse_utils.h"
#include "path_validate.h"
#include "tpm.h"

#define MIN_ATTEST_INTERVAL 30

/* Runtime config populated by --protect-pid / --trust-lib / --allow-verity. */
static uint32_t *g_protect_pids = NULL;
static int g_protect_pid_count = 0;
static char g_trust_libs[LOTA_CONFIG_MAX_LIBS][PATH_MAX];
static int g_trust_lib_count;
static char g_allow_verity[LOTA_CONFIG_MAX_VERITY][PATH_MAX];
static int g_allow_verity_count;

uint32_t **cli_runtime_protect_pids(void)
{
	return &g_protect_pids;
}

int *cli_runtime_protect_pid_count(void)
{
	return &g_protect_pid_count;
}

char (*cli_runtime_trust_libs(void)) [PATH_MAX] { return g_trust_libs; }

int *cli_runtime_trust_lib_count(void)
{
	return &g_trust_lib_count;
}

char (*cli_runtime_allow_verity(void)) [PATH_MAX] { return g_allow_verity; }

int *cli_runtime_allow_verity_count(void)
{
	return &g_allow_verity_count;
}

static int validate_path_arg(const char *key, const char *p)
{
	if (!key || !p)
		return -EINVAL;
	if (p[0] == '\0')
		return -EINVAL;
	if (lota_str_has_control(p)) {
		fprintf(stderr, "Invalid %s: contains control characters\n",
			key);
		return -EINVAL;
	}
	if (!lota_path_is_abs(p)) {
		fprintf(stderr, "Invalid %s: expected absolute path\n", key);
		return -EINVAL;
	}
	if (lota_path_has_dotdot_segment(p)) {
		fprintf(stderr,
			"Invalid %s: '..' path traversal is not allowed\n",
			key);
		return -EINVAL;
	}
	return 0;
}

static int copy_string_checked(const char *field, char *dst, size_t dst_sz,
			       const char *src)
{
	int n;

	if (!field || !dst || !src || dst_sz == 0)
		return -EINVAL;

	n = snprintf(dst, dst_sz, "%s", src);
	if (n < 0)
		return -EIO;

	if ((size_t)n >= dst_sz) {
		fprintf(
		    stderr,
		    "Value for %s is too long (%d bytes), max allowed is %zu\n",
		    field, n, dst_sz - 1);
		return -EOVERFLOW;
	}

	return 0;
}

static int load_config_into_options(struct cli_options *opts,
				    struct lota_config *cfg)
{
	int cfg_ret = config_load(cfg, opts->config_path);
	if (cfg_ret == -ENOENT && !opts->config_path) {
		/* default config file does not exist -> not an error */
	} else if (cfg_ret == -ENOENT) {
		fprintf(stderr, "Config file not found: %s\n",
			opts->config_path);
		return 1;
	} else if (cfg_ret < 0) {
		fprintf(stderr, "Failed to load config %s: %s\n",
			opts->config_path ? opts->config_path
					  : LOTA_CONFIG_DEFAULT_PATH,
			strerror(-cfg_ret));
		return 1;
	}

	opts->server_addr = cfg->server;
	opts->server_port = cfg->port;
	opts->ca_cert_path = cfg->ca_cert[0] ? cfg->ca_cert : NULL;
	opts->pin_sha256_hex = cfg->pin_sha256[0] ? cfg->pin_sha256 : NULL;
	opts->bpf_path = cfg->bpf_path;

	int cfg_mode = parse_mode(cfg->mode);
	if (cfg_mode >= 0) {
		agent_globals_lock(&g_agent);
		g_agent.mode = cfg_mode;
		agent_globals_unlock(&g_agent);
		opts->config_file_mode = cfg_mode;
	}

	opts->strict_mmap = cfg->strict_mmap;
	opts->strict_exec = cfg->strict_exec;
	opts->block_ptrace = cfg->block_ptrace;
	opts->strict_modules = cfg->strict_modules;
	opts->block_anon_exec = cfg->block_anon_exec;
	opts->attest_interval = cfg->attest_interval;
	opts->aik_ttl = cfg->aik_ttl;

	agent_globals_lock(&g_agent);
	g_agent.tpm_ctx.aik_handle = cfg->aik_handle;
	agent_globals_unlock(&g_agent);

	int kret = tpm_set_kernel_path(
	    &g_agent.tpm_ctx, cfg->kernel_path[0] ? cfg->kernel_path : NULL);
	if (kret < 0) {
		fprintf(stderr, "Invalid kernel_path in config: %s\n",
			strerror(-kret));
		return 1;
	}

	opts->daemon_flag = cfg->daemon ? 1 : 0;
	opts->pid_file_path = cfg->pid_file;
	opts->signing_key_path = cfg->signing_key[0] ? cfg->signing_key : NULL;
	opts->policy_pubkey_path =
	    cfg->policy_pubkey[0] ? cfg->policy_pubkey : NULL;

	g_protect_pid_count = 0;
	if (cfg->protect_pid_count > 0) {
		uint32_t *new_pids = realloc(
		    g_protect_pids, cfg->protect_pid_count * sizeof(uint32_t));
		if (!new_pids) {
			fprintf(stderr, "Memory allocation failed while "
					"loading protected PIDs "
					"from config\n");
			return 1;
		}
		g_protect_pids = new_pids;
		for (int i = 0; i < cfg->protect_pid_count; i++)
			g_protect_pids[i] = cfg->protect_pids[i];
		g_protect_pid_count = cfg->protect_pid_count;
	}

	g_trust_lib_count = cfg->trust_lib_count;
	for (int i = 0; i < cfg->trust_lib_count; i++) {
		if (copy_string_checked("trust_libs", g_trust_libs[i],
					sizeof(g_trust_libs[i]),
					cfg->trust_libs[i]) < 0) {
			return 1;
		}
	}

	g_allow_verity_count = cfg->allow_verity_count;
	for (int i = 0; i < cfg->allow_verity_count; i++) {
		if (copy_string_checked("allow_verity", g_allow_verity[i],
					sizeof(g_allow_verity[i]),
					cfg->allow_verity[i]) < 0) {
			return 1;
		}
	}

	return 0;
}

int cli_parse(int argc, char **argv, struct cli_options *opts,
	      struct lota_config *cfg)
{
	int opt;

	static struct option long_options[] = {
	    {"config", required_argument, 0, 'f'},
	    {"dump-config", no_argument, 0, 'Z'},
	    {"test-tpm", no_argument, 0, 't'},
	    {"test-iommu", no_argument, 0, 'i'},
	    {"test-ipc", no_argument, 0, 'c'},
	    {"test-signed", no_argument, 0, 'S'},
	    {"shutdown", no_argument, 0, 1001},
	    {"export-policy", no_argument, 0, 'E'},
	    {"attest", no_argument, 0, 'a'},
	    {"attest-interval", required_argument, 0, 'I'},
	    {"server", required_argument, 0, 's'},
	    {"port", required_argument, 0, 'p'},
	    {"ca-cert", required_argument, 0, 'C'},
	    {"no-verify-tls", no_argument, 0, 'K'},
	    {"insecure-allow-no-verify-tls", no_argument, 0, 1000},
	    {"insecure-allow-mode-downgrade", no_argument, 0, 1002},
	    {"insecure-allow-mutable-rootfs", no_argument, 0, 1003},
	    {"pin-sha256", required_argument, 0, 'F'},
	    {"bpf", required_argument, 0, 'b'},
	    {"mode", required_argument, 0, 'm'},
	    {"strict-mmap", no_argument, 0, 'M'},
	    {"strict-exec", no_argument, 0, 'Y'},
	    {"block-ptrace", no_argument, 0, 'P'},
	    {"strict-modules", no_argument, 0, 'J'},
	    {"block-anon-exec", no_argument, 0, 'X'},
	    {"protect-pid", required_argument, 0, 'R'},
	    {"trust-lib", required_argument, 0, 'L'},
	    {"allow-verity", required_argument, 0, 'A'},
	    {"daemon", no_argument, 0, 'd'},
	    {"pid-file", required_argument, 0, 'D'},
	    {"aik-ttl", required_argument, 0, 'T'},
	    {"gen-signing-key", required_argument, 0, 'G'},
	    {"sign-policy", required_argument, 0, 'g'},
	    {"verify-policy", required_argument, 0, 'V'},
	    {"signing-key", required_argument, 0, 'k'},
	    {"policy-pubkey", required_argument, 0, 'Q'},
	    {"help", no_argument, 0, 'h'},
	    {0, 0, 0, 0}};

	memset(opts, 0, sizeof(*opts));
	opts->bpf_path = LOTA_CLI_DEFAULT_BPF_PATH;
	opts->server_addr = "localhost";
	opts->server_port = LOTA_CLI_DEFAULT_VERIFIER_PORT;
	opts->aik_ttl = LOTA_CLI_DEFAULT_AIK_TTL;
	opts->config_file_mode = -1;

	/* Pre-scan for --config so config_load() runs before option defaults.
	 */
	for (int i = 1; i < argc; i++) {
		if ((strcmp(argv[i], "--config") == 0 ||
		     strcmp(argv[i], "-f") == 0) &&
		    i + 1 < argc) {
			opts->config_path = argv[++i];
		}
	}

	int rc = load_config_into_options(opts, cfg);
	if (rc != 0)
		return rc;

	while ((opt = getopt_long(
		    argc, argv,
		    "f:ZticSEaI:s:p:C:KF:b:m:MPJYXR:L:A:dD:T:G:g:V:k:Q:h",
		    long_options, NULL)) != -1) {
		switch (opt) {
		case 't':
			opts->test_tpm_flag = 1;
			break;
		case 'i':
			opts->test_iommu_flag = 1;
			break;
		case 'c':
			opts->test_ipc_flag = 1;
			break;
		case 'S':
			opts->test_signed_flag = 1;
			break;
		case 1001:
			opts->shutdown_flag = 1;
			break;
		case 'E':
			opts->export_policy_flag = 1;
			break;
		case 'a':
			opts->attest_flag = 1;
			break;
		case 'I':
			opts->attest_flag = 1;
			{
				long v;
				if (safe_parse_long(optarg, &v) < 0 || v < 0 ||
				    v > INT_MAX) {
					fprintf(stderr,
						"Invalid interval: %s\n",
						optarg);
					return 1;
				}
				opts->attest_interval = (int)v;
			}
			if (opts->attest_interval != 0 &&
			    opts->attest_interval < MIN_ATTEST_INTERVAL) {
				fprintf(stderr,
					"Warning: interval %d too low, using "
					"minimum %d seconds\n",
					opts->attest_interval,
					MIN_ATTEST_INTERVAL);
				opts->attest_interval = MIN_ATTEST_INTERVAL;
			}
			break;
		case 's':
			opts->server_addr = optarg;
			opts->server_overridden = true;
			break;
		case 'p': {
			long v;
			if (safe_parse_long(optarg, &v) < 0 || v <= 0 ||
			    v > 65535) {
				fprintf(stderr, "Invalid port: %s\n", optarg);
				return 1;
			}
			opts->server_port = (int)v;
		} break;
		case 'C':
			opts->ca_cert_path = optarg;
			break;
		case 'K':
			opts->no_verify_tls = 1;
			break;
		case 1000:
			opts->insecure_allow_no_verify_tls = 1;
			break;
		case 1002:
			opts->insecure_allow_mode_downgrade = 1;
			break;
		case 1003:
			opts->insecure_allow_mutable_rootfs = 1;
			break;
		case 'F':
			opts->pin_sha256_hex = optarg;
			break;
		case 'b':
			opts->bpf_path = optarg;
			break;
		case 'm': {
			int opt_mode = parse_mode(optarg);
			if (opt_mode < 0) {
				fprintf(stderr, "Invalid mode: %s\n", optarg);
				fprintf(stderr, "Valid modes: monitor, "
						"enforce, maintenance\n");
				return 1;
			}
			agent_globals_lock(&g_agent);
			g_agent.mode = opt_mode;
			agent_globals_unlock(&g_agent);
			opts->cli_mode_set = true;
			break;
		}
		case 'M':
			opts->strict_mmap = true;
			break;
		case 'Y':
			opts->strict_exec = true;
			break;
		case 'P':
			opts->block_ptrace = true;
			break;
		case 'J':
			opts->strict_modules = true;
			break;
		case 'X':
			opts->block_anon_exec = true;
			break;
		case 'R': {
			uint32_t v;
			if (safe_parse_u32_dec(optarg, &v) < 0 || v == 0) {
				fprintf(stderr, "Invalid PID: %s\n", optarg);
				return 1;
			}
			if (g_protect_pid_count >= LOTA_MAX_PROTECTED_PIDS) {
				fprintf(
				    stderr,
				    "Too many --protect-pid entries (max %d)\n",
				    LOTA_MAX_PROTECTED_PIDS);
				return 1;
			}
			uint32_t *new_pids =
			    realloc(g_protect_pids, (g_protect_pid_count + 1) *
							sizeof(uint32_t));
			if (!new_pids) {
				fprintf(stderr, "Memory allocation failed for "
						"protected PID\n");
				return 1;
			}
			g_protect_pids = new_pids;
			g_protect_pids[g_protect_pid_count++] = v;
		} break;
		case 'L':
			if (g_trust_lib_count < LOTA_CONFIG_MAX_LIBS) {
				if (copy_string_checked(
					"trust-lib",
					g_trust_libs[g_trust_lib_count],
					sizeof(g_trust_libs[g_trust_lib_count]),
					optarg) < 0) {
					return 1;
				}
				g_trust_lib_count++;
			} else {
				fprintf(
				    stderr,
				    "Too many --trust-lib entries (max %d)\n",
				    LOTA_CONFIG_MAX_LIBS);
				return 1;
			}
			break;
		case 'A':
			if (g_allow_verity_count >= LOTA_CONFIG_MAX_VERITY) {
				fprintf(stderr,
					"Too many --allow-verity entries (max "
					"%d)\n",
					LOTA_CONFIG_MAX_VERITY);
				return 1;
			}
			if (validate_path_arg("allow-verity", optarg) < 0)
				return 1;
			if (copy_string_checked(
				"allow-verity",
				g_allow_verity[g_allow_verity_count],
				sizeof(g_allow_verity[g_allow_verity_count]),
				optarg) < 0) {
				return 1;
			}
			g_allow_verity_count++;
			break;
		case 'd':
			opts->daemon_flag = 1;
			break;
		case 'D':
			opts->pid_file_path = optarg;
			break;
		case 'T': {
			uint32_t v;
			if (safe_parse_u32_dec(optarg, &v) < 0) {
				fprintf(stderr, "Invalid AIK TTL: %s\n",
					optarg);
				return 1;
			}
			opts->aik_ttl = v;
		}
			if (opts->aik_ttl > 0 && opts->aik_ttl < 3600) {
				fprintf(stderr,
					"Warning: AIK TTL %u too low, using "
					"3600s (1 hour)\n",
					opts->aik_ttl);
				opts->aik_ttl = 3600;
			}
			break;
		case 'G':
			opts->gen_signing_key_prefix = optarg;
			break;
		case 'g':
			opts->sign_policy_file = optarg;
			break;
		case 'V':
			opts->verify_policy_file = optarg;
			break;
		case 'k':
			opts->signing_key_path = optarg;
			break;
		case 'Q':
			opts->policy_pubkey_path = optarg;
			break;
		case 'f':
			/* --config: handled in pre-scan above */
			break;
		case 'Z':
			opts->dump_config_flag = 1;
			break;
		case 'h':
		default:
			print_usage(argv[0], LOTA_CLI_DEFAULT_BPF_PATH,
				    LOTA_CLI_DEFAULT_VERIFIER_PORT);
			return (opt == 'h') ? -1 : 1;
		}
	}

	return 0;
}

int cli_finalize_pin(struct cli_options *opts)
{
	if (!opts->pin_sha256_hex)
		return 0;
	if (net_parse_pin_sha256(opts->pin_sha256_hex, opts->pin_sha256_bin) <
	    0) {
		fprintf(stderr,
			"Invalid --pin-sha256 value: '%s'\n"
			"Expected 64 hex characters (colons/spaces "
			"allowed).\n"
			"Example: openssl x509 -in cert.pem "
			"-fingerprint -sha256 -noout\n",
			opts->pin_sha256_hex);
		return 1;
	}
	opts->has_pin = 1;
	if (opts->no_verify_tls) {
		fprintf(stderr, "Warning: --pin-sha256 with "
				"--no-verify-tls: PKI validation\n"
				"is disabled but certificate pinning "
				"remains active.\n");
	}
	return 0;
}

int cli_dump_config(struct cli_options *opts, struct lota_config *cfg)
{
	if (opts->server_overridden) {
		if (copy_string_checked("server", cfg->server,
					sizeof(cfg->server),
					opts->server_addr) < 0) {
			return 1;
		}
	}
	cfg->port = opts->server_port;
	if (opts->ca_cert_path) {
		if (opts->ca_cert_path != cfg->ca_cert) {
			if (copy_string_checked("ca_cert", cfg->ca_cert,
						sizeof(cfg->ca_cert),
						opts->ca_cert_path) < 0) {
				return 1;
			}
		}
	} else {
		cfg->ca_cert[0] = '\0';
	}
	if (opts->pin_sha256_hex) {
		if (opts->pin_sha256_hex != cfg->pin_sha256) {
			if (copy_string_checked("pin_sha256", cfg->pin_sha256,
						sizeof(cfg->pin_sha256),
						opts->pin_sha256_hex) < 0) {
				return 1;
			}
		}
	} else {
		cfg->pin_sha256[0] = '\0';
	}

	if (opts->bpf_path != cfg->bpf_path) {
		if (copy_string_checked("bpf_path", cfg->bpf_path,
					sizeof(cfg->bpf_path),
					opts->bpf_path) < 0) {
			return 1;
		}
	}
	if (g_agent.mode == LOTA_MODE_ENFORCE)
		snprintf(cfg->mode, sizeof(cfg->mode), "enforce");
	else if (g_agent.mode == LOTA_MODE_MAINTENANCE)
		snprintf(cfg->mode, sizeof(cfg->mode), "maintenance");
	else
		snprintf(cfg->mode, sizeof(cfg->mode), "monitor");

	cfg->strict_mmap = opts->strict_mmap;
	cfg->block_ptrace = opts->block_ptrace;
	cfg->strict_modules = opts->strict_modules;
	cfg->block_anon_exec = opts->block_anon_exec;
	cfg->attest_interval = opts->attest_interval;
	cfg->aik_ttl = opts->aik_ttl;
	cfg->aik_handle = g_agent.tpm_ctx.aik_handle;
	cfg->daemon = opts->daemon_flag ? true : false;
	if (opts->pid_file_path != cfg->pid_file) {
		if (copy_string_checked("pid_file", cfg->pid_file,
					sizeof(cfg->pid_file),
					opts->pid_file_path) < 0) {
			return 1;
		}
	}

	if (opts->signing_key_path) {
		if (opts->signing_key_path != cfg->signing_key) {
			if (copy_string_checked("signing_key", cfg->signing_key,
						sizeof(cfg->signing_key),
						opts->signing_key_path) < 0) {
				return 1;
			}
		}
	} else {
		cfg->signing_key[0] = '\0';
	}

	if (opts->policy_pubkey_path) {
		if (opts->policy_pubkey_path != cfg->policy_pubkey) {
			if (copy_string_checked("policy_pubkey",
						cfg->policy_pubkey,
						sizeof(cfg->policy_pubkey),
						opts->policy_pubkey_path) < 0) {
				return 1;
			}
		}
	} else {
		cfg->policy_pubkey[0] = '\0';
	}

	cfg->trust_lib_count = g_trust_lib_count;
	for (int i = 0; i < g_trust_lib_count; i++) {
		if (copy_string_checked("trust_libs", cfg->trust_libs[i],
					sizeof(cfg->trust_libs[i]),
					g_trust_libs[i]) < 0) {
			return 1;
		}
	}

	cfg->allow_verity_count = g_allow_verity_count;
	for (int i = 0; i < g_allow_verity_count; i++) {
		if (copy_string_checked("allow_verity", cfg->allow_verity[i],
					sizeof(cfg->allow_verity[i]),
					g_allow_verity[i]) < 0) {
			return 1;
		}
	}

	free(cfg->protect_pids);
	cfg->protect_pids = NULL;
	cfg->protect_pid_count = 0;
	if (g_protect_pid_count > 0) {
		cfg->protect_pids =
		    malloc(g_protect_pid_count * sizeof(uint32_t));
		if (!cfg->protect_pids) {
			fprintf(stderr, "Warning: failed to allocate "
					"protect_pid list for dump-config\n");
		} else {
			memcpy(cfg->protect_pids, g_protect_pids,
			       g_protect_pid_count * sizeof(uint32_t));
			cfg->protect_pid_count = g_protect_pid_count;
		}
	}

	config_dump(cfg, stdout);
	return 0;
}
