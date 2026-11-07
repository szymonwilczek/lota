/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - Diagnostic and admin one-shot dispatch
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include "diagnostics.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdbool.h>

#include "../../include/lota_ipc.h"
#include "agent.h"
#include "attest.h"
#include "daemon.h"
#include "enroll.h"
#include "io_utils.h"
#include "main_utils.h"
#include "selftest.h"
#include "status_cmd.h"
#include "terminate_report.h"
#include "test_servers.h"
#include "tpm.h"

#define SHUTDOWN_WAIT_MS 60000

static int ipc_request_shutdown(void)
{
	struct sockaddr_un addr;
	struct lota_ipc_request req = {
		.magic = LOTA_IPC_MAGIC,
		.version = LOTA_IPC_VERSION,
		.cmd = LOTA_IPC_CMD_SHUTDOWN,
		.payload_len = 0,
	};
	struct lota_ipc_response resp;
	int fd;
	int ret;

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, LOTA_IPC_SOCKET_PATH, sizeof(addr.sun_path) - 1);

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		ret = -errno;
		close(fd);
		return ret;
	}

	ret = lota_write_full(fd, &req, sizeof(req));
	if (ret < 0) {
		close(fd);
		return ret;
	}

	ret = lota_read_full(fd, &resp, sizeof(resp));
	close(fd);
	if (ret < 0)
		return ret;

	if (resp.magic != LOTA_IPC_MAGIC || resp.version != LOTA_IPC_VERSION)
		return -EPROTO;

	if (resp.result != LOTA_IPC_OK)
		return -EACCES;

	if (resp.payload_len != 0)
		return -EPROTO;

	return 0;
}

/* the agent ends it for its owner or root, so the player needs no sudo */
static int ipc_request_terminate_protected(uint32_t pid, uint32_t sig,
					   uint32_t *out_others)
{
	struct sockaddr_un addr;
	struct lota_ipc_request req = {
		.magic = LOTA_IPC_MAGIC,
		.version = LOTA_IPC_VERSION,
		.cmd = LOTA_IPC_CMD_TERMINATE_PROTECTED,
		.payload_len = sizeof(struct lota_ipc_terminate_request),
	};
	struct lota_ipc_terminate_request payload = {
		.pid = pid,
		.signal = sig,
	};
	struct lota_ipc_terminate_response body;
	struct lota_ipc_response resp;
	int fd;
	int ret;

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, LOTA_IPC_SOCKET_PATH, sizeof(addr.sun_path) - 1);

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		ret = -errno;
		close(fd);
		return ret;
	}

	ret = lota_write_full(fd, &req, sizeof(req));
	if (ret == 0)
		ret = lota_write_full(fd, &payload, sizeof(payload));
	if (ret < 0) {
		close(fd);
		return ret;
	}

	ret = lota_read_full(fd, &resp, sizeof(resp));
	if (ret < 0) {
		close(fd);
		return ret;
	}

	if (resp.magic != LOTA_IPC_MAGIC || resp.version != LOTA_IPC_VERSION) {
		close(fd);
		return -EPROTO;
	}

	if (resp.result != LOTA_IPC_OK) {
		close(fd);
		switch (resp.result) {
		case LOTA_IPC_ERR_NOT_PROTECTED:
			return -EINVAL;
		case LOTA_IPC_ERR_TARGET_REFUSED:
			return -EPERM;
		case LOTA_IPC_ERR_BAD_REQUEST:
			return -ESRCH;
		default:
			return -EACCES;
		}
	}

	if (resp.payload_len != sizeof(body)) {
		close(fd);
		return -EPROTO;
	}

	ret = lota_read_full(fd, &body, sizeof(body));
	close(fd);
	if (ret < 0)
		return ret;

	if (out_others)
		*out_others = body.other_protect_pid_count;

	return 0;
}

static int diagnostic_exit_code(int ret)
{
	if (ret < 0)
		return 1;
	return ret;
}

/* --server, or the file's server key: the CLI copies the latter into opts */
static bool opts_name_a_server(const struct cli_options *opts)
{
	return opts->server_addr && opts->server_addr[0] != '\0';
}

int diagnostics_dispatch(struct cli_options *opts, struct lota_config *cfg)
{
	g_agent.tpm_ctx.allow_env_tpm_overrides = attest_env_overrides_allowed(
		opts->attest_flag, opts->attest_interval,
		cfg ? cfg->profile_count : 0, opts_name_a_server(opts));

	if (opts->shutdown_flag) {
		int sret = ipc_request_shutdown();
		if (sret < 0) {
			fprintf(stderr, "Shutdown request failed: %s\n",
				strerror(-sret));
			return 1;
		}

		/*
		 * The daemon answers before it poisons PCR 14 and unloads its
		 * LSM; a start before then meets it still running.
		 */
		sret = pidfile_wait_released(opts->pid_file_path,
					     SHUTDOWN_WAIT_MS);
		if (sret < 0) {
			fprintf(stderr,
				"The agent accepted the shutdown but is still "
				"running after %d s (%s); its journal says "
				"where it stopped\n",
				SHUTDOWN_WAIT_MS / 1000, strerror(-sret));
			return 1;
		}
		fprintf(stderr,
			"Agent stopped. PCR14 is spent, so this host attests "
			"again only after a reboot; starting the agent before "
			"then is refused\n");
		return 0;
	}

	if (opts->status_flag) {
		struct lota_ipc_status st;
		char out[1024];
		int sret = status_request(LOTA_IPC_SOCKET_PATH, &st);

		if (sret < 0) {
			fprintf(stderr,
				"Cannot read the agent's status on %s: %s\n",
				LOTA_IPC_SOCKET_PATH, strerror(-sret));
			return 1;
		}
		status_format(&st, out, sizeof(out));
		fputs(out, stdout);
		return 0;
	}

	if (opts->terminate_protected_flag) {
		uint32_t sig = opts->force_flag ? SIGKILL : SIGTERM;
		uint32_t others = 0;
		char line[256];
		int tret = ipc_request_terminate_protected(
			opts->terminate_protected_pid, sig, &others);

		if (tret == -EINVAL) {
			fprintf(stderr,
				"PID %u is not a protected process, so an "
				"ordinary kill reaches it.\n",
				opts->terminate_protected_pid);
			return 1;
		}
		if (tret == -ESRCH) {
			fprintf(stderr,
				"No process with PID %u, or it is out of this "
				"agent's reach.\n",
				opts->terminate_protected_pid);
			return 1;
		}
		if (tret == -EPERM) {
			fprintf(stderr,
				"PID %u is not a process this verb ends. The "
				"agent stops with --shutdown, and PID 1 stops "
				"by rebooting.\n",
				opts->terminate_protected_pid);
			return 1;
		}
		if (tret == -EACCES) {
			fprintf(stderr,
				"The agent refused to end PID %u: it belongs "
				"to another user, so ending it needs root. Its "
				"journal names the reason.\n",
				opts->terminate_protected_pid);
			return 1;
		}
		if (tret < 0) {
			fprintf(stderr,
				"Could not ask the agent to end PID %u: %s\n",
				opts->terminate_protected_pid, strerror(-tret));
			return 1;
		}

		terminate_sent_message(opts->terminate_protected_pid,
				       opts->force_flag, others, line,
				       sizeof(line));
		printf("%s\n", line);
		return 0;
	}

	if (opts->dump_config_flag)
		return diagnostic_exit_code(cli_dump_config(opts, cfg));

	{
		struct policy_ops_args policy_ops = {
			.gen_signing_key_prefix = opts->gen_signing_key_prefix,
			.sign_policy_file = opts->sign_policy_file,
			.verify_policy_file = opts->verify_policy_file,
			.signing_key_path = opts->signing_key_path,
			.policy_pubkey_path = opts->policy_pubkey_path,
		};
		int ret = handle_policy_ops(&policy_ops);
		if (ret != -1)
			return diagnostic_exit_code(ret);
	}

	if (opts->test_tpm_flag)
		return diagnostic_exit_code(test_tpm());

	if (opts->seal_flag)
		return diagnostic_exit_code(do_seal(opts->seal_pcrs));

	if (opts->unseal_flag)
		return diagnostic_exit_code(do_unseal());

	if (opts->seal_aik_auth_migrate_flag)
		return diagnostic_exit_code(do_seal_aik_auth());

	if (opts->reprovision_aik_flag)
		return diagnostic_exit_code(do_reprovision_aik());

	if (opts->seal_persist_primary_flag)
		return diagnostic_exit_code(do_seal_persist_primary());

	if (opts->seal_evict_primary_flag)
		return diagnostic_exit_code(do_seal_evict_primary());

	if (opts->test_iommu_flag)
		return diagnostic_exit_code(test_iommu());

	if (opts->export_policy_flag)
		return diagnostic_exit_code(export_policy(g_agent.mode));

	if (opts->test_ipc_flag)
		return diagnostic_exit_code(run_ipc_test_server(cfg));

	if (opts->test_signed_flag)
		return diagnostic_exit_code(run_signed_ipc_test_server(cfg));

	/*
	 * These verbs answer a player on stderr, where the TSS library would
	 * add its own log lines; overwrite=0 keeps a TSS2_LOG the operator set.
	 */
	if (opts->list_publishers_flag || opts->forget_publisher ||
	    opts->allow_publisher || opts->add_publisher ||
	    opts->reenroll_flag || opts->enroll_flag)
		setenv("TSS2_LOG", "all+none", 0);

	if (opts->list_publishers_flag)
		return diagnostic_exit_code(do_list_publishers());

	if (opts->forget_publisher)
		return diagnostic_exit_code(
			do_forget_publisher(opts->forget_publisher));

	if (opts->allow_publisher)
		return diagnostic_exit_code(
			do_allow_publisher(opts->allow_publisher));

	/*
	 * Only a typed --server names this publisher's verifier; the file's
	 * server key belongs to the top level. NULL writes a publisher that
	 * runs none.
	 */
	if (opts->add_publisher)
		return diagnostic_exit_code(do_add_publisher(
			opts->config_path, opts->publisher_name,
			opts->add_publisher, opts->ca_port, opts->ca_cert_path,
			opts->server_overridden ? opts->server_addr : NULL,
			opts->server_port, opts->attest_interval,
			!opts->reporting_continuous));

	/* only a typed --ca-port overrides the recorded one */
	if (opts->reenroll_flag)
		return diagnostic_exit_code(
			do_reenroll(opts->ca_cert_path, opts->ca_server,
				    opts->ca_port_given ? opts->ca_port : 0));

	if (opts->enroll_flag) {
		if (!opts->ca_server) {
			fprintf(stderr,
				"ERROR: --enroll requires --ca-server HOST\n");
			return 1;
		}
		if (opts->no_verify_tls &&
		    !opts->insecure_allow_no_verify_tls) {
			fprintf(stderr,
				"ERROR: --no-verify-tls is INSECURE and "
				"requires explicit confirmation.\n"
				"Re-run with: --no-verify-tls "
				"--insecure-allow-no-verify-tls\n");
			return 1;
		}
		return diagnostic_exit_code(
			do_enroll(opts->ca_server, opts->ca_port,
				  opts->ca_cert_path, opts->no_verify_tls,
				  opts->has_pin ? opts->pin_sha256_bin : NULL,
				  opts->enroll_token_file));
	}

	if (opts->attest_flag) {
		int interval;

		if (opts->no_verify_tls &&
		    !opts->insecure_allow_no_verify_tls) {
			fprintf(stderr, "ERROR: --no-verify-tls is INSECURE "
					"and requires explicit "
					"confirmation.\n"
					"Re-run with: --no-verify-tls "
					"--insecure-allow-no-verify-tls\n");
			return 1;
		}
		if (opts->no_verify_tls && opts->ca_cert_path) {
			fprintf(stderr,
				"Warning: --ca-cert is not verified against "
				"when --no-verify-tls is set; it still names "
				"the publisher profile the AIK certificate is "
				"read from\n");
		}
		if (cfg && cfg->profile_count > 0) {
			if (opts->server_overridden) {
				fprintf(stderr,
					"ERROR: --server names one verifier, "
					"but %d publisher profile(s) are "
					"configured.\nRemove the flag, or the "
					"profiles, so there is one answer to "
					"where this host reports.\n",
					cfg->profile_count);
				return 1;
			}
			if (opts->has_pin) {
				fprintf(stderr,
					"ERROR: --pin-sha256 pins one "
					"verifier's certificate, but %d "
					"publisher profile(s) are "
					"configured.\nEach publisher runs its "
					"own verifier: write pin_sha256 inside "
					"the profile whose verifier presents "
					"that certificate.\n",
					cfg->profile_count);
				return 1;
			}
		}

		interval = attest_effective_interval(
			opts->attest_interval, cfg ? cfg->profile_count : 0,
			opts_name_a_server(opts));

		if (interval > 0)
			return diagnostic_exit_code(do_continuous_attest(
				cfg, opts->config_path, opts->server_addr,
				opts->server_port, opts->ca_cert_path,
				opts->no_verify_tls,
				opts->has_pin ? opts->pin_sha256_bin : NULL,
				interval, opts->aik_ttl));
		return diagnostic_exit_code(
			do_attest(opts->server_addr, opts->server_port,
				  opts->ca_cert_path, opts->no_verify_tls,
				  opts->has_pin ? opts->pin_sha256_bin : NULL));
	}

	/* the daemon does not take LOTA_TCTI or LOTA_AIK_META_PATH */
	g_agent.tpm_ctx.allow_env_tpm_overrides = false;
	return -1;
}
