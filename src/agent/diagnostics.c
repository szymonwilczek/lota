/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - Diagnostic and admin one-shot dispatch
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include "diagnostics.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdbool.h>

#include "../../include/lota_ipc.h"
#include "agent.h"
#include "attest.h"
#include "enroll.h"
#include "io_utils.h"
#include "main_utils.h"
#include "selftest.h"
#include "test_servers.h"
#include "tpm.h"

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

static int diagnostic_exit_code(int ret)
{
	if (ret < 0)
		return 1;
	return ret;
}

int diagnostics_dispatch(struct cli_options *opts, struct lota_config *cfg)
{
	/*
	 * Interactive one-shots (seal/unseal, enroll, attest, test servers,
	 * ...) may redirect the TPM endpoint and AIK key store via
	 * LOTA_TCTI / LOTA_AIK_META_PATH for the swtpm demo and tests. The
	 * persistent daemon must not: it is reached only when this function
	 * falls through to "return -1" below, where the flag is cleared again.
	 */
	g_agent.tpm_ctx.allow_env_tpm_overrides = true;

	if (opts->shutdown_flag) {
		int sret = ipc_request_shutdown();
		if (sret < 0) {
			fprintf(stderr, "Shutdown request failed: %s\n",
				strerror(-sret));
			return 1;
		}
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

	if (opts->reenroll_flag)
		return diagnostic_exit_code(do_reenroll());

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
				  opts->has_pin ? opts->pin_sha256_bin : NULL));
	}

	if (opts->attest_flag) {
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
			fprintf(stderr, "Warning: --ca-cert ignored when "
					"--no-verify-tls is set\n");
		}
		if (opts->attest_interval > 0)
			return diagnostic_exit_code(do_continuous_attest(
				opts->server_addr, opts->server_port,
				opts->ca_cert_path, opts->no_verify_tls,
				opts->has_pin ? opts->pin_sha256_bin : NULL,
				opts->attest_interval, opts->aik_ttl));
		return diagnostic_exit_code(
			do_attest(opts->server_addr, opts->server_port,
				  opts->ca_cert_path, opts->no_verify_tls,
				  opts->has_pin ? opts->pin_sha256_bin : NULL));
	}

	/* No one-shot matched: the caller will start the daemon.
	 * Clear the override permission so the daemon ignores
	 * LOTA_TCTI / LOTA_AIK_META_PATH. */
	g_agent.tpm_ctx.allow_env_tpm_overrides = false;
	return -1;
}
