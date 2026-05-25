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

#include "../../include/lota_ipc.h"
#include "agent.h"
#include "attest.h"
#include "io_utils.h"
#include "main_utils.h"
#include "selftest.h"
#include "test_servers.h"

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

int diagnostics_dispatch(struct cli_options *opts, struct lota_config *cfg)
{
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
		return cli_dump_config(opts, cfg);

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
			return ret;
	}

	if (opts->test_tpm_flag)
		return test_tpm();

	if (opts->test_iommu_flag)
		return test_iommu();

	if (opts->export_policy_flag)
		return export_policy(g_agent.mode);

	if (opts->test_ipc_flag)
		return run_ipc_test_server();

	if (opts->test_signed_flag)
		return run_signed_ipc_test_server();

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
			return do_continuous_attest(
			    opts->server_addr, opts->server_port,
			    opts->ca_cert_path, opts->no_verify_tls,
			    opts->has_pin ? opts->pin_sha256_bin : NULL,
			    opts->attest_interval, opts->aik_ttl);
		return do_attest(opts->server_addr, opts->server_port,
				 opts->ca_cert_path, opts->no_verify_tls,
				 opts->has_pin ? opts->pin_sha256_bin : NULL);
	}

	return -1;
}
