/* SPDX-License-Identifier: MIT */

#include "test_servers.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

#include "../../include/lota.h"
#include "../../include/lota_ipc.h"
#include "agent.h"
#include "dbus.h"
#include "ipc.h"
#include "main_utils.h"
#include "sdnotify.h"
#include "tpm.h"

int run_ipc_test_server(void)
{
	int ret;
	uint64_t valid_until;
	printf("=== IPC Test Server (Unsigned) ===\n\n");
	printf("Starting IPC server for testing...\n");
	ret = ipc_init_or_activate(&g_agent.ipc_ctx);
	if (ret < 0) {
		fprintf(stderr, "Failed to initialize IPC: %s\n",
			strerror(-ret));
		return 1;
	}
	setup_container_listener(&g_agent.ipc_ctx, NULL);
	setup_dbus(&g_agent.ipc_ctx);

	valid_until = (uint64_t)(time(NULL) + 3600);
	ipc_update_status(&g_agent.ipc_ctx,
			  LOTA_STATUS_ATTESTED | LOTA_STATUS_TPM_OK |
			      LOTA_STATUS_IOMMU_OK | LOTA_STATUS_BPF_LOADED,
			  valid_until);
	ipc_set_mode(&g_agent.ipc_ctx, LOTA_MODE_MONITOR);
	ipc_record_attestation(&g_agent.ipc_ctx, true);

	/*
	 * GET_TOKEN is gated by g_agent.policy_digest_set. The only
	 * producer is startup_policy_apply(), which --test-ipc skips.
	 * Provision a fixed-pattern digest so the IPC bridge issues
	 * tokens under the test profile; the pattern is reserved for
	 * test fixtures and never appears in a real SHA-256.
	 */
	agent_globals_lock(&g_agent);
	memset(g_agent.policy_digest, 0xA5, sizeof(g_agent.policy_digest));
	g_agent.policy_digest_set = 1;
	agent_globals_unlock(&g_agent);

	printf("IPC server running (simulated ATTESTED state, no TPM).\n");
	printf("Tokens will be UNSIGNED.\n");
	printf("Policy digest: synthetic test fixture (0xA5 x 32).\n");
	printf("Press Ctrl+C to stop.\n\n");

	sdnotify_ready();

	while (g_agent.running) {
		ipc_process(&g_agent.ipc_ctx, 1000);
		dbus_process(g_agent.dbus_ctx, 0);
	}

	sdnotify_stopping();
	printf("\nShutting down IPC test server...\n");
	dbus_cleanup(g_agent.dbus_ctx);
	ipc_cleanup(&g_agent.ipc_ctx);
	return 0;
}

int run_signed_ipc_test_server(void)
{
	int ret;
	uint64_t valid_until;
	printf("=== IPC Test Server (Signed Tokens) ===\n\n");

	printf("Initializing TPM...\n");
	ret = tpm_init(&g_agent.tpm_ctx);
	if (ret < 0) {
		fprintf(stderr, "Failed to initialize TPM: %s\n",
			strerror(-ret));
		return 1;
	}
	printf("TPM initialized\n");

	printf("Provisioning AIK...\n");
	ret = tpm_provision_aik(&g_agent.tpm_ctx);
	if (ret < 0) {
		fprintf(stderr, "Failed to provision AIK: %s\n",
			strerror(-ret));
		tpm_cleanup(&g_agent.tpm_ctx);
		return 1;
	}
	printf("AIK ready\n\n");

	printf("Starting IPC server...\n");
	ret = ipc_init_or_activate(&g_agent.ipc_ctx);
	if (ret < 0) {
		fprintf(stderr, "Failed to initialize IPC: %s\n",
			strerror(-ret));
		tpm_cleanup(&g_agent.tpm_ctx);
		return 1;
	}
	setup_container_listener(&g_agent.ipc_ctx, NULL);
	setup_dbus(&g_agent.ipc_ctx);

	ipc_set_tpm(&g_agent.ipc_ctx, &g_agent.tpm_ctx,
		    (1U << 0) | (1U << 1) | (1U << LOTA_PCR_SELF));

	valid_until = (uint64_t)(time(NULL) + 3600);
	ipc_update_status(&g_agent.ipc_ctx,
			  LOTA_STATUS_ATTESTED | LOTA_STATUS_TPM_OK |
			      LOTA_STATUS_IOMMU_OK | LOTA_STATUS_BPF_LOADED,
			  valid_until);
	ipc_set_mode(&g_agent.ipc_ctx, LOTA_MODE_MONITOR);
	ipc_record_attestation(&g_agent.ipc_ctx, true);

	/* Mirror the --test-ipc fixture so GET_TOKEN passes the
	 * policy_digest_set gate; startup_policy_apply() is skipped on
	 * the test server paths and is the only real producer of the
	 * digest. The signed-token path then runs through the real TPM
	 * quote. */
	agent_globals_lock(&g_agent);
	memset(g_agent.policy_digest, 0xA5, sizeof(g_agent.policy_digest));
	g_agent.policy_digest_set = 1;
	agent_globals_unlock(&g_agent);

	printf("IPC server running (simulated ATTESTED state).\n");
	printf("Tokens will be SIGNED by TPM AIK!\n");
	printf("Policy digest: synthetic test fixture (0xA5 x 32).\n");
	printf("Press Ctrl+C to stop.\n\n");

	sdnotify_ready();

	while (g_agent.running) {
		ipc_process(&g_agent.ipc_ctx, 1000);
		dbus_process(g_agent.dbus_ctx, 0);
	}

	sdnotify_stopping();
	printf("\nShutting down...\n");
	dbus_cleanup(g_agent.dbus_ctx);
	ipc_cleanup(&g_agent.ipc_ctx);
	tpm_cleanup(&g_agent.tpm_ctx);
	return 0;
}
