/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */

#include "test_servers.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdbool.h>
#include <stdint.h>

#include "../../include/lota.h"
#include "../../include/lota_ipc.h"
#include "../../include/lota_server.h"
#include "agent.h"
#include "dbus.h"
#include "ipc.h"
#include "main_utils.h"
#include "sdnotify.h"
#include "selftest.h"
#include "tpm.h"
#include "attest_targets.h"
#include "config.h"

/*
 * Hand the IPC layer the publishers the configuration names.
 *
 * A diagnostic server is started with the same file the daemon reads,
 * and a SET_PROFILE is resolved against the list the IPC layer holds.
 * Without this the list is empty for the life of the process, so every publisher
 * the configuration names is answered as one this host has never heard of,
 * and every profile-scoped answer -- the per-publisher view, TOKEN_ONLY,
 * CONSENT_REQUIRED -- is unreachable.
 *
 * @targets outlives the serving loop, so the IPC layer may keep the pointer.
 */
static void bind_configured_profiles(const struct lota_config *cfg,
				     struct attest_target *targets, size_t max,
				     size_t *count, uint64_t valid_until)
{
	int ret;

	*count = 0;
	ret = attest_targets_build(cfg, NULL, 0, NULL, 0, targets, max, count);
	if (ret < 0 || *count == 0) {
		*count = 0;
		printf("No publisher configured: SET_PROFILE has nothing to resolve against.\n");
		return;
	}

	for (size_t i = 0; i < *count; i++) {
		targets[i].attested = true;
		targets[i].valid_until = valid_until;
	}
	printf("Publishers bound: %zu.\n", *count);

	ipc_set_profiles(&g_agent.ipc_ctx, targets, *count);
}

int run_ipc_test_server(const struct lota_config *cfg)
{
	/*
	 * IPC context keeps this list for as long as it serves,
	 * so it cannot be one the frame owns -- and it is far too large for one
	 */
	static struct attest_target targets[LOTA_CONFIG_MAX_PROFILES];
	size_t target_count;
	int ret;
	uint64_t valid_until;
	printf("=== IPC Test Server (No TPM) ===\n\n");
	printf("Starting IPC server for testing...\n");
	ret = ipc_init_or_activate(&g_agent.ipc_ctx);
	if (ret < 0) {
		fprintf(stderr, "Failed to initialize IPC: %s\n",
			strerror(-ret));
		return 1;
	}
	setup_container_listener(&g_agent.ipc_ctx, cfg);
	setup_dbus(&g_agent.ipc_ctx);

	/*
	 * Size the token the way the attestation loop does, so relying party
	 * verifies what the test server hands out instead of refusing it as
	 * living implausibly long.
	 */
	valid_until = (uint64_t)(time(NULL) + LOTA_SERVER_MAX_TOKEN_AGE_SEC);
	bind_configured_profiles(cfg, targets, LOTA_CONFIG_MAX_PROFILES,
				 &target_count, valid_until);
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
	printf("%s\n", ipc_token_capability_str(&g_agent.ipc_ctx));
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

int run_signed_ipc_test_server(const struct lota_config *cfg)
{
	/* kept for the life of the server, as in the plain one above */
	static struct attest_target targets[LOTA_CONFIG_MAX_PROFILES];
	size_t target_count;
	int ret;
	uint64_t valid_until;
	printf("=== IPC Test Server (Signed Tokens) ===\n\n");

	/* socket first, because it is the only thing here that can refuse */
	printf("Starting IPC server...\n");
	ret = ipc_init_or_activate(&g_agent.ipc_ctx);
	if (ret < 0) {
		fprintf(stderr, "Failed to initialize IPC: %s\n",
			strerror(-ret));
		return 1;
	}

	printf("Initializing TPM...\n");
	ret = tpm_init(&g_agent.tpm_ctx);
	if (ret < 0) {
		fprintf(stderr, "Failed to initialize TPM: %s\n",
			tpm_strerror(ret));
		ipc_cleanup(&g_agent.ipc_ctx);
		return 1;
	}
	printf("TPM initialized\n");

	/*
	 * Unlike --test-tpm, this verb must sign, so it cannot skip provisioning.
	 * A new AIK is persistent: it outlives the server and takes one of the
	 * slots that cap how many publishers the host can answer to, so say so
	 * before creating it. An AIK already at the handle is reused for free.
	 */
	if (selftest_aik_plan(tpm_handle_holds_object(
		    &g_agent.tpm_ctx, g_agent.tpm_ctx.aik_handle)) ==
	    SELFTEST_AIK_SKIP)
		printf("No attestation key at handle 0x%08X: this server signs "
		       "tokens, so it creates one, and that key stays after "
		       "the server exits.\n",
		       g_agent.tpm_ctx.aik_handle);
	else
		printf("Using the attestation key already at handle 0x%08X.\n",
		       g_agent.tpm_ctx.aik_handle);

	printf("Provisioning AIK...\n");
	ret = tpm_provision_aik(&g_agent.tpm_ctx);
	if (ret < 0) {
		fprintf(stderr, "Failed to provision AIK: %s\n",
			tpm_strerror(ret));
		ipc_cleanup(&g_agent.ipc_ctx);
		tpm_cleanup(&g_agent.tpm_ctx);
		return 1;
	}
	printf("AIK ready\n\n");

	setup_container_listener(&g_agent.ipc_ctx, cfg);
	setup_dbus(&g_agent.ipc_ctx);

	ipc_set_tpm(&g_agent.ipc_ctx, &g_agent.tpm_ctx,
		    (1U << 0) | (1U << 1) | (1U << LOTA_PCR_SELF));

	/*
	 * size the token the way the attestation loop does, so relying party
	 * verifies what the test server hands out instead of refusing it as
	 * living implausibly long
	 */
	valid_until = (uint64_t)(time(NULL) + LOTA_SERVER_MAX_TOKEN_AGE_SEC);
	bind_configured_profiles(cfg, targets, LOTA_CONFIG_MAX_PROFILES,
				 &target_count, valid_until);
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
	printf("%s\n", ipc_token_capability_str(&g_agent.ipc_ctx));
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
