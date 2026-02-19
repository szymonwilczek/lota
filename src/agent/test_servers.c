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

extern volatile sig_atomic_t g_running;
extern struct tpm_context g_tpm_ctx;
extern struct ipc_context g_ipc_ctx;
extern struct dbus_context *g_dbus_ctx;

int run_ipc_test_server(void) {
  int ret;
  uint64_t valid_until;
  printf("=== IPC Test Server (Unsigned) ===\n\n");
  printf("Starting IPC server for testing...\n");
  ret = ipc_init_or_activate(&g_ipc_ctx);
  if (ret < 0) {
    fprintf(stderr, "Failed to initialize IPC: %s\n", strerror(-ret));
    return 1;
  }
  setup_container_listener(&g_ipc_ctx);
  setup_dbus(&g_ipc_ctx);

  valid_until = (uint64_t)(time(NULL) + 3600);
  ipc_update_status(&g_ipc_ctx,
                    LOTA_STATUS_ATTESTED | LOTA_STATUS_TPM_OK |
                        LOTA_STATUS_IOMMU_OK | LOTA_STATUS_BPF_LOADED,
                    valid_until);
  ipc_set_mode(&g_ipc_ctx, LOTA_MODE_MONITOR);
  ipc_record_attestation(&g_ipc_ctx, true);

  printf("IPC server running (simulated ATTESTED state, no TPM).\n");
  printf("Tokens will be UNSIGNED.\n");
  printf("Press Ctrl+C to stop.\n\n");

  sdnotify_ready();

  while (g_running) {
    ipc_process(&g_ipc_ctx, 1000);
    dbus_process(g_dbus_ctx, 0);
  }

  sdnotify_stopping();
  printf("\nShutting down IPC test server...\n");
  dbus_cleanup(g_dbus_ctx);
  ipc_cleanup(&g_ipc_ctx);
  return 0;
}

int run_signed_ipc_test_server(void) {
  int ret;
  uint64_t valid_until;
  printf("=== IPC Test Server (Signed Tokens) ===\n\n");

  printf("Initializing TPM...\n");
  ret = tpm_init(&g_tpm_ctx);
  if (ret < 0) {
    fprintf(stderr, "Failed to initialize TPM: %s\n", strerror(-ret));
    return 1;
  }
  printf("TPM initialized\n");

  printf("Provisioning AIK...\n");
  ret = tpm_provision_aik(&g_tpm_ctx);
  if (ret < 0) {
    fprintf(stderr, "Failed to provision AIK: %s\n", strerror(-ret));
    tpm_cleanup(&g_tpm_ctx);
    return 1;
  }
  printf("AIK ready\n\n");

  printf("Starting IPC server...\n");
  ret = ipc_init_or_activate(&g_ipc_ctx);
  if (ret < 0) {
    fprintf(stderr, "Failed to initialize IPC: %s\n", strerror(-ret));
    tpm_cleanup(&g_tpm_ctx);
    return 1;
  }
  setup_container_listener(&g_ipc_ctx);
  setup_dbus(&g_ipc_ctx);

  ipc_set_tpm(&g_ipc_ctx, &g_tpm_ctx,
              (1U << 0) | (1U << 1) | (1U << LOTA_PCR_SELF));

  valid_until = (uint64_t)(time(NULL) + 3600);
  ipc_update_status(&g_ipc_ctx,
                    LOTA_STATUS_ATTESTED | LOTA_STATUS_TPM_OK |
                        LOTA_STATUS_IOMMU_OK | LOTA_STATUS_BPF_LOADED,
                    valid_until);
  ipc_set_mode(&g_ipc_ctx, LOTA_MODE_MONITOR);
  ipc_record_attestation(&g_ipc_ctx, true);

  printf("IPC server running (simulated ATTESTED state).\n");
  printf("Tokens will be SIGNED by TPM AIK!\n");
  printf("Press Ctrl+C to stop.\n\n");

  sdnotify_ready();

  while (g_running) {
    ipc_process(&g_ipc_ctx, 1000);
    dbus_process(g_dbus_ctx, 0);
  }

  sdnotify_stopping();
  printf("\nShutting down...\n");
  dbus_cleanup(g_dbus_ctx);
  ipc_cleanup(&g_ipc_ctx);
  tpm_cleanup(&g_tpm_ctx);
  return 0;
}
