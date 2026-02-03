/* SPDX-License-Identifier: MIT */
/*
 * LOTA SDK Demo - Example game integration
 *
 * Demonstrates how a game would use the LOTA Gaming SDK
 * to verify system attestation before connecting to a server.
 *
 * Build:
 *   gcc -o sdk_demo sdk_demo.c -L../build -llotagaming -Wl,-rpath,../build
 *
 * Run:
 *   # First start the agent with --test-ipc
 *   sudo ../build/lota-agent --test-ipc
 *   # Then run this demo
 *   ./sdk_demo
 */

#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "../include/lota_gaming.h"

static void print_status(const struct lota_status *status) {
  char flags_str[128];
  time_t last_attest = (time_t)status->last_attest_time;
  time_t valid_until = (time_t)status->valid_until;

  lota_flags_to_string(status->flags, flags_str, sizeof(flags_str));

  printf("  Flags: 0x%08X (%s)\n", status->flags,
         flags_str[0] ? flags_str : "none");
  printf("  Last attestation: %s",
         last_attest ? ctime(&last_attest) : "never\n");
  printf("  Valid until: %s", valid_until ? ctime(&valid_until) : "N/A\n");
  printf("  Attestation count: %u (success) / %u (failed)\n",
         status->attest_count, status->fail_count);
}

static void print_token(const struct lota_token *token) {
  time_t issued = (time_t)token->issued_at;
  time_t valid = (time_t)token->valid_until;
  char flags_str[128];

  lota_flags_to_string(token->flags, flags_str, sizeof(flags_str));

  printf("  Issued at: %s", ctime(&issued));
  printf("  Valid until: %s", ctime(&valid));
  printf("  Flags: 0x%08X (%s)\n", token->flags,
         flags_str[0] ? flags_str : "none");
  printf("  TPM Quote:\n");
  printf("    Attest data: %zu bytes\n", token->attest_size);
  printf("    Signature: %zu bytes\n", token->signature_len);
  if (token->attest_size > 0) {
    printf("    Sig algorithm: 0x%04X\n", token->sig_alg);
    printf("    Hash algorithm: 0x%04X\n", token->hash_alg);
    printf("    PCR mask: 0x%08X\n", token->pcr_mask);
  } else {
    printf("    (unsigned token - no TPM context)\n");
  }

  /*
   * IMPORTANT NOTE: In a real game, send the token to the server for
   * verification: send_to_server(token); The server uses lota-verifier to
   * validate the TPM signature.
   */
}

int main(void) {
  struct lota_client *client;
  struct lota_status status;
  struct lota_token token;
  uint64_t uptime;
  int ret;

  printf("=== LOTA SDK Demo ===\n");
  printf("SDK Version: %s\n\n", lota_sdk_version());

  printf("Connecting to LOTA agent...\n");
  client = lota_connect();
  if (!client) {
    printf("ERROR: Could not connect to LOTA agent.\n");
    printf("Make sure the agent is running:\n");
    printf("  sudo lota-agent --test-ipc\n");
    return 1;
  }
  printf("Connected!\n\n");

  printf("Pinging agent...\n");
  ret = lota_ping(client, &uptime);
  if (ret != LOTA_OK) {
    printf("ERROR: Ping failed: %s\n", lota_strerror(ret));
    lota_disconnect(client);
    return 1;
  }
  printf("Agent is alive! Uptime: %lu seconds\n\n", (unsigned long)uptime);

  printf("Getting attestation status...\n");
  ret = lota_get_status(client, &status);
  if (ret != LOTA_OK) {
    printf("ERROR: Get status failed: %s\n", lota_strerror(ret));
    lota_disconnect(client);
    return 1;
  }
  print_status(&status);
  printf("\n");

  printf("Quick check: System is %s\n\n",
         lota_is_attested(client) ? "ATTESTED" : "NOT ATTESTED");

  printf("Requesting attestation token...\n");
  ret = lota_get_token(client, NULL, &token);
  if (ret == LOTA_OK) {
    printf("Token received!\n");
    print_token(&token);
    lota_token_free(&token);
  } else if (ret == LOTA_ERR_NOT_ATTESTED) {
    printf("No token available - system not attested.\n");
    printf("This is expected if running with --test-ipc without\n");
    printf("simulated attestation state.\n");
  } else {
    printf("ERROR: Get token failed: %s\n", lota_strerror(ret));
  }
  printf("\n");

  printf("Disconnecting...\n");
  lota_disconnect(client);
  printf("Done!\n");

  return 0;
}
