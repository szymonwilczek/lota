/* SPDX-License-Identifier: MIT */
/*
 * LOTA SDK Integration Test
 * Tests SDK functions against running lota-agent IPC server.
 *
 * Usage:
 *   1. Start agent: sudo ./build/lota-agent --test-ipc
 *   2. Run test:    ./build/test_sdk_ipc
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../include/lota_gaming.h"

#define TEST_PASS "\033[32m✓ PASS\033[0m"
#define TEST_FAIL "\033[31m✗ FAIL\033[0m"

static int tests_passed = 0;
static int tests_failed = 0;

static void test_result(const char *name, int passed, const char *detail) {
  if (passed) {
    printf("%s: %s\n", TEST_PASS, name);
    tests_passed++;
  } else {
    printf("%s: %s - %s\n", TEST_FAIL, name, detail);
    tests_failed++;
  }
}

int main(void) {
  struct lota_client *client;
  struct lota_status status;
  struct lota_token token;
  int ret;

  printf("=== LOTA SDK Integration Test ===\n\n");
  printf("Ensure lota-agent is running with --test-ipc or --test-signed\n\n");

  printf("--- Test 1: Connection ---\n");
  client = lota_connect();
  test_result("lota_connect()", client != NULL, "connection failed");

  if (!client) {
    printf("\nCannot continue without connection.\n");
    printf("Start agent: sudo ./build/lota-agent --test-ipc\n");
    return 1;
  }

  printf("\n--- Test 2: Get Status ---\n");
  ret = lota_get_status(client, &status);
  test_result("lota_get_status()", ret == 0, "status query failed");

  if (ret == 0) {
    char flags_str[256];
    lota_flags_to_string(status.flags, flags_str, sizeof(flags_str));

    printf("  Status flags: 0x%02x (%s)\n", status.flags, flags_str);
    printf("  Attested: %s\n",
           (status.flags & LOTA_FLAG_ATTESTED) ? "yes" : "no");
    printf("  TPM OK: %s\n", (status.flags & LOTA_FLAG_TPM_OK) ? "yes" : "no");
    printf("  IOMMU OK: %s\n",
           (status.flags & LOTA_FLAG_IOMMU_OK) ? "yes" : "no");
    printf("  BPF Loaded: %s\n",
           (status.flags & LOTA_FLAG_BPF_LOADED) ? "yes" : "no");
    printf("  Valid until: %lu\n", (unsigned long)status.valid_until);
    printf("  Attestations: %u success, %u failed\n", status.attest_count,
           status.fail_count);

    test_result("Status ATTESTED flag set",
                (status.flags & LOTA_FLAG_ATTESTED) != 0,
                "agent should report attested");
  }

  printf("\n--- Test 3: Quick Attestation Check ---\n");
  ret = lota_is_attested(client);
  test_result("lota_is_attested()", ret == 1, "should return 1 for attested");

  printf("\n--- Test 4: Get Token ---\n");

  uint8_t client_nonce[32];
  for (int i = 0; i < 32; i++) {
    client_nonce[i] = (uint8_t)i;
  }

  memset(&token, 0, sizeof(token));
  ret = lota_get_token(client, client_nonce, &token);
  test_result("lota_get_token()", ret == 0, lota_strerror(ret));

  if (ret == 0) {
    printf("  Issued at: %lu\n", (unsigned long)token.issued_at);
    printf("  Valid until: %lu\n", (unsigned long)token.valid_until);
    printf("  Token flags: 0x%02x\n", token.flags);
    printf("  Has signature: %s\n", token.signature_len > 0 ? "yes" : "no");
    printf("  Signature size: %zu bytes\n", token.signature_len);
    printf("  Attest data size: %zu bytes\n", token.attest_size);
    printf("  PCR mask: 0x%08x\n", token.pcr_mask);

    /* nonce should be echoed back */
    int nonce_match = (memcmp(token.nonce, client_nonce, 32) == 0);
    test_result("Client nonce echoed", nonce_match, "nonce mismatch");

    /* token validity check */
    int valid_times =
        (token.issued_at > 0 && token.valid_until > token.issued_at);
    test_result("Valid timestamps", valid_times, "invalid timestamps");

    /* for --test-signed mode, signature should be present */
    if (token.signature_len > 0) {
      printf("  Token is TPM-SIGNED!\n");
      test_result("TPM signature present", token.signature_len == 256,
                  "expected 256-byte RSA signature");
      test_result("Attest data present", token.attest_size > 100,
                  "expected ~145 byte TPMS_ATTEST");
    } else {
      printf("  Token is UNSIGNED (--test-ipc mode)\n");
    }

    lota_token_free(&token);
  }

  printf("\n--- Test 5: Token Freshness ---\n");

  struct lota_token token2;
  memset(&token2, 0, sizeof(token2));
  ret = lota_get_token(client, client_nonce, &token2);
  if (ret == 0) {
    int fresh = (token2.issued_at >= token.issued_at);
    test_result("Token timestamp fresh", fresh, "timestamp not advancing");
    lota_token_free(&token2);
  }

  printf("\n--- Test 6: Ping ---\n");
  uint64_t uptime = 0;
  ret = lota_ping(client, &uptime);
  test_result("lota_ping()", ret == LOTA_OK, lota_strerror(ret));
  if (ret == LOTA_OK) {
    printf("  Agent uptime: %lu seconds\n", (unsigned long)uptime);
  }

  printf("\n--- Test 7: Reconnection ---\n");
  lota_disconnect(client);
  test_result("lota_disconnect()", 1, "");

  client = lota_connect();
  test_result("Reconnect after disconnect", client != NULL, "reconnect failed");

  if (client) {
    ret = lota_get_status(client, &status);
    test_result("Status after reconnect", ret == 0, "status failed");
    lota_disconnect(client);
  }

  printf("\n--- Test 8: SDK Info ---\n");
  const char *ver = lota_sdk_version();
  test_result("lota_sdk_version()", ver != NULL && strlen(ver) > 0,
              "no version");
  printf("  SDK version: %s\n", ver);

  printf("\n=== Test Summary ===\n");
  printf("Passed: %d\n", tests_passed);
  printf("Failed: %d\n", tests_failed);

  return tests_failed > 0 ? 1 : 0;
}
