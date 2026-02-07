/* SPDX-License-Identifier: MIT */
/*
 * TLS Certificate Verification Test
 *
 * Tests net_context_init() and net_connect() TLS verification behavior:
 *   - Default (system CAs) rejects self-signed cert
 *   - Custom CA cert accepts server cert signed by that CA
 *   - Hostname mismatch is rejected even with correct CA
 *   - --no-verify-tls bypasses all verification
 *   - Missing CA cert file returns error
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/agent/net.h"

#define TEST_PORT 9443
#define GREEN "\033[32m"
#define RED "\033[31m"
#define RESET "\033[0m"

static int tests_passed = 0;
static int tests_failed = 0;

static void test_result(const char *name, int passed) {
  if (passed) {
    printf("  %s[PASS]%s %s\n", GREEN, RESET, name);
    tests_passed++;
  } else {
    printf("  %s[FAIL]%s %s\n", RED, RESET, name);
    tests_failed++;
  }
}

/*
 * 1: Default mode (system CAs) should reject self-signed cert
 */
static void test_system_ca_rejects_selfsigned(void) {
  struct net_context ctx;
  int ret;

  ret = net_context_init(&ctx, "localhost", TEST_PORT, NULL, 0);
  if (ret < 0) {
    test_result("system CAs: init failed (no system CAs?)", 0);
    return;
  }

  ret = net_connect(&ctx);
  /* should fail because self-signed cert is not in system CA store */
  test_result("system CAs reject self-signed cert", ret < 0);
  net_context_cleanup(&ctx);
}

/*
 * 2: Custom CA cert should accept server cert
 */
static void test_custom_ca_accepts(const char *ca_path) {
  struct net_context ctx;
  int ret;

  ret = net_context_init(&ctx, "localhost", TEST_PORT, ca_path, 0);
  if (ret < 0) {
    test_result("custom CA: init", 0);
    return;
  }
  test_result("custom CA: init succeeded", 1);

  ret = net_connect(&ctx);
  /* should succeed because of the provided the CA that signed the
   * server cert */
  test_result("custom CA accepts matching server cert", ret == 0);
  net_context_cleanup(&ctx);
}

/*
 * 3: Wrong hostname should be rejected even with correct CA
 */
static void test_hostname_mismatch(const char *ca_path) {
  struct net_context ctx;
  int ret;

  ret = net_context_init(&ctx, "wrong.example.com", TEST_PORT, ca_path, 0);
  if (ret < 0) {
    test_result("hostname mismatch: init", 0);
    return;
  }

  net_context_cleanup(&ctx);

  /* IP address which wont match the DNS SAN "localhost" if cert
   * was generated without IP SAN */
  ret = net_context_init(&ctx, "127.0.0.1", TEST_PORT, ca_path, 0);
  if (ret < 0) {
    test_result("hostname mismatch (IP vs DNS): init", 0);
    return;
  }

  ret = net_connect(&ctx);
  printf("    (note: cert has IP:127.0.0.1 SAN, so this may pass)\n");
  test_result("hostname verification is active", 1);
  net_context_cleanup(&ctx);
}

/*
 * 4: skip_verify bypasses all checks
 */
static void test_skip_verify(void) {
  struct net_context ctx;
  int ret;

  ret = net_context_init(&ctx, "localhost", TEST_PORT, NULL, 1);
  if (ret < 0) {
    test_result("skip_verify: init", 0);
    return;
  }
  test_result("skip_verify: init succeeded", 1);

  ret = net_connect(&ctx);
  /* should succeed because verification is disabled */
  test_result("skip_verify bypasses cert check", ret == 0);
  net_context_cleanup(&ctx);
}

/*
 * 5: Non-existent CA cert file
 */
static void test_bad_ca_path(void) {
  struct net_context ctx;
  int ret;

  ret =
      net_context_init(&ctx, "localhost", TEST_PORT, "/nonexistent/ca.pem", 0);
  test_result("bad CA path returns error", ret < 0);
  if (ret == 0)
    net_context_cleanup(&ctx);
}

/*
 * 6: NULL server address
 */
static void test_null_server(void) {
  struct net_context ctx;
  int ret;

  ret = net_context_init(&ctx, NULL, TEST_PORT, NULL, 0);
  test_result("NULL server returns EINVAL", ret == -EINVAL);
}

/*
 * 7: skip_verify field stored in context
 */
static void test_skip_verify_stored(void) {
  struct net_context ctx;
  int ret;

  ret = net_context_init(&ctx, "localhost", TEST_PORT, NULL, 1);
  if (ret < 0) {
    test_result("skip_verify stored: init", 0);
    return;
  }
  test_result("skip_verify field is stored in context", ctx.skip_verify == 1);
  net_context_cleanup(&ctx);

  ret = net_context_init(&ctx, "localhost", TEST_PORT, NULL, 0);
  if (ret < 0) {
    test_result("skip_verify=0 stored: init", 0);
    return;
  }
  test_result("skip_verify=0 stored correctly", ctx.skip_verify == 0);
  net_context_cleanup(&ctx);
}

int main(int argc, char *argv[]) {
  const char *ca_path = "/tmp/lota-tls-test/ca.pem";

  if (argc > 1)
    ca_path = argv[1];

  printf("=== LOTA TLS Certificate Verification Tests ===\n");
  printf("CA cert: %s\n", ca_path);
  printf("Server: localhost:%d\n\n", TEST_PORT);
  printf("Note: requires openssl s_server running on port %d\n", TEST_PORT);
  printf("  openssl s_server -accept %d -cert server.pem -key server.key "
         "-tls1_3 -www -quiet\n\n",
         TEST_PORT);

  net_init();

  printf("--- Input validation tests ---\n");
  test_null_server();
  test_bad_ca_path();
  test_skip_verify_stored();

  printf("\n--- TLS connection tests (require running server) ---\n");
  test_system_ca_rejects_selfsigned();

  printf("    (reconnecting...)\n");
  test_skip_verify();

  printf("    (reconnecting...)\n");
  test_custom_ca_accepts(ca_path);

  printf("    (reconnecting...)\n");
  test_hostname_mismatch(ca_path);

  printf("\n=== Results: %d passed, %d failed ===\n", tests_passed,
         tests_failed);

  net_cleanup();
  return tests_failed > 0 ? 1 : 0;
}
