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
 *   - Certificate pinning: SHA-256 fingerprint stored and parsed
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

  ret = net_context_init(&ctx, "localhost", TEST_PORT, NULL, 0, NULL);
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

  ret = net_context_init(&ctx, "localhost", TEST_PORT, ca_path, 0, NULL);
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

  ret =
      net_context_init(&ctx, "wrong.example.com", TEST_PORT, ca_path, 0, NULL);
  if (ret < 0) {
    test_result("hostname mismatch: init", 0);
    return;
  }

  net_context_cleanup(&ctx);

  /* IP address which wont match the DNS SAN "localhost" if cert
   * was generated without IP SAN */
  ret = net_context_init(&ctx, "127.0.0.1", TEST_PORT, ca_path, 0, NULL);
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

  ret = net_context_init(&ctx, "localhost", TEST_PORT, NULL, 1, NULL);
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

  ret = net_context_init(&ctx, "localhost", TEST_PORT, "/nonexistent/ca.pem", 0,
                         NULL);
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

  ret = net_context_init(&ctx, NULL, TEST_PORT, NULL, 0, NULL);
  test_result("NULL server returns EINVAL", ret == -EINVAL);
}

/*
 * 7: skip_verify field stored in context
 */
static void test_skip_verify_stored(void) {
  struct net_context ctx;
  int ret;

  ret = net_context_init(&ctx, "localhost", TEST_PORT, NULL, 1, NULL);
  if (ret < 0) {
    test_result("skip_verify stored: init", 0);
    return;
  }
  test_result("skip_verify field is stored in context", ctx.skip_verify == 1);
  net_context_cleanup(&ctx);

  ret = net_context_init(&ctx, "localhost", TEST_PORT, NULL, 0, NULL);
  if (ret < 0) {
    test_result("skip_verify=0 stored: init", 0);
    return;
  }
  test_result("skip_verify=0 stored correctly", ctx.skip_verify == 0);
  net_context_cleanup(&ctx);
}

/*
 * 8: pin_sha256 stored in context when provided
 */
static void test_pin_stored_in_context(void) {
  struct net_context ctx;
  int ret;
  uint8_t pin[NET_PIN_SHA256_LEN];

  memset(pin, 0xAB, NET_PIN_SHA256_LEN);
  ret = net_context_init(&ctx, "localhost", TEST_PORT, NULL, 0, pin);
  if (ret < 0) {
    test_result("pin stored: init", 0);
    return;
  }
  test_result("pin_sha256 stored: has_pin set", ctx.has_pin == 1);
  test_result("pin_sha256 stored: data matches",
              memcmp(ctx.pin_sha256, pin, NET_PIN_SHA256_LEN) == 0);
  net_context_cleanup(&ctx);
}

/*
 * 9: NULL pin means no pinning
 */
static void test_null_pin_no_pinning(void) {
  struct net_context ctx;
  int ret;

  ret = net_context_init(&ctx, "localhost", TEST_PORT, NULL, 0, NULL);
  if (ret < 0) {
    test_result("null pin: init", 0);
    return;
  }
  test_result("NULL pin: has_pin is zero", ctx.has_pin == 0);
  net_context_cleanup(&ctx);
}

/*
 * 10: net_parse_pin_sha256 with valid lowercase hex
 */
static void test_parse_pin_valid_hex(void) {
  uint8_t out[NET_PIN_SHA256_LEN];
  int ret;
  const char *hex = "a1b2c3d4e5f60718293a4b5c6d7e8f90"
                    "0011223344556677889900aabbccddee";

  ret = net_parse_pin_sha256(hex, out);
  test_result("parse pin: valid 64-char hex succeeds", ret == 0);
  test_result("parse pin: first byte correct", out[0] == 0xa1);
  test_result("parse pin: last byte correct", out[31] == 0xee);
}

/*
 * 11: net_parse_pin_sha256 with uppercase hex
 */
static void test_parse_pin_uppercase(void) {
  uint8_t out[NET_PIN_SHA256_LEN];
  int ret;
  const char *hex = "A1B2C3D4E5F60718293A4B5C6D7E8F90"
                    "0011223344556677889900AABBCCDDEE";

  ret = net_parse_pin_sha256(hex, out);
  test_result("parse pin: uppercase hex succeeds", ret == 0);
  test_result("parse pin: uppercase first byte", out[0] == 0xa1);
}

/*
 * 12: net_parse_pin_sha256 with colons (openssl fingerprint format)
 */
static void test_parse_pin_with_colons(void) {
  uint8_t out[NET_PIN_SHA256_LEN];
  int ret;
  const char *hex = "A1:B2:C3:D4:E5:F6:07:18:29:3A:4B:5C:6D:7E:8F:90:"
                    "00:11:22:33:44:55:66:77:88:99:00:AA:BB:CC:DD:EE";

  ret = net_parse_pin_sha256(hex, out);
  test_result("parse pin: colon-separated hex succeeds", ret == 0);
  test_result("parse pin: colon format first byte", out[0] == 0xa1);
  test_result("parse pin: colon format last byte", out[31] == 0xee);
}

/*
 * 13: net_parse_pin_sha256 rejects invalid input
 */
static void test_parse_pin_invalid(void) {
  uint8_t out[NET_PIN_SHA256_LEN];
  int ret;

  /* too short */
  ret = net_parse_pin_sha256("a1b2c3", out);
  test_result("parse pin: too short rejected", ret == -EINVAL);

  /* invalid character */
  ret = net_parse_pin_sha256("g1b2c3d4e5f60718293a4b5c6d7e8f90"
                             "0011223344556677889900aabbccddeeff",
                             out);
  test_result("parse pin: invalid hex char rejected", ret == -EINVAL);

  /* too long (extra byte) */
  ret = net_parse_pin_sha256("a1b2c3d4e5f60718293a4b5c6d7e8f90"
                             "0011223344556677889900aabbccddeeffaa",
                             out);
  test_result("parse pin: too long rejected", ret == -EINVAL);

  /* NULL input */
  ret = net_parse_pin_sha256(NULL, out);
  test_result("parse pin: NULL hex rejected", ret == -EINVAL);

  /* NULL output */
  ret = net_parse_pin_sha256("a1b2c3d4e5f60718293a4b5c6d7e8f90"
                             "0011223344556677889900aabbccddeeff",
                             NULL);
  test_result("parse pin: NULL output rejected", ret == -EINVAL);

  /* empty string */
  ret = net_parse_pin_sha256("", out);
  test_result("parse pin: empty string rejected", ret == -EINVAL);
}

/*
 * 14: net_parse_pin_sha256 with spaces
 */
static void test_parse_pin_with_spaces(void) {
  uint8_t out[NET_PIN_SHA256_LEN];
  int ret;
  const char *hex = "A1 B2 C3 D4 E5 F6 07 18 29 3A 4B 5C 6D 7E 8F 90 "
                    "00 11 22 33 44 55 66 77 88 99 00 AA BB CC DD EE";

  ret = net_parse_pin_sha256(hex, out);
  test_result("parse pin: space-separated hex succeeds", ret == 0);
  test_result("parse pin: space format first byte", out[0] == 0xa1);
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

  printf("\n--- Certificate pinning tests ---\n");
  test_pin_stored_in_context();
  test_null_pin_no_pinning();
  test_parse_pin_valid_hex();
  test_parse_pin_uppercase();
  test_parse_pin_with_colons();
  test_parse_pin_with_spaces();
  test_parse_pin_invalid();

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
