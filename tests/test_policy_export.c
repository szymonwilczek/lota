/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for policy YAML auto-generation (policy.h / policy.c).
 *
 * Tests the YAML serialization layer, which has no TPM or
 * kernel dependencies.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/agent/policy.h"

static int tests_run;
static int tests_passed;

#define TEST(name)                                                             \
  do {                                                                         \
    tests_run++;                                                               \
    printf("  [%2d] %-55s ", tests_run, name);                                 \
  } while (0)

#define PASS()                                                                 \
  do {                                                                         \
    tests_passed++;                                                            \
    printf("PASS\n");                                                          \
  } while (0)

#define FAIL(msg)                                                              \
  do {                                                                         \
    printf("FAIL: %s\n", msg);                                                 \
  } while (0)

/*
 * Build a fully-populated snapshot with deterministic data.
 */
static void build_full_snapshot(struct policy_snapshot *snap) {
  memset(snap, 0, sizeof(*snap));

  snprintf(snap->name, sizeof(snap->name), "test-host-baseline");
  snprintf(snap->description, sizeof(snap->description),
           "Auto-generated policy from test-host");
  snprintf(snap->hostname, sizeof(snap->hostname), "test-host");
  snprintf(snap->timestamp, sizeof(snap->timestamp), "2026-02-08T12:00:00Z");

  /* PCR 0: all 0x01 bytes */
  snap->pcr_count = 4;
  snap->pcrs[0].index = 0;
  memset(snap->pcrs[0].value, 0x01, LOTA_HASH_SIZE);
  snap->pcrs[0].valid = true;

  /* PCR 1: all 0x02 bytes */
  snap->pcrs[1].index = 1;
  memset(snap->pcrs[1].value, 0x02, LOTA_HASH_SIZE);
  snap->pcrs[1].valid = true;

  /* PCR 7: all 0x07 bytes */
  snap->pcrs[2].index = 7;
  memset(snap->pcrs[2].value, 0x07, LOTA_HASH_SIZE);
  snap->pcrs[2].valid = true;

  /* PCR 14: all 0x0E bytes */
  snap->pcrs[3].index = 14;
  memset(snap->pcrs[3].value, 0x0E, LOTA_HASH_SIZE);
  snap->pcrs[3].valid = true;

  /* Kernel hash: all 0xAA */
  snprintf(snap->kernel_path, sizeof(snap->kernel_path),
           "/boot/vmlinuz-6.12.0-test");
  memset(snap->kernel_hash, 0xAA, LOTA_HASH_SIZE);
  snap->kernel_hash_valid = true;

  /* Agent hash: all 0xBB */
  snprintf(snap->agent_path, sizeof(snap->agent_path), "/usr/sbin/lota-agent");
  memset(snap->agent_hash, 0xBB, LOTA_HASH_SIZE);
  snap->agent_hash_valid = true;

  /* Security features */
  snap->iommu_enabled = true;
  snap->enforce_mode = true;
  snap->module_sig = true;
  snap->secureboot = false;
  snap->lockdown = false;
}

/*
 * Emit snapshot to buffer and return pointer. Returns NULL on error.
 */
static char *emit_to_string(const struct policy_snapshot *snap,
                            size_t *out_len) {
  static char buf[8192];
  size_t written = 0;
  int ret;

  memset(buf, 0, sizeof(buf));
  ret = policy_emit_to_buf(snap, buf, sizeof(buf), &written);
  if (ret != 0)
    return NULL;

  if (out_len)
    *out_len = written;
  return buf;
}

/*
 * Check that a string contains a given substring.
 */
static int contains(const char *haystack, const char *needle) {
  return strstr(haystack, needle) != NULL;
}

/*
 * Check that a YAML line "key: value" exists.
 */
static int has_yaml_line(const char *yaml, const char *line) {
  const char *p = yaml;
  size_t line_len = strlen(line);

  while ((p = strstr(p, line)) != NULL) {
    if (p == yaml || *(p - 1) == '\n') {
      char after = p[line_len];
      if (after == '\n' || after == '\0')
        return 1;
    }
    p++;
  }
  return 0;
}

static void test_emit_full_snapshot(void) {
  TEST("policy_emit - full snapshot produces valid YAML");

  struct policy_snapshot snap;
  build_full_snapshot(&snap);

  char *yaml = emit_to_string(&snap, NULL);
  if (!yaml) {
    FAIL("emit_to_buf returned error");
    return;
  }

  if (!contains(yaml, "name: \"test-host-baseline\"")) {
    FAIL("missing name field");
    return;
  }
  if (!contains(yaml,
                "description: \"Auto-generated policy from test-host\"")) {
    FAIL("missing description field");
    return;
  }
  PASS();
}

static void test_emit_metadata_comments(void) {
  TEST("policy_emit - header contains hostname and timestamp");

  struct policy_snapshot snap;
  build_full_snapshot(&snap);

  char *yaml = emit_to_string(&snap, NULL);
  if (!yaml) {
    FAIL("emit_to_buf returned error");
    return;
  }

  if (!contains(yaml, "# Host: test-host")) {
    FAIL("missing hostname comment");
    return;
  }
  if (!contains(yaml, "# Date: 2026-02-08T12:00:00Z")) {
    FAIL("missing timestamp comment");
    return;
  }
  if (!contains(yaml, "# Generator: lota-agent --export-policy")) {
    FAIL("missing generator comment");
    return;
  }
  PASS();
}

static void test_emit_pcr_values(void) {
  TEST("policy_emit - PCR values formatted correctly");

  struct policy_snapshot snap;
  build_full_snapshot(&snap);

  char *yaml = emit_to_string(&snap, NULL);
  if (!yaml) {
    FAIL("emit_to_buf returned error");
    return;
  }

  /* PCR 0: 32 bytes of 0x01 -> "0101...01" (64 hex chars) */
  char expected_pcr0[128];
  snprintf(expected_pcr0, sizeof(expected_pcr0), "  0: \"%.*s\"", 64,
           "01010101010101010101010101010101"
           "01010101010101010101010101010101");

  if (!contains(yaml, expected_pcr0)) {
    FAIL("PCR 0 value mismatch");
    return;
  }

  /* PCR 7: 32 bytes of 0x07 */
  if (!contains(yaml, "  7: \"07070707")) {
    FAIL("PCR 7 value missing or wrong");
    return;
  }

  /* PCR 14: 32 bytes of 0x0E */
  if (!contains(yaml, "  14: \"0e0e0e0e")) {
    FAIL("PCR 14 value missing or wrong");
    return;
  }

  /* must have "pcrs:" section header */
  if (!contains(yaml, "pcrs:")) {
    FAIL("missing pcrs: section");
    return;
  }

  PASS();
}

static void test_emit_kernel_hash(void) {
  TEST("policy_emit - kernel hash in correct format");

  struct policy_snapshot snap;
  build_full_snapshot(&snap);

  char *yaml = emit_to_string(&snap, NULL);
  if (!yaml) {
    FAIL("emit_to_buf returned error");
    return;
  }

  if (!contains(yaml, "kernel_hashes:")) {
    FAIL("missing kernel_hashes section");
    return;
  }

  /* 32 bytes of 0xAA -> "aaaa..." */
  if (!contains(yaml, "  - \"aaaaaaaa")) {
    FAIL("kernel hash value mismatch");
    return;
  }

  if (!contains(yaml, "# Source: /boot/vmlinuz-6.12.0-test")) {
    FAIL("missing kernel path comment");
    return;
  }

  PASS();
}

static void test_emit_agent_hash(void) {
  TEST("policy_emit - agent hash in correct format");

  struct policy_snapshot snap;
  build_full_snapshot(&snap);

  char *yaml = emit_to_string(&snap, NULL);
  if (!yaml) {
    FAIL("emit_to_buf returned error");
    return;
  }

  if (!contains(yaml, "agent_hashes:")) {
    FAIL("missing agent_hashes section");
    return;
  }

  /* 32 bytes of 0xBB -> "bbbb..." */
  if (!contains(yaml, "  - \"bbbbbbbb")) {
    FAIL("agent hash value mismatch");
    return;
  }

  if (!contains(yaml, "# Source: /usr/sbin/lota-agent")) {
    FAIL("missing agent path comment");
    return;
  }

  PASS();
}

static void test_emit_security_flags(void) {
  TEST("policy_emit - security requirements match snapshot");

  struct policy_snapshot snap;
  build_full_snapshot(&snap);

  char *yaml = emit_to_string(&snap, NULL);
  if (!yaml) {
    FAIL("emit_to_buf returned error");
    return;
  }

  if (!has_yaml_line(yaml, "require_iommu: true")) {
    FAIL("require_iommu should be true");
    return;
  }
  if (!has_yaml_line(yaml, "require_enforce: true")) {
    FAIL("require_enforce should be true");
    return;
  }
  if (!has_yaml_line(yaml, "require_module_sig: true")) {
    FAIL("require_module_sig should be true");
    return;
  }
  if (!has_yaml_line(yaml, "require_secureboot: false")) {
    FAIL("require_secureboot should be false");
    return;
  }
  if (!has_yaml_line(yaml, "require_lockdown: false")) {
    FAIL("require_lockdown should be false");
    return;
  }

  PASS();
}

static void test_emit_no_pcrs(void) {
  TEST("policy_emit - no valid PCRs produces empty pcrs map");

  struct policy_snapshot snap;
  memset(&snap, 0, sizeof(snap));
  snprintf(snap.name, sizeof(snap.name), "empty");
  snprintf(snap.description, sizeof(snap.description), "empty policy");
  snap.pcr_count = 2;
  snap.pcrs[0].index = 0;
  snap.pcrs[0].valid = false;
  snap.pcrs[1].index = 7;
  snap.pcrs[1].valid = false;

  char *yaml = emit_to_string(&snap, NULL);
  if (!yaml) {
    FAIL("emit_to_buf returned error");
    return;
  }

  if (!has_yaml_line(yaml, "pcrs: {}")) {
    FAIL("expected 'pcrs: {}' for no valid PCRs");
    return;
  }

  PASS();
}

static void test_emit_no_kernel_hash(void) {
  TEST("policy_emit - missing kernel hash produces empty list");

  struct policy_snapshot snap;
  memset(&snap, 0, sizeof(snap));
  snprintf(snap.name, sizeof(snap.name), "no-kernel");
  snprintf(snap.description, sizeof(snap.description), "no kernel hash");
  snap.kernel_hash_valid = false;

  char *yaml = emit_to_string(&snap, NULL);
  if (!yaml) {
    FAIL("emit_to_buf returned error");
    return;
  }

  if (!has_yaml_line(yaml, "kernel_hashes: []")) {
    FAIL("expected 'kernel_hashes: []'");
    return;
  }

  PASS();
}

static void test_emit_no_agent_hash(void) {
  TEST("policy_emit - missing agent hash produces empty list");

  struct policy_snapshot snap;
  memset(&snap, 0, sizeof(snap));
  snprintf(snap.name, sizeof(snap.name), "no-agent");
  snprintf(snap.description, sizeof(snap.description), "no agent hash");
  snap.agent_hash_valid = false;

  char *yaml = emit_to_string(&snap, NULL);
  if (!yaml) {
    FAIL("emit_to_buf returned error");
    return;
  }

  if (!has_yaml_line(yaml, "agent_hashes: []")) {
    FAIL("expected 'agent_hashes: []'");
    return;
  }

  PASS();
}

static void test_emit_all_security_disabled(void) {
  TEST("policy_emit - all security flags false");

  struct policy_snapshot snap;
  memset(&snap, 0, sizeof(snap));
  snprintf(snap.name, sizeof(snap.name), "permissive");
  snprintf(snap.description, sizeof(snap.description), "permissive policy");

  char *yaml = emit_to_string(&snap, NULL);
  if (!yaml) {
    FAIL("emit_to_buf returned error");
    return;
  }

  if (!has_yaml_line(yaml, "require_iommu: false")) {
    FAIL("require_iommu should be false");
    return;
  }
  if (!has_yaml_line(yaml, "require_enforce: false")) {
    FAIL("require_enforce should be false");
    return;
  }
  if (!has_yaml_line(yaml, "require_module_sig: false")) {
    FAIL("require_module_sig should be false");
    return;
  }
  if (!has_yaml_line(yaml, "require_secureboot: false")) {
    FAIL("require_secureboot should be false");
    return;
  }
  if (!has_yaml_line(yaml, "require_lockdown: false")) {
    FAIL("require_lockdown should be false");
    return;
  }

  PASS();
}

static void test_emit_all_security_enabled(void) {
  TEST("policy_emit - all security flags true");

  struct policy_snapshot snap;
  memset(&snap, 0, sizeof(snap));
  snprintf(snap.name, sizeof(snap.name), "strict");
  snprintf(snap.description, sizeof(snap.description), "strict policy");
  snap.iommu_enabled = true;
  snap.enforce_mode = true;
  snap.module_sig = true;
  snap.secureboot = true;
  snap.lockdown = true;

  char *yaml = emit_to_string(&snap, NULL);
  if (!yaml) {
    FAIL("emit_to_buf returned error");
    return;
  }

  if (!has_yaml_line(yaml, "require_iommu: true")) {
    FAIL("require_iommu should be true");
    return;
  }
  if (!has_yaml_line(yaml, "require_enforce: true")) {
    FAIL("require_enforce should be true");
    return;
  }
  if (!has_yaml_line(yaml, "require_module_sig: true")) {
    FAIL("require_module_sig should be true");
    return;
  }
  if (!has_yaml_line(yaml, "require_secureboot: true")) {
    FAIL("require_secureboot should be true");
    return;
  }
  if (!has_yaml_line(yaml, "require_lockdown: true")) {
    FAIL("require_lockdown should be true");
    return;
  }

  PASS();
}

static void test_emit_null_args(void) {
  TEST("policy_emit - NULL arguments return EINVAL");

  struct policy_snapshot snap;
  memset(&snap, 0, sizeof(snap));

  int ret = policy_emit(NULL, stdout);
  if (ret != -EINVAL) {
    FAIL("expected -EINVAL for NULL snap");
    return;
  }

  ret = policy_emit(&snap, NULL);
  if (ret != -EINVAL) {
    FAIL("expected -EINVAL for NULL output");
    return;
  }

  PASS();
}

static void test_emit_to_buf_null_args(void) {
  TEST("policy_emit_to_buf - NULL arguments return EINVAL");

  struct policy_snapshot snap;
  memset(&snap, 0, sizeof(snap));
  char buf[128];
  size_t written;

  int ret = policy_emit_to_buf(NULL, buf, sizeof(buf), &written);
  if (ret != -EINVAL) {
    FAIL("expected -EINVAL for NULL snap");
    return;
  }

  ret = policy_emit_to_buf(&snap, NULL, sizeof(buf), &written);
  if (ret != -EINVAL) {
    FAIL("expected -EINVAL for NULL buf");
    return;
  }

  ret = policy_emit_to_buf(&snap, buf, 0, &written);
  if (ret != -EINVAL) {
    FAIL("expected -EINVAL for zero buf_size");
    return;
  }

  PASS();
}

static void test_emit_verifier_fields(void) {
  TEST("policy_emit - all verifier-required fields present");

  struct policy_snapshot snap;
  build_full_snapshot(&snap);

  char *yaml = emit_to_string(&snap, NULL);
  if (!yaml) {
    FAIL("emit_to_buf returned error");
    return;
  }

  /*
   * Go verifier PCRPolicy struct requires these top-level keys:
   *   name, description, pcrs, kernel_hashes, agent_hashes,
   *   require_iommu, require_enforce, require_module_sig,
   *   require_secureboot, require_lockdown
   */
  const char *required_keys[] = {
      "name:",
      "description:",
      "pcrs:",
      "kernel_hashes:",
      "agent_hashes:",
      "require_iommu:",
      "require_enforce:",
      "require_module_sig:",
      "require_secureboot:",
      "require_lockdown:",
  };
  int n = (int)(sizeof(required_keys) / sizeof(required_keys[0]));

  for (int i = 0; i < n; i++) {
    if (!contains(yaml, required_keys[i])) {
      char msg[128];
      snprintf(msg, sizeof(msg), "missing required key: %s", required_keys[i]);
      FAIL(msg);
      return;
    }
  }

  PASS();
}

static void test_emit_spdx_header(void) {
  TEST("policy_emit - SPDX license header present");

  struct policy_snapshot snap;
  memset(&snap, 0, sizeof(snap));
  snprintf(snap.name, sizeof(snap.name), "spdx-test");
  snprintf(snap.description, sizeof(snap.description), "spdx test");

  char *yaml = emit_to_string(&snap, NULL);
  if (!yaml) {
    FAIL("emit_to_buf returned error");
    return;
  }

  if (!contains(yaml, "# SPDX-License-Identifier: MIT")) {
    FAIL("missing SPDX header");
    return;
  }

  PASS();
}

static void test_emit_partial_pcrs(void) {
  TEST("policy_emit - only valid PCRs are emitted");

  struct policy_snapshot snap;
  memset(&snap, 0, sizeof(snap));
  snprintf(snap.name, sizeof(snap.name), "partial");
  snprintf(snap.description, sizeof(snap.description), "partial pcrs");

  snap.pcr_count = 3;
  snap.pcrs[0].index = 0;
  snap.pcrs[0].valid = false; /* PCR 0 failed -> skip */

  snap.pcrs[1].index = 7;
  memset(snap.pcrs[1].value, 0x77, LOTA_HASH_SIZE);
  snap.pcrs[1].valid = true;

  snap.pcrs[2].index = 14;
  snap.pcrs[2].valid = false; /* PCR 14 failed -> skip */

  char *yaml = emit_to_string(&snap, NULL);
  if (!yaml) {
    FAIL("emit_to_buf returned error");
    return;
  }

  /* only PCR 7 should appear */
  if (!contains(yaml, "  7: \"77777777")) {
    FAIL("PCR 7 should be present");
    return;
  }
  if (contains(yaml, "  0: \"")) {
    FAIL("PCR 0 should be absent (invalid)");
    return;
  }
  if (contains(yaml, "  14: \"")) {
    FAIL("PCR 14 should be absent (invalid)");
    return;
  }

  PASS();
}

static void test_emit_written_count(void) {
  TEST("policy_emit_to_buf - written count matches strlen");

  struct policy_snapshot snap;
  build_full_snapshot(&snap);

  char buf[8192];
  size_t written = 0;
  int ret = policy_emit_to_buf(&snap, buf, sizeof(buf), &written);
  if (ret != 0) {
    FAIL("emit_to_buf returned error");
    return;
  }

  if (written != strlen(buf)) {
    char msg[128];
    snprintf(msg, sizeof(msg), "written=%zu, strlen=%zu", written, strlen(buf));
    FAIL(msg);
    return;
  }

  if (written == 0) {
    FAIL("written should be > 0");
    return;
  }

  PASS();
}

int main(void) {
  printf("\n=== LOTA Policy Export - Test Suite ===\n\n");

  printf("YAML Serialization:\n");
  test_emit_full_snapshot();
  test_emit_metadata_comments();
  test_emit_pcr_values();
  test_emit_kernel_hash();
  test_emit_agent_hash();
  test_emit_security_flags();

  printf("\nEdge Cases:\n");
  test_emit_no_pcrs();
  test_emit_no_kernel_hash();
  test_emit_no_agent_hash();
  test_emit_partial_pcrs();
  test_emit_all_security_disabled();
  test_emit_all_security_enabled();

  printf("\nError Handling:\n");
  test_emit_null_args();
  test_emit_to_buf_null_args();

  printf("\nVerifier Compatibility:\n");
  test_emit_verifier_fields();
  test_emit_spdx_header();
  test_emit_written_count();

  printf("\n=== Results: %d/%d passed", tests_passed, tests_run);
  if (tests_passed < tests_run) {
    printf(" (%d FAILED)", tests_run - tests_passed);
  }
  printf(" ===\n\n");

  return tests_passed < tests_run ? 1 : 0;
}
