/* SPDX-License-Identifier: MIT */
/*
 * LOTA - Configuration File Parser Tests
 *
 * Tests config_init defaults, config_load parsing, config_dump output,
 * and edge cases (missing file, malformed lines, unknown keys, etc).
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../src/agent/config.h"

static int tests_run;
static int tests_passed;

#define TEST(name)                                                             \
  do {                                                                         \
    tests_run++;                                                               \
    printf("  [%d] %-50s ", tests_run, name);                                  \
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

static char tmpdir[64];

static void setup_tmpdir(void) {
  snprintf(tmpdir, sizeof(tmpdir), "/tmp/lota_test_config_XXXXXX");
  if (!mkdtemp(tmpdir)) {
    fprintf(stderr, "Failed to create temp dir: %s\n", strerror(errno));
    exit(1);
  }
}

static void cleanup_tmpdir(void) {
  char cmd[128];
  snprintf(cmd, sizeof(cmd), "rm -rf %s", tmpdir);
  int ret = system(cmd); (void)ret;
}

static int write_config(const char *name, const char *content) {
  char path[PATH_MAX];
  FILE *f;

  snprintf(path, sizeof(path), "%s/%s", tmpdir, name);
  f = fopen(path, "w");
  if (!f)
    return -1;
  fputs(content, f);
  fclose(f);
  return 0;
}

static void config_path(const char *name, char *out, size_t len) {
  snprintf(out, len, "%s/%s", tmpdir, name);
}

static void test_config_init_defaults(void) {
  struct lota_config cfg;

  TEST("config_init sets correct defaults");
  config_init(&cfg);

  if (strcmp(cfg.server, "localhost") != 0) {
    FAIL("server != localhost");
    return;
  }
  if (cfg.port != 8443) {
    FAIL("port != 8443");
    return;
  }
  if (cfg.no_verify_tls != false) {
    FAIL("no_verify_tls != false");
    return;
  }
  if (strcmp(cfg.bpf_path, "/usr/lib/lota/lota_lsm.bpf.o") != 0) {
    FAIL("bpf_path mismatch");
    return;
  }
  if (strcmp(cfg.mode, "monitor") != 0) {
    FAIL("mode != monitor");
    return;
  }
  if (cfg.strict_mmap != false) {
    FAIL("strict_mmap != false");
    return;
  }
  if (cfg.block_ptrace != false) {
    FAIL("block_ptrace != false");
    return;
  }
  if (cfg.attest_interval != 0) {
    FAIL("attest_interval != 0");
    return;
  }
  if (cfg.aik_ttl != 0) {
    FAIL("aik_ttl != 0");
    return;
  }
  if (cfg.aik_handle != 0x81010002) {
    FAIL("aik_handle != 0x81010002");
    return;
  }
  if (cfg.daemon != false) {
    FAIL("daemon != false");
    return;
  }
  if (strcmp(cfg.pid_file, "/run/lota/lota-agent.pid") != 0) {
    FAIL("pid_file mismatch");
    return;
  }
  if (strcmp(cfg.log_level, "info") != 0) {
    FAIL("log_level != info");
    return;
  }
  if (cfg.trust_lib_count != 0) {
    FAIL("trust_lib_count != 0");
    return;
  }
  if (cfg.protect_pid_count != 0) {
    FAIL("protect_pid_count != 0");
    return;
  }
  if (cfg.ca_cert[0] != '\0') {
    FAIL("ca_cert not empty");
    return;
  }
  if (cfg.signing_key[0] != '\0') {
    FAIL("signing_key not empty");
    return;
  }
  if (cfg.policy_pubkey[0] != '\0') {
    FAIL("policy_pubkey not empty");
    return;
  }
  PASS();
}

static void test_config_init_null(void) {
  TEST("config_init with NULL does not crash");
  config_init(NULL);
  PASS();
}

static void test_config_load_nonexistent(void) {
  struct lota_config cfg;
  int ret;

  TEST("config_load returns -ENOENT for missing file");
  config_init(&cfg);
  ret = config_load(&cfg, "/tmp/lota_nonexistent_XYZ.conf");
  if (ret != -ENOENT) {
    char msg[64];
    snprintf(msg, sizeof(msg), "expected -ENOENT, got %d", ret);
    FAIL(msg);
    return;
  }
  PASS();
}

static void test_config_load_null_cfg(void) {
  int ret;

  TEST("config_load with NULL cfg returns -EINVAL");
  ret = config_load(NULL, "/dev/null");
  if (ret != -EINVAL) {
    FAIL("expected -EINVAL");
    return;
  }
  PASS();
}

static void test_config_load_empty_file(void) {
  struct lota_config cfg;
  char path[PATH_MAX];
  int ret;

  TEST("config_load with empty file returns 0");
  write_config("empty.conf", "");
  config_path("empty.conf", path, sizeof(path));
  config_init(&cfg);
  ret = config_load(&cfg, path);
  if (ret != 0) {
    char msg[64];
    snprintf(msg, sizeof(msg), "expected 0, got %d", ret);
    FAIL(msg);
    return;
  }
  /* defaults should be unchanged */
  if (strcmp(cfg.server, "localhost") != 0) {
    FAIL("server changed after empty file");
    return;
  }
  PASS();
}

static void test_config_load_comments_only(void) {
  struct lota_config cfg;
  char path[PATH_MAX];
  int ret;

  TEST("config_load with comments only returns 0");
  write_config("comments.conf", "# comment 1\n# comment 2\n  # indented\n\n");
  config_path("comments.conf", path, sizeof(path));
  config_init(&cfg);
  ret = config_load(&cfg, path);
  if (ret != 0) {
    FAIL("expected 0");
    return;
  }
  PASS();
}

static void test_config_load_basic_values(void) {
  struct lota_config cfg;
  char path[PATH_MAX];
  int ret;

  TEST("config_load parses basic key = value pairs");
  write_config("basic.conf", "server = 10.0.0.1\n"
                             "port = 9443\n"
                             "mode = enforce\n"
                             "strict_mmap = true\n"
                             "block_ptrace = yes\n"
                             "attest_interval = 600\n"
                             "aik_ttl = 7200\n"
                             "aik_handle = 0x81010003\n"
                             "daemon = 1\n"
                             "log_level = debug\n");
  config_path("basic.conf", path, sizeof(path));
  config_init(&cfg);
  ret = config_load(&cfg, path);
  if (ret != 0) {
    char msg[64];
    snprintf(msg, sizeof(msg), "expected 0, got %d", ret);
    FAIL(msg);
    return;
  }
  if (strcmp(cfg.server, "10.0.0.1") != 0) {
    FAIL("server mismatch");
    return;
  }
  if (cfg.port != 9443) {
    FAIL("port mismatch");
    return;
  }
  if (strcmp(cfg.mode, "enforce") != 0) {
    FAIL("mode mismatch");
    return;
  }
  if (cfg.strict_mmap != true) {
    FAIL("strict_mmap != true");
    return;
  }
  if (cfg.block_ptrace != true) {
    FAIL("block_ptrace != true");
    return;
  }
  if (cfg.attest_interval != 600) {
    FAIL("attest_interval != 600");
    return;
  }
  if (cfg.aik_ttl != 7200) {
    FAIL("aik_ttl != 7200");
    return;
  }
  if (cfg.aik_handle != 0x81010003) {
    FAIL("aik_handle != 0x81010003");
    return;
  }
  if (cfg.daemon != true) {
    FAIL("daemon != true");
    return;
  }
  if (strcmp(cfg.log_level, "debug") != 0) {
    FAIL("log_level mismatch");
    return;
  }
  PASS();
}

static void test_config_load_string_fields(void) {
  struct lota_config cfg;
  char path[PATH_MAX];
  int ret;

  TEST("config_load parses string fields correctly");
  write_config("strings.conf", "ca_cert = /etc/lota/ca.pem\n"
                               "pin_sha256 = aabb1122\n"
                               "bpf_path = /opt/lota/custom.bpf.o\n"
                               "pid_file = /var/run/lota.pid\n"
                               "signing_key = /etc/lota/sign.key\n"
                               "policy_pubkey = /etc/lota/sign.pub\n");
  config_path("strings.conf", path, sizeof(path));
  config_init(&cfg);
  ret = config_load(&cfg, path);
  if (ret != 0) {
    FAIL("load failed");
    return;
  }
  if (strcmp(cfg.ca_cert, "/etc/lota/ca.pem") != 0) {
    FAIL("ca_cert mismatch");
    return;
  }
  if (strcmp(cfg.pin_sha256, "aabb1122") != 0) {
    FAIL("pin_sha256 mismatch");
    return;
  }
  if (strcmp(cfg.bpf_path, "/opt/lota/custom.bpf.o") != 0) {
    FAIL("bpf_path mismatch");
    return;
  }
  if (strcmp(cfg.pid_file, "/var/run/lota.pid") != 0) {
    FAIL("pid_file mismatch");
    return;
  }
  if (strcmp(cfg.signing_key, "/etc/lota/sign.key") != 0) {
    FAIL("signing_key mismatch");
    return;
  }
  if (strcmp(cfg.policy_pubkey, "/etc/lota/sign.pub") != 0) {
    FAIL("policy_pubkey mismatch");
    return;
  }
  PASS();
}

static void test_config_load_hyphen_keys(void) {
  struct lota_config cfg;
  char path[PATH_MAX];
  int ret;

  TEST("config_load accepts hyphen-form keys");
  write_config("hyphen.conf", "ca-cert = /etc/ca.pem\n"
                              "no-verify-tls = true\n"
                              "pin-sha256 = deadbeef\n"
                              "bpf-path = /opt/bpf.o\n"
                              "strict-mmap = true\n"
                              "block-ptrace = true\n"
                              "attest-interval = 120\n"
                              "aik-ttl = 3600\n"
                              "aik-handle = 0x81020001\n"
                              "pid-file = /tmp/test.pid\n"
                              "signing-key = /tmp/sign.key\n"
                              "policy-pubkey = /tmp/sign.pub\n"
                              "trust-lib = /usr/lib/libfoo.so\n"
                              "protect-pid = 42\n"
                              "log-level = warn\n");
  config_path("hyphen.conf", path, sizeof(path));
  config_init(&cfg);
  ret = config_load(&cfg, path);
  if (ret != 0) {
    FAIL("load failed");
    return;
  }
  if (strcmp(cfg.ca_cert, "/etc/ca.pem") != 0) {
    FAIL("ca-cert");
    return;
  }
  if (cfg.no_verify_tls != true) {
    FAIL("no-verify-tls");
    return;
  }
  if (strcmp(cfg.pin_sha256, "deadbeef") != 0) {
    FAIL("pin-sha256");
    return;
  }
  if (strcmp(cfg.bpf_path, "/opt/bpf.o") != 0) {
    FAIL("bpf-path");
    return;
  }
  if (cfg.strict_mmap != true) {
    FAIL("strict-mmap");
    return;
  }
  if (cfg.block_ptrace != true) {
    FAIL("block-ptrace");
    return;
  }
  if (cfg.attest_interval != 120) {
    FAIL("attest-interval");
    return;
  }
  if (cfg.aik_ttl != 3600) {
    FAIL("aik-ttl");
    return;
  }
  if (cfg.aik_handle != 0x81020001) {
    FAIL("aik-handle");
    return;
  }
  if (strcmp(cfg.pid_file, "/tmp/test.pid") != 0) {
    FAIL("pid-file");
    return;
  }
  if (strcmp(cfg.signing_key, "/tmp/sign.key") != 0) {
    FAIL("signing-key");
    return;
  }
  if (strcmp(cfg.policy_pubkey, "/tmp/sign.pub") != 0) {
    FAIL("policy-pubkey");
    return;
  }
  if (cfg.trust_lib_count != 1 ||
      strcmp(cfg.trust_libs[0], "/usr/lib/libfoo.so") != 0) {
    FAIL("trust-lib");
    return;
  }
  if (cfg.protect_pid_count != 1 || cfg.protect_pids[0] != 42) {
    FAIL("protect-pid");
    return;
  }
  if (strcmp(cfg.log_level, "warn") != 0) {
    FAIL("log-level");
    return;
  }
  PASS();
}

static void test_config_load_trust_libs_multiple(void) {
  struct lota_config cfg;
  char path[PATH_MAX];
  int ret;

  TEST("config_load accumulates multiple trust_lib entries");
  write_config("libs.conf", "trust_lib = /usr/lib/libc.so.6\n"
                            "trust_lib = /usr/lib/libssl.so.3\n"
                            "trust_lib = /usr/lib/libcrypto.so.3\n");
  config_path("libs.conf", path, sizeof(path));
  config_init(&cfg);
  ret = config_load(&cfg, path);
  if (ret != 0) {
    FAIL("load failed");
    return;
  }
  if (cfg.trust_lib_count != 3) {
    char msg[64];
    snprintf(msg, sizeof(msg), "count=%d, expected 3", cfg.trust_lib_count);
    FAIL(msg);
    return;
  }
  if (strcmp(cfg.trust_libs[0], "/usr/lib/libc.so.6") != 0) {
    FAIL("trust_libs[0]");
    return;
  }
  if (strcmp(cfg.trust_libs[1], "/usr/lib/libssl.so.3") != 0) {
    FAIL("trust_libs[1]");
    return;
  }
  if (strcmp(cfg.trust_libs[2], "/usr/lib/libcrypto.so.3") != 0) {
    FAIL("trust_libs[2]");
    return;
  }
  PASS();
}

static void test_config_load_protect_pids_multiple(void) {
  struct lota_config cfg;
  char path[PATH_MAX];
  int ret;

  TEST("config_load accumulates multiple protect_pid entries");
  write_config("pids.conf", "protect_pid = 100\n"
                            "protect_pid = 200\n"
                            "protect_pid = 300\n");
  config_path("pids.conf", path, sizeof(path));
  config_init(&cfg);
  ret = config_load(&cfg, path);
  if (ret != 0) {
    FAIL("load failed");
    return;
  }
  if (cfg.protect_pid_count != 3) {
    FAIL("count != 3");
    return;
  }
  if (cfg.protect_pids[0] != 100 || cfg.protect_pids[1] != 200 ||
      cfg.protect_pids[2] != 300) {
    FAIL("pid values");
    return;
  }
  PASS();
}

static void test_config_load_boolean_variants(void) {
  struct lota_config cfg;
  char path[PATH_MAX];
  int ret;

  TEST("config_load boolean: true/yes/1 -> true");
  write_config("bool_true.conf", "no_verify_tls = true\n"
                                 "strict_mmap = yes\n"
                                 "block_ptrace = 1\n");
  config_path("bool_true.conf", path, sizeof(path));
  config_init(&cfg);
  ret = config_load(&cfg, path);
  if (ret != 0) {
    FAIL("load failed");
    return;
  }
  if (!cfg.no_verify_tls || !cfg.strict_mmap || !cfg.block_ptrace) {
    FAIL("not all true");
    return;
  }
  PASS();

  TEST("config_load boolean: false/no/0 -> false");
  write_config("bool_false.conf", "no_verify_tls = false\n"
                                  "strict_mmap = no\n"
                                  "block_ptrace = 0\n");
  config_path("bool_false.conf", path, sizeof(path));
  config_init(&cfg);
  cfg.no_verify_tls = true;
  cfg.strict_mmap = true;
  cfg.block_ptrace = true;
  ret = config_load(&cfg, path);
  if (ret != 0) {
    FAIL("load failed");
    return;
  }
  if (cfg.no_verify_tls || cfg.strict_mmap || cfg.block_ptrace) {
    FAIL("not all false");
    return;
  }
  PASS();
}

static void test_config_load_whitespace_trimming(void) {
  struct lota_config cfg;
  char path[PATH_MAX];
  int ret;

  TEST("config_load trims whitespace around keys and values");
  write_config("ws.conf", "  server  =   myhost   \n"
                          "\tport\t=\t1234\t\n"
                          "  mode=enforce\n");
  config_path("ws.conf", path, sizeof(path));
  config_init(&cfg);
  ret = config_load(&cfg, path);
  if (ret != 0) {
    FAIL("load failed");
    return;
  }
  if (strcmp(cfg.server, "myhost") != 0) {
    FAIL("server trimming");
    return;
  }
  if (cfg.port != 1234) {
    FAIL("port != 1234");
    return;
  }
  if (strcmp(cfg.mode, "enforce") != 0) {
    FAIL("mode != enforce");
    return;
  }
  PASS();
}

static void test_config_load_unknown_keys(void) {
  struct lota_config cfg;
  char path[PATH_MAX];
  int ret;

  TEST("config_load logs unknown keys but returns 0");
  write_config("unknown.conf", "server = ok\n"
                               "totally_bogus_key = whatever\n"
                               "port = 1234\n");
  config_path("unknown.conf", path, sizeof(path));
  config_init(&cfg);
  ret = config_load(&cfg, path);
  /* unknown keys are logged but don't cause error return */
  if (ret != 0) {
    FAIL("expected 0");
    return;
  }
  /* valid keys should still be applied */
  if (strcmp(cfg.server, "ok") != 0) {
    FAIL("server not set");
    return;
  }
  if (cfg.port != 1234) {
    FAIL("port not set");
    return;
  }
  PASS();
}

static void test_config_load_malformed_lines(void) {
  struct lota_config cfg;
  char path[PATH_MAX];
  int ret;

  TEST("config_load returns -EINVAL for malformed lines");
  write_config("malformed.conf", "server = ok\n"
                                 "this line has no equals sign\n"
                                 "port = 1234\n");
  config_path("malformed.conf", path, sizeof(path));
  config_init(&cfg);
  ret = config_load(&cfg, path);
  if (ret != -EINVAL) {
    char msg[64];
    snprintf(msg, sizeof(msg), "expected -EINVAL, got %d", ret);
    FAIL(msg);
    return;
  }
  /* valid keys should still be applied despite the error */
  if (strcmp(cfg.server, "ok") != 0) {
    FAIL("server not set");
    return;
  }
  if (cfg.port != 1234) {
    FAIL("port not set after malformed line");
    return;
  }
  PASS();
}

static void test_config_load_empty_key(void) {
  struct lota_config cfg;
  char path[PATH_MAX];
  int ret;

  TEST("config_load returns -EINVAL for empty key");
  write_config("emptykey.conf", " = some_value\n");
  config_path("emptykey.conf", path, sizeof(path));
  config_init(&cfg);
  ret = config_load(&cfg, path);
  if (ret != -EINVAL) {
    FAIL("expected -EINVAL");
    return;
  }
  PASS();
}

static void test_config_load_empty_value(void) {
  struct lota_config cfg;
  char path[PATH_MAX];
  int ret;

  TEST("config_load allows empty value (clears field)");
  write_config("emptyval.conf", "ca_cert = /some/path\n"
                                "ca_cert =\n");
  config_path("emptyval.conf", path, sizeof(path));
  config_init(&cfg);
  ret = config_load(&cfg, path);
  if (ret != 0) {
    FAIL("expected 0");
    return;
  }
  if (cfg.ca_cert[0] != '\0') {
    FAIL("ca_cert not empty after clear");
    return;
  }
  PASS();
}

static void test_config_load_port_bounds(void) {
  struct lota_config cfg;
  char path[PATH_MAX];
  int ret;

  TEST("config_load ignores out-of-range port values");
  write_config("port_bad.conf", "port = 99999\n");
  config_path("port_bad.conf", path, sizeof(path));
  config_init(&cfg);
  ret = config_load(&cfg, path);
  if (ret != 0) {
    FAIL("expected 0");
    return;
  }
  /* port should remain at default because 99999 > 65535 */
  if (cfg.port != 8443) {
    char msg[64];
    snprintf(msg, sizeof(msg), "port=%d, expected 8443", cfg.port);
    FAIL(msg);
    return;
  }
  PASS();

  TEST("config_load ignores port = 0");
  write_config("port_zero.conf", "port = 0\n");
  config_path("port_zero.conf", path, sizeof(path));
  config_init(&cfg);
  ret = config_load(&cfg, path);
  if (ret != 0) {
    FAIL("expected 0");
    return;
  }
  if (cfg.port != 8443) {
    FAIL("port changed to 0");
    return;
  }
  PASS();
}

static void test_config_dump_roundtrip(void) {
  struct lota_config cfg1, cfg2;
  char dump_path[PATH_MAX];
  char reload_path[PATH_MAX];
  FILE *f;
  int ret;

  TEST("config_dump -> config_load roundtrip");
  config_init(&cfg1);

  /* set some non-default values */
  snprintf(cfg1.server, sizeof(cfg1.server), "verifier.example.com");
  cfg1.port = 9999;
  snprintf(cfg1.ca_cert, sizeof(cfg1.ca_cert), "/etc/ssl/ca.pem");
  cfg1.no_verify_tls = true;
  cfg1.strict_mmap = true;
  cfg1.attest_interval = 120;
  snprintf(cfg1.log_level, sizeof(cfg1.log_level), "error");
  cfg1.trust_lib_count = 1;
  snprintf(cfg1.trust_libs[0], sizeof(cfg1.trust_libs[0]), "/usr/lib/foo.so");
  cfg1.protect_pid_count = 2;
  cfg1.protect_pids[0] = 11;
  cfg1.protect_pids[1] = 22;

  /* dump to file */
  snprintf(dump_path, sizeof(dump_path), "%s/dumped.conf", tmpdir);
  f = fopen(dump_path, "w");
  if (!f) {
    FAIL("fopen dump");
    return;
  }
  config_dump(&cfg1, f);
  fclose(f);

  /* reload */
  config_init(&cfg2);
  snprintf(reload_path, sizeof(reload_path), "%s/dumped.conf", tmpdir);
  ret = config_load(&cfg2, reload_path);
  if (ret != 0) {
    char msg[64];
    snprintf(msg, sizeof(msg), "reload failed: %d", ret);
    FAIL(msg);
    return;
  }

  /* verify key fields survived roundtrip */
  if (strcmp(cfg2.server, "verifier.example.com") != 0) {
    FAIL("server mismatch");
    return;
  }
  if (cfg2.port != 9999) {
    FAIL("port mismatch");
    return;
  }
  if (strcmp(cfg2.ca_cert, "/etc/ssl/ca.pem") != 0) {
    FAIL("ca_cert mismatch");
    return;
  }
  if (cfg2.no_verify_tls != true) {
    FAIL("no_verify_tls mismatch");
    return;
  }
  if (cfg2.strict_mmap != true) {
    FAIL("strict_mmap mismatch");
    return;
  }
  if (cfg2.attest_interval != 120) {
    FAIL("attest_interval mismatch");
    return;
  }
  if (strcmp(cfg2.log_level, "error") != 0) {
    FAIL("log_level mismatch");
    return;
  }
  if (cfg2.trust_lib_count != 1) {
    FAIL("trust_lib_count mismatch");
    return;
  }
  if (cfg2.protect_pid_count != 2) {
    FAIL("protect_pid_count mismatch");
    return;
  }
  if (cfg2.protect_pids[0] != 11 || cfg2.protect_pids[1] != 22) {
    FAIL("protect_pids mismatch");
    return;
  }
  PASS();
}

static void test_config_dump_null(void) {
  struct lota_config cfg;

  TEST("config_dump with NULL args does not crash");
  config_init(&cfg);
  config_dump(NULL, stdout);
  config_dump(&cfg, NULL);
  config_dump(NULL, NULL);
  PASS();
}

static void test_config_load_all_known_keys(void) {
  struct lota_config cfg;
  char path[PATH_MAX];
  int ret;

  TEST("config_load with every known key returns 0");
  write_config("all.conf", "server = allhost\n"
                           "port = 5555\n"
                           "ca_cert = /all/ca.pem\n"
                           "no_verify_tls = true\n"
                           "pin_sha256 = abcdef0123456789\n"
                           "bpf_path = /all/lota.bpf.o\n"
                           "mode = maintenance\n"
                           "strict_mmap = true\n"
                           "block_ptrace = true\n"
                           "attest_interval = 999\n"
                           "aik_ttl = 86400\n"
                           "aik_handle = 0x81010005\n"
                           "daemon = true\n"
                           "pid_file = /all/pid\n"
                           "signing_key = /all/sign.key\n"
                           "policy_pubkey = /all/sign.pub\n"
                           "trust_lib = /all/lib1.so\n"
                           "trust_lib = /all/lib2.so\n"
                           "protect_pid = 1\n"
                           "protect_pid = 2\n"
                           "log_level = error\n");
  config_path("all.conf", path, sizeof(path));
  config_init(&cfg);
  ret = config_load(&cfg, path);
  if (ret != 0) {
    char msg[64];
    snprintf(msg, sizeof(msg), "expected 0, got %d", ret);
    FAIL(msg);
    return;
  }
  if (strcmp(cfg.server, "allhost") != 0) {
    FAIL("server");
    return;
  }
  if (cfg.port != 5555) {
    FAIL("port");
    return;
  }
  if (strcmp(cfg.ca_cert, "/all/ca.pem") != 0) {
    FAIL("ca_cert");
    return;
  }
  if (!cfg.no_verify_tls) {
    FAIL("no_verify_tls");
    return;
  }
  if (strcmp(cfg.pin_sha256, "abcdef0123456789") != 0) {
    FAIL("pin_sha256");
    return;
  }
  if (strcmp(cfg.bpf_path, "/all/lota.bpf.o") != 0) {
    FAIL("bpf_path");
    return;
  }
  if (strcmp(cfg.mode, "maintenance") != 0) {
    FAIL("mode");
    return;
  }
  if (!cfg.strict_mmap) {
    FAIL("strict_mmap");
    return;
  }
  if (!cfg.block_ptrace) {
    FAIL("block_ptrace");
    return;
  }
  if (cfg.attest_interval != 999) {
    FAIL("attest_interval");
    return;
  }
  if (cfg.aik_ttl != 86400) {
    FAIL("aik_ttl");
    return;
  }
  if (cfg.aik_handle != 0x81010005) {
    FAIL("aik_handle");
    return;
  }
  if (!cfg.daemon) {
    FAIL("daemon");
    return;
  }
  if (strcmp(cfg.pid_file, "/all/pid") != 0) {
    FAIL("pid_file");
    return;
  }
  if (strcmp(cfg.signing_key, "/all/sign.key") != 0) {
    FAIL("signing_key");
    return;
  }
  if (strcmp(cfg.policy_pubkey, "/all/sign.pub") != 0) {
    FAIL("policy_pubkey");
    return;
  }
  if (cfg.trust_lib_count != 2) {
    FAIL("trust_lib_count");
    return;
  }
  if (cfg.protect_pid_count != 2) {
    FAIL("protect_pid_count");
    return;
  }
  if (strcmp(cfg.log_level, "error") != 0) {
    FAIL("log_level");
    return;
  }
  PASS();
}

static void test_config_load_override_order(void) {
  struct lota_config cfg;
  char path[PATH_MAX];
  int ret;

  TEST("config_load last value wins for scalar fields");
  write_config("override.conf", "server = first\n"
                                "server = second\n"
                                "port = 1111\n"
                                "port = 2222\n");
  config_path("override.conf", path, sizeof(path));
  config_init(&cfg);
  ret = config_load(&cfg, path);
  if (ret != 0) {
    FAIL("load failed");
    return;
  }
  if (strcmp(cfg.server, "second") != 0) {
    FAIL("server should be 'second'");
    return;
  }
  if (cfg.port != 2222) {
    FAIL("port should be 2222");
    return;
  }
  PASS();
}

static void test_config_load_mixed_comments(void) {
  struct lota_config cfg;
  char path[PATH_MAX];
  int ret;

  TEST("config_load handles interleaved comments and values");
  write_config("mixed.conf", "# header comment\n"
                             "\n"
                             "server = host1\n"
                             "# middle comment\n"
                             "port = 1234\n"
                             "\n"
                             "# trailing comment\n");
  config_path("mixed.conf", path, sizeof(path));
  config_init(&cfg);
  ret = config_load(&cfg, path);
  if (ret != 0) {
    FAIL("expected 0");
    return;
  }
  if (strcmp(cfg.server, "host1") != 0 || cfg.port != 1234) {
    FAIL("values not parsed correctly");
    return;
  }
  PASS();
}

int main(void) {
  printf("=== LOTA Config Parser Tests ===\n\n");

  setup_tmpdir();

  test_config_init_defaults();
  test_config_init_null();
  test_config_load_nonexistent();
  test_config_load_null_cfg();
  test_config_load_empty_file();
  test_config_load_comments_only();
  test_config_load_basic_values();
  test_config_load_string_fields();
  test_config_load_hyphen_keys();
  test_config_load_trust_libs_multiple();
  test_config_load_protect_pids_multiple();
  test_config_load_boolean_variants();
  test_config_load_whitespace_trimming();
  test_config_load_unknown_keys();
  test_config_load_malformed_lines();
  test_config_load_empty_key();
  test_config_load_empty_value();
  test_config_load_port_bounds();
  test_config_dump_roundtrip();
  test_config_dump_null();
  test_config_load_all_known_keys();
  test_config_load_override_order();
  test_config_load_mixed_comments();

  cleanup_tmpdir();

  printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
  return (tests_passed == tests_run) ? 0 : 1;
}
