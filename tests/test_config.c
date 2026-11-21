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
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <syslog.h>
#include <unistd.h>
#include <stdbool.h>

#include "test.h"
#include "../src/agent/agent.h"
#include "../src/agent/attest.h"
#include "../src/agent/cli.h"
#include "../src/agent/config.h"
#include "../src/agent/journal.h"
#include "../src/agent/main_utils.h"
#include "../src/agent/policy_pubkey.h"
#include "../src/agent/tpm.h"

/* What cli.c reaches outside the parser */
struct agent_globals g_agent;

void journal_set_level(int priority)
{
	(void)priority;
}

int parse_mode(const char *mode_str)
{
	if (mode_str && strcmp(mode_str, "enforce") == 0)
		return LOTA_MODE_ENFORCE;
	if (mode_str && strcmp(mode_str, "monitor") == 0)
		return LOTA_MODE_MONITOR;
	return -1;
}

void print_usage(const char *prog, const char *default_bpf_path,
		 int default_verifier_port)
{
	(void)prog;
	(void)default_bpf_path;
	(void)default_verifier_port;
}

int tpm_set_kernel_path(struct tpm_context *ctx, const char *path)
{
	(void)ctx;
	(void)path;
	return 0;
}

const char *tpm_strerror(int err)
{
	(void)err;
	return "stub";
}

static char tmpdir[64];

static void setup_tmpdir(void)
{
	snprintf(tmpdir, sizeof(tmpdir), "/tmp/lota_test_config_XXXXXX");
	if (!mkdtemp(tmpdir)) {
		FAIL("Failed to create temp dir: %s", strerror(errno));
		exit(1);
	}
}

static void cleanup_tmpdir(void)
{
	char cmd[128];
	snprintf(cmd, sizeof(cmd), "rm -rf %s", tmpdir);
	int ret = system(cmd);
	(void)ret;
}

static int write_config(const char *name, const char *content)
{
	char path[PATH_MAX];
	FILE *f;

	snprintf(path, sizeof(path), "%s/%s", tmpdir, name);
	{
		int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
		f = fd >= 0 ? fdopen(fd, "w") : NULL;
		if (fd >= 0 && !f)
			close(fd);
	}
	if (!f)
		return -1;
	fputs(content, f);
	fclose(f);
	return 0;
}

static void config_path(const char *name, char *out, size_t len)
{
	snprintf(out, len, "%s/%s", tmpdir, name);
}

static void test_config_init_defaults(void)
{
	struct lota_config cfg;

	TEST("config_init sets correct defaults");
	config_init(&cfg);

	/* no verifier until one is named: the loop would report to it */
	if (cfg.server[0] != '\0') {
		FAIL("server has a default");
		return;
	}
	if (cfg.port != 8443) {
		FAIL("port != 8443");
		return;
	}
	if (strcmp(cfg.bpf_path, "/usr/lib/lota/lota_lsm.bpf.o") != 0) {
		FAIL("bpf_path mismatch");
		return;
	}
	if (strcmp(cfg.mode, "enforce") != 0) {
		FAIL("mode != enforce");
		return;
	}
	if (cfg.strict_mmap != false) {
		FAIL("strict_mmap != false");
		return;
	}
	if (cfg.strict_exec != false) {
		FAIL("strict_exec != false");
		return;
	}
	if (cfg.block_ptrace != false) {
		FAIL("block_ptrace != false");
		return;
	}
	if (cfg.strict_modules != false) {
		FAIL("strict_modules != false");
		return;
	}
	if (cfg.block_anon_exec != false) {
		FAIL("block_anon_exec != false");
		return;
	}
	if (cfg.seal_aik_auth != false) {
		FAIL("seal_aik_auth default != false");
		return;
	}
	if (cfg.seal_aik_auth_strict != false) {
		FAIL("seal_aik_auth_strict default != false");
		return;
	}
	if (cfg.attest_interval != 0) {
		FAIL("attest_interval != 0");
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
	if (cfg.container_listener_uid_count != 0) {
		FAIL("container_listener_uid_count != 0");
		return;
	}
	if (cfg.ca_cert[0] != '\0') {
		FAIL("ca_cert not empty");
		return;
	}
	if (cfg.policy_pubkey[0] != '\0') {
		FAIL("policy_pubkey not empty");
		return;
	}
}

static void test_config_load_nonexistent(void)
{
	struct lota_config cfg;
	int ret;

	TEST("config_load returns -ENOENT for missing file");
	config_init(&cfg);
	ret = config_load(&cfg, "/tmp/lota_nonexistent_XYZ.conf");
	if (ret != -ENOENT) {
		char msg[64];
		snprintf(msg, sizeof(msg), "expected -ENOENT, got %d", ret);
		FAIL("%s", msg);
		return;
	}
}

static void test_config_load_null_cfg(void)
{
	int ret;

	TEST("config_load with NULL cfg returns -EINVAL");
	ret = config_load(NULL, "/dev/null");
	if (ret != -EINVAL) {
		FAIL("expected -EINVAL");
		return;
	}
}

static void test_config_load_empty_file(void)
{
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
		FAIL("%s", msg);
		return;
	}
	/* defaults should be unchanged */
	if (cfg.server[0] != '\0') {
		FAIL("server changed after empty file");
		return;
	}
}

static void test_config_load_comments_only(void)
{
	struct lota_config cfg;
	char path[PATH_MAX];
	int ret;

	TEST("config_load with comments only returns 0");
	write_config("comments.conf",
		     "# comment 1\n# comment 2\n  # indented\n\n");
	config_path("comments.conf", path, sizeof(path));
	config_init(&cfg);
	ret = config_load(&cfg, path);
	if (ret != 0) {
		FAIL("expected 0");
		return;
	}
}

static void test_config_load_basic_values(void)
{
	struct lota_config cfg;
	char path[PATH_MAX];
	int ret;

	TEST("config_load parses basic key = value pairs");
	write_config("basic.conf", "server = 10.0.0.1\n"
				   "port = 9443\n"
				   "mode = enforce\n"
				   "strict_mmap = true\n"
				   "block_ptrace = yes\n"
				   "attest_interval = 240\n"
				   "aik_handle = 0x81010003\n"
				   "seal_aik_auth = true\n"
				   "seal_aik_auth_strict = true\n"
				   "daemon = 1\n"
				   "log_level = debug\n");
	config_path("basic.conf", path, sizeof(path));
	config_init(&cfg);
	ret = config_load(&cfg, path);
	if (ret != 0) {
		char msg[64];
		snprintf(msg, sizeof(msg), "expected 0, got %d", ret);
		FAIL("%s", msg);
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
	if (cfg.attest_interval != 240) {
		FAIL("attest_interval != 240");
		return;
	}
	if (cfg.aik_handle != 0x81010003) {
		FAIL("aik_handle != 0x81010003");
		return;
	}
	if (cfg.seal_aik_auth != true) {
		FAIL("seal_aik_auth != true");
		return;
	}
	if (cfg.seal_aik_auth_strict != true) {
		FAIL("seal_aik_auth_strict != true");
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
}

static void test_config_load_string_fields(void)
{
	struct lota_config cfg;
	char path[PATH_MAX];
	int ret;

	TEST("config_load parses string fields correctly");
	write_config(
		"strings.conf",
		"ca_cert = /etc/lota/ca.pem\n"
		"pin_sha256 = aabb112200000000000000000000000000000000000000000000000000000000\n"
		"bpf_path = /opt/lota/custom.bpf.o\n"
		"pid_file = /var/run/lota.pid\n"
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
	if (strcmp(cfg.pin_sha256,
		   "aabb112200000000000000000000000000000000000000000000000000000000") !=
	    0) {
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
	if (strcmp(cfg.policy_pubkey, "/etc/lota/sign.pub") != 0) {
		FAIL("policy_pubkey mismatch");
		return;
	}
}

static void test_config_load_hyphen_keys(void)
{
	struct lota_config cfg;
	char path[PATH_MAX];
	int ret;

	TEST("config_load accepts hyphen-form keys");
	write_config(
		"hyphen.conf",
		"ca-cert = /etc/ca.pem\n"
		"pin-sha256 = deadbeef11111111111111111111111111111111111111111111111111111111\n"
		"bpf-path = /opt/bpf.o\n"
		"strict-mmap = true\n"
		"block-ptrace = true\n"
		"attest-interval = 120\n"
		"aik-handle = 0x81020001\n"
		"pid-file = /tmp/test.pid\n"
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
	if (strcmp(cfg.pin_sha256,
		   "deadbeef11111111111111111111111111111111111111111111111111111111") !=
	    0) {
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
	if (cfg.aik_handle != 0x81020001) {
		FAIL("aik-handle");
		return;
	}
	if (strcmp(cfg.pid_file, "/tmp/test.pid") != 0) {
		FAIL("pid-file");
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
}

static void test_config_load_trust_libs_multiple(void)
{
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
		snprintf(msg, sizeof(msg), "count=%d, expected 3",
			 cfg.trust_lib_count);
		FAIL("%s", msg);
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
}

static void test_config_load_protect_pids_multiple(void)
{
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
}

static void test_config_load_container_listener_uids_multiple(void)
{
	struct lota_config cfg;
	char path[PATH_MAX];
	int ret;

	TEST("config_load accumulates multiple container_listener_uid entries");
	write_config("uids.conf", "container_listener_uid = 1000\n"
				  "container_listener_uid = 1001\n"
				  "container_listener_uid = 1002\n");
	config_path("uids.conf", path, sizeof(path));
	config_init(&cfg);
	ret = config_load(&cfg, path);
	if (ret != 0) {
		FAIL("load failed");
		return;
	}
	if (cfg.container_listener_uid_count != 3) {
		FAIL("count != 3");
		return;
	}
	if (cfg.container_listener_uids[0] != 1000 ||
	    cfg.container_listener_uids[1] != 1001 ||
	    cfg.container_listener_uids[2] != 1002) {
		FAIL("uid values");
		return;
	}
}

static void test_config_load_container_listener_uid_duplicate(void)
{
	struct lota_config cfg;
	char path[PATH_MAX];
	int ret;

	TEST("config_load rejects duplicate container_listener_uid");
	write_config("dup_uid.conf", "container_listener_uid = 1000\n"
				     "container_listener_uid = 1000\n");
	config_path("dup_uid.conf", path, sizeof(path));
	config_init(&cfg);
	ret = config_load(&cfg, path);
	if (ret == 0) {
		FAIL("expected non-zero return on duplicate UID");
		return;
	}
}

static void test_config_load_container_listener_uid_overflow(void)
{
	struct lota_config cfg;
	char path[PATH_MAX];
	char buf[512];
	int ret, len = 0;

	TEST("config_load rejects > LOTA_CONFIG_MAX_CONTAINER_LISTENERS UIDs");
	for (int i = 0; i <= LOTA_CONFIG_MAX_CONTAINER_LISTENERS; i++) {
		if (len < 0 || (size_t)len >= sizeof(buf))
			break;
		int w = snprintf(buf + len, sizeof(buf) - (size_t)len,
				 "container_listener_uid = %d\n", 1000 + i);
		if (w < 0 || (size_t)w >= sizeof(buf) - (size_t)len)
			break;
		len += w;
	}
	write_config("overflow_uid.conf", buf);
	config_path("overflow_uid.conf", path, sizeof(path));
	config_init(&cfg);
	ret = config_load(&cfg, path);
	if (ret == 0) {
		FAIL("expected non-zero return on overflow");
		return;
	}
}

static void test_config_load_container_listener_uid_invalid(void)
{
	struct lota_config cfg;
	char path[PATH_MAX];
	int ret;

	TEST("config_load rejects non-numeric container_listener_uid");
	write_config("bad_uid.conf", "container_listener_uid = root\n");
	config_path("bad_uid.conf", path, sizeof(path));
	config_init(&cfg);
	ret = config_load(&cfg, path);
	if (ret == 0) {
		FAIL("expected non-zero return on non-numeric UID");
		return;
	}
}

static void test_config_load_boolean_variants(void)
{
	struct lota_config cfg;
	char path[PATH_MAX];
	int ret;

	TEST("config_load boolean: true/yes/1 -> true");
	write_config("bool_true.conf", "strict_mmap = true\n"
				       "block_ptrace = yes\n"
				       "daemon = 1\n");
	config_path("bool_true.conf", path, sizeof(path));
	config_init(&cfg);
	ret = config_load(&cfg, path);
	if (ret != 0) {
		FAIL("load failed");
		return;
	}
	if (!cfg.strict_mmap || !cfg.block_ptrace || !cfg.daemon) {
		FAIL("not all true");
		return;
	}

	TEST("config_load boolean: false/no/0 -> false");
	write_config("bool_false.conf", "strict_mmap = false\n"
					"block_ptrace = no\n"
					"daemon = 0\n");
	config_path("bool_false.conf", path, sizeof(path));
	config_init(&cfg);
	cfg.strict_mmap = true;
	cfg.block_ptrace = true;
	cfg.daemon = true;
	ret = config_load(&cfg, path);
	if (ret != 0) {
		FAIL("load failed");
		return;
	}
	if (cfg.strict_mmap || cfg.block_ptrace || cfg.daemon) {
		FAIL("not all false");
		return;
	}
}

static void test_config_load_invalid_boolean(void)
{
	struct lota_config cfg;
	char path[PATH_MAX];
	int ret;

	TEST("config_load rejects invalid boolean tokens");
	write_config("bool_invalid.conf", "strict_mmap = maybe\n");
	config_path("bool_invalid.conf", path, sizeof(path));
	config_init(&cfg);
	ret = config_load(&cfg, path);
	if (ret != -EINVAL) {
		char msg[64];
		snprintf(msg, sizeof(msg), "expected -EINVAL, got %d", ret);
		FAIL("%s", msg);
		return;
	}
}

static void test_config_load_bench(void)
{
	struct lota_config cfg;
	char path[PATH_MAX];
	char *dump = NULL;
	size_t dump_len = 0;
	FILE *fp;

	TEST("config_load reads bench strictly and the dump keeps it");
	config_init(&cfg);
	if (cfg.bench) {
		FAIL("bench default != false");
		return;
	}

	write_config("bench.conf", "bench = true\n");
	config_path("bench.conf", path, sizeof(path));
	config_init(&cfg);
	if (config_load(&cfg, path) != 0 || !cfg.bench) {
		FAIL("bench = true not read");
		return;
	}

	fp = open_memstream(&dump, &dump_len);
	if (!fp) {
		FAIL("open_memstream");
		return;
	}
	config_dump(&cfg, fp);
	fclose(fp);
	if (!strstr(dump, "bench = true\n")) {
		free(dump);
		FAIL("dump drops bench");
		return;
	}
	free(dump);

	write_config("bench_bad.conf", "bench = maybe\n");
	config_path("bench_bad.conf", path, sizeof(path));
	config_init(&cfg);
	if (config_load(&cfg, path) != -EINVAL) {
		FAIL("bench = maybe accepted");
		return;
	}
}

static void test_config_load_invalid_mode(void)
{
	struct lota_config cfg;
	char path[PATH_MAX];
	int ret;

	TEST("config_load rejects invalid mode strings");
	write_config("mode_invalid.conf", "mode = enfroce\n");
	config_path("mode_invalid.conf", path, sizeof(path));
	config_init(&cfg);
	ret = config_load(&cfg, path);
	if (ret != -EINVAL) {
		char msg[64];
		snprintf(msg, sizeof(msg), "expected -EINVAL, got %d", ret);
		FAIL("%s", msg);
		return;
	}

	/* should remain default on parse failure */
	if (strcmp(cfg.mode, "enforce") != 0) {
		FAIL("mode changed on invalid input");
		return;
	}

	/* the mode switches policy, and monitor already lifts all of it */
	write_config("mode_maintenance.conf", "mode = maintenance\n");
	config_path("mode_maintenance.conf", path, sizeof(path));
	config_init(&cfg);
	if (config_load(&cfg, path) != -EINVAL) {
		FAIL("mode = maintenance is not a mode");
		return;
	}
}

static void test_config_load_invalid_log_level(void)
{
	static const char *const names[] = { "error", "warn", "info", "debug" };
	static const int prios[] = { LOG_ERR, LOG_WARNING, LOG_INFO,
				     LOG_DEBUG };
	struct lota_config cfg;
	char path[PATH_MAX];

	TEST("config_load refuses an unknown log_level");

	for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
		if (config_log_priority(names[i]) != prios[i]) {
			FAIL("%s", names[i]);
			return;
		}
	}
	if (config_log_priority("inof") != -1 ||
	    config_log_priority("") != -1) {
		FAIL("an unknown name maps to a priority");
		return;
	}

	write_config("loglevel_bad.conf", "log_level = inof\n");
	config_path("loglevel_bad.conf", path, sizeof(path));
	config_init(&cfg);
	if (config_load(&cfg, path) != -EINVAL) {
		FAIL("log_level = inof loads");
		return;
	}
	if (strcmp(cfg.log_level, "info") != 0) {
		FAIL("log_level changed on invalid input");
		return;
	}

	write_config("loglevel_warn.conf", "log_level = warn\n");
	config_path("loglevel_warn.conf", path, sizeof(path));
	config_init(&cfg);
	if (config_load(&cfg, path) != 0 ||
	    strcmp(cfg.log_level, "warn") != 0) {
		FAIL("log_level = warn refused");
		return;
	}
}

static void test_config_load_value_too_long(void)
{
	struct lota_config cfg;
	char path[PATH_MAX];
	char value[sizeof(cfg.server) + 1];
	char text[2 * sizeof(value) + 64];

	TEST("config_load refuses a value longer than its field");

	memset(value, 'a', sizeof(cfg.server));
	value[sizeof(cfg.server)] = '\0';
	snprintf(text, sizeof(text), "server = %s\n", value);
	write_config("long_server.conf", text);
	config_path("long_server.conf", path, sizeof(path));
	config_init(&cfg);
	if (config_load(&cfg, path) != -EINVAL) {
		FAIL("a server one byte too long loads");
		return;
	}

	value[sizeof(cfg.server) - 1] = '\0';
	snprintf(text, sizeof(text), "server = %s\n", value);
	write_config("long_server.conf", text);
	config_init(&cfg);
	if (config_load(&cfg, path) != 0 || strcmp(cfg.server, value) != 0) {
		FAIL("a server that fits is refused or changed");
		return;
	}

	memset(value, 'b', sizeof(cfg.profiles[0].verifier));
	value[sizeof(cfg.profiles[0].verifier)] = '\0';
	snprintf(text, sizeof(text),
		 "[profile \"p\"]\nca = ca.p.example\n"
		 "ca_cert = /etc/lota/p.pem\nverifier = %s\n",
		 value);
	write_config("long_verifier.conf", text);
	config_path("long_verifier.conf", path, sizeof(path));
	config_init(&cfg);
	if (config_load(&cfg, path) != -EINVAL) {
		FAIL("a profile verifier one byte too long loads");
		return;
	}

	value[sizeof(cfg.profiles[0].verifier) - 1] = '\0';
	snprintf(text, sizeof(text),
		 "[profile \"p\"]\nca = ca.p.example\n"
		 "ca_cert = /etc/lota/p.pem\nverifier = %s\n",
		 value);
	write_config("long_verifier.conf", text);
	config_init(&cfg);
	if (config_load(&cfg, path) != 0 ||
	    strcmp(cfg.profiles[0].verifier, value) != 0) {
		FAIL("a profile verifier that fits is refused or changed");
		return;
	}
}

/* fgets keeps one byte for the newline and one for the NUL */
static void test_config_load_line_limit(void)
{
	struct lota_config cfg;
	char path[PATH_MAX];
	char log_path[PATH_MAX];
	char text[LOTA_CONFIG_MAX_LINE + 2];
	char log[256] = "";
	struct lota_profile prof;
	char want[96];
	char why[256];
	size_t anchor;
	int saved, fd, rc;

	TEST("config_load takes a line of the documented length, no longer");

	memset(text, '#', LOTA_CONFIG_MAX_LINE - 2);
	text[LOTA_CONFIG_MAX_LINE - 2] = '\n';
	text[LOTA_CONFIG_MAX_LINE - 1] = '\0';
	write_config("line_limit.conf", text);
	config_path("line_limit.conf", path, sizeof(path));
	config_init(&cfg);
	if (config_load(&cfg, path) != 0) {
		FAIL("a line of the limit is refused");
		return;
	}

	memset(text, '#', LOTA_CONFIG_MAX_LINE - 1);
	text[LOTA_CONFIG_MAX_LINE - 1] = '\n';
	text[LOTA_CONFIG_MAX_LINE] = '\0';
	write_config("line_limit.conf", text);
	config_path("line_limit.log", log_path, sizeof(log_path));
	saved = dup(STDERR_FILENO);
	fd = open(log_path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (saved < 0 || fd < 0) {
		FAIL("setup");
		return;
	}
	fflush(stderr);
	dup2(fd, STDERR_FILENO);
	config_init(&cfg);
	rc = config_load(&cfg, path);
	fflush(stderr);
	dup2(saved, STDERR_FILENO);
	close(saved);
	if (pread(fd, log, sizeof(log) - 1, 0) < 0)
		log[0] = '\0';
	close(fd);
	unlink(log_path);

	if (rc != -EINVAL) {
		FAIL("a line one character too long loads");
		return;
	}
	snprintf(want, sizeof(want), ":1: line exceeds %d characters\n",
		 LOTA_CONFIG_MAX_LINE - 2);
	if (!strstr(log, want)) {
		FAIL("%s", log);
		return;
	}

	/* the writer refuses what the parser would refuse, by the same count */
	memset(&prof, 0, sizeof(prof));
	strcpy(prof.name, "limit");
	strcpy(prof.ca, "ca.example");
	prof.token_only = true;
	anchor = LOTA_CONFIG_MAX_LINE - 2 - strlen("ca_cert = ");
	prof.ca_cert[0] = '/';
	memset(prof.ca_cert + 1, 'a', anchor - 1);
	prof.ca_cert[anchor] = '\0';
	if (config_profile_defect(&prof, why, sizeof(why)) != 0) {
		FAIL("%s", why);
		return;
	}
	prof.ca_cert[anchor] = 'a';
	prof.ca_cert[anchor + 1] = '\0';
	snprintf(want, sizeof(want),
		 "needs a %d-character line; the parser reads at most %d",
		 LOTA_CONFIG_MAX_LINE - 1, LOTA_CONFIG_MAX_LINE - 2);
	if (config_profile_defect(&prof, why, sizeof(why)) != -EILSEQ ||
	    !strstr(why, want)) {
		FAIL("%s", why);
		return;
	}
}

static void test_config_load_whitespace_trimming(void)
{
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
}

static void test_config_load_unknown_keys(void)
{
	struct lota_config cfg;
	char path[PATH_MAX];
	int ret;

	TEST("config_load rejects unknown keys (fail-closed)");
	write_config("unknown.conf", "server = ok\n"
				     "totally_bogus_key = whatever\n"
				     "port = 1234\n");
	config_path("unknown.conf", path, sizeof(path));
	config_init(&cfg);
	ret = config_load(&cfg, path);
	if (ret != -EINVAL) {
		char msg[64];
		snprintf(msg, sizeof(msg), "expected -EINVAL, got %d", ret);
		FAIL("%s", msg);
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
}

static void test_config_load_malformed_lines(void)
{
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
		FAIL("%s", msg);
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
}

static void test_config_load_empty_key(void)
{
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
}

static void test_config_load_empty_value(void)
{
	struct lota_config cfg;
	char path[PATH_MAX];
	int ret;

	TEST("config_load clears a field on an empty value, not a list");
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

	write_config("emptyval_list.conf", "trust_lib =\n");
	config_path("emptyval_list.conf", path, sizeof(path));
	config_init(&cfg);
	if (config_load(&cfg, path) != -EINVAL || cfg.trust_lib_count != 0) {
		FAIL("an empty trust_lib entry loads");
		return;
	}
	write_config("emptyval_list.conf", "allow_verity =\n");
	config_init(&cfg);
	if (config_load(&cfg, path) != -EINVAL || cfg.allow_verity_count != 0) {
		FAIL("an empty allow_verity entry loads");
		return;
	}
}

static void test_config_load_port_bounds(void)
{
	struct lota_config cfg;
	char path[PATH_MAX];
	int ret;

	TEST("config_load rejects out-of-range port values");
	write_config("port_bad.conf", "port = 99999\n");
	config_path("port_bad.conf", path, sizeof(path));
	config_init(&cfg);
	ret = config_load(&cfg, path);
	if (ret != -EINVAL) {
		char msg[64];
		snprintf(msg, sizeof(msg), "expected -EINVAL, got %d", ret);
		FAIL("%s", msg);
		return;
	}
	/* port should remain at default because 99999 > 65535 */
	if (cfg.port != 8443) {
		char msg[64];
		snprintf(msg, sizeof(msg), "port=%d, expected 8443", cfg.port);
		FAIL("%s", msg);
		return;
	}

	TEST("config_load rejects port = 0");
	write_config("port_zero.conf", "port = 0\n");
	config_path("port_zero.conf", path, sizeof(path));
	config_init(&cfg);
	ret = config_load(&cfg, path);
	if (ret != -EINVAL) {
		char msg[64];
		snprintf(msg, sizeof(msg), "expected -EINVAL, got %d", ret);
		FAIL("%s", msg);
		return;
	}
	if (cfg.port != 8443) {
		FAIL("port changed to 0");
		return;
	}
}

/*
 * Interval above the ceiling mints tokens whose valid_until sits past the token
 * age the SDK verifiers accept, so only their clock skew keeps them verifiable.
 * The mistake has to be caught where it is made.
 */
static void test_config_load_attest_interval_bounds(void)
{
	struct lota_config cfg;
	char path[PATH_MAX];
	char content[64];
	int ret;

	TEST("config_load accepts attest_interval at the ceiling");
	snprintf(content, sizeof(content), "attest_interval = %d\n",
		 MAX_ATTEST_INTERVAL);
	write_config("interval_max.conf", content);
	config_path("interval_max.conf", path, sizeof(path));
	config_init(&cfg);
	ret = config_load(&cfg, path);
	if (ret != 0) {
		char msg[64];
		snprintf(msg, sizeof(msg), "expected 0, got %d", ret);
		FAIL("%s", msg);
		return;
	}
	if (cfg.attest_interval != MAX_ATTEST_INTERVAL) {
		FAIL("interval not applied");
		return;
	}

	TEST("config_load rejects attest_interval above the ceiling");
	snprintf(content, sizeof(content), "attest_interval = %d\n",
		 MAX_ATTEST_INTERVAL + 1);
	write_config("interval_high.conf", content);
	config_path("interval_high.conf", path, sizeof(path));
	config_init(&cfg);
	ret = config_load(&cfg, path);
	if (ret != -EINVAL) {
		char msg[64];
		snprintf(msg, sizeof(msg), "expected -EINVAL, got %d", ret);
		FAIL("%s", msg);
		return;
	}
	if (cfg.attest_interval != 0) {
		FAIL("out-of-range interval was applied");
		return;
	}

	TEST("config_load rejects attest_interval below the floor");
	snprintf(content, sizeof(content), "attest_interval = %d\n",
		 MIN_ATTEST_INTERVAL - 1);
	write_config("interval_low.conf", content);
	config_path("interval_low.conf", path, sizeof(path));
	config_init(&cfg);
	ret = config_load(&cfg, path);
	if (ret != -EINVAL) {
		char msg[64];
		snprintf(msg, sizeof(msg), "expected -EINVAL, got %d", ret);
		FAIL("%s", msg);
		return;
	}

	TEST("config_load accepts attest_interval = 0 (one-shot)");
	write_config("interval_zero.conf", "attest_interval = 0\n");
	config_path("interval_zero.conf", path, sizeof(path));
	config_init(&cfg);
	ret = config_load(&cfg, path);
	if (ret != 0) {
		char msg[64];
		snprintf(msg, sizeof(msg), "expected 0, got %d", ret);
		FAIL("%s", msg);
		return;
	}
}

static void test_config_load_refuses_aik_ttl(void)
{
	struct lota_config cfg;
	char path[PATH_MAX];

	TEST("config_load refuses aik_ttl");
	write_config("aik_ttl.conf", "aik_ttl = 7200\n");
	config_path("aik_ttl.conf", path, sizeof(path));
	config_init(&cfg);
	if (config_load(&cfg, path) != -EINVAL) {
		FAIL("aik_ttl was accepted");
		return;
	}
}

static void test_config_load_refuses_signing_key(void)
{
	struct lota_config cfg;
	char path[PATH_MAX];

	TEST("config_load refuses signing_key");
	write_config("signing_key.conf", "signing_key = /etc/lota/sign.key\n");
	config_path("signing_key.conf", path, sizeof(path));
	config_init(&cfg);
	if (config_load(&cfg, path) != -EINVAL) {
		FAIL("signing_key was accepted");
		return;
	}
}

static void test_config_load_profiles(void)
{
	struct lota_config cfg;
	char path[PATH_MAX];
	int ret;

	TEST("config_load parses a publisher profile list");
	write_config("profiles.conf", "server = top.example\n"
				      "\n"
				      "[profile \"alpha\"]\n"
				      "ca = ca.alpha.example\n"
				      "ca_cert = /etc/lota/alpha.pem\n"
				      "verifier = verifier.alpha.example\n"
				      "interval = 60\n"
				      "\n"
				      "[profile \"beta\"]\n"
				      "ca = ca.beta.example\n"
				      "ca_port = 9444\n"
				      "ca-cert = /etc/lota/beta.pem\n"
				      "verifier = verifier.beta.example\n"
				      "verifier_port = 9443\n");
	config_path("profiles.conf", path, sizeof(path));
	config_init(&cfg);
	ret = config_load(&cfg, path);
	if (ret != 0) {
		char msg[64];
		snprintf(msg, sizeof(msg), "expected 0, got %d", ret);
		FAIL("%s", msg);
		return;
	}
	if (cfg.profile_count != 2) {
		FAIL("profile_count != 2");
		return;
	}
	/* keys above the first section still reach the top level */
	if (strcmp(cfg.server, "top.example") != 0) {
		FAIL("top-level key not applied");
		return;
	}
	if (strcmp(cfg.profiles[0].name, "alpha") != 0 ||
	    strcmp(cfg.profiles[0].ca, "ca.alpha.example") != 0 ||
	    strcmp(cfg.profiles[0].ca_cert, "/etc/lota/alpha.pem") != 0 ||
	    strcmp(cfg.profiles[0].verifier, "verifier.alpha.example") != 0 ||
	    cfg.profiles[0].attest_interval != 60) {
		FAIL("profile 'alpha' mismatch");
		return;
	}
	/* unset ports fall back to the defaults, not to zero */
	if (cfg.profiles[0].ca_port != LOTA_DEFAULT_CA_PORT ||
	    cfg.profiles[0].verifier_port != LOTA_DEFAULT_VERIFIER_PORT) {
		FAIL("profile 'alpha' default ports");
		return;
	}
	if (strcmp(cfg.profiles[1].name, "beta") != 0 ||
	    cfg.profiles[1].ca_port != 9444 ||
	    cfg.profiles[1].verifier_port != 9443 ||
	    strcmp(cfg.profiles[1].ca_cert, "/etc/lota/beta.pem") != 0) {
		FAIL("profile 'beta' mismatch");
		return;
	}
	/* unset interval means "inherit", not "one-shot" */
	if (cfg.profiles[1].attest_interval != 0) {
		FAIL("profile 'beta' interval");
		return;
	}
	/* profile reports while a title of its publisher runs, by default */
	if (!cfg.profiles[0].session_gated || !cfg.profiles[1].session_gated) {
		FAIL("a profile should default to session-gated reporting");
		return;
	}
}

/*
 * Fleet whose publishers are all its own wants the continuous stream that session
 * gating exists to stop, so the profile can say so -- and nothing else may.
 */
static void test_config_profile_reporting(void)
{
	struct lota_config cfg;
	char path[PATH_MAX];
	int ret;

	TEST("config_load reads a profile's reporting mode");
	write_config("reporting.conf", "[profile \"fleet\"]\n"
				       "ca = ca.example\n"
				       "ca_cert = /etc/lota/ca.pem\n"
				       "verifier = verifier.example\n"
				       "reporting = continuous\n");
	config_path("reporting.conf", path, sizeof(path));
	config_init(&cfg);
	ret = config_load(&cfg, path);
	if (ret != 0) {
		FAIL("continuous reporting rejected");
		return;
	}
	if (cfg.profiles[0].session_gated) {
		FAIL("reporting = continuous not applied");
		return;
	}

	write_config("reporting-bad.conf", "[profile \"fleet\"]\n"
					   "ca = ca.example\n"
					   "ca_cert = /etc/lota/ca.pem\n"
					   "verifier = verifier.example\n"
					   "reporting = sometimes\n");
	config_path("reporting-bad.conf", path, sizeof(path));
	config_init(&cfg);
	if (config_load(&cfg, path) == 0) {
		FAIL("an unknown reporting mode was accepted");
		return;
	}
}

static void test_config_load_profile_incomplete(void)
{
	struct lota_config cfg;
	char path[PATH_MAX];
	int ret;

	TEST("config_load rejects a profile with no trust anchor");
	write_config("profile_noanchor.conf", "[profile \"alpha\"]\n"
					      "ca = ca.alpha.example\n"
					      "verifier = v.alpha.example\n");
	config_path("profile_noanchor.conf", path, sizeof(path));
	config_init(&cfg);
	ret = config_load(&cfg, path);
	if (ret != -EINVAL) {
		char msg[64];
		snprintf(msg, sizeof(msg), "expected -EINVAL, got %d", ret);
		FAIL("%s", msg);
		return;
	}

	TEST("config_load rejects a profile with no verifier");
	write_config("profile_noverifier.conf",
		     "[profile \"alpha\"]\n"
		     "ca = ca.alpha.example\n"
		     "ca_cert = /etc/lota/alpha.pem\n");
	config_path("profile_noverifier.conf", path, sizeof(path));
	config_init(&cfg);
	ret = config_load(&cfg, path);
	if (ret != -EINVAL) {
		FAIL("expected -EINVAL");
		return;
	}

	TEST("config_load accepts a publisher who runs no verifier");
	/* light path:
	 * their backend checks tokens, so nothing is reported and the profile
	 * says so rather than omitting the key */
	write_config("profile_tokenonly.conf", "[profile \"alpha\"]\n"
					       "ca = ca.alpha.example\n"
					       "ca_cert = /etc/lota/alpha.pem\n"
					       "verifier = none\n");
	config_path("profile_tokenonly.conf", path, sizeof(path));
	config_init(&cfg);
	ret = config_load(&cfg, path);
	if (ret != 0) {
		FAIL("a token-only publisher was refused");
		return;
	}
	if (!cfg.profiles[0].token_only || cfg.profiles[0].verifier[0]) {
		FAIL("verifier = none did not record a token-only publisher");
		return;
	}

	TEST("config_load rejects verifier = none with a verifier port");
	write_config("profile_tokenonly_port.conf",
		     "[profile \"alpha\"]\n"
		     "ca = ca.alpha.example\n"
		     "ca_cert = /etc/lota/alpha.pem\n"
		     "verifier = none\n"
		     "verifier_port = 9443\n");
	config_path("profile_tokenonly_port.conf", path, sizeof(path));
	config_init(&cfg);
	ret = config_load(&cfg, path);
	if (ret != -EINVAL) {
		FAIL("a port for a verifier declared absent was accepted");
		return;
	}
	write_config("profile_tokenonly_port.conf",
		     "[profile \"alpha\"]\n"
		     "ca = ca.alpha.example\n"
		     "ca_cert = /etc/lota/alpha.pem\n"
		     "verifier_port = 8443\n"
		     "verifier = none\n");
	config_init(&cfg);
	ret = config_load(&cfg, path);
	if (ret != -EINVAL) {
		FAIL("the default verifier port beside none was accepted");
		return;
	}

	TEST("config_load rejects an empty profile section");
	write_config("profile_empty.conf", "[profile \"alpha\"]\n");
	config_path("profile_empty.conf", path, sizeof(path));
	config_init(&cfg);
	ret = config_load(&cfg, path);
	if (ret != -EINVAL) {
		FAIL("expected -EINVAL");
		return;
	}
}

static void test_config_load_profile_malformed(void)
{
	struct lota_config cfg;
	char path[PATH_MAX];
	int ret;
	size_t i;
	static const char *const bad[] = {
		"[profile alpha]\n",	      "[profile \"alpha]\n",
		"[profile \"alpha\"] junk\n", "[publisher \"alpha\"]\n",
		"[profile \"\"]\n",
	};

	for (i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		char name[64];

		TEST("config_load rejects a malformed profile header");
		snprintf(name, sizeof(name), "profile_bad_%zu.conf", i);
		write_config(name, bad[i]);
		config_path(name, path, sizeof(path));
		config_init(&cfg);
		ret = config_load(&cfg, path);
		if (ret != -EINVAL) {
			char msg[64];
			snprintf(msg, sizeof(msg), "expected -EINVAL, got %d",
				 ret);
			FAIL("%s", msg);
			return;
		}
		if (cfg.profile_count != 0) {
			FAIL("malformed header opened a profile");
			return;
		}
	}

	TEST("config_load rejects a duplicate profile name");
	write_config("profile_dup.conf", "[profile \"alpha\"]\n"
					 "ca = ca.alpha.example\n"
					 "ca_cert = /etc/lota/alpha.pem\n"
					 "verifier = v.alpha.example\n"
					 "[profile \"alpha\"]\n"
					 "ca = ca.other.example\n"
					 "ca_cert = /etc/lota/other.pem\n"
					 "verifier = v.other.example\n");
	config_path("profile_dup.conf", path, sizeof(path));
	config_init(&cfg);
	ret = config_load(&cfg, path);
	if (ret != -EINVAL) {
		FAIL("expected -EINVAL");
		return;
	}
	if (cfg.profile_count != 1) {
		FAIL("duplicate name opened a second profile");
		return;
	}

	TEST("config_load rejects a top-level key inside a profile");
	write_config("profile_toplevel.conf", "[profile \"alpha\"]\n"
					      "ca = ca.alpha.example\n"
					      "ca_cert = /etc/lota/alpha.pem\n"
					      "verifier = v.alpha.example\n"
					      "mode = enforce\n");
	config_path("profile_toplevel.conf", path, sizeof(path));
	config_init(&cfg);
	ret = config_load(&cfg, path);
	if (ret != -EINVAL) {
		FAIL("expected -EINVAL");
		return;
	}

	TEST("config_load rejects a per-profile interval above the ceiling");
	{
		char content[256];
		snprintf(content, sizeof(content),
			 "[profile \"alpha\"]\n"
			 "ca = ca.alpha.example\n"
			 "ca_cert = /etc/lota/alpha.pem\n"
			 "verifier = v.alpha.example\n"
			 "interval = %d\n",
			 MAX_ATTEST_INTERVAL + 1);
		write_config("profile_interval.conf", content);
	}
	config_path("profile_interval.conf", path, sizeof(path));
	config_init(&cfg);
	ret = config_load(&cfg, path);
	if (ret != -EINVAL) {
		FAIL("expected -EINVAL");
		return;
	}
}

static void test_config_load_profile_overflow(void)
{
	struct lota_config cfg;
	char path[PATH_MAX];
	char content[4096];
	size_t off = 0;
	int ret;

	TEST("config_load rejects more profiles than there are slots");
	for (int i = 0; i <= LOTA_CONFIG_MAX_PROFILES; i++) {
		int n = snprintf(content + off, sizeof(content) - off,
				 "[profile \"p%d\"]\n"
				 "ca = ca%d.example\n"
				 "ca_cert = /etc/lota/p%d.pem\n"
				 "verifier = v%d.example\n",
				 i, i, i, i);
		if (n < 0 || (size_t)n >= sizeof(content) - off) {
			FAIL("fixture too large");
			return;
		}
		off += (size_t)n;
	}
	write_config("profile_overflow.conf", content);
	config_path("profile_overflow.conf", path, sizeof(path));
	config_init(&cfg);
	ret = config_load(&cfg, path);
	if (ret != -EINVAL) {
		char msg[64];
		snprintf(msg, sizeof(msg), "expected -EINVAL, got %d", ret);
		FAIL("%s", msg);
		return;
	}
	if (cfg.profile_count != LOTA_CONFIG_MAX_PROFILES) {
		FAIL("profile_count past the cap");
		return;
	}
}

static void test_config_load_rejects_group_writable(void)
{
	struct lota_config cfg;
	char path[PATH_MAX];
	int ret;

	TEST("config_load rejects group/world writable config");
	write_config("group_writable.conf", "mode = enforce\n");
	config_path("group_writable.conf", path, sizeof(path));

	if (chmod(path, 0664) != 0) {
		FAIL("chmod failed");
		return;
	}

	config_init(&cfg);
	ret = config_load(&cfg, path);
	if (ret != -EPERM) {
		char msg[64];
		snprintf(msg, sizeof(msg), "expected -EPERM, got %d", ret);
		FAIL("%s", msg);
		return;
	}
}

static void test_config_load_rejects_symlink(void)
{
	struct lota_config cfg;
	char real_path[PATH_MAX];
	char link_path[PATH_MAX];
	int ret;

	TEST("config_load rejects symlink config path");
	write_config("real_secure.conf", "mode = enforce\n");
	config_path("real_secure.conf", real_path, sizeof(real_path));
	config_path("symlink.conf", link_path, sizeof(link_path));

	unlink(link_path);
	if (symlink(real_path, link_path) != 0) {
		FAIL("symlink creation failed");
		return;
	}

	config_init(&cfg);
	ret = config_load(&cfg, link_path);
	if (ret != -ELOOP) {
		char msg[64];
		snprintf(msg, sizeof(msg), "expected -ELOOP, got %d", ret);
		FAIL("%s", msg);
		return;
	}
}

static void test_config_load_rejects_fifo(void)
{
	struct lota_config cfg;
	char path[PATH_MAX];
	int ret;

	TEST("config_load rejects a FIFO with no writer");
	config_path("fifo.conf", path, sizeof(path));

	unlink(path);
	if (mkfifo(path, 0600) != 0) {
		FAIL("mkfifo failed");
		return;
	}

	config_init(&cfg);
	alarm(10);
	ret = config_load(&cfg, path);
	alarm(0);
	if (ret != -EINVAL) {
		char msg[64];
		snprintf(msg, sizeof(msg), "expected -EINVAL, got %d", ret);
		FAIL("%s", msg);
		return;
	}
}

/*
 * Certificate pinning belongs to the publisher, not to the host: each publisher
 * runs its own verifier with its own certificate, so one fingerprint can match
 * at most one of them.
 *
 * The pin is checked through the file rather than the struct, because what
 * an operator writes and what a writer emits are the two ways it gets in.
 */
static void test_config_profile_pin_sha256(void)
{
	static const char pin_a[] = "4fd24ead1c6c1c0d2e5f0a9b8c7d6e5f"
				    "4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d";
	static const char pin_b[] = "0123456789abcdef0123456789abcdef"
				    "fedcba9876543210fedcba9876543210";
	struct lota_config cfg;
	char path[PATH_MAX];
	char dump_path[PATH_MAX];
	char body[1024];
	char dumped[8192];
	FILE *f;
	int fd;
	int ret;

	TEST("a profile pins its own verifier certificate");
	snprintf(body, sizeof(body),
		 "[profile \"alpha\"]\n"
		 "ca = ca.alpha.example\n"
		 "ca_cert = /etc/lota/alpha.pem\n"
		 "verifier = v.alpha.example\n"
		 "pin_sha256 = %s\n"
		 "\n"
		 "[profile \"beta\"]\n"
		 "ca = ca.beta.example\n"
		 "ca_cert = /etc/lota/beta.pem\n"
		 "verifier = v.beta.example\n"
		 "pin-sha256 = %s\n",
		 pin_a, pin_b);
	write_config("profile-pin.conf", body);
	config_path("profile-pin.conf", path, sizeof(path));
	config_init(&cfg);
	ret = config_load(&cfg, path);
	if (ret != 0) {
		char msg[64];
		snprintf(msg, sizeof(msg), "expected 0, got %d", ret);
		FAIL("%s", msg);
		return;
	}

	/* a writer that cannot say the pin writes a host that stops pinning */
	TEST("config_dump writes each profile's own pin");
	snprintf(dump_path, sizeof(dump_path), "%s/profile-pin-dump.conf",
		 tmpdir);
	fd = open(dump_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	f = fd >= 0 ? fdopen(fd, "w") : NULL;
	if (fd >= 0 && !f)
		close(fd);
	if (!f) {
		FAIL("fopen dump");
		return;
	}
	config_dump(&cfg, f);
	fclose(f);

	fd = open(dump_path, O_RDONLY);
	if (fd < 0) {
		FAIL("reopen dump");
		return;
	}
	{
		ssize_t n = read(fd, dumped, sizeof(dumped) - 1);

		close(fd);
		if (n < 0) {
			FAIL("read dump");
			return;
		}
		dumped[n] = '\0';
	}
	if (!strstr(dumped, pin_a) || !strstr(dumped, pin_b)) {
		FAIL("the dump dropped the profile pins");
		return;
	}

	TEST("the dumped profile pins parse back");
	config_init(&cfg);
	if (config_load(&cfg, dump_path) != 0) {
		FAIL("the dump does not parse back");
		return;
	}

	/* a pin that is not 32 bytes of hex would pin nothing at all */
	TEST("a malformed profile pin is refused");
	write_config("profile-pin-bad.conf", "[profile \"alpha\"]\n"
					     "ca = ca.alpha.example\n"
					     "ca_cert = /etc/lota/alpha.pem\n"
					     "verifier = v.alpha.example\n"
					     "pin_sha256 = not-a-digest\n");
	config_path("profile-pin-bad.conf", path, sizeof(path));
	config_init(&cfg);
	if (config_load(&cfg, path) == 0) {
		FAIL("a malformed pin was accepted");
		return;
	}
}

/*
 * The host-level key stays the single-verifier deployment's, because one
 * fingerprint applied to several publishers matches at most one of them
 * and fails the rest at TLS time, before any verdict.
 */
static void test_config_host_pin_beside_profiles(void)
{
	static const char pin_a[] = "4fd24ead1c6c1c0d2e5f0a9b8c7d6e5f"
				    "4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d";
	struct lota_config cfg;
	char path[PATH_MAX];
	char body[1024];

	TEST("a host-level pin beside publisher profiles is refused");
	snprintf(body, sizeof(body),
		 "pin_sha256 = %s\n"
		 "\n"
		 "[profile \"alpha\"]\n"
		 "ca = ca.alpha.example\n"
		 "ca_cert = /etc/lota/alpha.pem\n"
		 "verifier = v.alpha.example\n",
		 pin_a);
	write_config("profile-pin-toplevel.conf", body);
	config_path("profile-pin-toplevel.conf", path, sizeof(path));
	config_init(&cfg);
	if (config_load(&cfg, path) == 0) {
		FAIL("a host-level pin was accepted beside profiles");
		return;
	}

	/* the single-verifier deployment keeps the key it always had */
	TEST("a host-level pin without profiles still loads");
	snprintf(body, sizeof(body),
		 "server = v.example\n"
		 "pin_sha256 = %s\n",
		 pin_a);
	write_config("pin-toplevel-only.conf", body);
	config_path("pin-toplevel-only.conf", path, sizeof(path));
	config_init(&cfg);
	if (config_load(&cfg, path) != 0 ||
	    strcmp(cfg.pin_sha256, pin_a) != 0) {
		FAIL("the single-verifier pin stopped working");
		return;
	}
}

/*
 * --add-publisher rewrites lota.conf from the dump, so a host that never
 * named a verifier must not get one written for it
 */
static void test_config_dump_keeps_server_unset(void)
{
	struct lota_config cfg;
	struct lota_config reloaded;
	char path[PATH_MAX];
	char line[512];
	FILE *f;
	int fd;

	TEST("config_dump writes no server the host never named");
	config_init(&cfg);

	snprintf(path, sizeof(path), "%s/unset_server.conf", tmpdir);
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	f = fd >= 0 ? fdopen(fd, "w") : NULL;
	if (fd >= 0 && !f)
		close(fd);
	if (!f) {
		FAIL("fopen dump");
		return;
	}
	config_dump(&cfg, f);
	fclose(f);

	f = fopen(path, "re");
	if (!f) {
		FAIL("reopen dump");
		return;
	}
	while (fgets(line, sizeof(line), f)) {
		if (strncmp(line, "server", 6) == 0) {
			fclose(f);
			FAIL("dump names a server");
			return;
		}
	}
	fclose(f);

	config_init(&reloaded);
	if (config_load(&reloaded, path) != 0) {
		FAIL("reload dump");
		return;
	}
	if (reloaded.server[0] != '\0') {
		FAIL("reloaded dump names a server");
		return;
	}
}

static void test_config_dump_roundtrip(void)
{
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
	cfg1.strict_mmap = true;
	cfg1.attest_interval = 120;
	snprintf(cfg1.log_level, sizeof(cfg1.log_level), "error");
	cfg1.trust_lib_count = 1;
	snprintf(cfg1.trust_libs[0], sizeof(cfg1.trust_libs[0]),
		 "/usr/lib/foo.so");
	cfg1.protect_pid_count = 2;
	cfg1.protect_pids[0] = 11;
	cfg1.protect_pids[1] = 22;
	cfg1.container_listener_uid_count = 2;
	cfg1.container_listener_uids[0] = 1000;
	cfg1.container_listener_uids[1] = 1001;
	cfg1.profile_count = 1;
	snprintf(cfg1.profiles[0].name, sizeof(cfg1.profiles[0].name), "alpha");
	snprintf(cfg1.profiles[0].ca, sizeof(cfg1.profiles[0].ca),
		 "ca.alpha.example");
	cfg1.profiles[0].ca_port = 9444;
	snprintf(cfg1.profiles[0].ca_cert, sizeof(cfg1.profiles[0].ca_cert),
		 "/etc/lota/alpha.pem");
	snprintf(cfg1.profiles[0].verifier, sizeof(cfg1.profiles[0].verifier),
		 "v.alpha.example");
	cfg1.profiles[0].verifier_port = 9443;
	cfg1.profiles[0].attest_interval = 90;

	/* second publisher who runs no verifier:
	 * the dump has to say "verifier = none" and omit the port,
	 * or it will not parse back */
	cfg1.profile_count = 2;
	snprintf(cfg1.profiles[1].name, sizeof(cfg1.profiles[1].name), "beta");
	snprintf(cfg1.profiles[1].ca, sizeof(cfg1.profiles[1].ca),
		 "ca.beta.example");
	cfg1.profiles[1].ca_port = 8444;
	snprintf(cfg1.profiles[1].ca_cert, sizeof(cfg1.profiles[1].ca_cert),
		 "/etc/lota/beta.pem");
	cfg1.profiles[1].token_only = true;
	cfg1.profiles[1].verifier_port = LOTA_DEFAULT_VERIFIER_PORT;

	/* dump to file */
	snprintf(dump_path, sizeof(dump_path), "%s/dumped.conf", tmpdir);
	{
		int fd = open(dump_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
		f = fd >= 0 ? fdopen(fd, "w") : NULL;
		if (fd >= 0 && !f)
			close(fd);
	}
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
		FAIL("%s", msg);
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
	if (cfg2.container_listener_uid_count != 2 ||
	    cfg2.container_listener_uids[0] != 1000 ||
	    cfg2.container_listener_uids[1] != 1001) {
		FAIL("container_listener_uids mismatch");
		return;
	}
	if (cfg2.profile_count != 2 ||
	    strcmp(cfg2.profiles[0].name, "alpha") != 0 ||
	    strcmp(cfg2.profiles[0].ca, "ca.alpha.example") != 0 ||
	    cfg2.profiles[0].ca_port != 9444 ||
	    strcmp(cfg2.profiles[0].ca_cert, "/etc/lota/alpha.pem") != 0 ||
	    strcmp(cfg2.profiles[0].verifier, "v.alpha.example") != 0 ||
	    cfg2.profiles[0].verifier_port != 9443 ||
	    cfg2.profiles[0].attest_interval != 90 ||
	    cfg2.profiles[0].token_only ||
	    strcmp(cfg2.profiles[1].name, "beta") != 0 ||
	    !cfg2.profiles[1].token_only ||
	    cfg2.profiles[1].verifier[0] != '\0') {
		FAIL("profile mismatch");
		return;
	}
}

/*
 * A key the dump omits reloads at its default. For the sealing keys that
 * silently brings back the plaintext AIK auth seal_aik_auth_strict removes.
 */
static void test_config_dump_keeps_the_sealing_keys(void)
{
	struct lota_config cfg1, cfg2;
	char dump_path[PATH_MAX];
	FILE *f;
	int fd;

	TEST("config_dump -> config_load keeps at-rest sealing");
	config_init(&cfg1);
	cfg1.seal_persistent_primary = true;
	cfg1.seal_aik_auth = true;
	cfg1.seal_aik_auth_strict = true;

	snprintf(dump_path, sizeof(dump_path), "%s/sealing.conf", tmpdir);
	fd = open(dump_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	f = fd >= 0 ? fdopen(fd, "w") : NULL;
	if (fd >= 0 && !f)
		close(fd);
	if (!f) {
		FAIL("fopen dump");
		return;
	}
	config_dump(&cfg1, f);
	fclose(f);

	config_init(&cfg2);
	if (config_load(&cfg2, dump_path) != 0) {
		FAIL("reload failed");
		return;
	}

	if (!cfg2.seal_persistent_primary) {
		FAIL("seal_persistent_primary did not survive the dump");
		return;
	}
	if (!cfg2.seal_aik_auth) {
		FAIL("seal_aik_auth did not survive the dump");
		return;
	}
	if (!cfg2.seal_aik_auth_strict) {
		FAIL("seal_aik_auth_strict did not survive the dump");
		return;
	}
}

/*
 * Every key config_load() accepts must be printed by config_dump();
 * deliberate exceptions go in exempt[] with the reason.
 */
static bool dump_prints_key(const char *body, const char *key)
{
	char needle[128];

	snprintf(needle, sizeof(needle), "\"%s = ", key);
	return strstr(body, needle) != NULL;
}

static void test_dump_prints_every_key_the_parser_takes(void)
{
	static const struct {
		const char *key;
		const char *why;
	} exempt[] = {
		{ "bpf", "an alias; the dump prints it as bpf_path" },
		{ "no_verify_tls",
		  "refused from a file on purpose, so a dump that emitted it "
		  "would not parse back" },
	};
	char *source = NULL;
	char *body;
	char *end;
	size_t len = 0;
	FILE *fp;
	const char *p;
	unsigned missing = 0;

	TEST("config_dump prints every key config_load accepts");

	fp = fopen("src/agent/config.c", "re");
	if (!fp)
		fp = fopen("../src/agent/config.c", "re");
	if (!fp) {
		FAIL("could not open config.c");
		return;
	}
	fseek(fp, 0, SEEK_END);
	len = (size_t)ftell(fp);
	rewind(fp);
	source = malloc(len + 1);
	if (!source || fread(source, 1, len, fp) != len) {
		free(source);
		fclose(fp);
		FAIL("could not read config.c");
		return;
	}
	source[len] = '\0';
	fclose(fp);

	body = strstr(source, "void config_dump(");
	if (!body) {
		free(source);
		FAIL("could not find config_dump");
		return;
	}
	end = strstr(body, "\n}\n");
	if (end)
		*end = '\0';

	for (p = source; (p = strstr(p, "strcmp(key, \"")) != NULL;) {
		char key[64];
		char underscored[64];
		char *dash;
		const char *start;
		const char *stop;
		size_t n;
		bool ok;

		start = p + strlen("strcmp(key, \"");
		stop = strchr(start, '"');
		p = start;
		if (!stop)
			continue;
		n = (size_t)(stop - start);
		if (n == 0 || n >= sizeof(key))
			continue;
		memcpy(key, start, n);
		key[n] = '\0';

		/* hyphenated aliases are dumped with underscores */
		snprintf(underscored, sizeof(underscored), "%s", key);
		for (dash = underscored; *dash; dash++)
			if (*dash == '-')
				*dash = '_';

		ok = dump_prints_key(body, key) ||
		     dump_prints_key(body, underscored);
		for (size_t i = 0;
		     !ok && i < sizeof(exempt) / sizeof(exempt[0]); i++)
			ok = strcmp(underscored, exempt[i].key) == 0;
		if (!ok) {
			FAIL("the dump never prints %s", key);
			missing++;
		}
	}
	free(source);

	if (missing) {
		FAIL("a key the parser accepts does not survive a dump");
		return;
	}
}

/* join a dump's comment lines so checks ignore where they wrapped */
static int collect_dump_comments(const char *path, char *out, size_t outsz)
{
	char line[512];
	size_t used = 0;
	FILE *fp;

	out[0] = '\0';
	fp = fopen(path, "re");
	if (!fp)
		return -1;

	while (fgets(line, sizeof(line), fp)) {
		size_t len;

		if (line[0] != '#')
			continue;
		len = strlen(line);
		if (used + len + 1 >= outsz)
			break;
		memcpy(out + used, line, len);
		used += len;
		out[used] = '\0';
	}
	fclose(fp);
	return 0;
}

/*
 * The strict flags apply only in enforce mode; outside it the dump must say
 * which ones set are inert, or it reads as protection in force.
 */
static void test_a_weaker_mode_names_the_flags_it_ignores(void)
{
	struct lota_config cfg;
	const char *inert[LOTA_STRICT_FLAG_COUNT];
	int n;

	TEST("a mode below enforce names every strict flag it ignores");
	config_init(&cfg);
	snprintf(cfg.mode, sizeof(cfg.mode), "monitor");
	cfg.strict_mmap = true;
	cfg.strict_exec = true;
	cfg.block_ptrace = true;
	cfg.strict_modules = true;
	cfg.block_anon_exec = true;

	n = config_inert_strict_flags(&cfg, inert, LOTA_STRICT_FLAG_COUNT);
	if (n != LOTA_STRICT_FLAG_COUNT) {
		FAIL("monitor mode reported a gate it does not run as live");
		return;
	}
	if (strcmp(inert[0], "strict_mmap") != 0 ||
	    strcmp(inert[1], "strict_exec") != 0 ||
	    strcmp(inert[2], "block_ptrace") != 0 ||
	    strcmp(inert[3], "strict_modules") != 0 ||
	    strcmp(inert[4], "block_anon_exec") != 0) {
		FAIL("the inert keys are not named in the order they print");
		return;
	}

	snprintf(cfg.mode, sizeof(cfg.mode), "enforce");
	if (config_inert_strict_flags(&cfg, inert, LOTA_STRICT_FLAG_COUNT) !=
	    0) {
		FAIL("enforce mode runs every gate, so nothing is inert");
		return;
	}
}

/* a flag that is off is not named */
static void test_only_the_flags_that_are_on_are_named(void)
{
	struct lota_config cfg;
	const char *inert[LOTA_STRICT_FLAG_COUNT];
	int n;

	TEST("only a strict flag that is on is reported as inert");
	config_init(&cfg);
	snprintf(cfg.mode, sizeof(cfg.mode), "monitor");
	cfg.strict_mmap = false;
	cfg.strict_exec = false;
	cfg.block_ptrace = false;
	cfg.strict_modules = true;
	cfg.block_anon_exec = false;

	n = config_inert_strict_flags(&cfg, inert, LOTA_STRICT_FLAG_COUNT);
	if (n != 1 || strcmp(inert[0], "strict_modules") != 0) {
		FAIL("the one flag that is on was not the one reported");
		return;
	}
}

/* the note must appear in --dump-config and the dump must still parse */
static void test_the_dump_marks_the_keys_the_mode_ignores(void)
{
	struct lota_config cfg1, cfg2;
	char dump_path[PATH_MAX];
	char comments[4096];
	FILE *f;
	int fd;

	TEST("config_dump marks the keys the mode leaves inert");
	config_init(&cfg1);
	snprintf(cfg1.mode, sizeof(cfg1.mode), "monitor");
	cfg1.strict_mmap = true;
	cfg1.strict_exec = true;
	cfg1.block_ptrace = true;
	cfg1.strict_modules = true;
	cfg1.block_anon_exec = true;

	snprintf(dump_path, sizeof(dump_path), "%s/inert.conf", tmpdir);
	fd = open(dump_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	f = fd >= 0 ? fdopen(fd, "w") : NULL;
	if (fd >= 0 && !f)
		close(fd);
	if (!f) {
		FAIL("fopen dump");
		return;
	}
	config_dump(&cfg1, f);
	fclose(f);

	if (collect_dump_comments(dump_path, comments, sizeof(comments)) != 0) {
		FAIL("could not read the dump back");
		return;
	}
	for (int i = 0; i < LOTA_STRICT_FLAG_COUNT; i++) {
		static const char *const keys[LOTA_STRICT_FLAG_COUNT] = {
			"strict_mmap", "strict_exec", "block_ptrace",
			"strict_modules", "block_anon_exec"
		};

		if (!strstr(comments, keys[i])) {
			FAIL("the dump never says %s is inert", keys[i]);
			FAIL("an inert key is printed as if it were applied");
			return;
		}
	}

	config_init(&cfg2);
	if (config_load(&cfg2, dump_path) != 0) {
		FAIL("the marked dump no longer parses");
		return;
	}
	if (strcmp(cfg2.mode, "monitor") != 0 || !cfg2.strict_mmap ||
	    !cfg2.strict_exec || !cfg2.block_ptrace || !cfg2.strict_modules ||
	    !cfg2.block_anon_exec) {
		FAIL("the marking cost the dump its values");
		return;
	}

	/* enforce runs every gate, so nothing is marked */
	snprintf(cfg1.mode, sizeof(cfg1.mode), "enforce");
	fd = open(dump_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	f = fd >= 0 ? fdopen(fd, "w") : NULL;
	if (fd >= 0 && !f)
		close(fd);
	if (!f) {
		FAIL("fopen dump");
		return;
	}
	config_dump(&cfg1, f);
	fclose(f);
	if (collect_dump_comments(dump_path, comments, sizeof(comments)) != 0) {
		FAIL("could not read the dump back");
		return;
	}
	if (strstr(comments, "inert")) {
		FAIL("enforce mode marked a gate it does run");
		return;
	}
}

static void test_config_load_all_known_keys(void)
{
	struct lota_config cfg;
	char path[PATH_MAX];
	int ret;

	TEST("config_load with every known key returns 0");
	write_config(
		"all.conf",
		"server = allhost\n"
		"port = 5555\n"
		"ca_cert = /all/ca.pem\n"
		"pin_sha256 = abcdef0123456789222222222222222222222222222222222222222222222222\n"
		"bpf_path = /all/lota.bpf.o\n"
		"mode = monitor\n"
		"strict_mmap = true\n"
		"block_ptrace = true\n"
		"bench = true\n"
		"attest_interval = 240\n"
		"aik_handle = 0x81010005\n"
		"daemon = true\n"
		"pid_file = /all/pid\n"
		"policy_pubkey = /all/sign.pub\n"
		"trust_lib = /all/lib1.so\n"
		"trust_lib = /all/lib2.so\n"
		"protect_pid = 1\n"
		"protect_pid = 2\n"
		"container_listener_uid = 1000\n"
		"container_listener_uid = 1001\n"
		"log_level = error\n");
	config_path("all.conf", path, sizeof(path));
	config_init(&cfg);
	ret = config_load(&cfg, path);
	if (ret != 0) {
		char msg[64];
		snprintf(msg, sizeof(msg), "expected 0, got %d", ret);
		FAIL("%s", msg);
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
	if (strcmp(cfg.pin_sha256,
		   "abcdef0123456789222222222222222222222222222222222222222222222222") !=
	    0) {
		FAIL("pin_sha256");
		return;
	}
	if (strcmp(cfg.bpf_path, "/all/lota.bpf.o") != 0) {
		FAIL("bpf_path");
		return;
	}
	if (strcmp(cfg.mode, "monitor") != 0) {
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
	if (cfg.attest_interval != 240) {
		FAIL("attest_interval");
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
	if (cfg.container_listener_uid_count != 2 ||
	    cfg.container_listener_uids[0] != 1000 ||
	    cfg.container_listener_uids[1] != 1001) {
		FAIL("container_listener_uids");
		return;
	}
	if (strcmp(cfg.log_level, "error") != 0) {
		FAIL("log_level");
		return;
	}
}

static void test_config_load_override_order(void)
{
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
}

/*
 * Which key verifies the enforcement object.
 *
 * The order is what keeps fleet that signs enforcement itself from being
 * overwritten by an upgrade, and host that made no such choice from being left
 * with key the object no longer matches.
 * Both are silent failures if the order is wrong, so it is pinned here rather
 * than left to the two callers to agree on.
 */
static void test_policy_pubkey_resolve(void)
{
	char override_path[PATH_MAX];
	char packaged_path[PATH_MAX];
	const char *got;

	TEST("policy_pubkey_resolve follows configured, override, packaged");

	config_path("override.pub", override_path, sizeof(override_path));
	config_path("packaged.pub", packaged_path, sizeof(packaged_path));
	write_config("packaged.pub", "packaged\n");

	got = policy_pubkey_resolve(NULL, override_path, packaged_path);
	if (!got || strcmp(got, packaged_path) != 0) {
		FAIL("with no operator key the packaged one is used");
		return;
	}

	write_config("override.pub", "operator\n");
	got = policy_pubkey_resolve(NULL, override_path, packaged_path);
	if (!got || strcmp(got, override_path) != 0) {
		FAIL("an operator key present on disk wins over the packaged one");
		return;
	}

	got = policy_pubkey_resolve(override_path, override_path,
				    packaged_path);
	if (!got || strcmp(got, override_path) != 0) {
		FAIL("policy_pubkey names the key outright");
		return;
	}

	/*
	 * Named key that is no longer on disk is a leftover, not a choice:
	 * older installer wrote this line, and the file it named is one upgrade
	 * can take away.
	 * Falling back keeps enforcement armed on host whose package brought
	 * key of its own.
	 */
	got = policy_pubkey_resolve("/nonexistent/named.pub",
				    "/nonexistent/override.pub", packaged_path);
	if (!got || strcmp(got, packaged_path) != 0) {
		FAIL("a named key that no longer exists falls back to the "
		     "packaged one");
		return;
	}

	got = policy_pubkey_resolve(NULL, "/nonexistent/override.pub",
				    "/nonexistent/packaged.pub");
	if (got != NULL) {
		FAIL("no readable key resolves to nothing, not to a guess");
		return;
	}

	unlink(override_path);
	unlink(packaged_path);
}

static void test_config_load_mixed_comments(void)
{
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
}

static void test_config_load_from_fd(void)
{
	struct lota_config cfg;
	char path[PATH_MAX];
	int fd;
	int ret;

	TEST("config_load_from_fd parses from opened descriptor");
	write_config("fdload.conf", "server = fdhost\nport = 12345\n");
	config_path("fdload.conf", path, sizeof(path));

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		FAIL("open failed");
		return;
	}

	config_init(&cfg);
	ret = config_load_from_fd(&cfg, fd, path);
	close(fd);

	if (ret != 0) {
		char msg[64];
		snprintf(msg, sizeof(msg), "expected 0, got %d", ret);
		FAIL("%s", msg);
		return;
	}

	if (strcmp(cfg.server, "fdhost") != 0 || cfg.port != 12345) {
		FAIL("parsed values mismatch");
		return;
	}
}

static int cli_parse_argv(const char *const *args, int n,
			  struct cli_options *opts, struct lota_config *cfg)
{
	char *argv[8];

	for (int i = 0; i < n; i++)
		argv[i] = (char *)args[i];
	argv[n] = NULL;
	config_init(cfg);
	return cli_parse(n, argv, opts, cfg);
}

static void test_cli_config_spellings(void)
{
	struct cli_options opts;
	struct lota_config *cfg;
	char path[PATH_MAX];
	char joined[PATH_MAX + 16];
	char fused[PATH_MAX + 8];

	TEST("every --config spelling getopt accepts loads that file");

	write_config("cli_monitor.conf", "mode = monitor\n");
	config_path("cli_monitor.conf", path, sizeof(path));
	snprintf(joined, sizeof(joined), "--config=%s", path);
	snprintf(fused, sizeof(fused), "-f%s", path);

	const char *const forms[][3] = {
		{ "lota-agent", "--config", path },
		{ "lota-agent", joined, NULL },
		{ "lota-agent", fused, NULL },
		{ "lota-agent", "--conf", path },
		{ "lota-agent", "-tf", path },
	};

	cfg = config_new();
	if (!cfg) {
		FAIL("out of memory");
		return;
	}
	for (size_t i = 0; i < sizeof(forms) / sizeof(forms[0]); i++) {
		int n = forms[i][2] ? 3 : 2;

		if (cli_parse_argv(forms[i], n, &opts, cfg) != 0) {
			FAIL("%s", forms[i][1]);
			config_free(cfg);
			return;
		}
		if (strcmp(cfg->mode, "monitor") != 0 || !opts.config_path ||
		    strcmp(opts.config_path, path) != 0) {
			FAIL("%s", forms[i][1]);
			config_free(cfg);
			return;
		}
	}
	config_free(cfg);
}

static void test_cli_attest_interval_bounds(void)
{
	static const struct {
		const char *arg;
		int ret;
		int interval;
	} cases[] = {
		{ "29", 1, 0 },	   { "30", 0, 30 }, { "0", 0, 0 },
		{ "240", 0, 240 }, { "241", 1, 0 },
	};
	struct cli_options opts;
	struct lota_config *cfg;
	char path[PATH_MAX];

	TEST("--attest-interval refuses what the file refuses");

	write_config("cli_empty.conf", "");
	config_path("cli_empty.conf", path, sizeof(path));
	cfg = config_new();
	if (!cfg) {
		FAIL("out of memory");
		return;
	}
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		const char *const args[] = { "lota-agent", "--config", path,
					     "--attest-interval",
					     cases[i].arg };

		if (cli_parse_argv(args, 5, &opts, cfg) != cases[i].ret ||
		    (cases[i].ret == 0 &&
		     opts.attest_interval != cases[i].interval)) {
			FAIL("%s", cases[i].arg);
			config_free(cfg);
			return;
		}
	}
	config_free(cfg);
}

static void test_cli_trust_lib_path(void)
{
	static const char *const bad[] = { "", "lib/libx.so",
					   "/usr/lib/../libx.so" };
	struct cli_options opts;
	struct lota_config *cfg;
	char path[PATH_MAX];

	TEST("--trust-lib refuses what --allow-verity refuses");

	write_config("cli_empty.conf", "");
	config_path("cli_empty.conf", path, sizeof(path));
	cfg = config_new();
	if (!cfg) {
		FAIL("out of memory");
		return;
	}
	for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		const char *const lib[] = { "lota-agent", "--config", path,
					    "--trust-lib", bad[i] };
		const char *const verity[] = { "lota-agent", "--config", path,
					       "--allow-verity", bad[i] };

		if (cli_parse_argv(verity, 5, &opts, cfg) != 1 ||
		    cli_parse_argv(lib, 5, &opts, cfg) != 1) {
			FAIL("%s", bad[i]);
			config_free(cfg);
			return;
		}
	}
	config_free(cfg);
}

static void test_cli_policy_pubkey_unreadable(void)
{
	struct cli_options opts;
	struct lota_config *cfg;
	char path[PATH_MAX];
	char log_path[PATH_MAX];
	char log[512] = "";
	int saved, fd, rc;
	bool quiet;

	TEST("an unreadable policy_pubkey is reported with its errno");

	write_config("cli_pubkey.conf",
		     "policy_pubkey = /nonexistent/named.pub\n");
	config_path("cli_pubkey.conf", path, sizeof(path));
	config_path("cli_pubkey.log", log_path, sizeof(log_path));
	cfg = config_new();
	saved = dup(STDERR_FILENO);
	fd = open(log_path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (!cfg || saved < 0 || fd < 0) {
		FAIL("setup");
		config_free(cfg);
		return;
	}

	const char *const argv[] = { "lota-agent", "--config", path,
				     "--policy-pubkey",
				     "/nonexistent/flag.pub" };

	fflush(stderr);
	dup2(fd, STDERR_FILENO);
	rc = cli_parse_argv(argv, 5, &opts, cfg);
	fflush(stderr);
	quiet = lseek(fd, 0, SEEK_END) == 0;
	rc = rc ?: cli_parse_argv(argv, 3, &opts, cfg);
	fflush(stderr);
	dup2(saved, STDERR_FILENO);
	close(saved);
	if (pread(fd, log, sizeof(log) - 1, 0) < 0)
		log[0] = '\0';
	close(fd);
	unlink(log_path);
	config_free(cfg);

	if (rc != 0) {
		FAIL("the configuration is refused");
		return;
	}
	if (!quiet) {
		FAIL("warned about the file key under --policy-pubkey");
		return;
	}
	if (!strstr(log, "/nonexistent/named.pub") ||
	    !strstr(log, strerror(ENOENT))) {
		FAIL("%s", log);
		return;
	}
}

/* A host file the daemon would refuse does not stop the file commands */
static void test_cli_file_commands_skip_the_config(void)
{
	struct cli_options opts;
	struct lota_config *cfg;
	char path[PATH_MAX];
	int saved, fd, rc;

	TEST("key and signature commands do not read the config file");

	write_config("cli_broken.conf", "aik_ttl = 0\n");
	config_path("cli_broken.conf", path, sizeof(path));
	cfg = config_new();
	saved = dup(STDOUT_FILENO);
	fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
	if (!cfg || saved < 0 || fd < 0) {
		FAIL("setup");
		config_free(cfg);
		return;
	}

	const char *const status[] = { "lota-agent", "--config", path,
				       "--status" };
	const char *const gen[] = { "lota-agent", "--config", path,
				    "--gen-signing-key", "/nonexistent/key" };
	const char *const sign[] = {
		"lota-agent",	   "--config",	       path,
		"--sign-policy",   "/nonexistent/obj", "--signing-key",
		"/nonexistent/key"
	};
	const char *const verify[] = { "lota-agent", "--config", path,
				       "--verify-policy", "/nonexistent/obj" };
	const char *const help[] = { "lota-agent", "--config", path, "--help" };

	fflush(stdout);
	dup2(fd, STDOUT_FILENO);
	if (cli_parse_argv(status, 4, &opts, cfg) == 0) {
		rc = -2;
	} else if (cli_parse_argv(gen, 5, &opts, cfg) != 0 ||
		   !opts.gen_signing_key_prefix) {
		rc = 1;
	} else if (cli_parse_argv(sign, 7, &opts, cfg) != 0 ||
		   !opts.sign_policy_file || !opts.signing_key_path) {
		rc = 2;
	} else if (cli_parse_argv(verify, 5, &opts, cfg) != 0 ||
		   !opts.verify_policy_file) {
		rc = 3;
	} else if (cli_parse_argv(help, 4, &opts, cfg) != -1) {
		rc = 4;
	} else {
		rc = 0;
	}
	fflush(stdout);
	dup2(saved, STDOUT_FILENO);
	close(saved);
	close(fd);
	config_free(cfg);

	if (rc == -2)
		FAIL("the daemon accepted the key the file commands must skip");
	else if (rc)
		FAIL("%s", rc == 1 ? "--gen-signing-key read the file" :
			   rc == 2 ? "--sign-policy read the file" :
			   rc == 3 ? "--verify-policy read the file" :
				     "--help read the file");
}

static void test_cli_dump_with_a_file_command_reads_the_config(void)
{
	struct cli_options opts;
	struct lota_config *cfg;
	char path[PATH_MAX];
	int saved, fd, rc, help_rc;

	TEST("--dump-config next to a file command reads the config file");

	write_config("cli_dump_broken.conf", "aik_ttl = 0\n");
	config_path("cli_dump_broken.conf", path, sizeof(path));
	cfg = config_new();
	if (!cfg) {
		FAIL("setup");
		return;
	}

	const char *const argv[] = {
		"lota-agent",	 "--config",	    path,
		"--dump-config", "--verify-policy", "/nonexistent/obj"
	};

	const char *const help[] = { "lota-agent", "--config", path,
				     "--dump-config", "--help" };

	rc = cli_parse_argv(argv, 6, &opts, cfg);
	saved = dup(STDOUT_FILENO);
	fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
	fflush(stdout);
	if (saved >= 0 && fd >= 0)
		dup2(fd, STDOUT_FILENO);
	help_rc = cli_parse_argv(help, 5, &opts, cfg);
	fflush(stdout);
	if (saved >= 0) {
		dup2(saved, STDOUT_FILENO);
		close(saved);
	}
	if (fd >= 0)
		close(fd);
	config_free(cfg);

	if (rc == 0)
		FAIL("the dump left out the file it was given");
	else if (help_rc != -1)
		FAIL("--help read the file next to --dump-config");
}

static void test_cli_policy_pubkey_into_config(void)
{
	struct cli_options opts;
	struct lota_config *cfg;
	char path[PATH_MAX];
	char key[PATH_MAX];

	TEST("the key the start resolves is the one the snapshot holds");

	write_config("cli_nokey.conf", "");
	write_config("cli_flag.pub", "");
	config_path("cli_nokey.conf", path, sizeof(path));
	config_path("cli_flag.pub", key, sizeof(key));
	cfg = config_new();
	if (!cfg) {
		FAIL("out of memory");
		return;
	}

	const char *const argv[] = { "lota-agent", "--config", path,
				     "--policy-pubkey", key };

	if (cli_parse_argv(argv, 5, &opts, cfg) != 0) {
		FAIL("the command line is refused");
	} else if (strcmp(cfg->policy_pubkey, key) != 0) {
		FAIL("--policy-pubkey does not reach the snapshot");
	}
	config_free(cfg);
}

int main(void)
{
	test_begin("config");

	setup_tmpdir();

	/*
	 * Dispatch through a function-pointer table rather than direct
	 * calls. Each test puts a 1.3 MB struct lota_config on its stack;
	 * called directly, clang inlines all of them into main() and the
	 * cumulative frame overflows the 8 MB stack under ASan. An opaque
	 * pointer call keeps every test in its own frame.
	 */
	static void (*const tests[])(void) = {
		test_config_init_defaults,
		test_config_load_nonexistent,
		test_config_load_null_cfg,
		test_config_load_empty_file,
		test_config_load_comments_only,
		test_config_load_basic_values,
		test_config_load_string_fields,
		test_config_load_hyphen_keys,
		test_config_load_trust_libs_multiple,
		test_config_load_protect_pids_multiple,
		test_config_load_container_listener_uids_multiple,
		test_config_load_container_listener_uid_duplicate,
		test_config_load_container_listener_uid_overflow,
		test_config_load_container_listener_uid_invalid,
		test_config_load_boolean_variants,
		test_config_load_invalid_boolean,
		test_config_load_bench,
		test_config_load_invalid_mode,
		test_config_load_invalid_log_level,
		test_config_load_value_too_long,
		test_config_load_line_limit,
		test_config_load_whitespace_trimming,
		test_config_load_unknown_keys,
		test_config_load_malformed_lines,
		test_config_load_empty_key,
		test_config_load_empty_value,
		test_config_load_port_bounds,
		test_config_load_attest_interval_bounds,
		test_config_load_refuses_aik_ttl,
		test_config_load_refuses_signing_key,
		test_config_load_profiles,
		test_config_profile_reporting,
		test_config_load_profile_incomplete,
		test_config_load_profile_malformed,
		test_config_load_profile_overflow,
		test_config_profile_pin_sha256,
		test_config_host_pin_beside_profiles,
		test_config_load_rejects_group_writable,
		test_config_load_rejects_symlink,
		test_config_load_rejects_fifo,
		test_config_dump_keeps_server_unset,
		test_config_dump_roundtrip,
		test_config_dump_keeps_the_sealing_keys,
		test_dump_prints_every_key_the_parser_takes,
		test_a_weaker_mode_names_the_flags_it_ignores,
		test_only_the_flags_that_are_on_are_named,
		test_the_dump_marks_the_keys_the_mode_ignores,
		test_config_load_all_known_keys,
		test_config_load_override_order,
		test_policy_pubkey_resolve,
		test_config_load_mixed_comments,
		test_config_load_from_fd,
		test_cli_config_spellings,
		test_cli_attest_interval_bounds,
		test_cli_trust_lib_path,
		test_cli_policy_pubkey_unreadable,
		test_cli_policy_pubkey_into_config,
		test_cli_file_commands_skip_the_config,
		test_cli_dump_with_a_file_command_reads_the_config,
	};

	for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++)
		tests[i]();

	cleanup_tmpdir();

	return test_end();
}
