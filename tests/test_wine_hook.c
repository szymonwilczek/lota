/* SPDX-License-Identifier: MIT */
/*
 * LOTA Wine/Proton Hook Unit Tests
 *
 * Tests the internal helper functions of the LD_PRELOAD hook library.
 * #define LOTA_HOOK_TESTING is to suppress the constructor/destructor
 * and allow direct access to static functions.
 *
 * Build:
 *   gcc -Wall -Wextra -Werror -O2 -g -Iinclude -D_GNU_SOURCE \
 *       -DLOTA_HOOK_TESTING \
 *       -o build/test_wine_hook \
 *       tests/test_wine_hook.c src/sdk/lota_gaming.c -lpthread
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

/* skip constructor/destructor when testing */
#ifndef LOTA_HOOK_TESTING
#define LOTA_HOOK_TESTING
#endif
#include <dirent.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test.h"

#include "../src/sdk/lota_wine_hook.c"
int lota_protect_main(int argc, char **argv);
#define main lota_protect_main
#include "../src/sdk/lota_protect.c"
#undef main
#include "lota_gaming.h"
#include "lota_ipc.h"

static void SKIP(const char *msg)
{
	tests_passed++;
	printf("SKIP (%s)\n", msg);
}

/* temp directory for test artifacts */
static char tmpdir[64];

static void setup_tmpdir(void)
{
	snprintf(tmpdir, sizeof(tmpdir), "/tmp/lota_test_hook_XXXXXX");
	if (!mkdtemp(tmpdir)) {
		fprintf(stderr, "mkdtemp failed: %s\n", strerror(errno));
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

/* read entire file contents */
static ssize_t read_file_contents(const char *path, char *buf, size_t buflen)
{
	int fd;
	ssize_t n;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -errno;

	n = read(fd, buf, buflen - 1);
	close(fd);

	if (n < 0)
		return -errno;

	buf[n] = '\0';
	return n;
}

static int count_tmp_entries_with_prefix(const char *dir, const char *prefix)
{
	DIR *d;
	struct dirent *ent;
	int count = 0;

	d = opendir(dir);
	if (!d)
		return -1;

	while ((ent = readdir(d)) != NULL) {
		if (strncmp(ent->d_name, prefix, strlen(prefix)) == 0)
			count++;
	}

	closedir(d);
	return count;
}

static void test_parse_log_level_debug(void)
{
	TEST("parse_log_level(\"debug\") -> DEBUG");
	if (parse_log_level("debug") != HOOK_LOG_DEBUG) {
		FAIL("wrong level");
		return;
	}
	PASS();
}

static void test_parse_log_level_info(void)
{
	TEST("parse_log_level(\"info\") -> INFO");
	if (parse_log_level("info") != HOOK_LOG_INFO) {
		FAIL("wrong level");
		return;
	}
	PASS();
}

static void test_parse_log_level_warn(void)
{
	TEST("parse_log_level(\"warn\") -> WARN");
	if (parse_log_level("warn") != HOOK_LOG_WARN) {
		FAIL("wrong level");
		return;
	}
	PASS();
}

static void test_parse_log_level_error(void)
{
	TEST("parse_log_level(\"error\") -> ERROR");
	if (parse_log_level("error") != HOOK_LOG_ERROR) {
		FAIL("wrong level");
		return;
	}
	PASS();
}

static void test_parse_log_level_silent(void)
{
	TEST("parse_log_level(\"silent\") -> SILENT");
	if (parse_log_level("silent") != HOOK_LOG_SILENT) {
		FAIL("wrong level");
		return;
	}
	PASS();
}

static void test_parse_log_level_null(void)
{
	TEST("parse_log_level(NULL) -> WARN default");
	if (parse_log_level(NULL) != HOOK_LOG_WARN) {
		FAIL("wrong default");
		return;
	}
	PASS();
}

static void test_parse_log_level_invalid(void)
{
	TEST("parse_log_level(\"garbage\") -> WARN default");
	if (parse_log_level("garbage") != HOOK_LOG_WARN) {
		FAIL("wrong default");
		return;
	}
	PASS();
}

static void test_token_dir_candidate_explicit(void)
{
	TEST("token dir candidate 0: LOTA_HOOK_TOKEN_DIR takes priority");

	setenv("LOTA_HOOK_TOKEN_DIR", "/custom/token/path", 1);
	setenv("XDG_RUNTIME_DIR", "/run/user/9999", 1);

	memset(g_hook.token_dir, 0, sizeof(g_hook.token_dir));
	if (token_dir_candidate(0) != 0) {
		FAIL("the override was not offered first");
		return;
	}

	unsetenv("LOTA_HOOK_TOKEN_DIR");
	unsetenv("XDG_RUNTIME_DIR");

	if (strcmp(g_hook.token_dir, "/custom/token/path") != 0) {
		FAIL("wrong dir");
		return;
	}
	PASS();
}

/*
 * The daemon owns $XDG_RUNTIME_DIR/lota: it creates it root:lota 0750 to hold
 * the container socket. A hook that writes its secrets there cannot work,
 * so the default candidate is a directory of the player's own.
 */
static void test_token_dir_candidate_xdg(void)
{
	TEST("token dir candidate 1: XDG_RUNTIME_DIR + /lota-hook");

	unsetenv("LOTA_HOOK_TOKEN_DIR");
	setenv("XDG_RUNTIME_DIR", "/run/user/1234", 1);

	memset(g_hook.token_dir, 0, sizeof(g_hook.token_dir));
	if (token_dir_candidate(1) != 0) {
		FAIL("no candidate for a set XDG_RUNTIME_DIR");
		return;
	}

	unsetenv("XDG_RUNTIME_DIR");

	if (strcmp(g_hook.token_dir, "/run/user/1234/lota-hook") != 0) {
		FAIL("wrong dir");
		return;
	}
	PASS();
}

static void test_token_dir_candidates_never_the_socket_dir(void)
{
	TEST("token dir candidates: never the directory the daemon owns");

	unsetenv("LOTA_HOOK_TOKEN_DIR");
	setenv("XDG_RUNTIME_DIR", "/run/user/1234", 1);

	for (int n = 0; n < 3; n++) {
		memset(g_hook.token_dir, 0, sizeof(g_hook.token_dir));
		if (token_dir_candidate(n) != 0)
			continue;
		if (strcmp(g_hook.token_dir, "/run/user/1234/lota") == 0) {
			unsetenv("XDG_RUNTIME_DIR");
			FAIL("a candidate is the daemon's socket directory");
			return;
		}
	}

	unsetenv("XDG_RUNTIME_DIR");
	PASS();
}

static void test_token_dir_candidate_fallback(void)
{
	char expected[PATH_MAX];

	TEST("token dir candidate 2: /tmp/lota-<uid>");

	unsetenv("LOTA_HOOK_TOKEN_DIR");
	unsetenv("XDG_RUNTIME_DIR");

	memset(g_hook.token_dir, 0, sizeof(g_hook.token_dir));
	if (token_dir_candidate(2) != 0) {
		FAIL("no last-resort candidate");
		return;
	}

	snprintf(expected, sizeof(expected), "/tmp/lota-%u",
		 (unsigned)getuid());

	if (strcmp(g_hook.token_dir, expected) != 0) {
		FAIL("wrong fallback dir");
		return;
	}
	PASS();
}

/*
 * A candidate that cannot be used is not the end of the hook.
 * The player gets attestation from whichever directory works, and the log says
 * which one that was.
 */
static void test_setup_token_dir_falls_through(void)
{
	char expected[PATH_MAX];
	char blocker[PATH_MAX];
	int fd;

	TEST("setup_token_dir: an unusable candidate is skipped, not fatal");

	snprintf(blocker, sizeof(blocker), "%s/lota-hook", tmpdir);
	fd = open(blocker, O_CREAT | O_WRONLY, 0644);
	if (fd >= 0)
		close(fd);

	unsetenv("LOTA_HOOK_TOKEN_DIR");
	setenv("XDG_RUNTIME_DIR", tmpdir, 1);

	memset(g_hook.token_dir, 0, sizeof(g_hook.token_dir));
	g_hook.log_level = HOOK_LOG_SILENT;
	int ret = setup_token_dir();
	g_hook.log_level = HOOK_LOG_WARN;

	unsetenv("XDG_RUNTIME_DIR");
	unlink(blocker);

	snprintf(expected, sizeof(expected), "/tmp/lota-%u",
		 (unsigned)getuid());

	if (ret != 0) {
		FAIL("gave up instead of falling through");
		return;
	}
	if (strcmp(g_hook.token_dir, expected) != 0) {
		FAIL("did not settle on the fallback");
		return;
	}
	PASS();
}

static void test_setup_token_dir_explicit_refused_falls_through(void)
{
	char blocker[PATH_MAX];
	char expected[PATH_MAX];
	int fd;

	TEST("setup_token_dir: a refused override falls through too");

	snprintf(blocker, sizeof(blocker), "%s/override_is_a_file", tmpdir);
	fd = open(blocker, O_CREAT | O_WRONLY, 0644);
	if (fd >= 0)
		close(fd);

	setenv("LOTA_HOOK_TOKEN_DIR", blocker, 1);
	setenv("XDG_RUNTIME_DIR", tmpdir, 1);

	memset(g_hook.token_dir, 0, sizeof(g_hook.token_dir));
	g_hook.log_level = HOOK_LOG_SILENT;
	int ret = setup_token_dir();
	g_hook.log_level = HOOK_LOG_WARN;

	unsetenv("LOTA_HOOK_TOKEN_DIR");
	unsetenv("XDG_RUNTIME_DIR");
	unlink(blocker);

	snprintf(expected, sizeof(expected), "%s/lota-hook", tmpdir);

	if (ret != 0) {
		FAIL("gave up instead of falling through");
		return;
	}
	if (strcmp(g_hook.token_dir, expected) != 0) {
		FAIL("did not settle on the next candidate");
		return;
	}
	rmdir(expected);
	PASS();
}

static void test_ensure_token_dir_creates(void)
{
	struct stat st;

	TEST("ensure_token_dir creates directory with mode 0700");

	snprintf(g_hook.token_dir, sizeof(g_hook.token_dir), "%s/subdir",
		 tmpdir);

	if (ensure_token_dir(NULL) != 0) {
		FAIL("ensure_token_dir failed");
		return;
	}
	if (stat(g_hook.token_dir, &st) != 0) {
		FAIL("directory does not exist");
		return;
	}
	if (!S_ISDIR(st.st_mode)) {
		FAIL("not a directory");
		return;
	}
	if ((st.st_mode & 0777) != 0700) {
		FAIL("wrong mode");
		return;
	}
	PASS();
}

static void test_ensure_token_dir_exists(void)
{
	TEST("ensure_token_dir succeeds if directory exists");

	/* tmpdir already exists */
	snprintf(g_hook.token_dir, sizeof(g_hook.token_dir), "%s", tmpdir);

	if (ensure_token_dir(NULL) != 0) {
		FAIL("ensure_token_dir failed");
		return;
	}
	PASS();
}

static void test_ensure_token_dir_not_a_dir(void)
{
	char path[sizeof(g_hook.token_dir)];
	int fd;

	TEST("ensure_token_dir rejects non-directory");

	snprintf(path, sizeof(path), "%s/file_not_dir", tmpdir);
	fd = open(path, O_CREAT | O_WRONLY, 0644);
	if (fd >= 0)
		close(fd);

	snprintf(g_hook.token_dir, sizeof(g_hook.token_dir), "%s", path);

	/* suppress stderr for this test */
	g_hook.log_level = HOOK_LOG_SILENT;
	int ret = ensure_token_dir(NULL);
	g_hook.log_level = HOOK_LOG_WARN;

	if (ret != -ENOTDIR) {
		FAIL("expected -ENOTDIR");
		return;
	}
	PASS();
}

static void test_ensure_token_dir_rejects_symlink(void)
{
	char target[sizeof(g_hook.token_dir)];
	char linkpath[sizeof(g_hook.token_dir)];

	TEST("ensure_token_dir rejects symlink target path");

	snprintf(target, sizeof(target), "%s/real_dir", tmpdir);
	if (mkdir(target, 0700) != 0) {
		FAIL("mkdir target failed");
		return;
	}

	snprintf(linkpath, sizeof(linkpath), "%s/link_dir", tmpdir);
	if (symlink(target, linkpath) != 0) {
		FAIL("symlink create failed");
		return;
	}

	snprintf(g_hook.token_dir, sizeof(g_hook.token_dir), "%s", linkpath);

	g_hook.log_level = HOOK_LOG_SILENT;
	int ret = ensure_token_dir(NULL);
	g_hook.log_level = HOOK_LOG_WARN;

	if (ret != -ELOOP && ret != -ENOTDIR) {
		FAIL("expected -ELOOP or -ENOTDIR");
		return;
	}

	PASS();
}

/* a trailing slash makes open() follow the link despite O_NOFOLLOW */
static void test_token_dir_override_trailing_slash_symlink(void)
{
	char target[sizeof(g_hook.token_dir)];
	char linkpath[sizeof(g_hook.token_dir)];
	char env[sizeof(g_hook.token_dir) + 2];
	int ret;

	TEST("a token dir override with a trailing slash is still no symlink");

	snprintf(target, sizeof(target), "%s/slash_real", tmpdir);
	snprintf(linkpath, sizeof(linkpath), "%s/slash_link", tmpdir);
	if (mkdir(target, 0700) != 0 || symlink(target, linkpath) != 0) {
		FAIL("setup");
		return;
	}
	snprintf(env, sizeof(env), "%s//", linkpath);
	setenv("LOTA_HOOK_TOKEN_DIR", env, 1);

	ret = token_dir_candidate(0);
	unsetenv("LOTA_HOOK_TOKEN_DIR");
	if (ret != 0) {
		FAIL("the override was not offered");
		return;
	}
	g_hook.log_level = HOOK_LOG_SILENT;
	ret = ensure_token_dir(NULL);
	g_hook.log_level = HOOK_LOG_WARN;

	if (ret != -ELOOP && ret != -ENOTDIR) {
		FAIL("the symlink was followed");
		return;
	}
	PASS();
}

static void test_ensure_token_dir_existing_mode_tightened(void)
{
	struct stat st;
	char path[sizeof(g_hook.token_dir)];

	TEST("ensure_token_dir tightens existing dir mode to 0700");

	snprintf(path, sizeof(path), "%s/perms_dir", tmpdir);
	if (mkdir(path, 0755) != 0) {
		FAIL("mkdir perms_dir failed");
		return;
	}

	snprintf(g_hook.token_dir, sizeof(g_hook.token_dir), "%s", path);

	if (ensure_token_dir(NULL) != 0) {
		FAIL("ensure_token_dir failed");
		return;
	}

	if (stat(path, &st) != 0) {
		FAIL("stat failed");
		return;
	}

	if ((st.st_mode & 0777) != 0700) {
		FAIL("mode was not tightened to 0700");
		return;
	}

	PASS();
}

static void test_atomic_write_creates_file(void)
{
	char path[PATH_MAX];
	char buf[128];
	ssize_t n;

	TEST("atomic_write creates file with correct content");

	snprintf(path, sizeof(path), "%s/test_write", tmpdir);

	if (atomic_write(path, "hello\n", 6) != 0) {
		FAIL("atomic_write failed");
		return;
	}
	n = read_file_contents(path, buf, sizeof(buf));
	if (n != 6 || memcmp(buf, "hello\n", 6) != 0) {
		FAIL("content mismatch");
		return;
	}
	PASS();
}

static void test_atomic_write_overwrites(void)
{
	char path[PATH_MAX];
	char buf[128];
	ssize_t n;

	TEST("atomic_write atomically overwrites existing file");

	snprintf(path, sizeof(path), "%s/test_overwrite", tmpdir);

	atomic_write(path, "first", 5);
	if (atomic_write(path, "second", 6) != 0) {
		FAIL("second write failed");
		return;
	}
	n = read_file_contents(path, buf, sizeof(buf));
	if (n != 6 || memcmp(buf, "second", 6) != 0) {
		FAIL("content mismatch");
		return;
	}
	PASS();
}

static void test_atomic_write_no_tmp_leftover(void)
{
	char path[256];
	int tmp_count;

	TEST("atomic_write leaves no .tmp files on success");

	snprintf(path, sizeof(path), "%s/test_notmp", tmpdir);

	if (atomic_write(path, "data", 4) != 0) {
		FAIL("atomic_write failed");
		return;
	}

	tmp_count = count_tmp_entries_with_prefix(tmpdir, "test_notmp.tmp.");
	if (tmp_count < 0) {
		FAIL("opendir failed");
		return;
	}
	if (tmp_count != 0) {
		FAIL(".tmp files left behind");
		return;
	}
	PASS();
}

static void test_atomic_write_ignores_predictable_symlink_tmp(void)
{
	char path[PATH_MAX];
	char victim[PATH_MAX];
	char planted_tmp[PATH_MAX];
	char buf[64];
	ssize_t n;
	int fd;
	size_t base_len;
	size_t suffix_len;
	int pid_len;

	TEST("atomic_write resists planted symlink at legacy temp name");

	snprintf(path, sizeof(path), "%s/test_symlink_guard", tmpdir);
	snprintf(victim, sizeof(victim), "%s/victim_file", tmpdir);

	base_len = strlen(path);
	suffix_len = strlen(".tmp.");
	if (base_len + suffix_len + 16 >= sizeof(planted_tmp)) {
		FAIL("temp path too long");
		return;
	}
	memcpy(planted_tmp, path, base_len);
	memcpy(planted_tmp + base_len, ".tmp.", suffix_len);
	pid_len = snprintf(planted_tmp + base_len + suffix_len,
			   sizeof(planted_tmp) - base_len - suffix_len, "%d",
			   (int)getpid());
	if (pid_len < 0 ||
	    (size_t)pid_len >= sizeof(planted_tmp) - base_len - suffix_len) {
		FAIL("temp path build failed");
		return;
	}

	fd = open(victim, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0) {
		FAIL("open victim failed");
		return;
	}
	if (write(fd, "victim", 6) != 6) {
		close(fd);
		FAIL("write victim failed");
		return;
	}
	close(fd);

	if (symlink(victim, planted_tmp) != 0) {
		FAIL("symlink setup failed");
		return;
	}

	if (atomic_write(path, "safe", 4) != 0) {
		FAIL("atomic_write failed");
		unlink(planted_tmp);
		return;
	}

	n = read_file_contents(path, buf, sizeof(buf));
	if (n != 4 || memcmp(buf, "safe", 4) != 0) {
		FAIL("target content mismatch");
		unlink(planted_tmp);
		return;
	}

	n = read_file_contents(victim, buf, sizeof(buf));
	if (n != 6 || memcmp(buf, "victim", 6) != 0) {
		FAIL("planted symlink redirected write");
		unlink(planted_tmp);
		return;
	}

	unlink(planted_tmp);
	PASS();
}

static void test_atomic_write_file_mode(void)
{
	char path[PATH_MAX];
	struct stat st;

	TEST("atomic_write creates file with mode 0600");

	snprintf(path, sizeof(path), "%s/test_mode", tmpdir);
	atomic_write(path, "x", 1);

	if (stat(path, &st) != 0) {
		FAIL("stat failed");
		return;
	}
	if ((st.st_mode & 0777) != 0600) {
		char msg[64];
		snprintf(msg, sizeof(msg), "mode=%o", st.st_mode & 0777);
		FAIL(msg);
		return;
	}
	PASS();
}

static void test_write_status_attested(void)
{
	char buf[1024];
	ssize_t n;
	struct lota_status status;

	TEST("write_status: attested system generates correct file");

	snprintf(g_hook.status_path, sizeof(g_hook.status_path),
		 "%s/status_att", tmpdir);

	memset(&status, 0, sizeof(status));
	status.flags = LOTA_FLAG_ATTESTED | LOTA_FLAG_TPM_OK |
		       LOTA_FLAG_BPF_LOADED;
	status.valid_until = 1738957200;
	status.attest_count = 42;
	status.fail_count = 1;

	if (write_status(&status) != 0) {
		FAIL("write_status failed");
		return;
	}
	n = read_file_contents(g_hook.status_path, buf, sizeof(buf));
	if (n <= 0) {
		FAIL("read failed");
		return;
	}
	if (!strstr(buf, "LOTA_ATTESTED=1")) {
		FAIL("missing LOTA_ATTESTED=1");
		return;
	}
	if (!strstr(buf, "LOTA_FLAGS=0x0000000b")) {
		FAIL("wrong flags");
		return;
	}
	if (!strstr(buf, "LOTA_VALID_UNTIL=1738957200")) {
		FAIL("wrong valid_until");
		return;
	}
	if (!strstr(buf, "LOTA_ATTEST_COUNT=42")) {
		FAIL("wrong attest_count");
		return;
	}
	if (!strstr(buf, "LOTA_FAIL_COUNT=1")) {
		FAIL("wrong fail_count");
		return;
	}
	if (!strstr(buf, "LOTA_UPDATED=")) {
		FAIL("missing LOTA_UPDATED");
		return;
	}
	if (!strstr(buf, "LOTA_PID=")) {
		FAIL("missing LOTA_PID");
		return;
	}
	PASS();
}

/* a hook that has nothing new to say still rewrites LOTA_UPDATED */
static void test_status_heartbeat(void)
{
	struct lota_status status = { .flags = LOTA_FLAG_ATTESTED };
	char path[PATH_MAX], buf[1024];

	TEST("heartbeat: rewrites a status refresh_sec old, not a fresh one");

	snprintf(path, sizeof(path), "%s/status_beat", tmpdir);
	snprintf(g_hook.status_path, sizeof(g_hook.status_path), "%s", path);
	g_hook.refresh_sec = 60;
	atomic_store(&g_hook.offline_published, 0);
	hook_cache_status(&status);

	atomic_store(&g_hook.status_written, (long)time(NULL));
	hook_status_heartbeat();
	if (access(path, F_OK) == 0) {
		FAIL("a status written just now was rewritten");
		goto out;
	}

	atomic_store(&g_hook.status_written, (long)time(NULL) - 60);
	hook_status_heartbeat();
	if (read_file_contents(path, buf, sizeof(buf)) <= 0 ||
	    !strstr(buf, "LOTA_ATTESTED=1")) {
		FAIL("a status refresh_sec old was not rewritten");
		goto out;
	}
	if (time(NULL) - atomic_load(&g_hook.status_written) > 1) {
		FAIL("the rewrite did not move the write time");
		goto out;
	}
	PASS();
out:
	atomic_store(&g_hook.have_status, 0);
	unlink(path);
}

static void test_rate_limit_reason(void)
{
	const char *why = hook_token_reason(LOTA_ERR_RATE_LIMITED);

	TEST("token reason: a rate limit names its scope and the retry");

	if (!why || !strstr(why, "this user or this session") ||
	    !strstr(why, "the next refresh asks again")) {
		FAIL(why ? why : "no reason");
		return;
	}
	PASS();
}

static void test_write_status_not_attested(void)
{
	char buf[1024];
	ssize_t n;
	struct lota_status status;

	TEST("write_status: non-attested system writes LOTA_ATTESTED=0");

	snprintf(g_hook.status_path, sizeof(g_hook.status_path),
		 "%s/status_noatt", tmpdir);

	memset(&status, 0, sizeof(status));
	status.flags = LOTA_FLAG_TPM_OK;

	if (write_status(&status) != 0) {
		FAIL("write_status failed");
		return;
	}
	n = read_file_contents(g_hook.status_path, buf, sizeof(buf));
	if (n <= 0) {
		FAIL("read failed");
		return;
	}
	if (!strstr(buf, "LOTA_ATTESTED=0")) {
		FAIL("missing LOTA_ATTESTED=0");
		return;
	}
	PASS();
}

static void test_write_status_zero_flags(void)
{
	char buf[1024];
	ssize_t n;
	struct lota_status status;

	TEST("write_status: zero flags produces valid output");

	snprintf(g_hook.status_path, sizeof(g_hook.status_path),
		 "%s/status_zero", tmpdir);

	memset(&status, 0, sizeof(status));

	if (write_status(&status) != 0) {
		FAIL("write_status failed");
		return;
	}
	n = read_file_contents(g_hook.status_path, buf, sizeof(buf));
	if (n <= 0) {
		FAIL("read failed");
		return;
	}
	if (!strstr(buf, "LOTA_ATTESTED=0")) {
		FAIL("missing LOTA_ATTESTED=0");
		return;
	}
	if (!strstr(buf, "LOTA_FLAGS=0x00000000")) {
		FAIL("wrong flags");
		return;
	}
	PASS();
}

/*
 * Process-activation policy. policy_should_activate() is pure and
 * takes the exe path plus the two env-string overrides as
 * arguments so each scenario can drive the decision with synthetic
 * paths instead of round-tripping through /proc/self/exe.
 *
 * Tests pass NULL/NULL for the env overrides when they mean the
 * default FHS policy; the env-read wrapper in should_activate()
 * is trivial and is covered by the live agent runs.
 */

static void test_policy_default_skips_usr_bin(void)
{
	TEST("policy: default skips /usr/bin/* (FHS system path)");
	if (!policy_should_activate("/usr/bin/bash", NULL, NULL) &&
	    !policy_should_activate("/usr/bin/basename", NULL, NULL) &&
	    !policy_should_activate("/usr/bin/sudo", NULL, NULL) &&
	    !policy_should_activate("/usr/sbin/ldconfig", NULL, NULL) &&
	    !policy_should_activate("/usr/libexec/foo", NULL, NULL))
		PASS();
	else
		FAIL("FHS /usr path must be skipped by default");
}

static void test_policy_default_skips_legacy_bin(void)
{
	TEST("policy: default skips /bin /sbin /lib /lib64 (non-usrmerge)");
	if (!policy_should_activate("/bin/sh", NULL, NULL) &&
	    !policy_should_activate("/sbin/init", NULL, NULL) &&
	    !policy_should_activate("/lib/x86_64-linux-gnu/ld-linux.so.2", NULL,
				    NULL) &&
	    !policy_should_activate("/lib64/ld-linux-x86-64.so.2", NULL, NULL))
		PASS();
	else
		FAIL("legacy /bin /sbin /lib /lib64 must be skipped by default");
}

static void test_policy_default_skips_pressure_vessel_host(void)
{
	TEST("policy: default skips /run/host/usr/* (pressure-vessel)");
	if (!policy_should_activate("/run/host/usr/bin/basename", NULL, NULL) &&
	    !policy_should_activate("/run/host/usr/sbin/ldconfig", NULL,
				    NULL) &&
	    !policy_should_activate("/run/host/lib64/ld-linux.so.2", NULL,
				    NULL))
		PASS();
	else
		FAIL("pressure-vessel /run/host/usr path must be skipped");
}

static void test_policy_default_activates_steam_path(void)
{
	TEST("policy: default activates Steam install paths");
	if (policy_should_activate(
		    "~/.local/share/Steam/steamapps/common/"
		    "Counter-Strike Global Offensive/game/bin/linuxsteamrt64/cs2",
		    NULL, NULL) &&
	    policy_should_activate("~/.local/share/Steam/ubuntu12_32/reaper",
				   NULL, NULL))
		PASS();
	else
		FAIL("Steam-tree binaries must activate by default");
}

static void test_policy_default_activates_opt_and_home(void)
{
	TEST("policy: default activates /opt, /home, /srv (non-FHS-system)");
	if (policy_should_activate("/opt/games/cs2", NULL, NULL) &&
	    policy_should_activate("/home/user/games/foo", NULL, NULL) &&
	    policy_should_activate("/srv/games/bar", NULL, NULL))
		PASS();
	else
		FAIL("/opt /home /srv must activate by default");
}

static void test_policy_default_activates_snap_and_flatpak(void)
{
	TEST("policy: default activates /snap and Flatpak paths");
	if (policy_should_activate("/snap/cs2/current/cs2", NULL, NULL) &&
	    policy_should_activate(
		    "/var/lib/flatpak/app/com.valvesoftware.Steam/current/cs2",
		    NULL, NULL))
		PASS();
	else
		FAIL("Snap and Flatpak operator-installed paths must activate");
}

static void test_policy_empty_exe_defaults_to_activate(void)
{
	TEST("policy: empty exe falls back to activate (read_self_exe failure)");
	if (policy_should_activate("", NULL, NULL) &&
	    policy_should_activate(NULL, NULL, NULL))
		PASS();
	else
		FAIL("empty/NULL exe must fall back to activate");
}

static void test_policy_handles_deleted_suffix(void)
{
	TEST("policy: handles '(deleted)' suffix on /proc/self/exe");
	/* unlinked binary in /usr/ -> still matches /usr/ prefix -> skip */
	if (!policy_should_activate("/usr/bin/cat (deleted)", NULL, NULL) &&
	    /* unlinked binary outside /usr/ -> still activates */
	    policy_should_activate("~/Steam/cs2 (deleted)", NULL, NULL))
		PASS();
	else
		FAIL("(deleted) suffix must not change prefix match outcome");
}

static void test_policy_activate_pin_is_positive(void)
{
	TEST("policy: LOTA_HOOK_ACTIVATE_PATH is a positive pin");
	const char *allow = "~/.local/share/Steam,/opt/games";
	if (policy_should_activate(
		    "~/.local/share/Steam/steamapps/common/cs2/cs2", allow,
		    NULL) &&
	    policy_should_activate("/opt/games/foo", allow, NULL) &&
	    !policy_should_activate("/usr/bin/bash", allow, NULL) &&
	    !policy_should_activate("/tmp/random/binary", allow, NULL) &&
	    !policy_should_activate("~/other/path", allow, NULL))
		PASS();
	else
		FAIL("ACTIVATE_PATH must be exclusive whitelist");
}

static void test_policy_activate_pin_overrides_fhs_skip(void)
{
	TEST("policy: ACTIVATE_PATH overrides FHS skip default");
	/*
	 * A deliberately weird configuration: pin to /usr/local/games.
	 * The default FHS rule would skip any path under /usr/local/games;
	 * the explicit pin must win because the operator has spoken.
	 */
	const char *allow = "/usr/local/games/";
	if (policy_should_activate("/usr/local/games/foo", allow, NULL) &&
	    !policy_should_activate("/usr/bin/bash", allow, NULL))
		PASS();
	else
		FAIL("ACTIVATE_PATH must override the FHS default");
}

static void test_policy_skip_extends_default(void)
{
	TEST("policy: LOTA_HOOK_SKIP_PATH extends the FHS skip list");
	const char *skip = "/nix/store/,/run/current-system/";
	if (!policy_should_activate("/nix/store/abcdef/bin/bash", NULL, skip) &&
	    !policy_should_activate("/run/current-system/sw/bin/foo", NULL,
				    skip) &&
	    /* FHS default still applies */
	    !policy_should_activate("/usr/bin/cat", NULL, skip) &&
	    /* paths outside both skip lists activate */
	    policy_should_activate("~/Steam/cs2", NULL, skip))
		PASS();
	else
		FAIL("SKIP_PATH must extend FHS without replacing it");
}

static void test_policy_activate_pin_ignores_skip(void)
{
	TEST("policy: ACTIVATE_PATH set short-circuits SKIP_PATH");
	const char *allow = "~/Steam/";
	const char *skip = "~/Steam/";
	/* ACTIVATE_PATH is evaluated first; SKIP_PATH never consulted */
	if (policy_should_activate("~/Steam/cs2", allow, skip) &&
	    !policy_should_activate("/usr/bin/cat", allow, skip))
		PASS();
	else
		FAIL("ACTIVATE_PATH must take precedence over SKIP_PATH");
}

static void test_policy_empty_env_strings_ignored(void)
{
	TEST("policy: empty env strings behave as unset");
	if (!policy_should_activate("/usr/bin/cat", "", "") &&
	    policy_should_activate("~/Steam/cs2", "", "") &&
	    /* whitespace-only entries inside lists are ignored */
	    !policy_should_activate("/usr/bin/cat", NULL, "   ,, ") &&
	    policy_should_activate("~/Steam/cs2", "", NULL))
		PASS();
	else
		FAIL("empty env strings must not flip the decision");
}

static void test_policy_prefix_must_match_at_start(void)
{
	TEST("policy: prefix match anchors at the start of the path");
	/* "/usrlocal/..." must not match "/usr/" (no trailing slash boundary)
	 */
	if (policy_should_activate("/usrlocal/bin/foo", NULL, NULL) &&
	    /* "/home/usr/x" must not be skipped just because "usr" appears */
	    policy_should_activate("/home/usr/x", NULL, NULL) &&
	    /* "/usr/" exact prefix still skips */
	    !policy_should_activate("/usr/bin/cat", NULL, NULL))
		PASS();
	else
		FAIL("prefix match must anchor at index 0");
}

static void test_policy_whitespace_tolerant(void)
{
	TEST("policy: comma list tolerates whitespace around entries");
	const char *allow = " /opt/games ,  /home/games/ ,/srv/games/";
	if (policy_should_activate("/opt/games/foo", allow, NULL) &&
	    policy_should_activate("/home/games/bar", allow, NULL) &&
	    policy_should_activate("/srv/games/baz", allow, NULL) &&
	    !policy_should_activate("/usr/bin/cat", allow, NULL))
		PASS();
	else
		FAIL("path_has_prefix_in must strip leading/trailing "
		     "whitespace");
}

/*
 * Every process of a Wine prefix runs the same pinned loader, so a Wine
 * process is decided by its Windows program (argv[1]) against the title's
 * directory.
 *
 * Made-up library; only Wine's loader and system32 names are real.
 */
#define TEST_LIBRARY "/srv/library"
#define TEST_TOOL TEST_LIBRARY "/steamapps/common/Compat Tool"
#define TEST_TITLE TEST_LIBRARY "/steamapps/common/A Title"
#define TEST_WINE TEST_TOOL "/files/lib/wine/"
#define TEST_TITLE_DIR "steamapps/common/A Title/"
#define TEST_PIN TEST_TITLE "/," TEST_TOOL "/"

static void test_policy_wine_title_is_attested(void)
{
	TEST("policy: the Windows title under Wine's loader is attested");
	if (policy_should_activate_process(
		    TEST_WINE "i386-unix/wine-preloader",
		    "D:\\steamapps\\common\\A Title\\title.exe", TEST_TITLE_DIR,
		    TEST_PIN, NULL))
		PASS();
	else
		FAIL("the title's program must activate the hook");
}

static void test_policy_wine_prefix_processes_are_skipped(void)
{
	TEST("policy: the prefix Wine starts beside the title is not");
	const char *loader = TEST_WINE "i386-unix/wine64-preloader";
	if (!policy_should_activate_process(
		    loader, "C:\\windows\\system32\\services.exe",
		    TEST_TITLE_DIR, TEST_PIN, NULL) &&
	    !policy_should_activate_process(
		    loader, "C:\\windows\\system32\\explorer.exe",
		    TEST_TITLE_DIR, TEST_PIN, NULL) &&
	    !policy_should_activate_process(
		    loader,
		    "\\\\?\\D:\\steamapps\\common\\Compat Tool\\files\\"
		    "share\\wine/../../helper/helper.exe",
		    TEST_TITLE_DIR, TEST_PIN, NULL) &&
	    !policy_should_activate_process(
		    TEST_WINE "x86_64-unix/wine-preloader",
		    "c:\\windows\\system32\\launcher.exe", TEST_TITLE_DIR,
		    TEST_PIN, NULL))
		PASS();
	else
		FAIL("a prefix service must not be attested for the title");
}

static void test_policy_wine_title_any_drive_any_case(void)
{
	TEST("policy: the title is found through any drive, in any case");
	if (policy_should_activate_process(
		    TEST_WINE "x86_64-unix/wine",
		    "Z:\\SRV\\library\\STEAMAPPS\\common\\a title\\bin\\"
		    "title.exe",
		    TEST_TITLE_DIR, TEST_PIN, NULL) &&
	    policy_should_activate_process(
		    TEST_WINE "x86_64-unix/wine64",
		    "d:/steamapps/common/A Title/title.exe", TEST_TITLE_DIR,
		    TEST_PIN, NULL))
		PASS();
	else
		FAIL("drive letter, separator and case must not matter");
}

static void test_policy_wine_title_matches_whole_components(void)
{
	TEST("policy: the title directory matches whole components");
	const char *loader = TEST_WINE "i386-unix/wine-preloader";
	if (!policy_should_activate_process(
		    loader, "D:\\steamapps\\common\\A Title II\\title.exe",
		    TEST_TITLE_DIR, TEST_PIN, NULL) &&
	    !policy_should_activate_process(
		    loader, "D:\\oldsteamapps\\common\\A Title\\title.exe",
		    TEST_TITLE_DIR, TEST_PIN, NULL) &&
	    !policy_should_activate_process(loader,
					    "D:\\steamapps\\common\\A Title",
					    TEST_TITLE_DIR, TEST_PIN, NULL))
		PASS();
	else
		FAIL("a neighbour whose name only starts the same matched");
}

static void test_policy_wine_loader_without_program_is_skipped(void)
{
	TEST("policy: Wine's loader with no program is not the title");
	const char *loader = TEST_WINE "i386-unix/wine-preloader";
	if (!policy_should_activate_process(loader, NULL, TEST_TITLE_DIR,
					    TEST_PIN, NULL) &&
	    !policy_should_activate_process(loader, "", TEST_TITLE_DIR,
					    TEST_PIN, NULL) &&
	    policy_should_activate_process(
		    TEST_WINE "i386-unix/wine-preloader (deleted)",
		    "D:\\steamapps\\common\\A Title\\title.exe", TEST_TITLE_DIR,
		    TEST_PIN, NULL))
		PASS();
	else
		FAIL("a loader hosting nothing must not be attested");
}

static void test_policy_program_leaves_native_processes_alone(void)
{
	TEST("policy: a native process is still decided by its path");
	if (policy_should_activate_process(TEST_TITLE "/title", NULL,
					   TEST_TITLE_DIR, TEST_PIN, NULL) &&
	    !policy_should_activate_process(
		    TEST_LIBRARY "/client/helper",
		    "D:\\steamapps\\common\\A Title\\title.exe", TEST_TITLE_DIR,
		    TEST_PIN, NULL) &&
	    !policy_should_activate_process("/usr/bin/python3",
					    TEST_TOOL "/launch", TEST_TITLE_DIR,
					    TEST_PIN, NULL) &&
	    policy_should_activate_process(TEST_TOOL "/files/bin/wineserver",
					   NULL, TEST_TITLE_DIR, TEST_PIN,
					   NULL))
		PASS();
	else
		FAIL("the program rule must answer for Wine's loader only");
}

static void test_policy_wine_without_title_dir_uses_the_pin(void)
{
	TEST("policy: with no title directory Wine's loader uses the pin");
	const char *loader = TEST_WINE "i386-unix/wine-preloader";
	if (policy_should_activate_process(
		    loader, "C:\\windows\\system32\\explorer.exe", NULL,
		    TEST_PIN, NULL) &&
	    policy_should_activate_process(
		    loader, "C:\\windows\\system32\\explorer.exe", "", TEST_PIN,
		    NULL) &&
	    !policy_should_activate_process(loader, "C:\\game.exe", NULL,
					    "/opt/games/", NULL))
		PASS();
	else
		FAIL("an unset title directory must leave the pin in charge");
}

static void test_write_status_marks_online_branch(void)
{
	char buf[1024];
	ssize_t n;
	struct lota_status status;

	TEST("write_status: live branch stamps LOTA_OFFLINE=0");

	snprintf(g_hook.status_path, sizeof(g_hook.status_path),
		 "%s/status_live_marker", tmpdir);

	memset(&status, 0, sizeof(status));
	status.flags = LOTA_FLAG_ATTESTED | LOTA_FLAG_TPM_OK;
	if (write_status(&status) != 0) {
		FAIL("write_status failed");
		return;
	}
	n = read_file_contents(g_hook.status_path, buf, sizeof(buf));
	if (n <= 0) {
		FAIL("read failed");
		return;
	}
	if (!strstr(buf, "LOTA_OFFLINE=0")) {
		FAIL("missing LOTA_OFFLINE=0");
		return;
	}
	if (!strstr(buf, "LOTA_ATTESTED=1")) {
		FAIL("missing LOTA_ATTESTED=1");
		return;
	}
	PASS();
}

static void test_write_status_payload_offline_marker(void)
{
	char buf[1024];
	ssize_t n;
	struct lota_status zero;

	TEST("write_status_payload(offline=1) stamps LOTA_OFFLINE=1");

	snprintf(g_hook.status_path, sizeof(g_hook.status_path),
		 "%s/status_offline_marker", tmpdir);

	memset(&zero, 0, sizeof(zero));
	if (write_status_payload(&zero, 1) != 0) {
		FAIL("write_status_payload failed");
		return;
	}
	n = read_file_contents(g_hook.status_path, buf, sizeof(buf));
	if (n <= 0) {
		FAIL("read failed");
		return;
	}
	if (!strstr(buf, "LOTA_OFFLINE=1")) {
		FAIL("missing LOTA_OFFLINE=1");
		return;
	}
	if (!strstr(buf, "LOTA_ATTESTED=0")) {
		FAIL("attested flag leaked into offline payload");
		return;
	}
	PASS();
}

/*
 * The disconnect episode. A lost agent reaches the sink through
 * hook_offline_publish(): the status file states OFFLINE, the token
 * and the snapshot go away, and a second refusal inside the same episode
 * rewrites nothing. hook_offline_clear() ends the episode, which is what
 * a reconnect does.
 */

static int touch_file(const char *path, const char *body)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);

	if (fd < 0)
		return -errno;
	if (write(fd, body, strlen(body)) < 0) {
		close(fd);
		return -errno;
	}
	close(fd);
	return 0;
}

static char offline_status[sizeof(g_hook.status_path)];
static char offline_token[sizeof(g_hook.token_path)];
static char offline_snapshot[sizeof(g_hook.snapshot_path)];

static void offline_paths(const char *tag)
{
	snprintf(offline_status, sizeof(offline_status), "%s/status_%s", tmpdir,
		 tag);
	snprintf(offline_token, sizeof(offline_token), "%s/token_%s", tmpdir,
		 tag);
	snprintf(offline_snapshot, sizeof(offline_snapshot), "%s/snap_%s",
		 tmpdir, tag);

	memcpy(g_hook.status_path, offline_status, sizeof(offline_status));
	memcpy(g_hook.token_path, offline_token, sizeof(offline_token));
	memcpy(g_hook.snapshot_path, offline_snapshot,
	       sizeof(offline_snapshot));
}

static void test_offline_publish_replaces_the_last_good_status(void)
{
	char buf[1024];
	struct lota_status status;

	TEST("offline publish: a lost agent clears the attested sink");

	offline_paths("lost");
	hook_offline_clear();

	memset(&status, 0, sizeof(status));
	status.flags = LOTA_FLAG_ATTESTED | LOTA_FLAG_TPM_OK;
	if (write_status(&status) != 0 ||
	    touch_file(offline_token, "token") != 0 ||
	    touch_file(offline_snapshot, "snap") != 0) {
		FAIL("setup failed");
		return;
	}

	hook_offline_publish(false);

	if (read_file_contents(offline_status, buf, sizeof(buf)) <= 0) {
		FAIL("read failed");
		return;
	}
	if (!strstr(buf, "LOTA_OFFLINE=1")) {
		FAIL("status still reports the agent as reachable");
		return;
	}
	if (!strstr(buf, "LOTA_ATTESTED=0")) {
		FAIL("attested verdict outlived the agent");
		return;
	}
	if (access(offline_token, F_OK) == 0) {
		FAIL("token survived the disconnect");
		return;
	}
	if (access(offline_snapshot, F_OK) == 0) {
		FAIL("snapshot survived the disconnect");
		return;
	}
	PASS();
}

static void test_offline_publish_writes_once_per_episode(void)
{
	TEST("offline publish: a second refusal rewrites nothing");

	offline_paths("repeat");
	hook_offline_clear();

	hook_offline_publish(false);
	if (touch_file(offline_token, "token") != 0) {
		FAIL("setup failed");
		return;
	}

	hook_offline_publish(false);

	if (access(offline_token, F_OK) != 0) {
		FAIL("the same episode published twice");
		return;
	}
	PASS();
}

static void test_offline_clear_arms_the_next_disconnect(void)
{
	TEST("offline publish: a reconnect arms the next disconnect");

	offline_paths("rearm");
	hook_offline_clear();

	hook_offline_publish(false);
	if (touch_file(offline_token, "token") != 0) {
		FAIL("setup failed");
		return;
	}

	/* what a successful connect does */
	hook_offline_clear();
	hook_offline_publish(false);

	if (access(offline_token, F_OK) == 0) {
		FAIL("the second disconnect never reached the sink");
		return;
	}
	PASS();
}

/* a refusal or a registration between agents must not revive the cache */
static void test_a_republish_while_offline_stays_offline(void)
{
	struct lota_status status;
	char buf[1024];

	TEST("offline publish: a republish keeps the agent lost");

	offline_paths("republish");
	hook_offline_clear();

	memset(&status, 0, sizeof(status));
	status.flags = LOTA_FLAG_ATTESTED;
	status.valid_until = 1;
	hook_cache_status(&status);
	hook_offline_publish(false);
	hook_publish_state();
	hook_offline_clear();
	atomic_store(&g_hook.have_status, 0);

	if (read_file_contents(offline_status, buf, sizeof(buf)) <= 0) {
		FAIL("read failed");
		return;
	}
	if (!strstr(buf, "LOTA_OFFLINE=1")) {
		FAIL("the republish reports the agent as reachable");
		return;
	}
	if (!strstr(buf, "LOTA_ATTESTED=0")) {
		FAIL("the republish restored the cached verdict");
		return;
	}
	PASS();
}

/* a publisher refusal is the agent saying no, not an agent gone */
static void test_a_publisher_refusal_is_not_offline(void)
{
	char buf[1024];

	TEST("offline publish: a publisher refusal is no lost agent");

	offline_paths("refused");
	hook_offline_clear();

	if (touch_file(offline_token, "token") != 0) {
		FAIL("setup failed");
		return;
	}
	hook_offline_publish(true);
	hook_publish_state();
	if (read_file_contents(offline_status, buf, sizeof(buf)) <= 0) {
		FAIL("read failed");
		return;
	}
	if (!strstr(buf, "LOTA_OFFLINE=0") || !strstr(buf, "LOTA_ATTESTED=0")) {
		FAIL("the refusal was published as a lost agent");
		return;
	}
	if (access(offline_token, F_OK) == 0) {
		FAIL("the token survived the refusal");
		return;
	}

	hook_offline_publish(false);
	hook_offline_clear();
	if (read_file_contents(offline_status, buf, sizeof(buf)) <= 0 ||
	    !strstr(buf, "LOTA_OFFLINE=1")) {
		FAIL("an agent lost after the refusal stayed reachable");
		return;
	}
	PASS();
}

/* lota_poll_events() returns a count; only below zero is a failure */
static void test_a_quiet_wait_is_not_a_failure(void)
{
	TEST("a poll that delivered nothing is not a failure");

	if (hook_poll_failed(0)) {
		FAIL("zero events read as a failure");
		return;
	}
	PASS();
}

static void test_a_delivered_event_is_not_a_failure(void)
{
	TEST("a poll that delivered events is not a failure");

	if (hook_poll_failed(1) || hook_poll_failed(7)) {
		FAIL("a delivered event read as a failure");
		return;
	}
	PASS();
}

static void test_a_refusal_is_a_failure(void)
{
	TEST("a refused poll is a failure");

	if (!hook_poll_failed(LOTA_ERR_PROTOCOL) ||
	    !hook_poll_failed(LOTA_ERR_NOT_CONNECTED)) {
		FAIL("a refusal read as success");
		return;
	}
	PASS();
}

static void test_hook_active_when_not_started(void)
{
	TEST("lota_hook_active() returns 0 when not initialized");

	g_hook.thread_started = 0;
	g_hook.running = 0;

	if (lota_hook_active() != 0) {
		FAIL("expected 0");
		return;
	}
	PASS();
}

static void test_hook_status_path_when_set(void)
{
	TEST("lota_hook_status_path() returns path when set");

	snprintf(g_hook.status_path, sizeof(g_hook.status_path),
		 "/run/user/1000/lota-hook/lota-status");

	const char *p = lota_hook_status_path();
	if (!p || strcmp(p, "/run/user/1000/lota-hook/lota-status") != 0) {
		FAIL("wrong path");
		return;
	}
	PASS();
}

static void test_hook_status_path_when_empty(void)
{
	TEST("lota_hook_status_path() returns NULL when empty");

	g_hook.status_path[0] = '\0';

	if (lota_hook_status_path() != NULL) {
		FAIL("expected NULL");
		return;
	}
	PASS();
}

static void test_hook_token_path_when_set(void)
{
	TEST("lota_hook_token_path() returns path when set");

	snprintf(g_hook.token_path, sizeof(g_hook.token_path),
		 "/run/user/1000/lota-hook/lota-token.bin");

	const char *p = lota_hook_token_path();
	if (!p || strcmp(p, "/run/user/1000/lota-hook/lota-token.bin") != 0) {
		FAIL("wrong path");
		return;
	}
	PASS();
}

static void test_hook_token_path_when_empty(void)
{
	TEST("lota_hook_token_path() returns NULL when empty");

	g_hook.token_path[0] = '\0';

	if (lota_hook_token_path() != NULL) {
		FAIL("expected NULL");
		return;
	}
	PASS();
}

/* mock agent: a child answers the SDK and logs each command id it gets */
static char mock_socket[104];
static char mock_cmdlog[PATH_MAX];
static int mock_agent_errno;
static uint32_t mock_protect_result = LOTA_IPC_OK;
/* GET_REFUSAL answers this object, "" for none; stale dates it at boot */
static char mock_refusal_object[256];
static int mock_refusal_stale;

static int mock_errno_is_sandbox(int err)
{
	return err == EPERM || err == EACCES || err == EROFS;
}

static int mock_send_response(int fd, uint32_t result, const void *payload,
			      uint32_t payload_len)
{
	struct lota_ipc_response resp;

	resp.magic = LOTA_IPC_MAGIC;
	resp.version = LOTA_IPC_VERSION;
	resp.result = result;
	resp.payload_len = payload_len;

	if (send(fd, &resp, sizeof(resp), MSG_NOSIGNAL) != sizeof(resp))
		return -1;

	if (payload_len > 0 && payload) {
		if (send(fd, payload, payload_len, MSG_NOSIGNAL) !=
		    (ssize_t)payload_len)
			return -1;
	}

	return 0;
}

static int mock_recv_request(int fd, struct lota_ipc_request *req,
			     void *payload, size_t max_payload)
{
	ssize_t n;

	n = recv(fd, req, sizeof(*req), MSG_WAITALL);
	if (n != sizeof(*req))
		return -1;

	if (req->payload_len > 0) {
		size_t want = req->payload_len;

		if (want > max_payload)
			want = max_payload;
		n = recv(fd, payload, want, MSG_WAITALL);
		if (n != (ssize_t)want)
			return -1;
	}

	return 0;
}

/* Serve one client until it hangs up, recording each command id. */
static void mock_agent_serve(int client_fd)
{
	struct lota_ipc_request req;
	uint8_t payload[256];
	FILE *log;
	int fd;

	fd = open(mock_cmdlog, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
	if (fd < 0)
		_exit(90);
	log = fdopen(fd, "a");
	if (!log)
		_exit(90);

	while (mock_recv_request(client_fd, &req, payload, sizeof(payload)) ==
	       0) {
		fprintf(log, "%u\n", req.cmd);
		fflush(log);

		if (req.cmd == LOTA_IPC_CMD_GET_STATUS) {
			struct lota_ipc_status status;

			memset(&status, 0, sizeof(status));
			if (mock_send_response(client_fd, LOTA_IPC_OK, &status,
					       sizeof(status)) < 0)
				break;
			continue;
		}

		if (req.cmd == LOTA_IPC_CMD_PROTECT_PID) {
			if (mock_send_response(client_fd, mock_protect_result,
					       NULL, 0) < 0)
				break;
			continue;
		}

		if (req.cmd == LOTA_IPC_CMD_GET_REFUSAL) {
			struct lota_ipc_refusal r;

			memset(&r, 0, sizeof(r));
			if (mock_refusal_object[0]) {
				r.at_ns = mock_refusal_stale ? 1 :
							       hook_now_ns();
				snprintf(r.object, sizeof(r.object), "%s",
					 mock_refusal_object);
			}
			if (mock_send_response(client_fd, LOTA_IPC_OK, &r,
					       sizeof(r)) < 0)
				break;
			continue;
		}

		if (mock_send_response(client_fd, LOTA_IPC_OK, NULL, 0) < 0)
			break;
	}

	fclose(log);
}

static pid_t start_mock_agent(void)
{
	struct sockaddr_un addr;
	int listen_fd;
	pid_t pid;

	mock_agent_errno = 0;
	snprintf(mock_socket, sizeof(mock_socket), "%s/agent.sock", tmpdir);
	snprintf(mock_cmdlog, sizeof(mock_cmdlog), "%s/agent.cmds", tmpdir);
	unlink(mock_socket);
	unlink(mock_cmdlog);

	listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (listen_fd < 0) {
		mock_agent_errno = errno;
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, mock_socket, sizeof(addr.sun_path) - 1);

	if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		mock_agent_errno = errno;
		close(listen_fd);
		return -1;
	}

	if (listen(listen_fd, 4) < 0) {
		mock_agent_errno = errno;
		close(listen_fd);
		unlink(mock_socket);
		return -1;
	}

	pid = fork();
	if (pid < 0) {
		mock_agent_errno = errno;
		close(listen_fd);
		unlink(mock_socket);
		return -1;
	}

	if (pid == 0) {
		/* child: serve clients until the parent kills us */
		for (;;) {
			int client_fd = accept(listen_fd, NULL, NULL);

			if (client_fd < 0)
				_exit(99);
			mock_agent_serve(client_fd);
			close(client_fd);
		}
	}

	close(listen_fd);
	usleep(30000); /* let the child reach accept() */
	return pid;
}

static void stop_mock_agent(pid_t pid)
{
	int status;

	kill(pid, SIGKILL);
	waitpid(pid, &status, 0);
	unlink(mock_socket);
}

/* How many times @cmd appears in the mock agent's command log. */
static int mock_cmd_count(uint32_t cmd)
{
	char line[32];
	FILE *log;
	int count = 0;

	log = fopen(mock_cmdlog, "r");
	if (!log)
		return -1;

	while (fgets(line, sizeof(line), log)) {
		if ((uint32_t)strtoul(line, NULL, 10) == cmd)
			count++;
	}

	fclose(log);
	return count;
}

/* Point the hook's files and socket at the test directory. */
static void hook_state_for_mock_agent(const char *tag)
{
	snprintf(g_hook.socket_path, sizeof(g_hook.socket_path), "%s",
		 mock_socket);
	snprintf(g_hook.token_dir, sizeof(g_hook.token_dir), "%s", tmpdir);
	snprintf(g_hook.status_path, sizeof(g_hook.status_path), "%s/%s.status",
		 tmpdir, tag);
	snprintf(g_hook.token_path, sizeof(g_hook.token_path), "%s/%s.token",
		 tmpdir, tag);
	snprintf(g_hook.snapshot_path, sizeof(g_hook.snapshot_path),
		 "%s/%s.snapshot", tmpdir, tag);
	g_hook.refresh_sec = 1;
	atomic_store(&g_hook.self_protected, 0);
	atomic_store(&g_hook.offline_published, 0);
}

/*
 * The refresh thread connects before calling refresh_once(),
 * so registering only on its NULL-client branch never runs.
 */
static void test_the_launch_path_registers_the_title(void)
{
	pid_t agent;
	int count;

	TEST("the launch path registers the title it hooks");

	agent = start_mock_agent();
	if (agent < 0) {
		if (mock_errno_is_sandbox(mock_agent_errno)) {
			SKIP("no unix socket in this sandbox");
			return;
		}
		FAIL("mock agent did not start");
		return;
	}

	hook_state_for_mock_agent("launch");

	/* exactly what refresh_thread_fn() does when it comes up */
	g_hook.client = hook_connect();
	if (!g_hook.client) {
		stop_mock_agent(agent);
		FAIL("hook did not connect to the mock agent");
		return;
	}
	refresh_once();

	lota_disconnect(g_hook.client);
	g_hook.client = NULL;
	stop_mock_agent(agent);

	count = mock_cmd_count(LOTA_IPC_CMD_PROTECT_PID);
	if (count < 0) {
		FAIL("no command log from the mock agent");
		return;
	}
	if (count == 0) {
		FAIL("PROTECT_PID never sent, the title is not protected");
		return;
	}

	PASS();
}

/* The latch holds: a later refresh does not re-register the process. */
static void test_the_registration_is_not_repeated(void)
{
	pid_t agent;
	int count;

	TEST("a later refresh does not register twice");

	agent = start_mock_agent();
	if (agent < 0) {
		if (mock_errno_is_sandbox(mock_agent_errno)) {
			SKIP("no unix socket in this sandbox");
			return;
		}
		FAIL("mock agent did not start");
		return;
	}

	hook_state_for_mock_agent("repeat");

	g_hook.client = hook_connect();
	if (!g_hook.client) {
		stop_mock_agent(agent);
		FAIL("hook did not connect to the mock agent");
		return;
	}
	refresh_once();
	refresh_once();

	/* a reconnect takes the other branch and must not re-register */
	lota_disconnect(g_hook.client);
	g_hook.client = NULL;
	refresh_once();

	if (g_hook.client) {
		lota_disconnect(g_hook.client);
		g_hook.client = NULL;
	}
	stop_mock_agent(agent);

	count = mock_cmd_count(LOTA_IPC_CMD_PROTECT_PID);
	if (count < 0) {
		FAIL("no command log from the mock agent");
		return;
	}
	if (count == 0) {
		FAIL("PROTECT_PID never sent, the title is not protected");
		return;
	}
	if (count > 1) {
		FAIL("registration repeated after the first success");
		return;
	}

	PASS();
}

/* lota-protect protects from exec, so nothing is left to wait for. */
static void test_the_first_refresh_registers(void)
{
	pid_t agent;
	int count;

	TEST("the first refresh registers the title");

	agent = start_mock_agent();
	if (agent < 0) {
		if (mock_errno_is_sandbox(mock_agent_errno)) {
			SKIP("no unix socket in this sandbox");
			return;
		}
		FAIL("mock agent did not start");
		return;
	}

	hook_state_for_mock_agent("first_refresh");

	g_hook.client = hook_connect();
	if (!g_hook.client) {
		stop_mock_agent(agent);
		FAIL("hook did not connect to the mock agent");
		return;
	}
	refresh_once();
	refresh_once();

	lota_disconnect(g_hook.client);
	g_hook.client = NULL;
	stop_mock_agent(agent);

	count = mock_cmd_count(LOTA_IPC_CMD_PROTECT_PID);
	if (count != 1) {
		FAIL("the title is not registered exactly once");
		return;
	}

	PASS();
}

/* The player's file sink says it happened, not only the agent journal. */
static void test_the_status_file_names_the_refused_object(void)
{
	struct lota_status status;
	char path[PATH_MAX];
	char buf[1024];
	ssize_t n;

	TEST("the status file names the object the gate refused");

	snprintf(path, sizeof(path), "%s/status_refused", tmpdir);
	snprintf(g_hook.status_path, sizeof(g_hook.status_path), "%s", path);
	atomic_store(&g_hook.self_protected, 1);
	hook_record_refusal("/opt/game/lib/libcodec.so");

	memset(&status, 0, sizeof(status));
	status.flags = LOTA_FLAG_ATTESTED;
	if (write_status(&status) != 0) {
		FAIL("write_status failed");
		return;
	}

	n = read_file_contents(path, buf, sizeof(buf));
	if (n <= 0) {
		FAIL("read failed");
		return;
	}
	if (!strstr(buf, "LOTA_PROTECTED=1")) {
		FAIL("the sink does not say the title is in the protected set");
		return;
	}
	if (!strstr(buf, "LOTA_REFUSED_OBJECT=/opt/game/lib/libcodec.so")) {
		FAIL("the sink does not name the refused object");
		return;
	}
	if (!strstr(buf, "LOTA_REFUSED_AT=")) {
		FAIL("the sink does not say when it happened");
		return;
	}

	atomic_store(&g_hook.self_protected, 0);
	g_refusal->object[0] = '\0';
	PASS();
}

/* A forked child's refusal survives the parent's next status write. */
static void test_a_child_refusal_reaches_the_parent_status(void)
{
	struct lota_status status;
	char path[PATH_MAX];
	char buf[1024];
	int wstatus;
	pid_t pid;
	ssize_t n;

	TEST("a forked child's refusal reaches the parent's status file");

	snprintf(path, sizeof(path), "%s/status_child_refused", tmpdir);
	snprintf(g_hook.status_path, sizeof(g_hook.status_path), "%s", path);
	hook_share_refusal();

	pid = fork();
	if (pid < 0) {
		FAIL("fork failed");
		return;
	}
	if (pid == 0) {
		hook_record_refusal("/opt/game/lib/libchild.so");
		_exit(0);
	}
	if (waitpid(pid, &wstatus, 0) != pid || !WIFEXITED(wstatus)) {
		FAIL("the child did not exit");
		return;
	}

	memset(&status, 0, sizeof(status));
	status.flags = LOTA_FLAG_ATTESTED;
	if (write_status(&status) != 0) {
		FAIL("write_status failed");
		return;
	}
	n = read_file_contents(path, buf, sizeof(buf));
	g_refusal->object[0] = '\0';
	if (n <= 0) {
		FAIL("read failed");
		return;
	}
	if (!strstr(buf, "LOTA_REFUSED_OBJECT=/opt/game/lib/libchild.so")) {
		FAIL("the parent's status dropped the child's refusal");
		return;
	}

	PASS();
}

#define TORN_WRITERS 4
#define TORN_ROUNDS 20000

/* one path per writer, each a long run of the writer's own letter */
static void torn_path(char *buf, size_t len, int writer)
{
	size_t off = (size_t)snprintf(buf, len, "/opt/game/lib/");

	memset(buf + off, 'a' + writer, len - off - 1);
	buf[len - 1] = '\0';
}

static void *torn_writer(void *arg)
{
	char path[200];

	torn_path(path, sizeof(path), (int)(long)arg);
	for (int i = 0; i < TORN_ROUNDS; i++)
		hook_record_refusal(path);
	return NULL;
}

/* Threads and forked children record at once; the status names one whole. */
static void test_a_concurrent_refusal_is_never_torn(void)
{
	struct lota_status status = { .flags = LOTA_FLAG_ATTESTED };
	char paths[TORN_WRITERS][200];
	pthread_t threads[2];
	pid_t children[2];
	char path[PATH_MAX];
	char buf[1024];
	int torn = 0;
	int seen = 0;

	TEST("a refusal recorded concurrently reaches the status whole");

	snprintf(path, sizeof(path), "%s/status_torn", tmpdir);
	snprintf(g_hook.status_path, sizeof(g_hook.status_path), "%s", path);
	hook_share_refusal();
	for (int w = 0; w < TORN_WRITERS; w++)
		torn_path(paths[w], sizeof(paths[w]), w);

	for (int c = 0; c < 2; c++) {
		children[c] = fork();
		if (children[c] == 0) {
			torn_writer((void *)(long)(2 + c));
			_exit(0);
		}
	}
	for (int t = 0; t < 2; t++)
		pthread_create(&threads[t], NULL, torn_writer, (void *)(long)t);

	for (int i = 0; i < 2000; i++) {
		char *line;
		char *end;
		int whole = 0;

		if (write_status(&status) != 0 ||
		    read_file_contents(path, buf, sizeof(buf)) <= 0)
			continue;
		line = strstr(buf, "LOTA_REFUSED_OBJECT=");
		if (!line)
			continue;
		line += strlen("LOTA_REFUSED_OBJECT=");
		end = strchr(line, '\n');
		if (end)
			*end = '\0';
		seen++;
		for (int w = 0; w < TORN_WRITERS; w++)
			whole |= strcmp(line, paths[w]) == 0;
		torn += !whole;
	}

	for (int t = 0; t < 2; t++)
		pthread_join(threads[t], NULL);
	for (int c = 0; c < 2; c++)
		waitpid(children[c], NULL, 0);
	g_refusal->object[0] = '\0';

	if (!seen) {
		FAIL("no status named a refusal");
		return;
	}
	if (torn) {
		printf("    %d of %d names torn\n", torn, seen);
		FAIL("the status named a torn refusal");
		return;
	}
	PASS();
}

/* A child dead inside the lock leaves no half name and no stuck lock. */
static void test_a_child_dead_in_the_lock_frees_it(void)
{
	pid_t pid;

	TEST("a child that died holding the refusal lock does not stop it");

	hook_share_refusal();
	pid = fork();
	if (pid == 0) {
		pthread_mutex_lock(&g_refusal->lock);
		snprintf(g_refusal->object, sizeof(g_refusal->object),
			 "/opt/ga");
		_exit(0);
	}
	waitpid(pid, NULL, 0);

	if (hook_refusal_lock() != 0) {
		FAIL("the lock stayed dead");
		return;
	}
	if (g_refusal->object[0]) {
		pthread_mutex_unlock(&g_refusal->lock);
		FAIL("the half written name was kept");
		return;
	}
	pthread_mutex_unlock(&g_refusal->lock);

	hook_record_refusal("/opt/game/lib/libnext.so");
	if (strcmp(g_refusal->object, "/opt/game/lib/libnext.so") != 0) {
		FAIL("the next refusal was not recorded");
		return;
	}
	g_refusal->object[0] = '\0';
	PASS();
}

/* Nothing the hook does to explain a refusal may change what loads. */
static void test_the_loader_wrapper_hands_back_what_it_got(void)
{
	const char *missing = "/nonexistent/lota-no-such-object.so";
	void *handle;
	pid_t agent;

	TEST("the dlopen wrapper hands back what the loader returned");

	mock_refusal_object[0] = '\0';
	mock_refusal_stale = 0;
	agent = start_mock_agent();
	if (agent < 0) {
		if (mock_errno_is_sandbox(mock_agent_errno)) {
			SKIP("no unix socket in this sandbox");
			return;
		}
		FAIL("mock agent did not start");
		return;
	}
	hook_state_for_mock_agent("wrapper");
	g_hook.log_level = HOOK_LOG_SILENT;
	atomic_store(&g_hook.self_protected, 1);
	g_refusal->object[0] = '\0';

	handle = dlopen("libm.so.6", RTLD_NOW);
	if (handle) {
		dlclose(handle);
		if (g_refusal->object[0] ||
		    mock_cmd_count(LOTA_IPC_CMD_GET_REFUSAL) > 0) {
			atomic_store(&g_hook.self_protected, 0);
			stop_mock_agent(agent);
			FAIL("a load that succeeded was taken for a refusal");
			return;
		}
	}

	handle = dlopen(missing, RTLD_NOW);
	stop_mock_agent(agent);
	atomic_store(&g_hook.self_protected, 0);
	if (handle) {
		dlclose(handle);
		FAIL("a load of nothing returned a handle");
		return;
	}
	if (mock_cmd_count(LOTA_IPC_CMD_GET_REFUSAL) != 1) {
		FAIL("a failed load did not ask the agent what was refused");
		return;
	}
	if (g_refusal->object[0]) {
		FAIL("a failed load the gate did not refuse was recorded");
		return;
	}

	PASS();
}

/*
 * The title asks for a trusted object and the gate refuses a dependency
 * the loader pulls in: the agent names the dependency.
 */
static void test_a_refused_dependency_is_named(void)
{
	const char *dep = "/opt/game/lib/libdep.so";
	char logpath[PATH_MAX], log[1024];
	int fd, saved;
	pid_t agent;

	TEST("a refused dependency is named, not the object asked for");

	snprintf(mock_refusal_object, sizeof(mock_refusal_object), "%s", dep);
	mock_refusal_stale = 0;
	agent = start_mock_agent();
	if (agent < 0) {
		mock_refusal_object[0] = '\0';
		if (mock_errno_is_sandbox(mock_agent_errno)) {
			SKIP("no unix socket in this sandbox");
			return;
		}
		FAIL("mock agent did not start");
		return;
	}
	hook_state_for_mock_agent("dependency");
	g_hook.log_level = HOOK_LOG_SILENT;
	atomic_store(&g_hook.self_protected, 1);
	g_refusal->object[0] = '\0';

	snprintf(logpath, sizeof(logpath), "%s/dependency.log", tmpdir);
	fd = open(logpath, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	fflush(stderr);
	saved = dup(STDERR_FILENO);
	if (fd >= 0 && saved >= 0)
		dup2(fd, STDERR_FILENO);
	g_hook.log_level = HOOK_LOG_ERROR;
	(void)dlopen("/nonexistent/lota-trusted-title.so", RTLD_NOW);
	g_hook.log_level = HOOK_LOG_SILENT;
	fflush(stderr);
	if (saved >= 0) {
		dup2(saved, STDERR_FILENO);
		close(saved);
	}
	if (fd >= 0)
		close(fd);
	stop_mock_agent(agent);
	if (strcmp(g_refusal->object, dep) != 0) {
		atomic_store(&g_hook.self_protected, 0);
		mock_refusal_object[0] = '\0';
		FAIL("the refused dependency went unnamed");
		return;
	}
	if (read_file_contents(logpath, log, sizeof(log)) <= 0 ||
	    !strstr(log, "an allow_verity or trust_lib entry in lota.conf")) {
		atomic_store(&g_hook.self_protected, 0);
		mock_refusal_object[0] = '\0';
		FAIL("the refusal named no lota.conf key");
		return;
	}

	/* a refusal from before this load is not its cause */
	g_refusal->object[0] = '\0';
	mock_refusal_stale = 1;
	agent = start_mock_agent();
	if (agent < 0) {
		atomic_store(&g_hook.self_protected, 0);
		mock_refusal_object[0] = '\0';
		mock_refusal_stale = 0;
		FAIL("mock agent did not start again");
		return;
	}
	(void)dlopen("/nonexistent/lota-trusted-title.so", RTLD_NOW);
	stop_mock_agent(agent);
	atomic_store(&g_hook.self_protected, 0);
	mock_refusal_object[0] = '\0';
	mock_refusal_stale = 0;
	if (g_refusal->object[0]) {
		g_refusal->object[0] = '\0';
		FAIL("an earlier refusal was blamed for this load");
		return;
	}

	PASS();
}

/*
 * The file is rewritten only on an agent status event, so a registration
 * made between events leaves LOTA_PROTECTED=0 on disk indefinitely.
 */
static void test_a_registration_publishes_itself(void)
{
	pid_t agent;
	char path[PATH_MAX];
	char buf[1024];
	ssize_t n;

	TEST("a registration reaches the status file when it is made");

	agent = start_mock_agent();
	if (agent < 0) {
		if (mock_errno_is_sandbox(mock_agent_errno)) {
			SKIP("no unix socket in this sandbox");
			return;
		}
		FAIL("mock agent did not start");
		return;
	}

	hook_state_for_mock_agent("publish");
	snprintf(path, sizeof(path), "%s/publish.status", tmpdir);

	g_hook.client = hook_connect();
	if (!g_hook.client) {
		stop_mock_agent(agent);
		FAIL("hook did not connect to the mock agent");
		return;
	}
	hook_register_self();

	lota_disconnect(g_hook.client);
	g_hook.client = NULL;
	stop_mock_agent(agent);
	atomic_store(&g_hook.self_protected, 0);

	n = read_file_contents(path, buf, sizeof(buf));
	if (n <= 0) {
		FAIL("no status file to read");
		return;
	}
	if (!strstr(buf, "LOTA_PROTECTED=1")) {
		FAIL("the sink still says the title is not in the gates");
		return;
	}

	PASS();
}

/* likewise a refusal: no agent event follows it */
static void test_a_refusal_publishes_itself(void)
{
	const char *refused = "/opt/game/lib/libpublish.so";
	pid_t agent;
	char path[PATH_MAX];
	char buf[1024];
	void *handle;
	ssize_t n;

	TEST("a refusal reaches the status file when the load fails");

	snprintf(mock_refusal_object, sizeof(mock_refusal_object), "%s",
		 refused);
	mock_refusal_stale = 0;
	agent = start_mock_agent();
	if (agent < 0) {
		mock_refusal_object[0] = '\0';
		if (mock_errno_is_sandbox(mock_agent_errno)) {
			SKIP("no unix socket in this sandbox");
			return;
		}
		FAIL("mock agent did not start");
		return;
	}

	hook_state_for_mock_agent("refused_publish");
	snprintf(path, sizeof(path), "%s/refused_publish.status", tmpdir);

	g_hook.client = hook_connect();
	if (!g_hook.client) {
		stop_mock_agent(agent);
		mock_refusal_object[0] = '\0';
		FAIL("hook did not connect to the mock agent");
		return;
	}
	refresh_once();
	lota_disconnect(g_hook.client);
	g_hook.client = NULL;

	atomic_store(&g_hook.self_protected, 1);
	handle = dlopen("/nonexistent/lota-publish.so", RTLD_NOW);
	atomic_store(&g_hook.self_protected, 0);
	stop_mock_agent(agent);
	mock_refusal_object[0] = '\0';
	if (handle) {
		dlclose(handle);
		FAIL("a load of nothing returned a handle");
		return;
	}

	n = read_file_contents(path, buf, sizeof(buf));
	g_refusal->object[0] = '\0';
	if (n <= 0) {
		FAIL("no status file to read");
		return;
	}
	if (!strstr(buf, "LOTA_REFUSED_OBJECT=/opt/game/lib/libpublish.so")) {
		FAIL("the sink does not carry the refusal the title just met");
		return;
	}

	PASS();
}

/*
 * Run lota-protect against @socket on a program that leaves a marker
 * and exits 7. Returns its exit status, or -1; *@ran says if it ran.
 */
static int run_lota_protect(const char *socket, int *ran)
{
	char marker[PATH_MAX];
	char script[PATH_MAX + 32];
	char *argv[] = { "lota-protect", "--", "/bin/sh", "-c", script, NULL };
	int status;
	pid_t pid;

	snprintf(marker, sizeof(marker), "%s/protect.ran", tmpdir);
	snprintf(script, sizeof(script), "touch '%s'; exit 7", marker);
	unlink(marker);

	pid = fork();
	if (pid < 0)
		return -1;
	if (pid == 0) {
		int null_fd = open("/dev/null", O_WRONLY | O_CLOEXEC);

		if (null_fd >= 0)
			dup2(null_fd, STDERR_FILENO);
		setenv(LOTA_HOOK_ENV_SOCKET, socket, 1);
		unsetenv(LOTA_HOOK_ENV_PUBLISHER);
		_exit(lota_protect_main(5, argv));
	}

	if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status))
		return -1;

	*ran = access(marker, F_OK) == 0;
	unlink(marker);
	return WEXITSTATUS(status);
}

static void test_lota_protect_protects_then_starts(void)
{
	pid_t agent;
	int ran = 0;
	int rc;

	TEST("lota-protect asks for protection, then becomes the program");

	mock_protect_result = LOTA_IPC_OK;
	agent = start_mock_agent();
	if (agent < 0) {
		if (mock_errno_is_sandbox(mock_agent_errno)) {
			SKIP("no unix socket in this sandbox");
			return;
		}
		FAIL("mock agent did not start");
		return;
	}

	rc = run_lota_protect(mock_socket, &ran);
	stop_mock_agent(agent);

	if (rc != 7 || !ran) {
		FAIL("the program did not run with its own exit status");
		return;
	}
	if (mock_cmd_count(LOTA_IPC_CMD_PROTECT_PID) != 1) {
		FAIL("the agent was not asked exactly once");
		return;
	}
	PASS();
}

/* a tracer holding the process: the game must not start unprotected */
static void test_lota_protect_refused_does_not_start(void)
{
	pid_t agent;
	int ran = 0;
	int rc;

	TEST("lota-protect does not start a program the agent refused");

	mock_protect_result = LOTA_IPC_ERR_ACCESS_DENIED;
	agent = start_mock_agent();
	mock_protect_result = LOTA_IPC_OK;
	if (agent < 0) {
		if (mock_errno_is_sandbox(mock_agent_errno)) {
			SKIP("no unix socket in this sandbox");
			return;
		}
		FAIL("mock agent did not start");
		return;
	}

	rc = run_lota_protect(mock_socket, &ran);
	stop_mock_agent(agent);

	if (ran) {
		FAIL("the program ran after the agent refused it");
		return;
	}
	if (rc != PROTECT_EXIT_REFUSED) {
		FAIL("the refusal did not exit with 125");
		return;
	}
	PASS();
}

/* the thread asks again every cycle; the player's log hears it once */
static void test_a_repeated_registration_refusal_warns_once(void)
{
	char logpath[PATH_MAX];
	char line[256];
	int saved, fd, warned = 0;
	pid_t agent;
	FILE *f;

	TEST("a refused registration asked again warns once");

	mock_protect_result = LOTA_IPC_ERR_ACCESS_DENIED;
	agent = start_mock_agent();
	mock_protect_result = LOTA_IPC_OK;
	if (agent < 0) {
		if (mock_errno_is_sandbox(mock_agent_errno)) {
			SKIP("no unix socket in this sandbox");
			return;
		}
		FAIL("mock agent did not start");
		return;
	}

	hook_state_for_mock_agent("refused");
	g_hook.client = hook_connect();
	if (!g_hook.client) {
		stop_mock_agent(agent);
		FAIL("hook did not connect to the mock agent");
		return;
	}

	snprintf(logpath, sizeof(logpath), "%s/refused.log", tmpdir);
	fd = open(logpath, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	fflush(stderr);
	saved = dup(STDERR_FILENO);
	if (fd >= 0 && saved >= 0)
		dup2(fd, STDERR_FILENO);
	g_hook.log_level = HOOK_LOG_WARN;
	for (int i = 0; i < 3; i++)
		hook_register_self();
	g_hook.log_level = HOOK_LOG_SILENT;
	fflush(stderr);
	if (saved >= 0) {
		dup2(saved, STDERR_FILENO);
		close(saved);
	}
	if (fd >= 0)
		close(fd);

	lota_disconnect(g_hook.client);
	g_hook.client = NULL;
	stop_mock_agent(agent);
	atomic_store(&g_hook.protect_errno, 0);

	f = fopen(logpath, "r");
	while (f && fgets(line, sizeof(line), f))
		warned += strstr(line, "lota_protect_self") != NULL;
	if (f)
		fclose(f);

	if (warned != 1) {
		printf("FAIL: %d warnings\n", warned);
		return;
	}
	PASS();
}

/* no agent: the game starts, and the agent's absence is what reports it */
static void test_lota_protect_without_agent_starts(void)
{
	char socket[PATH_MAX];
	int ran = 0;
	int rc;

	TEST("lota-protect starts the program when no agent answers");

	snprintf(socket, sizeof(socket), "%s/no-agent.sock", tmpdir);
	unlink(socket);

	rc = run_lota_protect(socket, &ran);
	if (rc != 7 || !ran) {
		FAIL("the program did not run without an agent");
		return;
	}
	PASS();
}

/* a token directory repaired to 0700 must log the mode it had */
static void test_a_repaired_token_dir_mode_is_reported(void)
{
	mode_t repaired;
	struct stat st;

	TEST("a token directory repaired to 0700 says what it was");

	snprintf(g_hook.token_dir, sizeof(g_hook.token_dir), "%s/loose",
		 tmpdir);
	if (mkdir(g_hook.token_dir, 0777) != 0 && errno != EEXIST) {
		FAIL("could not create the test directory");
		return;
	}
	if (chmod(g_hook.token_dir, 0777) != 0) {
		FAIL("could not set the test mode");
		return;
	}

	repaired = 0;
	if (ensure_token_dir(&repaired) != 0) {
		FAIL("ensure_token_dir refused a directory it owns");
		return;
	}
	if (stat(g_hook.token_dir, &st) != 0 || (st.st_mode & 0777) != 0700) {
		FAIL("the directory was not tightened to 0700");
		return;
	}
	if (repaired != 0777) {
		FAIL("the repair does not name the mode it found");
		return;
	}

	PASS();
}

/* A directory that was already 0700 was not repaired and says nothing. */
static void test_an_untouched_token_dir_reports_no_repair(void)
{
	mode_t repaired;

	TEST("a token directory already at 0700 reports no repair");

	snprintf(g_hook.token_dir, sizeof(g_hook.token_dir), "%s/tight",
		 tmpdir);
	if (mkdir(g_hook.token_dir, 0700) != 0 && errno != EEXIST) {
		FAIL("could not create the test directory");
		return;
	}

	repaired = 0777;
	if (ensure_token_dir(&repaired) != 0) {
		FAIL("ensure_token_dir refused a directory it owns");
		return;
	}
	if (repaired != 0) {
		FAIL("a directory that was not repaired reports a repair");
		return;
	}

	PASS();
}

/*
 * Each connect failure needs its own line: a session without the lota group
 * and a socket never created must not read the same.
 */
static void test_an_unreachable_socket_is_classified(void)
{
	char judged[PATH_MAX];
	char sock[PATH_MAX];
	int fd;
	int ret;

	TEST("the hook names why the agent socket could not be opened");

	snprintf(sock, sizeof(sock), "%s/absent.sock", tmpdir);
	snprintf(g_hook.socket_path, sizeof(g_hook.socket_path), "%s", sock);

	ret = hook_probe_socket(judged, sizeof(judged));
	if (ret != -ENOENT) {
		g_hook.socket_path[0] = '\0';
		FAIL("a socket that is not there is not reported as absent");
		return;
	}
	if (strcmp(judged, sock) != 0) {
		g_hook.socket_path[0] = '\0';
		FAIL("the probe does not name the path it judged");
		return;
	}

	snprintf(sock, sizeof(sock), "%s/closed.sock", tmpdir);
	snprintf(g_hook.socket_path, sizeof(g_hook.socket_path), "%s", sock);
	fd = open(sock, O_CREAT | O_WRONLY | O_TRUNC, 0000);
	if (fd < 0) {
		g_hook.socket_path[0] = '\0';
		FAIL("could not create the test socket path");
		return;
	}
	close(fd);

	if (getuid() == 0) {
		unlink(sock);
		g_hook.socket_path[0] = '\0';
		SKIP("root opens a mode 0000 path");
		return;
	}

	ret = hook_probe_socket(judged, sizeof(judged));
	unlink(sock);
	g_hook.socket_path[0] = '\0';
	if (ret != -EACCES) {
		FAIL("a socket this process may not open is not reported as refused");
		return;
	}

	PASS();
}

/* The reason a player can act on, not the errno alone. */
static void test_a_refused_socket_names_the_group(void)
{
	const char *denied;
	const char *absent;

	TEST("a refused socket names the group a player is missing");

	denied = hook_connect_reason(-EACCES);
	if (!denied || !strstr(denied, "lota group")) {
		FAIL("permission denied does not name the group");
		return;
	}

	absent = hook_connect_reason(-ENOENT);
	if (!absent || strstr(absent, "lota group")) {
		FAIL("an absent socket is explained as a group problem");
		return;
	}

	if (hook_connect_reason(-EPROTO)) {
		FAIL("an errno with nothing to say invents a reason");
		return;
	}

	PASS();
}

int main(void)
{
	printf("=== LOTA Wine Hook Unit Tests ===\n\n");

	setup_tmpdir();

	/* silence hook logs during tests */
	g_hook.log_level = HOOK_LOG_SILENT;

	/* parse_log_level */
	test_parse_log_level_debug();
	test_parse_log_level_info();
	test_parse_log_level_warn();
	test_parse_log_level_error();
	test_parse_log_level_silent();
	test_parse_log_level_null();
	test_parse_log_level_invalid();

	/* resolve_token_dir */
	test_token_dir_candidate_explicit();
	test_token_dir_candidate_xdg();
	test_token_dir_candidates_never_the_socket_dir();
	test_token_dir_candidate_fallback();
	test_setup_token_dir_falls_through();
	test_setup_token_dir_explicit_refused_falls_through();

	/* ensure_token_dir */
	test_ensure_token_dir_creates();
	test_ensure_token_dir_exists();
	test_ensure_token_dir_not_a_dir();
	test_ensure_token_dir_rejects_symlink();
	test_token_dir_override_trailing_slash_symlink();
	test_ensure_token_dir_existing_mode_tightened();
	test_a_repaired_token_dir_mode_is_reported();
	test_an_untouched_token_dir_reports_no_repair();
	test_an_unreachable_socket_is_classified();
	test_a_refused_socket_names_the_group();

	/* atomic_write */
	test_atomic_write_creates_file();
	test_atomic_write_overwrites();
	test_atomic_write_no_tmp_leftover();
	test_atomic_write_ignores_predictable_symlink_tmp();
	test_atomic_write_file_mode();

	/* write_status */
	test_write_status_attested();
	test_write_status_not_attested();
	test_write_status_zero_flags();
	test_status_heartbeat();
	test_rate_limit_reason();
	test_write_status_marks_online_branch();
	test_write_status_payload_offline_marker();

	/* offline publication */
	test_offline_publish_replaces_the_last_good_status();
	test_offline_publish_writes_once_per_episode();
	test_offline_clear_arms_the_next_disconnect();
	test_a_republish_while_offline_stays_offline();
	test_a_publisher_refusal_is_not_offline();

	/* process activation policy */
	test_policy_default_skips_usr_bin();
	test_policy_default_skips_legacy_bin();
	test_policy_default_skips_pressure_vessel_host();
	test_policy_default_activates_steam_path();
	test_policy_default_activates_opt_and_home();
	test_policy_default_activates_snap_and_flatpak();
	test_policy_empty_exe_defaults_to_activate();
	test_policy_handles_deleted_suffix();
	test_policy_activate_pin_is_positive();
	test_policy_activate_pin_overrides_fhs_skip();
	test_policy_skip_extends_default();
	test_policy_activate_pin_ignores_skip();
	test_policy_empty_env_strings_ignored();
	test_policy_prefix_must_match_at_start();
	test_policy_whitespace_tolerant();
	test_policy_wine_title_is_attested();
	test_policy_wine_prefix_processes_are_skipped();
	test_policy_wine_title_any_drive_any_case();
	test_policy_wine_title_matches_whole_components();
	test_policy_wine_loader_without_program_is_skipped();
	test_policy_program_leaves_native_processes_alone();
	test_policy_wine_without_title_dir_uses_the_pin();

	/* connect-then-register sequence */
	test_the_launch_path_registers_the_title();
	test_the_registration_is_not_repeated();
	test_the_first_refresh_registers();
	test_the_status_file_names_the_refused_object();
	test_a_child_refusal_reaches_the_parent_status();
	test_a_concurrent_refusal_is_never_torn();
	test_a_child_dead_in_the_lock_frees_it();
	test_the_loader_wrapper_hands_back_what_it_got();
	test_a_refused_dependency_is_named();
	test_a_registration_publishes_itself();
	test_a_refusal_publishes_itself();

	/* lota-protect: protected before the program's first instruction */
	test_lota_protect_protects_then_starts();
	test_lota_protect_refused_does_not_start();
	test_a_repeated_registration_refusal_warns_once();
	test_lota_protect_without_agent_starts();

	/* how the refresh thread reads a poll */
	test_a_quiet_wait_is_not_a_failure();
	test_a_delivered_event_is_not_a_failure();
	test_a_refusal_is_a_failure();

	/* exported query functions */
	test_hook_active_when_not_started();
	test_hook_status_path_when_set();
	test_hook_status_path_when_empty();
	test_hook_token_path_when_set();
	test_hook_token_path_when_empty();

	cleanup_tmpdir();

	printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
	return (tests_passed == tests_run) ? 0 : 1;
}
