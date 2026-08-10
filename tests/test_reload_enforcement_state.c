/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for what a configuration reload does to enforcement state that
 * came from the command line.
 *
 * --trust-lib and --protect-pid are startup flags: the trusted-library set
 * and the protected set they build live in BPF maps, and the file the daemon
 * re-reads on SIGHUP does not necessarily mention either. A reload that keeps
 * only what the file lists therefore disarms the substitution hooks on a host
 * configured through its unit, and the operator is told a count rather than
 * a removal.
 *
 * The BPF layer is stubbed to record what it was asked to trust and protect,
 * because the assertion is about which entries survive a reload, not about
 * the maps themselves.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <fcntl.h>
#include <limits.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../src/agent/agent.h"
#include "../src/agent/bpf_loader.h"
#include "../src/agent/config.h"
#include "../src/agent/main_utils.h"
#include "../src/agent/reload.h"
#include "../src/agent/sdnotify.h"

struct agent_globals g_agent;

/* What the BPF layer currently holds, as this test's stubs see it */
static char stub_trusted[LOTA_CONFIG_MAX_LIBS][PATH_MAX];
static int stub_trusted_count;
static uint32_t stub_protected[64];
static int stub_protected_count;

int bpf_loader_trust_lib(struct bpf_loader_ctx *ctx, const char *path)
{
	(void)ctx;
	if (!path || stub_trusted_count >= LOTA_CONFIG_MAX_LIBS)
		return -EINVAL;
	snprintf(stub_trusted[stub_trusted_count], PATH_MAX, "%s", path);
	stub_trusted_count++;
	return 0;
}

int bpf_loader_untrust_lib(struct bpf_loader_ctx *ctx, const char *path)
{
	(void)ctx;
	for (int i = 0; i < stub_trusted_count; i++) {
		if (strcmp(stub_trusted[i], path) != 0)
			continue;
		for (int k = i; k < stub_trusted_count - 1; k++)
			snprintf(stub_trusted[k], PATH_MAX, "%s",
				 stub_trusted[k + 1]);
		stub_trusted_count--;
		return 0;
	}
	return -ENOENT;
}

int bpf_loader_protect_pid(struct bpf_loader_ctx *ctx, uint32_t pid)
{
	(void)ctx;
	if (stub_protected_count >=
	    (int)(sizeof(stub_protected) / sizeof(stub_protected[0])))
		return -ENOSPC;
	stub_protected[stub_protected_count++] = pid;
	return 0;
}

int bpf_loader_unprotect_pid(struct bpf_loader_ctx *ctx, uint32_t pid)
{
	(void)ctx;
	for (int i = 0; i < stub_protected_count; i++) {
		if (stub_protected[i] != pid)
			continue;
		for (int k = i; k < stub_protected_count - 1; k++)
			stub_protected[k] = stub_protected[k + 1];
		stub_protected_count--;
		return 0;
	}
	return -ENOENT;
}

int bpf_loader_set_mode(struct bpf_loader_ctx *ctx, uint32_t mode)
{
	(void)ctx;
	(void)mode;
	return 0;
}

/*
 * The two mode helpers, which live in the daemon's main_utils.c beside the whole
 * start-up path. Linking that here would drag in the IPC listener, D-Bus
 * and the Steam runtime probe, none of which a reload test has any use for.
 */
const char *mode_to_string(int mode)
{
	if (mode == LOTA_MODE_ENFORCE)
		return "enforce";
	if (mode == LOTA_MODE_MAINTENANCE)
		return "maintenance";
	return "monitor";
}

int parse_mode(const char *mode_str)
{
	if (!mode_str || !mode_str[0])
		return -1;
	if (strcmp(mode_str, "enforce") == 0)
		return LOTA_MODE_ENFORCE;
	if (strcmp(mode_str, "maintenance") == 0)
		return LOTA_MODE_MAINTENANCE;
	if (strcmp(mode_str, "monitor") == 0)
		return LOTA_MODE_MONITOR;
	return -1;
}

int bpf_loader_set_config(struct bpf_loader_ctx *ctx, uint32_t key,
			  uint32_t value)
{
	(void)ctx;
	(void)key;
	(void)value;
	return 0;
}

int sdnotify_ready(void)
{
	return 0;
}

int sdnotify_reloading(void)
{
	return 0;
}

int sdnotify_status(const char *fmt, ...)
{
	(void)fmt;
	return 0;
}

static int tests_run;
static int tests_passed;

#define TEST(name)                                         \
	do {                                               \
		tests_run++;                               \
		printf("  [%2d] %-58s ", tests_run, name); \
	} while (0)

#define PASS()                    \
	do {                      \
		tests_passed++;   \
		printf("PASS\n"); \
	} while (0)

#define FAIL(msg)                          \
	do {                               \
		printf("FAIL: %s\n", msg); \
	} while (0)

static const char *const flag_lib = "/usr/local/lib/from-the-command-line.so";
static const uint32_t flag_pid = 4242;

/* A config the daemon would accept, naming no enforcement state of its own */
static int write_config(char *path, size_t pathlen, const char *extra)
{
	FILE *f;
	int fd;

	snprintf(path, pathlen, "/tmp/lota-reload-state-XXXXXX.conf");
	fd = mkstemps(path, 5);
	if (fd < 0)
		return -1;
	f = fdopen(fd, "w");
	if (!f) {
		close(fd);
		unlink(path);
		return -1;
	}
	fprintf(f, "mode = enforce\n");
	fprintf(f, "log_level = error\n");
	if (extra)
		fputs(extra, f);
	return fclose(f) == 0 ? 0 : -1;
}

/*
 * The daemon's runtime state as it stands after startup: whatever the config
 * had, plus what the flags added.
 * Here the flags are the only source.
 */
static void seed_runtime(char trust_libs[LOTA_CONFIG_MAX_LIBS][PATH_MAX],
			 int *trust_lib_count, uint32_t **protect_pids,
			 int *protect_pid_count)
{
	snprintf(trust_libs[0], PATH_MAX, "%s", flag_lib);
	*trust_lib_count = 1;

	*protect_pids = calloc(1, sizeof(**protect_pids));
	(*protect_pids)[0] = flag_pid;
	*protect_pid_count = 1;

	stub_trusted_count = 0;
	snprintf(stub_trusted[stub_trusted_count++], PATH_MAX, "%s", flag_lib);
	stub_protected_count = 0;
	stub_protected[stub_protected_count++] = flag_pid;
}

static bool stub_holds_lib(const char *path)
{
	for (int i = 0; i < stub_trusted_count; i++) {
		if (strcmp(stub_trusted[i], path) == 0)
			return true;
	}
	return false;
}

static bool stub_holds_pid(uint32_t pid)
{
	for (int i = 0; i < stub_protected_count; i++) {
		if (stub_protected[i] == pid)
			return true;
	}
	return false;
}

/*
 * A reload must not disarm the host.
 *
 * The library was trusted because the unit said so, and the config file has
 * never mentioned it. Dropping it leaves lota_sb_mount with nothing to refuse,
 * which is the substitution the hook exists to stop -- and the daemon cannot
 * be restarted to put it back, because it burns its boot commitment on shutdown.
 */
static void test_command_line_trust_lib_survives_reload(void)
{
	char trust_libs[LOTA_CONFIG_MAX_LIBS][PATH_MAX] = { { 0 } };
	uint32_t *protect_pids = NULL;
	int trust_lib_count = 0, protect_pid_count = 0;
	struct lota_config *cfg;
	char path[PATH_MAX];
	int mode = LOTA_MODE_ENFORCE;
	bool t = true, f = false;

	TEST("a trusted library from the command line survives a reload");

	if (write_config(path, sizeof(path), NULL) < 0) {
		FAIL("cannot write a config under /tmp");
		return;
	}

	cfg = config_new();
	if (!cfg) {
		FAIL("out of memory");
		return;
	}
	snprintf(cfg->mode, sizeof(cfg->mode), "enforce");
	seed_runtime(trust_libs, &trust_lib_count, &protect_pids,
		     &protect_pid_count);

	agent_reload_config(path, cfg, &mode, &t, &f, &t, &t, &f, &protect_pids,
			    &protect_pid_count, trust_libs, &trust_lib_count);

	if (!stub_holds_lib(flag_lib))
		FAIL("the reload dropped it, so the hooks have nothing to refuse");
	else if (trust_lib_count != 1)
		FAIL("the daemon's own count no longer names it");
	else
		PASS();

	config_free(cfg);
	free(protect_pids);
	unlink(path);
}

/*
 * The protected set is the same story:
 * --protect-pid is startup-only (there is no runtime verb), so the command
 * line is the only place it can come from and a reload can only ever empty it.
 */
static void test_command_line_protect_pid_survives_reload(void)
{
	char trust_libs[LOTA_CONFIG_MAX_LIBS][PATH_MAX] = { { 0 } };
	uint32_t *protect_pids = NULL;
	int trust_lib_count = 0, protect_pid_count = 0;
	struct lota_config *cfg;
	char path[PATH_MAX];
	int mode = LOTA_MODE_ENFORCE;
	bool t = true, f = false;

	TEST("a protected PID from the command line survives a reload");

	if (write_config(path, sizeof(path), NULL) < 0) {
		FAIL("cannot write a config under /tmp");
		return;
	}

	cfg = config_new();
	if (!cfg) {
		FAIL("out of memory");
		return;
	}
	snprintf(cfg->mode, sizeof(cfg->mode), "enforce");
	seed_runtime(trust_libs, &trust_lib_count, &protect_pids,
		     &protect_pid_count);

	agent_reload_config(path, cfg, &mode, &t, &f, &t, &t, &f, &protect_pids,
			    &protect_pid_count, trust_libs, &trust_lib_count);

	if (!stub_holds_pid(flag_pid))
		FAIL("the reload emptied the protected set");
	else if (protect_pid_count != 1)
		FAIL("the daemon's own count no longer names it");
	else
		PASS();

	config_free(cfg);
	free(protect_pids);
	unlink(path);
}

/*
 * And the file still owns what the file says.
 *
 * Keeping the command line is not the same as never removing anything:
 * a library the operator takes out of the config has to leave the map,
 * or a reload could only ever add.
 */
static void test_config_removal_still_takes_effect(void)
{
	char trust_libs[LOTA_CONFIG_MAX_LIBS][PATH_MAX] = { { 0 } };
	uint32_t *protect_pids = NULL;
	int trust_lib_count = 0, protect_pid_count = 0;
	const char *const file_lib = "/usr/local/lib/from-the-config.so";
	struct lota_config *cfg;
	char path[PATH_MAX];
	int mode = LOTA_MODE_ENFORCE;
	bool t = true, f = false;

	TEST("a library dropped from the config leaves the trusted set");

	if (write_config(path, sizeof(path), NULL) < 0) {
		FAIL("cannot write a config under /tmp");
		return;
	}

	cfg = config_new();
	if (!cfg) {
		FAIL("out of memory");
		return;
	}
	snprintf(cfg->mode, sizeof(cfg->mode), "enforce");
	seed_runtime(trust_libs, &trust_lib_count, &protect_pids,
		     &protect_pid_count);

	/* it was in the file at startup and is not in the file now */
	snprintf(trust_libs[trust_lib_count], PATH_MAX, "%s", file_lib);
	trust_lib_count++;
	snprintf(stub_trusted[stub_trusted_count++], PATH_MAX, "%s", file_lib);

	agent_reload_config(path, cfg, &mode, &t, &f, &t, &t, &f, &protect_pids,
			    &protect_pid_count, trust_libs, &trust_lib_count);

	if (stub_holds_lib(file_lib))
		FAIL("a removal in the file did not take effect");
	else if (!stub_holds_lib(flag_lib))
		FAIL("the command-line entry went with it");
	else
		PASS();

	config_free(cfg);
	free(protect_pids);
	unlink(path);
}

int main(void)
{
	printf("=== reload keeps command-line enforcement state ===\n\n");

	test_command_line_trust_lib_survives_reload();
	test_command_line_protect_pid_survives_reload();
	test_config_removal_still_takes_effect();

	printf("\n=== %d/%d passed ===\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
