/* SPDX-License-Identifier: MIT */
/*
 * LOTA container listener tracking unit tests
 *
 * The listener a Proton title connects to lives under the launching
 * user's runtime directory, and systemd-logind creates that directory
 * at login -- long after the agent starts.
 *
 * These tests drive the tracking with a runtime root the test owns,
 * so the login can be staged: the directory appears, goes away,
 * and comes back while the watch is already running.
 *
 * Build:
 *   gcc -Wall -Wextra -Werror -O2 -g -Iinclude -D_GNU_SOURCE \
 *       -o build/test_container_watch \
 *       tests/test_container_watch.c src/agent/container_watch.c
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../src/agent/container_watch.h"

static int tests_run;
static int tests_passed;

#define TEST(name)                                        \
	do {                                              \
		tests_run++;                              \
		printf("  [%d] %-55s ", tests_run, name); \
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

#define PLAYER_UID 1000u
#define OTHER_UID 1001u

/* What the ops recorded, so a test can assert on the calls themselves */
struct call_log {
	uint32_t bound[8];
	int bound_count;
	uint32_t unbound[8];
	int unbound_count;
	int bind_result;
};

static int record_bind(uint32_t uid, void *user)
{
	struct call_log *log = user;

	if (log->bind_result != 0)
		return log->bind_result;

	if (log->bound_count <
	    (int)(sizeof(log->bound) / sizeof(log->bound[0])))
		log->bound[log->bound_count++] = uid;

	return 0;
}

static void record_unbind(uint32_t uid, void *user)
{
	struct call_log *log = user;

	if (log->unbound_count <
	    (int)(sizeof(log->unbound) / sizeof(log->unbound[0])))
		log->unbound[log->unbound_count++] = uid;
}

static char root[64];

static void setup_root(void)
{
	snprintf(root, sizeof(root), "/tmp/lota_test_cwatch_XXXXXX");
	if (!mkdtemp(root)) {
		fprintf(stderr, "mkdtemp failed: %s\n", strerror(errno));
		exit(1);
	}
}

static void login(uint32_t uid)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/%u", root, uid);
	if (mkdir(path, 0700) < 0 && errno != EEXIST) {
		fprintf(stderr, "mkdir(%s) failed: %s\n", path,
			strerror(errno));
		exit(1);
	}
}

static void logout(uint32_t uid)
{
	char path[PATH_MAX];

	snprintf(path, sizeof(path), "%s/%u", root, uid);
	if (rmdir(path) < 0 && errno != ENOENT) {
		fprintf(stderr, "rmdir(%s) failed: %s\n", path,
			strerror(errno));
		exit(1);
	}
}

static void cleanup_root(void)
{
	logout(PLAYER_UID);
	logout(OTHER_UID);
	rmdir(root);
}

static int init_watch(struct container_watch *w, struct call_log *log,
		      const uint32_t *uids, int uid_count)
{
	struct container_watch_ops ops = {
		.bind = record_bind,
		.unbind = record_unbind,
		.user = log,
	};

	memset(log, 0, sizeof(*log));
	return container_watch_init(w, root, uids, uid_count, &ops);
}

/* Wait for the watch to report that the runtime root changed */
static int wait_readable(const struct container_watch *w, int timeout_ms)
{
	struct pollfd pfd;

	pfd.fd = container_watch_fd(w);
	pfd.events = POLLIN;
	pfd.revents = 0;

	if (pfd.fd < 0)
		return -EBADF;

	return poll(&pfd, 1, timeout_ms);
}

static void test_binds_existing_login(void)
{
	const uint32_t uids[] = { PLAYER_UID };
	struct container_watch w;
	struct call_log log;

	TEST("a UID already logged in is bound at init");
	login(PLAYER_UID);

	if (init_watch(&w, &log, uids, 1) != 0) {
		FAIL("init refused");
		return;
	}

	if (log.bound_count != 1 || log.bound[0] != PLAYER_UID)
		FAIL("the logged-in UID was not bound");
	else
		PASS();

	container_watch_cleanup(&w);
	logout(PLAYER_UID);
}

static void test_binds_login_after_start(void)
{
	const uint32_t uids[] = { PLAYER_UID };
	struct container_watch w;
	struct call_log log;
	int ret;

	TEST("a UID that logs in after the agent starts is bound");

	if (init_watch(&w, &log, uids, 1) != 0) {
		FAIL("init refused");
		return;
	}

	if (log.bound_count != 0) {
		FAIL("bound a UID with no runtime directory");
		container_watch_cleanup(&w);
		return;
	}

	/* the login the agent was not running for */
	login(PLAYER_UID);

	if (wait_readable(&w, 2000) != 1) {
		FAIL("the login never woke the watch");
		container_watch_cleanup(&w);
		logout(PLAYER_UID);
		return;
	}

	ret = container_watch_process(&w);
	if (ret < 0)
		FAIL("processing the login failed");
	else if (log.bound_count != 1 || log.bound[0] != PLAYER_UID)
		FAIL("the login did not produce a listener");
	else
		PASS();

	container_watch_cleanup(&w);
	logout(PLAYER_UID);
}

static void test_rebinds_second_login(void)
{
	const uint32_t uids[] = { PLAYER_UID };
	struct container_watch w;
	struct call_log log;

	TEST("logging out drops the listener and logging back in restores it");

	if (init_watch(&w, &log, uids, 1) != 0) {
		FAIL("init refused");
		return;
	}

	login(PLAYER_UID);
	(void)wait_readable(&w, 2000);
	(void)container_watch_process(&w);

	logout(PLAYER_UID);
	(void)wait_readable(&w, 2000);
	(void)container_watch_process(&w);

	if (log.unbound_count != 1 || log.unbound[0] != PLAYER_UID) {
		FAIL("the logout did not drop the listener");
		container_watch_cleanup(&w);
		return;
	}

	login(PLAYER_UID);
	(void)wait_readable(&w, 2000);
	(void)container_watch_process(&w);

	if (log.bound_count != 2)
		FAIL("the second login did not produce a listener");
	else
		PASS();

	container_watch_cleanup(&w);
	logout(PLAYER_UID);
}

static void test_ignores_unconfigured_uid(void)
{
	const uint32_t uids[] = { PLAYER_UID };
	struct container_watch w;
	struct call_log log;

	TEST("a login by an unconfigured UID is ignored");

	if (init_watch(&w, &log, uids, 1) != 0) {
		FAIL("init refused");
		return;
	}

	login(OTHER_UID);
	(void)wait_readable(&w, 500);
	(void)container_watch_process(&w);

	if (log.bound_count != 0)
		FAIL("bound a UID that was never configured");
	else
		PASS();

	container_watch_cleanup(&w);
	logout(OTHER_UID);
}

static void test_retries_failed_bind(void)
{
	const uint32_t uids[] = { PLAYER_UID };
	struct container_watch w;
	struct call_log log;

	TEST("a bind that fails is retried on the next observation");

	if (init_watch(&w, &log, uids, 1) != 0) {
		FAIL("init refused");
		return;
	}

	log.bind_result = -EACCES;
	login(PLAYER_UID);
	(void)wait_readable(&w, 2000);
	(void)container_watch_process(&w);

	if (log.bound_count != 0) {
		FAIL("a failed bind was recorded as bound");
		container_watch_cleanup(&w);
		logout(PLAYER_UID);
		return;
	}

	log.bind_result = 0;
	if (container_watch_process(&w) < 0)
		FAIL("the retry failed");
	else if (log.bound_count != 1)
		FAIL("the failed bind was never retried");
	else
		PASS();

	container_watch_cleanup(&w);
	logout(PLAYER_UID);
}

/*
 * The single-operator host names no UID and is pointed at the agent's own
 * runtime directory by the shipped drop-in. That directory belongs to one
 * login, so it names the UID whose login the listener has to follow
 * -- the daemon starts at multi-user.target, before anyone has logged in,
 * and logind creates the directory at login.
 */
static void test_a_runtime_dir_names_the_login_to_watch(void)
{
	uint32_t uids[LOTA_CONFIG_MAX_CONTAINER_LISTENERS];
	int n;

	TEST("the agent's runtime directory names the login to watch");

	n = container_watch_plan(NULL, 0, "/run/user/1000", uids,
				 LOTA_CONFIG_MAX_CONTAINER_LISTENERS);
	if (n < 0)
		FAIL("the runtime directory produced no plan");
	else if (n != 1)
		FAIL("the runtime directory named no single login");
	else if (uids[0] != 1000)
		FAIL("the wrong login was planned for");
	else
		PASS();
}

/* A configuration that names UIDs answers for itself, runtime dir or not. */
static void test_configured_uids_win_over_the_runtime_dir(void)
{
	const uint32_t cfg_uids[] = { 1001, 1002 };
	uint32_t uids[LOTA_CONFIG_MAX_CONTAINER_LISTENERS];
	int n;

	TEST("configured UIDs are the plan, runtime directory or not");

	n = container_watch_plan(cfg_uids, 2, "/run/user/1000", uids,
				 LOTA_CONFIG_MAX_CONTAINER_LISTENERS);
	if (n != 2)
		FAIL("the configured UIDs were not the plan");
	else if (uids[0] != 1001 || uids[1] != 1002)
		FAIL("the plan is not the configured UIDs");
	else
		PASS();
}

/*
 * A runtime directory that is not one of logind's cannot name a login,
 * so there is nothing to watch for and the caller has to hear about it.
 */
static void test_a_foreign_runtime_dir_names_no_login(void)
{
	uint32_t uids[LOTA_CONFIG_MAX_CONTAINER_LISTENERS];
	uint32_t uid = 4242;

	TEST("a runtime directory outside /run/user names no login");

	if (container_watch_plan(NULL, 0, "/tmp/some-runtime", uids,
				 LOTA_CONFIG_MAX_CONTAINER_LISTENERS) != 0)
		FAIL("a directory that names no login produced a plan");
	else if (container_watch_uid_of_runtime_dir("/tmp/some-runtime",
						    &uid) >= 0)
		FAIL("a directory outside the runtime root named a login");
	else if (container_watch_uid_of_runtime_dir("/run/user/notanumber",
						    &uid) >= 0)
		FAIL("a runtime directory with no UID in it named a login");
	else if (container_watch_uid_of_runtime_dir("/run/user/1000/", &uid) <
			 0 ||
		 uid != 1000)
		FAIL("a trailing slash lost the login");
	else
		PASS();
}

/* Nothing to go on at all is a plan of nothing, not a guess. */
static void test_no_configuration_and_no_runtime_dir_plans_nothing(void)
{
	uint32_t uids[LOTA_CONFIG_MAX_CONTAINER_LISTENERS];

	TEST("no configuration and no runtime directory plans nothing");
	if (container_watch_plan(NULL, 0, NULL, uids,
				 LOTA_CONFIG_MAX_CONTAINER_LISTENERS) != 0)
		FAIL("something was planned out of nothing");
	else
		PASS();
}

int main(void)
{
	printf("=== LOTA container listener tracking tests ===\n\n");

	setup_root();

	test_binds_existing_login();
	test_binds_login_after_start();
	test_rebinds_second_login();
	test_ignores_unconfigured_uid();
	test_retries_failed_bind();
	test_a_runtime_dir_names_the_login_to_watch();
	test_configured_uids_win_over_the_runtime_dir();
	test_a_foreign_runtime_dir_names_no_login();
	test_no_configuration_and_no_runtime_dir_plans_nothing();

	cleanup_root();

	printf("\n%d/%d tests passed\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
