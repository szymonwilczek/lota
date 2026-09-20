/* SPDX-License-Identifier: MIT */
/*
 * What the Wine/Proton hook asks the agent to tell it about
 *
 * The hook's status file is only as fresh as its event subscription.
 * The real library is dlopen()ed against a mock agent that records
 * the subscription mask and pushes one end-of-round notification.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "lota_ipc.h"
#include "lota_wine_hook.h"

#ifndef LOTA_HOOK_LIB_PATH
#define LOTA_HOOK_LIB_PATH "build/liblota_wine_hook.so"
#endif

#define FIRST_ATTEST_COUNT 1u /* status query answer */
#define FRESH_ATTEST_COUNT 2u /* notification, one round later */

/*
 * Registration is refused this long, so the hook's own publish
 * on registration follows the notified status.
 */
#define PROTECT_HOLD_SEC 2

static int tests_run;
static int tests_passed;

#define TEST(name)                                        \
	do {                                              \
		tests_run++;                              \
		printf("  [%d] %-58s ", tests_run, name); \
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

static char tmpdir[64]; /* short: paths built from it must fit */
static char sock_path[104];
static char status_path[PATH_MAX];
static char mask_path[PATH_MAX];
static char protect_path[PATH_MAX];

/* Mock agent */

static int mock_send(int fd, uint32_t result, const void *payload,
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

static int mock_recv(int fd, struct lota_ipc_request *req, void *payload,
		     size_t max_payload)
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

static void write_line(const char *path, const char *line)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	FILE *f = fd < 0 ? NULL : fdopen(fd, "w");

	if (!f)
		_exit(91);
	fprintf(f, "%s\n", line);
	fclose(f);
}

/* End-of-round notify: subscribed bits only, none if no bit is shared */
static int mock_push_round(int fd, uint32_t mask)
{
	struct lota_ipc_notify notify;
	uint32_t events = LOTA_IPC_EVENT_STATUS | LOTA_IPC_EVENT_ATTEST;

	events &= mask;
	if (!events)
		return 0;

	memset(&notify, 0, sizeof(notify));
	notify.events = events;
	notify.flags = 0;
	notify.last_attest_time = (uint64_t)time(NULL);
	notify.valid_until = (uint64_t)time(NULL) + 600;
	notify.attest_count = FRESH_ATTEST_COUNT;

	return mock_send(fd, LOTA_IPC_NOTIFY, &notify, sizeof(notify));
}

/* Until the hook hangs up */
static void mock_serve(int client_fd)
{
	struct lota_ipc_request req;
	uint8_t payload[256];
	uint32_t mask = 0;
	time_t subscribed_at = 0;

	while (mock_recv(client_fd, &req, payload, sizeof(payload)) == 0) {
		if (req.cmd == LOTA_IPC_CMD_GET_STATUS) {
			struct lota_ipc_status status;

			memset(&status, 0, sizeof(status));
			status.attest_count = FIRST_ATTEST_COUNT;
			status.last_attest_time = (uint64_t)time(NULL);
			if (mock_send(client_fd, LOTA_IPC_OK, &status,
				      sizeof(status)) < 0)
				return;
			continue;
		}

		if (req.cmd == LOTA_IPC_CMD_SUBSCRIBE) {
			struct lota_ipc_subscribe_request sub;
			char line[32];

			memset(&sub, 0, sizeof(sub));
			if (req.payload_len >= sizeof(sub))
				memcpy(&sub, payload, sizeof(sub));

			mask = sub.event_mask;
			snprintf(line, sizeof(line), "0x%08x", mask);
			write_line(mask_path, line);

			if (mock_send(client_fd, LOTA_IPC_OK, NULL, 0) < 0)
				return;

			subscribed_at = time(NULL);
			if (mock_push_round(client_fd, mask) < 0)
				return;
			continue;
		}

		if (req.cmd == LOTA_IPC_CMD_PROTECT_PID) {
			int due = subscribed_at != 0 &&
				  time(NULL) - subscribed_at >=
					  PROTECT_HOLD_SEC;

			if (!due) {
				if (mock_send(client_fd, LOTA_IPC_ERR_INTERNAL,
					      NULL, 0) < 0)
					return;
				continue;
			}

			if (mock_send(client_fd, LOTA_IPC_OK, NULL, 0) < 0)
				return;
			write_line(protect_path, "ok");
			continue;
		}

		if (mock_send(client_fd, LOTA_IPC_OK, NULL, 0) < 0)
			return;
	}
}

static pid_t start_mock_agent(void)
{
	struct sockaddr_un addr;
	int listen_fd;
	pid_t pid;

	listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (listen_fd < 0)
		return -1;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1);

	if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(listen_fd);
		return -1;
	}

	if (listen(listen_fd, 4) < 0) {
		close(listen_fd);
		unlink(sock_path);
		return -1;
	}

	pid = fork();
	if (pid < 0) {
		close(listen_fd);
		unlink(sock_path);
		return -1;
	}

	if (pid == 0) {
		for (;;) {
			int client_fd = accept(listen_fd, NULL, NULL);

			if (client_fd < 0)
				_exit(99);
			mock_serve(client_fd);
			close(client_fd);
		}
	}

	close(listen_fd);
	usleep(30000); /* let the child reach accept() */
	return pid;
}

/* Hook output */

/* @key from the status file, or -1 */
static long status_field(const char *key)
{
	char line[256];
	size_t keylen = strlen(key);
	long value = -1;
	FILE *f;

	f = fopen(status_path, "r");
	if (!f)
		return -1;

	while (fgets(line, sizeof(line), f)) {
		if (strncmp(line, key, keylen) == 0 && line[keylen] == '=') {
			value = strtol(line + keylen + 1, NULL, 0);
			break;
		}
	}

	fclose(f);
	return value;
}

static long read_mask(void)
{
	char line[32];
	long value = -1;
	FILE *f;

	f = fopen(mask_path, "r");
	if (!f)
		return -1;

	if (fgets(line, sizeof(line), f))
		value = strtol(line, NULL, 0);

	fclose(f);
	return value;
}

static int wait_for_file(const char *path, int timeout_sec)
{
	for (int i = 0; i < timeout_sec * 10; i++) {
		struct stat st;

		if (stat(path, &st) == 0)
			return 0;
		usleep(100000);
	}

	return -1;
}

/* Tests */

static void *hook_lib;

/*
 * Activation matches the executable path, so the test binary names itself
 * rather than depend on where the build tree sits.
 */
static int load_hook(void)
{
	char exe[PATH_MAX];
	ssize_t n;

	n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
	if (n < 0)
		return -1;
	exe[n] = '\0';

	setenv("LOTA_HOOK_ACTIVATE_PATH", exe, 1);
	setenv(LOTA_HOOK_ENV_SOCKET, sock_path, 1);
	setenv(LOTA_HOOK_ENV_TOKEN_DIR, tmpdir, 1);
	setenv(LOTA_HOOK_ENV_LOG_LEVEL, "silent", 1);
	setenv(LOTA_HOOK_ENV_REFRESH_SEC, "1", 1);
	setenv(LOTA_HOOK_ENV_PROTECT_DELAY, "0", 1);

	hook_lib = dlopen(LOTA_HOOK_LIB_PATH, RTLD_NOW);
	if (!hook_lib) {
		printf("  dlopen(%s): %s\n", LOTA_HOOK_LIB_PATH, dlerror());
		return -1;
	}

	return 0;
}

/* An attesting host changes no flag for hours: the round must notify */
static void test_the_subscription_covers_an_attestation_round(void)
{
	long mask;

	TEST("the subscription covers an attestation round");

	mask = read_mask();
	if (mask < 0) {
		FAIL("the hook never subscribed");
		return;
	}

	if (!((uint32_t)mask & LOTA_IPC_EVENT_ATTEST)) {
		printf("FAIL: mask 0x%08x has no attestation bit\n",
		       (uint32_t)mask);
		return;
	}

	PASS();
}

/*
 * The hook's own publish writes the cached agent status,
 * so a notified status must land in that cache or the file regresses.
 */
static void test_a_local_publish_keeps_the_notified_status(void)
{
	long count;

	TEST("a hook-local publish keeps the status the round brought");

	if (wait_for_file(protect_path, 20) < 0) {
		FAIL("the registration never landed");
		return;
	}

	/* let the post-registration publish land */
	sleep(1);

	count = status_field("LOTA_ATTEST_COUNT");
	if (count != (long)FRESH_ATTEST_COUNT) {
		printf("FAIL: published count %ld, agent is at %u\n", count,
		       FRESH_ATTEST_COUNT);
		return;
	}

	PASS();
}

int main(void)
{
	pid_t agent;
	char template[] = "/tmp/lota-hook-events-XXXXXX";
	int failures;

	printf("\n=== Wine hook event subscription ===\n\n");

	if (!mkdtemp(template)) {
		perror("mkdtemp");
		return 1;
	}
	snprintf(tmpdir, sizeof(tmpdir), "%s", template);
	snprintf(sock_path, sizeof(sock_path), "%s/agent.sock", tmpdir);
	snprintf(mask_path, sizeof(mask_path), "%s/subscribe.mask", tmpdir);
	snprintf(protect_path, sizeof(protect_path), "%s/protect.ok", tmpdir);
	snprintf(status_path, sizeof(status_path), "%s/%s", tmpdir,
		 LOTA_HOOK_STATUS_FILE);

	agent = start_mock_agent();
	if (agent < 0) {
		printf("  cannot start the mock agent: %s\n", strerror(errno));
		return 2;
	}

	if (load_hook() != 0) {
		kill(agent, SIGKILL);
		waitpid(agent, NULL, 0);
		return 2;
	}

	if (wait_for_file(status_path, 10) < 0)
		printf("  the hook published nothing\n");

	test_the_subscription_covers_an_attestation_round();
	test_a_local_publish_keeps_the_notified_status();

	kill(agent, SIGKILL);
	waitpid(agent, NULL, 0);
	unlink(sock_path);

	printf("\n%d/%d passed\n\n", tests_passed, tests_run);
	failures = tests_run - tests_passed;

	/* the hook's destructor would join its thread on a dead agent */
	fflush(stdout);
	_exit(failures ? 1 : 0);
}
