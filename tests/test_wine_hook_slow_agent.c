/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for the Wine/Proton hook against a slow agent
 *
 * The real library is dlopen()ed (the connection and its deadlines are in
 * the load-time half) against a mock agent that answers correctly but slowly.
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

/* Longer than the hook's socket deadline, short of a dead agent */
#define AGENT_THINK_SEC 3

#define AGENT_ATTEST_COUNT 7u

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

/* short enough that every path built from it fits its buffer */
static char tmpdir[64];
static char sock_path[104];
static char status_path[PATH_MAX];
static char accept_path[PATH_MAX];

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

/* One line per accepted connection */
static void record_accept(void)
{
	int fd = open(accept_path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC,
		      0600);
	FILE *f = fd < 0 ? NULL : fdopen(fd, "a");

	if (!f)
		_exit(91);
	fprintf(f, "accept %ld\n", (long)time(NULL));
	fclose(f);
}

static int count_accepts(void)
{
	char line[64];
	int count = 0;
	FILE *f;

	f = fopen(accept_path, "r");
	if (!f)
		return 0;

	while (fgets(line, sizeof(line), f))
		count++;

	fclose(f);
	return count;
}

/* Only the status answer is slow, as on a host protecting a game */
static void mock_serve(int client_fd)
{
	struct lota_ipc_request req;
	uint8_t payload[256];

	while (mock_recv(client_fd, &req, payload, sizeof(payload)) == 0) {
		if (req.cmd == LOTA_IPC_CMD_GET_STATUS) {
			struct lota_ipc_status status;

			sleep(AGENT_THINK_SEC);

			memset(&status, 0, sizeof(status));
			status.attest_count = AGENT_ATTEST_COUNT;
			status.last_attest_time = (uint64_t)time(NULL);
			status.valid_until = (uint64_t)time(NULL) + 600;
			if (mock_send(client_fd, LOTA_IPC_OK, &status,
				      sizeof(status)) < 0)
				return;
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
			record_accept();
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

static int wait_for_status(int timeout_sec)
{
	for (int i = 0; i < timeout_sec * 10; i++) {
		struct stat st;

		if (stat(status_path, &st) == 0)
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

/* Consumers act on OFFLINE, so a slow agent must not be reported as one */
static void test_a_slow_answer_is_not_an_absent_agent(void)
{
	long offline;
	long count;

	TEST("a slow answer is not an absent agent");

	offline = status_field("LOTA_OFFLINE");
	count = status_field("LOTA_ATTEST_COUNT");

	if (offline != 0) {
		printf("FAIL: published OFFLINE=%ld for an agent that answered\n",
		       offline);
		return;
	}

	if (count != (long)AGENT_ATTEST_COUNT) {
		printf("FAIL: published count %ld, agent answered %u\n", count,
		       AGENT_ATTEST_COUNT);
		return;
	}

	PASS();
}

/*
 * The connection carries the subscription; a reconnect loses notifications
 * and is served no faster.
 */
static void test_the_connection_survives_a_slow_answer(void)
{
	int accepts;

	TEST("the connection survives a slow answer");

	accepts = count_accepts();
	if (accepts != 1) {
		printf("FAIL: %d connections for one agent that answers\n",
		       accepts);
		return;
	}

	PASS();
}

int main(void)
{
	pid_t agent;
	char template[] = "/tmp/lota-hook-slow-XXXXXX";
	int failures;

	printf("\n=== Wine hook against a slow agent ===\n\n");

	if (!mkdtemp(template)) {
		perror("mkdtemp");
		return 1;
	}
	snprintf(tmpdir, sizeof(tmpdir), "%s", template);
	snprintf(sock_path, sizeof(sock_path), "%s/agent.sock", tmpdir);
	snprintf(accept_path, sizeof(accept_path), "%s/accepts", tmpdir);
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

	/* the answer plus the retry a hook that gave up would have made */
	if (wait_for_status(20) < 0)
		printf("  the hook published nothing\n");
	sleep(AGENT_THINK_SEC + 3);

	test_a_slow_answer_is_not_an_absent_agent();
	test_the_connection_survives_a_slow_answer();

	kill(agent, SIGKILL);
	waitpid(agent, NULL, 0);
	unlink(sock_path);

	printf("\n%d/%d passed\n\n", tests_passed, tests_run);
	failures = tests_run - tests_passed;

	/* the hook's destructor would join its thread on a dead agent */
	fflush(stdout);
	_exit(failures ? 1 : 0);
}
