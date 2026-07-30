/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for selecting the publisher a connection attests for.
 *
 * Title names its publisher; the machine holds one enrollment per publisher.
 * What is pinned here is that the name reaches the agent intact, that name
 * the agent cannot answer for fails the connection instead of silently handing
 * back another publisher's evidence, and that a title naming nobody still connects
 * without the exchange.
 *
 * Child process acts as a mock agent, the parent uses the SDK, and the socket
 * lives in /tmp so the tests need no root.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>

#include "../include/lota_gaming.h"
#include "../include/lota_ipc.h"

static int tests_run;
static int tests_passed;

#define TEST(name)                                         \
	do {                                               \
		tests_run++;                               \
		printf("  [%2d] %-56s ", tests_run, name); \
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

static void SKIP(const char *msg)
{
	tests_passed++;
	printf("SKIP (%s)\n", msg);
}

static char test_socket[64];
static int mock_errno;

/* the publisher a title asks for, and the bytes that name has to arrive as */
static const char *const PROFILE_HEX = "0011223344556677" /* 8 */
				       "8899aabbccddeeff" /* 16 */
				       "0f1e2d3c4b5a6978" /* 24 */
				       "8796a5b4c3d2e1f0"; /* 32 bytes */

static const uint8_t PROFILE_BYTES[32] = {
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
	0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a,
	0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
};

static int socket_errno_is_sandbox(int err)
{
	return err == EPERM || err == EACCES || err == EROFS;
}

static int read_exact(int fd, void *buf, size_t len)
{
	uint8_t *p = buf;
	size_t got = 0;

	while (got < len) {
		ssize_t n = read(fd, p + got, len - got);

		if (n <= 0)
			return -1;
		got += (size_t)n;
	}
	return 0;
}

static int send_result(int fd, uint32_t result)
{
	struct lota_ipc_response resp;

	memset(&resp, 0, sizeof(resp));
	resp.magic = LOTA_IPC_MAGIC;
	resp.version = LOTA_IPC_VERSION;
	resp.result = result;
	resp.payload_len = 0;

	return write(fd, &resp, sizeof(resp)) == (ssize_t)sizeof(resp) ? 0 : -1;
}

/*
 * Scenarios.
 * Exit code is the assertion: the parent reads it back, so mock that saw
 * the wrong bytes fails the test rather than the connection.
 */

/* accept the publisher, after checking the name arrived byte for byte */
static void server_accept_profile(int client_fd)
{
	struct lota_ipc_set_profile payload;
	struct lota_ipc_request req;

	if (read_exact(client_fd, &req, sizeof(req)) < 0)
		_exit(2);
	if (req.magic != LOTA_IPC_MAGIC || req.version != LOTA_IPC_VERSION)
		_exit(3);
	if (req.cmd != LOTA_IPC_CMD_SET_PROFILE)
		_exit(4);
	if (req.payload_len != sizeof(payload))
		_exit(5);
	if (read_exact(client_fd, &payload, sizeof(payload)) < 0)
		_exit(6);
	if (memcmp(payload.profile_id, PROFILE_BYTES, sizeof(PROFILE_BYTES)))
		_exit(7);
	if (send_result(client_fd, LOTA_IPC_OK) < 0)
		_exit(8);

	usleep(50000);
}

/* the host holds no enrollment for that publisher */
static void server_refuse_profile(int client_fd)
{
	struct lota_ipc_set_profile payload;
	struct lota_ipc_request req;

	if (read_exact(client_fd, &req, sizeof(req)) < 0)
		_exit(2);
	if (read_exact(client_fd, &payload, sizeof(payload)) < 0)
		_exit(3);
	if (send_result(client_fd, LOTA_IPC_ERR_UNKNOWN_PROFILE) < 0)
		_exit(4);

	usleep(50000);
}

/* title that names nobody must not send SET_PROFILE at all */
static void server_expect_no_profile(int client_fd)
{
	struct lota_ipc_request req;

	if (read_exact(client_fd, &req, sizeof(req)) < 0)
		_exit(0); /* connection closed with nothing sent: correct */
	if (req.cmd == LOTA_IPC_CMD_SET_PROFILE)
		_exit(2);

	_exit(0);
}

typedef void (*scenario_fn)(int client_fd);

static pid_t start_mock_agent(scenario_fn scenario)
{
	struct sockaddr_un addr;
	int listen_fd;
	pid_t pid;

	mock_errno = 0;
	listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (listen_fd < 0) {
		mock_errno = errno;
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, test_socket, sizeof(addr.sun_path) - 1);
	unlink(test_socket);

	if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		mock_errno = errno;
		close(listen_fd);
		return -1;
	}
	if (listen(listen_fd, 1) < 0) {
		mock_errno = errno;
		close(listen_fd);
		unlink(test_socket);
		return -1;
	}

	pid = fork();
	if (pid < 0) {
		mock_errno = errno;
		close(listen_fd);
		unlink(test_socket);
		return -1;
	}

	if (pid == 0) {
		int client_fd = accept(listen_fd, NULL, NULL);

		close(listen_fd);
		if (client_fd < 0)
			_exit(99);
		scenario(client_fd);
		close(client_fd);
		_exit(0);
	}

	close(listen_fd);
	usleep(30000);
	return pid;
}

static int wait_agent(pid_t pid)
{
	int status;

	waitpid(pid, &status, 0);
	unlink(test_socket);
	if (WIFEXITED(status))
		return WEXITSTATUS(status);
	return -1;
}

static void test_named_publisher_reaches_the_agent(void)
{
	struct lota_connect_opts opts = { 0 };
	struct lota_client *client;
	pid_t server;
	int rc;

	TEST("a named publisher is sent to the agent as its 32 bytes");

	server = start_mock_agent(server_accept_profile);
	if (server < 0) {
		if (socket_errno_is_sandbox(mock_errno)) {
			SKIP("no unix sockets in this sandbox");
			return;
		}
		FAIL("could not start the mock agent");
		return;
	}

	opts.struct_size = sizeof(opts);
	opts.socket_path = test_socket;
	opts.timeout_ms = 2000;
	opts.publisher_profile = PROFILE_HEX;

	client = lota_connect_opts(&opts);
	if (client)
		lota_disconnect(client);

	rc = wait_agent(server);
	if (!client) {
		FAIL("connection failed although the agent accepted the "
		     "publisher");
		return;
	}
	if (rc != 0) {
		char msg[80];

		snprintf(msg, sizeof(msg),
			 "mock agent rejected the exchange (code %d)", rc);
		FAIL(msg);
		return;
	}
	PASS();
}

static void test_unknown_publisher_fails_the_connection(void)
{
	struct lota_connect_opts opts = { 0 };
	struct lota_client *client;
	pid_t server;

	TEST("an unknown publisher fails the connection, no fallback");

	server = start_mock_agent(server_refuse_profile);
	if (server < 0) {
		if (socket_errno_is_sandbox(mock_errno)) {
			SKIP("no unix sockets in this sandbox");
			return;
		}
		FAIL("could not start the mock agent");
		return;
	}

	opts.struct_size = sizeof(opts);
	opts.socket_path = test_socket;
	opts.timeout_ms = 2000;
	opts.publisher_profile = PROFILE_HEX;

	client = lota_connect_opts(&opts);
	wait_agent(server);

	if (client) {
		FAIL("a title was handed a connection the agent cannot answer "
		     "for");
		lota_disconnect(client);
		return;
	}
	PASS();
}

static void test_malformed_publisher_is_refused(void)
{
	struct lota_connect_opts opts = { 0 };
	struct lota_client *client;
	pid_t server;

	TEST("a malformed publisher name never reaches the agent");

	server = start_mock_agent(server_expect_no_profile);
	if (server < 0) {
		if (socket_errno_is_sandbox(mock_errno)) {
			SKIP("no unix sockets in this sandbox");
			return;
		}
		FAIL("could not start the mock agent");
		return;
	}

	opts.struct_size = sizeof(opts);
	opts.socket_path = test_socket;
	opts.timeout_ms = 2000;
	opts.publisher_profile = "not-a-sha256";

	client = lota_connect_opts(&opts);
	wait_agent(server);

	if (client) {
		FAIL("a name that is not a profile identity was accepted");
		lota_disconnect(client);
		return;
	}
	PASS();
}

static void test_no_publisher_sends_nothing(void)
{
	struct lota_connect_opts opts = { 0 };
	struct lota_client *client;
	pid_t server;
	int rc;

	TEST("naming no publisher connects without the exchange");

	server = start_mock_agent(server_expect_no_profile);
	if (server < 0) {
		if (socket_errno_is_sandbox(mock_errno)) {
			SKIP("no unix sockets in this sandbox");
			return;
		}
		FAIL("could not start the mock agent");
		return;
	}

	opts.struct_size = sizeof(opts);
	opts.socket_path = test_socket;
	opts.timeout_ms = 2000;

	client = lota_connect_opts(&opts);
	if (client)
		lota_disconnect(client);

	rc = wait_agent(server);
	if (!client) {
		FAIL("a single-publisher title could not connect");
		return;
	}
	if (rc != 0) {
		FAIL("the agent saw a SET_PROFILE nobody asked for");
		return;
	}
	PASS();
}

int main(void)
{
	printf("=== Publisher selection tests ===\n\n");

	snprintf(test_socket, sizeof(test_socket), "/tmp/lota-pubsel.%d.sock",
		 getpid());

	test_named_publisher_reaches_the_agent();
	test_unknown_publisher_fails_the_connection();
	test_malformed_publisher_is_refused();
	test_no_publisher_sends_nothing();

	printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
