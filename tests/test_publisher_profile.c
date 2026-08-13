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

/* the agent refused the command itself, not the publisher */
static void server_bad_request(int client_fd)
{
	struct lota_ipc_set_profile payload;
	struct lota_ipc_request req;

	if (read_exact(client_fd, &req, sizeof(req)) < 0)
		_exit(2);
	if (read_exact(client_fd, &payload, sizeof(payload)) < 0)
		_exit(3);
	if (send_result(client_fd, LOTA_IPC_ERR_BAD_REQUEST) < 0)
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

/*
 * Refusal of the command is not refusal of the publisher.
 * Agent rejects malformed SET_PROFILE before any handler sees it, and reporting
 * that as unknown publisher sends integrator to check an identity that was
 * never the problem.
 */
static void test_bad_request_is_not_an_unknown_publisher(void)
{
	struct lota_connect_opts opts = { .struct_size = sizeof(opts) };
	struct lota_client *client;
	pid_t server;

	TEST("a refused command does not read as an unknown publisher");

	server = start_mock_agent(server_bad_request);
	if (server < 0) {
		if (socket_errno_is_sandbox(mock_errno)) {
			SKIP("no unix sockets in this sandbox");
			return;
		}
		FAIL("could not start the mock agent");
		return;
	}

	opts.socket_path = test_socket;
	opts.timeout_ms = 1000;
	opts.publisher_profile = PROFILE_HEX;

	client = lota_connect_opts(&opts);
	wait_agent(server);

	if (client) {
		FAIL("a refused SET_PROFILE still produced a connection");
		lota_disconnect(client);
		return;
	}
	if (lota_connect_last_error() != LOTA_ERR_INVALID_ARG) {
		FAIL("a bad request was reported as something else");
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

/*
 * "Nobody here has agreed to that publisher" is a screen for the player,
 * not error to log, so the title has to be able to tell it from every other
 * reason a connection fails.
 */
static void server_consent_required(int client_fd)
{
	struct lota_ipc_set_profile payload;
	struct lota_ipc_request req;

	if (read_exact(client_fd, &req, sizeof(req)) < 0)
		_exit(2);
	if (read_exact(client_fd, &payload, sizeof(payload)) < 0)
		_exit(3);
	if (send_result(client_fd, LOTA_IPC_ERR_CONSENT_REQUIRED) < 0)
		_exit(4);

	usleep(50000);
}

static void test_consent_required_is_distinguishable(void)
{
	struct lota_connect_opts opts = { 0 };
	struct lota_client *client;
	pid_t server;

	TEST("a publisher nobody agreed to is reported as needing consent");

	server = start_mock_agent(server_consent_required);
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
		FAIL("connected to a publisher nobody agreed to");
		lota_disconnect(client);
		return;
	}
	if (lota_connect_last_error() != LOTA_ERR_CONSENT_REQUIRED) {
		FAIL("the title cannot tell consent from any other failure");
		return;
	}
	PASS();
}

/*
 * struct_size is what lets these options grow without second entry point,
 * so caller that never set it has to be refused rather than guessed at.
 * Nothing here needs agent: the size is settled before socket is touched, which
 * is also why caller that gets it wrong sees the same NULL on every machine.
 */
static void server_status_token_only(int client_fd)
{
	struct lota_ipc_set_profile profile;
	struct lota_ipc_response resp;
	struct lota_ipc_status status;
	struct lota_ipc_request req;

	if (read_exact(client_fd, &req, sizeof(req)) < 0)
		_exit(2);
	if (req.cmd != LOTA_IPC_CMD_SET_PROFILE)
		_exit(3);
	if (read_exact(client_fd, &profile, sizeof(profile)) < 0)
		_exit(4);
	if (send_result(client_fd, LOTA_IPC_OK) < 0)
		_exit(5);

	if (read_exact(client_fd, &req, sizeof(req)) < 0)
		_exit(6);
	if (req.cmd != LOTA_IPC_CMD_GET_STATUS)
		_exit(7);

	memset(&resp, 0, sizeof(resp));
	resp.magic = LOTA_IPC_MAGIC;
	resp.version = LOTA_IPC_VERSION;
	resp.result = LOTA_IPC_OK;
	resp.payload_len = sizeof(status);

	memset(&status, 0, sizeof(status));
	status.flags = LOTA_STATUS_TPM_OK | LOTA_STATUS_TOKEN_ONLY;

	if (write(client_fd, &resp, sizeof(resp)) != (ssize_t)sizeof(resp) ||
	    write(client_fd, &status, sizeof(status)) !=
		    (ssize_t)sizeof(status))
		_exit(8);

	usleep(50000);
}

typedef void (*scenario_fn)(int client_fd);

static void test_connect_struct_size(void)
{
	struct lota_client *client;

	TEST("connect: unset struct_size -> NULL with INVALID_ARG");
	{
		struct lota_connect_opts zero = {
			.socket_path = test_socket,
			.timeout_ms = 100,
		};

		client = lota_connect_opts(&zero);
		if (client) {
			FAIL("options that never stated their size were "
			     "accepted");
			lota_disconnect(client);
			return;
		}
		if (lota_connect_last_error() != LOTA_ERR_INVALID_ARG) {
			FAIL("the caller cannot tell a bad struct from a "
			     "missing agent");
			return;
		}
	}
	PASS();

	TEST("connect: undersized struct_size -> NULL");
	{
		struct lota_connect_opts small = {
			.struct_size = LOTA_CONNECT_OPTS_SIZE_MIN - 1,
			.socket_path = test_socket,
			.timeout_ms = 100,
		};

		client = lota_connect_opts(&small);
		if (client) {
			FAIL("options smaller than the 1.0 surface were "
			     "accepted");
			lota_disconnect(client);
			return;
		}
		if (lota_connect_last_error() != LOTA_ERR_INVALID_ARG) {
			FAIL("an undersized struct was not reported as one");
			return;
		}
	}
	PASS();

	TEST("connect: struct_size from a newer caller reaches the socket");
	{
		/* caller built against later header passes a size this build
		 * does not know; it is answered by the members it does */
		struct lota_connect_opts bigger = {
			.struct_size = sizeof(bigger) + 64,
			.socket_path = "/nonexistent/lota-agent.sock",
			.timeout_ms = 100,
		};

		client = lota_connect_opts(&bigger);
		if (client) {
			FAIL("connected to a socket that does not exist");
			lota_disconnect(client);
			return;
		}
		if (lota_connect_last_error() == LOTA_ERR_INVALID_ARG) {
			FAIL("a caller built against a newer header was "
			     "refused");
			return;
		}
	}
	PASS();
}

static void test_token_only_publisher_is_distinguishable(void)
{
	struct lota_connect_opts opts = { 0 };
	struct lota_status status;
	struct lota_client *client;
	pid_t server;

	TEST("a publisher who runs no verifier is reported as token-only");

	server = start_mock_agent(server_status_token_only);
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
	if (!client) {
		FAIL("connection failed although the agent accepted the "
		     "publisher");
		wait_agent(server);
		return;
	}

	memset(&status, 0, sizeof(status));
	if (lota_get_status(client, &status) != LOTA_OK) {
		FAIL("status request failed");
		lota_disconnect(client);
		wait_agent(server);
		return;
	}
	lota_disconnect(client);
	wait_agent(server);

	/*
	 * Title has to be able to tell "nobody verifies here, check the token yourself"
	 * from "this machine failed something"
	 * and both look like clear ATTESTED bit...
	 */
	if (!(status.flags & LOTA_FLAG_TOKEN_ONLY)) {
		FAIL("the token-only publisher was not surfaced as one");
		return;
	}
	if (status.flags & LOTA_FLAG_ATTESTED) {
		FAIL("a verdict was claimed for a publisher nobody reports to");
		return;
	}
	PASS();
}

/* two headers state the same bits;
 * title reads the SDK name for what the agent set under the IPC name */

static void test_flag_constants_agree(void)
{
	TEST("the token-only flag is the same bit on both sides");
	if (LOTA_FLAG_TOKEN_ONLY != LOTA_STATUS_TOKEN_ONLY ||
	    LOTA_FLAG_ATTESTED != LOTA_STATUS_ATTESTED ||
	    LOTA_FLAG_PROTECTED_TERMINATED !=
		    LOTA_STATUS_PROTECTED_TERMINATED) {
		FAIL("IPC and SDK status flags disagree");
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
	test_bad_request_is_not_an_unknown_publisher();
	test_no_publisher_sends_nothing();
	test_consent_required_is_distinguishable();
	test_connect_struct_size();
	test_token_only_publisher_is_distinguishable();
	test_flag_constants_agree();

	printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
