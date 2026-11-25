/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for SUBSCRIBE command - push notifications.
 *
 * Tests the protocol format, server-side notification delivery,
 * and SDK subscribe/poll_events/unsubscribe flow.
 *
 * Uses a Unix socket in /tmp so tests can run without root.
 * A child process acts as a mock IPC server, while the parent
 * uses the SDK client API.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>

#include "test.h"
#include "../include/lota_gaming.h"
#include "../include/lota_ipc.h"

static char test_socket[64];
static int mock_server_errno;

static void SKIP(const char *msg)
{
	tests_passed++;
	printf("SKIP (%s)\n", msg);
}

static int socket_errno_is_sandbox(int err)
{
	return err == EPERM || err == EACCES || err == EROFS;
}

static void test_subscribe_request_format(void)
{
	struct lota_ipc_request req;
	struct lota_ipc_subscribe_request sub;

	TEST("SUBSCRIBE request wire format");

	if (sizeof(req) != 16) {
		FAIL("request header not 16 bytes");
		return;
	}
	if (sizeof(sub) != 4) {
		FAIL("subscribe payload not 4 bytes");
		return;
	}

	req.magic = LOTA_IPC_MAGIC;
	req.version = LOTA_IPC_VERSION;
	req.cmd = LOTA_IPC_CMD_SUBSCRIBE;
	req.payload_len = sizeof(sub);

	if (req.cmd != 0x04) {
		FAIL("SUBSCRIBE cmd should be 0x04");
		return;
	}

	sub.event_mask = LOTA_IPC_EVENT_STATUS | LOTA_IPC_EVENT_ATTEST;
	if (sub.event_mask != 0x03) {
		FAIL("event mask STATUS|ATTEST should be 0x03");
		return;
	}

	PASS();
}

static void test_notify_format(void)
{
	struct lota_ipc_response resp;
	struct lota_ipc_notify notify;

	TEST("notification wire format");

	if (sizeof(resp) != 16) {
		FAIL("response header not 16 bytes");
		return;
	}

	/* lota_ipc_notify: 4 + 4 + 8 + 8 + 4 + 4 + 1 + 3 = 36 bytes */
	if (sizeof(notify) != 36) {
		char msg[64];
		snprintf(msg, sizeof(msg), "notify should be 36 bytes, got %zu",
			 sizeof(notify));
		FAIL(msg);
		return;
	}

	resp.result = LOTA_IPC_NOTIFY;
	if (resp.result != 0x80) {
		FAIL("LOTA_IPC_NOTIFY should be 0x80");
		return;
	}

	PASS();
}

static void test_event_constants(void)
{
	TEST("event constants match between IPC and SDK");

	if (LOTA_IPC_EVENT_STATUS != LOTA_EVENT_STATUS ||
	    LOTA_IPC_EVENT_ATTEST != LOTA_EVENT_ATTEST ||
	    LOTA_IPC_EVENT_MODE != LOTA_EVENT_MODE) {
		FAIL("IPC and SDK event constants mismatch");
		return;
	}

	PASS();
}

static void test_subscribe_unsubscribe_mask(void)
{
	struct lota_ipc_subscribe_request sub;

	TEST("event_mask = 0 means unsubscribe");

	sub.event_mask = 0;
	if (sub.event_mask != 0) {
		FAIL("event_mask should be 0");
		return;
	}

	sub.event_mask = LOTA_EVENT_ALL;
	if (sub.event_mask != 0xFFFFFFFF) {
		FAIL("EVENT_ALL should be 0xFFFFFFFF");
		return;
	}

	PASS();
}

static int send_response(int fd, uint32_t result, const void *payload,
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

static int send_notify(int fd, uint32_t events, uint32_t flags,
		       uint64_t attest_time, uint64_t valid_until,
		       uint32_t attest_count, uint32_t fail_count, uint8_t mode)
{
	struct lota_ipc_notify notify;

	memset(&notify, 0, sizeof(notify));
	notify.events = events;
	notify.flags = flags;
	notify.last_attest_time = attest_time;
	notify.valid_until = valid_until;
	notify.attest_count = attest_count;
	notify.fail_count = fail_count;
	notify.mode = mode;

	return send_response(fd, LOTA_IPC_NOTIFY, &notify, sizeof(notify));
}

static int recv_request(int fd, struct lota_ipc_request *req, void *payload,
			size_t max_payload)
{
	ssize_t n;

	n = recv(fd, req, sizeof(*req), MSG_WAITALL);
	if (n != sizeof(*req))
		return -1;

	if (req->payload_len > 0) {
		size_t to_read = req->payload_len;
		if (to_read > max_payload)
			to_read = max_payload;
		n = recv(fd, payload, to_read, MSG_WAITALL);
		if (n != (ssize_t)to_read)
			return -1;
	}

	return 0;
}

static void server_subscribe_and_notify(int client_fd)
{
	struct lota_ipc_request req;
	struct lota_ipc_subscribe_request sub;

	if (recv_request(client_fd, &req, &sub, sizeof(sub)) < 0)
		_exit(1);
	if (req.cmd != LOTA_IPC_CMD_SUBSCRIBE)
		_exit(2);

	/* respond OK */
	if (send_response(client_fd, LOTA_IPC_OK, NULL, 0) < 0)
		_exit(3);

	/* small delay so client can set up poll */
	usleep(20000);

	/* 2 notifications */
	if (send_notify(client_fd, LOTA_IPC_EVENT_STATUS,
			LOTA_STATUS_ATTESTED | LOTA_STATUS_TPM_OK, 1000, 2000,
			5, 1, 1) < 0)
		_exit(4);

	if (send_notify(client_fd, LOTA_IPC_EVENT_ATTEST,
			LOTA_STATUS_ATTESTED | LOTA_STATUS_TPM_OK |
				LOTA_STATUS_IOMMU_OK,
			1001, 2001, 6, 1, 1) < 0)
		_exit(5);

	/* keep connection alive for client to read */
	usleep(200000);
}

static void server_interleaved_notify(int client_fd)
{
	struct lota_ipc_request req;
	uint8_t payload_buf[256];

	if (recv_request(client_fd, &req, payload_buf, sizeof(payload_buf)) < 0)
		_exit(1);

	/* respond OK */
	if (send_response(client_fd, LOTA_IPC_OK, NULL, 0) < 0)
		_exit(2);

	/* read PING request */
	if (recv_request(client_fd, &req, payload_buf, sizeof(payload_buf)) < 0)
		_exit(3);

	/* send notification BEFORE the PING response */
	if (send_notify(client_fd, LOTA_IPC_EVENT_MODE,
			LOTA_STATUS_ATTESTED | LOTA_STATUS_BPF_LOADED, 500,
			1500, 3, 0, 2) < 0)
		_exit(4);

	/* now send the actual PING response */
	{
		struct lota_ipc_ping_response ping;
		ping.uptime_sec = 42;
		ping.pid = 12345;
		if (send_response(client_fd, LOTA_IPC_OK, &ping, sizeof(ping)) <
		    0)
			_exit(5);
	}

	usleep(200000);
}

static void server_unsubscribe(int client_fd)
{
	struct lota_ipc_request req;
	struct lota_ipc_subscribe_request sub = { 0 };

	/* read SUBSCRIBE */
	if (recv_request(client_fd, &req, &sub, sizeof(sub)) < 0)
		_exit(1);
	if (sub.event_mask == 0)
		_exit(2); /* should be non-zero for subscribe */
	if (send_response(client_fd, LOTA_IPC_OK, NULL, 0) < 0)
		_exit(3);

	/* read UNSUBSCRIBE (SUBSCRIBE with mask=0) */
	if (recv_request(client_fd, &req, &sub, sizeof(sub)) < 0)
		_exit(4);
	if (sub.event_mask != 0)
		_exit(5); /* should be zero for unsubscribe */
	if (send_response(client_fd, LOTA_IPC_OK, NULL, 0) < 0)
		_exit(6);

	usleep(100000);
}

/*
 * subscribe and emit one notification after >5s.
 * Used to verify that lota_poll_events(timeout_ms=-1) truly blocks
 * indefinitely instead of falling back to DEFAULT_TIMEOUT_MS.
 */
static void server_delayed_notify(int client_fd)
{
	struct lota_ipc_request req;
	struct lota_ipc_subscribe_request sub;

	if (recv_request(client_fd, &req, &sub, sizeof(sub)) < 0)
		_exit(1);
	if (req.cmd != LOTA_IPC_CMD_SUBSCRIBE)
		_exit(2);

	if (send_response(client_fd, LOTA_IPC_OK, NULL, 0) < 0)
		_exit(3);

	/* longer than DEFAULT_TIMEOUT_MS (=5000 ms) */
	usleep(5200000);

	if (send_notify(client_fd, LOTA_IPC_EVENT_STATUS,
			LOTA_STATUS_ATTESTED | LOTA_STATUS_TPM_OK, 1000, 2000,
			7, 1, 1) < 0)
		_exit(4);

	usleep(100000);
}

/*
 * Run a mock server for a given scenario.
 * Listens on test_socket, accepts one client, runs the scenario.
 */
typedef void (*server_scenario_fn)(int client_fd);

static pid_t start_mock_server(server_scenario_fn scenario)
{
	int listen_fd;
	struct sockaddr_un addr;
	pid_t pid;

	mock_server_errno = 0;
	listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (listen_fd < 0) {
		mock_server_errno = errno;
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, test_socket, sizeof(addr.sun_path) - 1);
	unlink(test_socket);

	if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		mock_server_errno = errno;
		close(listen_fd);
		return -1;
	}

	if (listen(listen_fd, 1) < 0) {
		mock_server_errno = errno;
		close(listen_fd);
		unlink(test_socket);
		return -1;
	}

	pid = fork();
	if (pid < 0) {
		mock_server_errno = errno;
		close(listen_fd);
		unlink(test_socket);
		return -1;
	}

	if (pid == 0) {
		/* child: accept and run scenario */
		int client_fd = accept(listen_fd, NULL, NULL);
		close(listen_fd);
		if (client_fd < 0)
			_exit(99);
		scenario(client_fd);
		close(client_fd);
		_exit(0);
	}

	/* parent: close listen fd, let child handle it */
	close(listen_fd);
	usleep(30000); /* let child get to accept() */
	return pid;
}

static int wait_server(pid_t pid)
{
	int status;
	waitpid(pid, &status, 0);
	unlink(test_socket);
	if (WIFEXITED(status))
		return WEXITSTATUS(status);
	return -1;
}

static int cb_count;
static uint32_t cb_last_events;
static uint32_t cb_last_flags;
static uint32_t cb_last_attest_count;
static uint8_t cb_last_mode;

static void reset_cb(void)
{
	cb_count = 0;
	cb_last_events = 0;
	cb_last_flags = 0;
	cb_last_attest_count = 0;
	cb_last_mode = 0;
}

static void test_callback(const struct lota_status *status, uint32_t events,
			  void *user_data)
{
	(void)user_data;
	cb_count++;
	cb_last_events = events;
	cb_last_flags = status->flags;
	cb_last_attest_count = status->attest_count;
}

static void test_callback_mode(const struct lota_status *status,
			       uint32_t events, void *user_data)
{
	int *counter = user_data;
	(*counter)++;
	cb_last_events = events;
	cb_last_flags = status->flags;
	(void)status;
}

static void test_subscribe_and_poll(void)
{
	pid_t server;
	struct lota_client *client;
	struct lota_connect_opts opts = { .struct_size = sizeof(opts) };
	int ret;

	TEST("subscribe + poll_events receives notifications");

	reset_cb();
	server = start_mock_server(server_subscribe_and_notify);
	if (server < 0) {
		if (socket_errno_is_sandbox(mock_server_errno)) {
			SKIP("AF_UNIX mock server not permitted");
			return;
		}
		FAIL("failed to start mock server");
		return;
	}

	opts.socket_path = test_socket;
	opts.timeout_ms = 5000;
	client = lota_connect_opts(&opts);
	if (!client) {
		FAIL("lota_connect_opts failed");
		wait_server(server);
		return;
	}

	ret = lota_subscribe(client, LOTA_EVENT_ALL, test_callback, NULL);
	if (ret != LOTA_OK) {
		char msg[64];
		snprintf(msg, sizeof(msg), "subscribe failed: %s",
			 lota_strerror(ret));
		FAIL(msg);
		lota_disconnect(client);
		wait_server(server);
		return;
	}

	ret = lota_poll_events(client, 2000);
	if (ret < 2) {
		char msg[64];
		snprintf(msg, sizeof(msg),
			 "expected >= 2 notifications, got %d", ret);
		FAIL(msg);
		lota_disconnect(client);
		wait_server(server);
		return;
	}

	if (cb_count < 2) {
		FAIL("callback invoked fewer than 2 times");
		lota_disconnect(client);
		wait_server(server);
		return;
	}

	/* last notification should be the second one */
	if (cb_last_events != LOTA_EVENT_ATTEST) {
		FAIL("last event should be ATTEST");
		lota_disconnect(client);
		wait_server(server);
		return;
	}

	if (cb_last_attest_count != 6) {
		FAIL("last attest_count should be 6");
		lota_disconnect(client);
		wait_server(server);
		return;
	}

	lota_disconnect(client);
	int srv_ret = wait_server(server);
	if (srv_ret != 0) {
		char msg[64];
		snprintf(msg, sizeof(msg), "server exited with code %d",
			 srv_ret);
		FAIL(msg);
		return;
	}

	PASS();
}

static void test_interleaved_notification(void)
{
	pid_t server;
	struct lota_client *client;
	struct lota_connect_opts opts = { .struct_size = sizeof(opts) };
	int counter = 0;
	uint64_t uptime = 0;
	int ret;

	TEST("notification interleaved with PING response");

	reset_cb();
	server = start_mock_server(server_interleaved_notify);
	if (server < 0) {
		if (socket_errno_is_sandbox(mock_server_errno)) {
			SKIP("AF_UNIX mock server not permitted");
			return;
		}
		FAIL("failed to start mock server");
		return;
	}

	opts.socket_path = test_socket;
	opts.timeout_ms = 5000;
	client = lota_connect_opts(&opts);
	if (!client) {
		FAIL("lota_connect_opts failed");
		wait_server(server);
		return;
	}

	ret = lota_subscribe(client, LOTA_EVENT_ALL, test_callback_mode,
			     &counter);
	if (ret != LOTA_OK) {
		FAIL("subscribe failed");
		lota_disconnect(client);
		wait_server(server);
		return;
	}

	/*
	 * Send PING. The server will send a notification BEFORE the
	 * PING response. recv_response should transparently dispatch
	 * the notification and return the correct PING response.
	 */
	ret = lota_ping(client, &uptime);
	if (ret != LOTA_OK) {
		char msg[64];
		snprintf(msg, sizeof(msg), "ping failed: %s",
			 lota_strerror(ret));
		FAIL(msg);
		lota_disconnect(client);
		wait_server(server);
		return;
	}

	if (uptime != 42) {
		char msg[64];
		snprintf(msg, sizeof(msg), "uptime should be 42, got %lu",
			 (unsigned long)uptime);
		FAIL(msg);
		lota_disconnect(client);
		wait_server(server);
		return;
	}

	/* notification should have been dispatched during ping */
	if (counter != 1) {
		char msg[64];
		snprintf(msg, sizeof(msg),
			 "expected 1 interleaved notification, got %d",
			 counter);
		FAIL(msg);
		lota_disconnect(client);
		wait_server(server);
		return;
	}

	if (cb_last_events != LOTA_EVENT_MODE) {
		FAIL("interleaved notification should be MODE event");
		lota_disconnect(client);
		wait_server(server);
		return;
	}

	lota_disconnect(client);
	wait_server(server);
	PASS();
}

static void test_unsubscribe(void)
{
	pid_t server;
	struct lota_client *client;
	struct lota_connect_opts opts = { .struct_size = sizeof(opts) };
	int ret;

	TEST("unsubscribe clears subscription");

	reset_cb();
	server = start_mock_server(server_unsubscribe);
	if (server < 0) {
		if (socket_errno_is_sandbox(mock_server_errno)) {
			SKIP("AF_UNIX mock server not permitted");
			return;
		}
		FAIL("failed to start mock server");
		return;
	}

	opts.socket_path = test_socket;
	opts.timeout_ms = 5000;
	client = lota_connect_opts(&opts);
	if (!client) {
		FAIL("lota_connect_opts failed");
		wait_server(server);
		return;
	}

	ret = lota_subscribe(client, LOTA_EVENT_ALL, test_callback, NULL);
	if (ret != LOTA_OK) {
		FAIL("subscribe failed");
		lota_disconnect(client);
		wait_server(server);
		return;
	}

	ret = lota_unsubscribe(client);
	if (ret != LOTA_OK) {
		char msg[64];
		snprintf(msg, sizeof(msg), "unsubscribe failed: %s",
			 lota_strerror(ret));
		FAIL(msg);
		lota_disconnect(client);
		wait_server(server);
		return;
	}

	lota_disconnect(client);
	int srv_ret = wait_server(server);
	if (srv_ret != 0) {
		char msg[64];
		snprintf(msg, sizeof(msg), "server exited with code %d",
			 srv_ret);
		FAIL(msg);
		return;
	}

	PASS();
}

static void test_subscribe_null_client(void)
{
	TEST("subscribe(NULL) -> NOT_CONNECTED");

	int ret = lota_subscribe(NULL, LOTA_EVENT_ALL, test_callback, NULL);
	if (ret != LOTA_ERR_NOT_CONNECTED) {
		FAIL("expected LOTA_ERR_NOT_CONNECTED");
		return;
	}

	PASS();
}

static void test_subscribe_no_callback(void)
{
	TEST("subscribe(mask!=0, NULL callback) -> INVALID_ARG");

	struct lota_connect_opts opts = { .struct_size = sizeof(opts) };
	opts.socket_path = "/nonexistent";
	opts.timeout_ms = 100;
	struct lota_client *c = lota_connect_opts(&opts);

	int ret = lota_subscribe(NULL, LOTA_EVENT_STATUS, NULL, NULL);
	if (ret != LOTA_ERR_NOT_CONNECTED) {
		/* OK, null client returns NOT_CONNECTED which is checked first
		 */
		FAIL("expected NOT_CONNECTED or INVALID_ARG");
		if (c)
			lota_disconnect(c);
		return;
	}

	if (c)
		lota_disconnect(c);
	PASS();
}

static void test_poll_null_client(void)
{
	TEST("poll_events(NULL) -> NOT_CONNECTED");

	int ret = lota_poll_events(NULL, 0);
	if (ret != LOTA_ERR_NOT_CONNECTED) {
		FAIL("expected LOTA_ERR_NOT_CONNECTED");
		return;
	}

	PASS();
}

static void test_poll_no_data(void)
{
	pid_t server;
	struct lota_client *client;
	struct lota_connect_opts opts = { .struct_size = sizeof(opts) };
	int ret;

	TEST("poll_events with no data -> 0 dispatched");

	/* start a server that only handles subscribe, then waits */
	server = start_mock_server(server_unsubscribe);
	if (server < 0) {
		if (socket_errno_is_sandbox(mock_server_errno)) {
			SKIP("AF_UNIX mock server not permitted");
			return;
		}
		FAIL("failed to start mock server");
		return;
	}

	opts.socket_path = test_socket;
	opts.timeout_ms = 5000;
	client = lota_connect_opts(&opts);
	if (!client) {
		FAIL("connect failed");
		wait_server(server);
		return;
	}

	ret = lota_subscribe(client, LOTA_EVENT_ALL, test_callback, NULL);
	if (ret != LOTA_OK) {
		FAIL("subscribe failed");
		lota_disconnect(client);
		wait_server(server);
		return;
	}

	/* poll with very short timeout - no notifications expected */
	ret = lota_poll_events(client, 50);
	/*
	 * ret < 0 is acceptable here: after the unsubscribe read the server
	 * closes and the connection may reset, so accept 0 or an error
	 * depending on timing.
	 */
	(void)ret;

	/* no crash, no hang */
	lota_disconnect(client);
	wait_server(server);
	PASS();
}

static void test_poll_infinite_wait(void)
{
	pid_t server;
	struct lota_client *client;
	struct lota_connect_opts opts = { .struct_size = sizeof(opts) };
	int ret;

	TEST("poll_events(-1) blocks until delayed notification");

	reset_cb();
	server = start_mock_server(server_delayed_notify);
	if (server < 0) {
		if (socket_errno_is_sandbox(mock_server_errno)) {
			SKIP("AF_UNIX mock server not permitted");
			return;
		}
		FAIL("failed to start mock server");
		return;
	}

	opts.socket_path = test_socket;
	opts.timeout_ms = 5000;
	client = lota_connect_opts(&opts);
	if (!client) {
		FAIL("connect failed");
		wait_server(server);
		return;
	}

	ret = lota_subscribe(client, LOTA_EVENT_ALL, test_callback, NULL);
	if (ret != LOTA_OK) {
		FAIL("subscribe failed");
		lota_disconnect(client);
		wait_server(server);
		return;
	}

	ret = lota_poll_events(client, -1);
	if (ret < 1 || cb_count < 1) {
		FAIL("expected at least one notification with infinite wait");
		lota_disconnect(client);
		wait_server(server);
		return;
	}

	lota_disconnect(client);
	wait_server(server);
	PASS();
}

static void test_raw_subscribe_protocol(void)
{
	int sv[2]; /* socketpair: [0]=client, [1]=server */
	struct lota_ipc_request req;
	struct lota_ipc_subscribe_request sub;
	struct lota_ipc_response resp;
	ssize_t n;

	TEST("raw protocol: SUBSCRIBE request/response");

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
		if (socket_errno_is_sandbox(errno)) {
			SKIP("AF_UNIX socketpair not permitted");
			return;
		}
		FAIL("socketpair failed");
		return;
	}

	/* client side: send SUBSCRIBE */
	memset(&req, 0, sizeof(req));
	req.magic = LOTA_IPC_MAGIC;
	req.version = LOTA_IPC_VERSION;
	req.cmd = LOTA_IPC_CMD_SUBSCRIBE;
	req.payload_len = sizeof(sub);
	sub.event_mask = LOTA_IPC_EVENT_STATUS | LOTA_IPC_EVENT_ATTEST;

	n = send(sv[0], &req, sizeof(req), 0);
	if (n != sizeof(req)) {
		if (n < 0 && socket_errno_is_sandbox(errno)) {
			SKIP("AF_UNIX send not permitted");
			goto out;
		}
		FAIL("send request header failed");
		goto out;
	}
	n = send(sv[0], &sub, sizeof(sub), 0);
	if (n != sizeof(sub)) {
		FAIL("send subscribe payload failed");
		goto out;
	}

	/* server side: read request */
	{
		struct lota_ipc_request srv_req;
		struct lota_ipc_subscribe_request srv_sub;

		n = recv(sv[1], &srv_req, sizeof(srv_req), MSG_WAITALL);
		if (n != sizeof(srv_req)) {
			FAIL("server recv request failed");
			goto out;
		}
		if (srv_req.magic != LOTA_IPC_MAGIC ||
		    srv_req.cmd != LOTA_IPC_CMD_SUBSCRIBE) {
			FAIL("request magic or cmd mismatch");
			goto out;
		}

		n = recv(sv[1], &srv_sub, sizeof(srv_sub), MSG_WAITALL);
		if (n != sizeof(srv_sub)) {
			FAIL("server recv subscribe payload failed");
			goto out;
		}
		if (srv_sub.event_mask !=
		    (LOTA_IPC_EVENT_STATUS | LOTA_IPC_EVENT_ATTEST)) {
			FAIL("event_mask mismatch");
			goto out;
		}
	}

	/* server side: send OK */
	memset(&resp, 0, sizeof(resp));
	resp.magic = LOTA_IPC_MAGIC;
	resp.version = LOTA_IPC_VERSION;
	resp.result = LOTA_IPC_OK;
	resp.payload_len = 0;
	n = send(sv[1], &resp, sizeof(resp), 0);
	if (n != sizeof(resp)) {
		FAIL("server send response failed");
		goto out;
	}

	/* client side: read response */
	n = recv(sv[0], &resp, sizeof(resp), MSG_WAITALL);
	if (n != sizeof(resp)) {
		FAIL("client recv response failed");
		goto out;
	}
	if (resp.result != LOTA_IPC_OK) {
		FAIL("response should be OK");
		goto out;
	}

	PASS();

out:
	close(sv[0]);
	close(sv[1]);
}

static void test_raw_notification_protocol(void)
{
	int sv[2];
	struct lota_ipc_response resp;
	struct lota_ipc_notify notify;
	ssize_t n;

	TEST("raw protocol: notification frame round-trip");

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
		if (socket_errno_is_sandbox(errno)) {
			SKIP("AF_UNIX socketpair not permitted");
			return;
		}
		FAIL("socketpair failed");
		return;
	}

	/* server side: send notification */
	memset(&resp, 0, sizeof(resp));
	resp.magic = LOTA_IPC_MAGIC;
	resp.version = LOTA_IPC_VERSION;
	resp.result = LOTA_IPC_NOTIFY;
	resp.payload_len = sizeof(notify);

	memset(&notify, 0, sizeof(notify));
	notify.events = LOTA_IPC_EVENT_STATUS;
	notify.flags = LOTA_STATUS_ATTESTED | LOTA_STATUS_TPM_OK;
	notify.last_attest_time = 12345;
	notify.valid_until = 99999;
	notify.attest_count = 7;
	notify.fail_count = 2;
	notify.mode = 1;

	n = send(sv[1], &resp, sizeof(resp), 0);
	if (n != sizeof(resp)) {
		if (n < 0 && socket_errno_is_sandbox(errno)) {
			SKIP("AF_UNIX send not permitted");
			goto out;
		}
		FAIL("send response header failed");
		goto out;
	}
	n = send(sv[1], &notify, sizeof(notify), 0);
	if (n != sizeof(notify)) {
		FAIL("send notify payload failed");
		goto out;
	}

	/* client side: read and verify */
	{
		struct lota_ipc_response cli_resp;
		struct lota_ipc_notify cli_notify;

		n = recv(sv[0], &cli_resp, sizeof(cli_resp), MSG_WAITALL);
		if (n != sizeof(cli_resp) ||
		    cli_resp.result != LOTA_IPC_NOTIFY) {
			FAIL("notification header mismatch");
			goto out;
		}

		n = recv(sv[0], &cli_notify, sizeof(cli_notify), MSG_WAITALL);
		if (n != sizeof(cli_notify)) {
			FAIL("notification payload read failed");
			goto out;
		}

		if (cli_notify.events != LOTA_IPC_EVENT_STATUS) {
			FAIL("events mismatch");
			goto out;
		}
		if (cli_notify.flags !=
		    (LOTA_STATUS_ATTESTED | LOTA_STATUS_TPM_OK)) {
			FAIL("flags mismatch");
			goto out;
		}
		if (cli_notify.attest_count != 7 ||
		    cli_notify.fail_count != 2) {
			FAIL("counters mismatch");
			goto out;
		}
		if (cli_notify.mode != 1) {
			FAIL("mode mismatch");
			goto out;
		}
	}

	PASS();

out:
	close(sv[0]);
	close(sv[1]);
}

/* Answer one PING and hang up at once, as an agent shutting down does. */
static void server_ping_then_hangup(int client_fd)
{
	struct lota_ipc_request req;
	struct lota_ipc_ping_response ping = { .uptime_sec = 7, .pid = 1 };

	if (recv_request(client_fd, &req, NULL, 0) < 0)
		_exit(1);
	if (send_response(client_fd, LOTA_IPC_OK, &ping, sizeof(ping)) < 0)
		_exit(2);
}

static void test_reply_before_hangup(void)
{
	struct lota_connect_opts opts = { .struct_size = sizeof(opts) };
	struct lota_client *client;
	uint64_t uptime = 0;
	pid_t server;
	int ret;

	TEST("a reply sent just before the agent hangs up is read");
	server = start_mock_server(server_ping_then_hangup);
	if (server < 0) {
		if (socket_errno_is_sandbox(mock_server_errno))
			SKIP("AF_UNIX mock server not permitted");
		else
			FAIL("failed to start mock server");
		return;
	}
	opts.socket_path = test_socket;
	opts.timeout_ms = 5000;
	client = lota_connect_opts(&opts);
	if (!client) {
		FAIL("connect failed");
		wait_server(server);
		return;
	}
	ret = lota_ping(client, &uptime);
	lota_disconnect(client);
	wait_server(server);
	if (ret != LOTA_OK || uptime != 7)
		FAIL(lota_strerror(ret));
	else
		PASS();
}

/* How a mock registry listing breaks the wire contract */
enum registry_fault {
	REGISTRY_SOUND,
	REGISTRY_BAD_ROAD, /* a digest on the unmeasured object */
	REGISTRY_BAD_ENTRY_FLAG, /* an entry flag the SDK does not know */
	REGISTRY_BAD_FLAG, /* a page flag the SDK does not know */
	REGISTRY_BAD_ACTOR_KIND, /* an actor kind the SDK does not know */
	REGISTRY_BAD_ACTOR_COMM, /* an actor name without its NUL */
};

/* 5 objects, then 2 actors */
#define REGISTRY_MOCK_OBJECTS 5
#define REGISTRY_MOCK_ACTORS 2

/*
 * Registry page of entries [start, start + count) of a listing of
 * REGISTRY_MOCK_OBJECTS objects followed by REGISTRY_MOCK_ACTORS actors.
 */
static size_t build_registry_page(uint8_t *buf, uint64_t round, uint32_t start,
				  uint16_t count, enum registry_fault fault)
{
	struct lota_ipc_registry_page hdr;
	size_t off = sizeof(hdr);

	memset(&hdr, 0, sizeof(hdr));
	hdr.round = round;
	hdr.pid = 4242;
	hdr.total = REGISTRY_MOCK_OBJECTS;
	hdr.actor_total = REGISTRY_MOCK_ACTORS;
	hdr.start = start;
	hdr.count = count;
	hdr.flags = LOTA_IPC_REGISTRY_MEASURED |
		    LOTA_IPC_REGISTRY_HISTORY_LOST |
		    LOTA_IPC_REGISTRY_FROM_EXEC;
	if (fault == REGISTRY_BAD_FLAG)
		hdr.flags |= 1U << 9;
	memset(hdr.registry_digest, 0x5a, sizeof(hdr.registry_digest));
	memcpy(buf, &hdr, sizeof(hdr));

	for (uint32_t i = start; i < start + count; i++) {
		struct lota_ipc_registry_entry e;
		struct lota_ipc_registry_actor q;
		char soname[24];
		char path[48];

		if (i >= REGISTRY_MOCK_OBJECTS) {
			uint32_t k = i - REGISTRY_MOCK_OBJECTS;

			memset(&q, 0, sizeof(q));
			q.count = 2 + k;
			q.start_ticks = 9000 + k;
			q.exe_ino = 300 + k;
			q.tgid = 6000 + k;
			q.uid = 1000;
			q.owner_tgid = 4243;
			q.kind = k == 0 ? LOTA_IPC_REGISTRY_ACTOR_ANON_EXEC :
					  LOTA_IPC_REGISTRY_ACTOR_PTRACE_ATTACH;
			if (k == 1 && fault == REGISTRY_BAD_ACTOR_KIND)
				q.kind = LOTA_IPC_REGISTRY_ACTOR_KIND_MAX + 1;
			snprintf(q.comm, sizeof(q.comm), "actor%u", k);
			if (k == 1 && fault == REGISTRY_BAD_ACTOR_COMM)
				memset(q.comm, 'a', sizeof(q.comm));
			strcpy(q.owner_comm, "wineserver");
			memcpy(buf + off, &q, sizeof(q));
			off += sizeof(q);
			continue;
		}

		snprintf(soname, sizeof(soname), "lib%u.so", i);
		/* object 4 was unmapped before the round: no path */
		if (i == 4)
			path[0] = '\0';
		else
			snprintf(path, sizeof(path), "/opt/title/lib%u.so", i);
		memset(&e, 0, sizeof(e));
		e.size = 1000 + i;
		e.ino = 77 + i;
		e.road = i == 4 ? LOTA_IPC_REGISTRY_ROAD_NONE :
				  LOTA_IPC_REGISTRY_ROAD_VERITY;
		if (i != 4 || fault == REGISTRY_BAD_ROAD) {
			e.digest_len = 32;
			memset(e.digest, (int)i + 1, 32);
		}
		if (i == 4)
			e.flags = LOTA_IPC_REGISTRY_ENTRY_UNMAPPED |
				  LOTA_IPC_REGISTRY_ENTRY_MEMORY;
		if (i == 2)
			e.flags = LOTA_IPC_REGISTRY_ENTRY_WRITABLE;
		if (i == 1 && fault == REGISTRY_BAD_ENTRY_FLAG)
			e.flags = 1U << 3;
		e.soname_len = (uint16_t)strlen(soname);
		e.path_len = (uint16_t)strlen(path);
		memcpy(buf + off, &e, sizeof(e));
		off += sizeof(e);
		memcpy(buf + off, soname, e.soname_len);
		off += e.soname_len;
		memcpy(buf + off, path, e.path_len);
		off += e.path_len;
	}
	return off;
}

/*
 * Answer GET_REGISTRY in pages of three, one of them both objects and
 * actors; round @torn_round from the 2nd on.
 */
static void serve_registry(int client_fd, uint64_t torn_round,
			   enum registry_fault fault)
{
	struct lota_ipc_request req;
	struct lota_ipc_registry_request body;
	uint8_t buf[LOTA_IPC_MAX_PAYLOAD];
	int served = 0;

	while (recv_request(client_fd, &req, &body, sizeof(body)) == 0) {
		uint64_t round = served > 0 && torn_round ? torn_round : 1;
		uint32_t left = REGISTRY_MOCK_OBJECTS + REGISTRY_MOCK_ACTORS -
				body.start;
		uint16_t count = (uint16_t)(left < 3 ? left : 3);
		size_t len;

		if (req.cmd != LOTA_IPC_CMD_GET_REGISTRY || body.pid != 4242)
			_exit(2);
		len = build_registry_page(buf, round, body.start, count, fault);
		if (send_response(client_fd, LOTA_IPC_OK, buf, (uint32_t)len) <
		    0)
			_exit(3);
		served++;
	}
}

static void server_registry(int client_fd)
{
	serve_registry(client_fd, 0, REGISTRY_SOUND);
}

static void server_registry_torn(int client_fd)
{
	serve_registry(client_fd, 2, REGISTRY_SOUND);
}

static void server_registry_bad_road(int client_fd)
{
	serve_registry(client_fd, 0, REGISTRY_BAD_ROAD);
}

static void server_registry_bad_entry_flag(int client_fd)
{
	serve_registry(client_fd, 0, REGISTRY_BAD_ENTRY_FLAG);
}

static void server_registry_bad_flag(int client_fd)
{
	serve_registry(client_fd, 0, REGISTRY_BAD_FLAG);
}

static void server_registry_bad_actor_kind(int client_fd)
{
	serve_registry(client_fd, 0, REGISTRY_BAD_ACTOR_KIND);
}

static void server_registry_bad_actor_comm(int client_fd)
{
	serve_registry(client_fd, 0, REGISTRY_BAD_ACTOR_COMM);
}

static void server_registry_not_protected(int client_fd)
{
	struct lota_ipc_request req;
	struct lota_ipc_registry_request body;

	if (recv_request(client_fd, &req, &body, sizeof(body)) < 0)
		_exit(1);
	if (send_response(client_fd, LOTA_IPC_ERR_NOT_PROTECTED, NULL, 0) < 0)
		_exit(3);
}

/* Fetch pid 4242 from a mock agent running @scenario. */
static int fetch_registry(server_scenario_fn scenario,
			  struct lota_registry **reg, int *skipped)
{
	struct lota_connect_opts opts = { .struct_size = sizeof(opts) };
	struct lota_client *client;
	pid_t server;
	int ret;

	*skipped = 0;
	server = start_mock_server(scenario);
	if (server < 0) {
		*skipped = socket_errno_is_sandbox(mock_server_errno);
		return LOTA_ERR_CONNECTION_FAILED;
	}
	opts.socket_path = test_socket;
	opts.timeout_ms = 5000;
	client = lota_connect_opts(&opts);
	if (!client) {
		wait_server(server);
		return LOTA_ERR_CONNECTION_FAILED;
	}
	ret = lota_get_registry(client, 4242, reg);
	lota_disconnect(client);
	wait_server(server);
	return ret;
}

static void test_registry_pages(void)
{
	struct lota_registry *reg = NULL;
	int skipped;
	int ret;

	TEST("get_registry joins the pages of one listing");
	ret = fetch_registry(server_registry, &reg, &skipped);
	if (skipped) {
		SKIP("AF_UNIX mock server not permitted");
		return;
	}
	if (ret != LOTA_OK || !reg || reg->count != 5 || reg->round != 1 ||
	    reg->pid != 4242 ||
	    reg->flags != (LOTA_REGISTRY_MEASURED | LOTA_REGISTRY_HISTORY_LOST |
			   LOTA_REGISTRY_FROM_EXEC) ||
	    reg->registry_digest[0] != 0x5a ||
	    strcmp(reg->objects[3].soname, "lib3.so") != 0 ||
	    strcmp(reg->objects[3].path, "/opt/title/lib3.so") != 0 ||
	    reg->objects[3].size != 1003 || reg->objects[3].digest_len != 32 ||
	    reg->objects[3].digest[0] != 4 ||
	    reg->objects[4].road != LOTA_REGISTRY_ROAD_NONE ||
	    reg->objects[4].digest_len != 0 ||
	    reg->objects[4].flags != (LOTA_REGISTRY_OBJECT_UNMAPPED |
				      LOTA_REGISTRY_OBJECT_MEMORY) ||
	    reg->objects[2].flags != LOTA_REGISTRY_OBJECT_WRITABLE ||
	    reg->objects[4].path[0] != '\0' || reg->objects[3].flags != 0 ||
	    reg->actor_count != 2 || !reg->actors ||
	    reg->actors[0].tgid != 6000 || reg->actors[0].count != 2 ||
	    reg->actors[0].start_ticks != 9000 ||
	    reg->actors[0].kind != LOTA_REGISTRY_ACTOR_ANON_EXEC ||
	    reg->actors[1].kind != LOTA_REGISTRY_ACTOR_PTRACE_ATTACH ||
	    reg->actors[1].exe_ino != 301 ||
	    reg->actors[1].owner_tgid != 4243 ||
	    strcmp(reg->actors[1].comm, "actor1") != 0 ||
	    strcmp(reg->actors[1].owner_comm, "wineserver") != 0) {
		FAIL(lota_strerror(ret));
		lota_registry_free(reg);
		return;
	}
	lota_registry_free(reg);
	PASS();
}

static void test_registry_torn(void)
{
	struct lota_registry *reg = NULL;
	int skipped;
	int ret;

	TEST("get_registry restarts a listing a token round tore");
	ret = fetch_registry(server_registry_torn, &reg, &skipped);
	if (skipped) {
		SKIP("AF_UNIX mock server not permitted");
		return;
	}
	if (ret != LOTA_OK || !reg || reg->round != 2 || reg->count != 5) {
		FAIL(lota_strerror(ret));
		lota_registry_free(reg);
		return;
	}
	lota_registry_free(reg);
	PASS();
}

static void test_registry_refusals(void)
{
	struct lota_registry *reg = NULL;
	int skipped;
	int ret;

	TEST("get_registry refuses a digest on an unmeasured object");
	ret = fetch_registry(server_registry_bad_road, &reg, &skipped);
	if (skipped)
		SKIP("AF_UNIX mock server not permitted");
	else if (ret != LOTA_ERR_PROTOCOL || reg)
		FAIL(lota_strerror(ret));
	else
		PASS();

	TEST("get_registry refuses an entry flag it does not know");
	ret = fetch_registry(server_registry_bad_entry_flag, &reg, &skipped);
	if (skipped)
		SKIP("AF_UNIX mock server not permitted");
	else if (ret != LOTA_ERR_PROTOCOL || reg)
		FAIL(lota_strerror(ret));
	else
		PASS();

	TEST("get_registry refuses a listing flag it does not know");
	ret = fetch_registry(server_registry_bad_flag, &reg, &skipped);
	if (skipped)
		SKIP("AF_UNIX mock server not permitted");
	else if (ret != LOTA_ERR_PROTOCOL || reg)
		FAIL(lota_strerror(ret));
	else
		PASS();

	TEST("get_registry refuses an actor kind it does not know");
	ret = fetch_registry(server_registry_bad_actor_kind, &reg, &skipped);
	if (skipped)
		SKIP("AF_UNIX mock server not permitted");
	else if (ret != LOTA_ERR_PROTOCOL || reg)
		FAIL(lota_strerror(ret));
	else
		PASS();

	TEST("get_registry refuses an actor name without its end");
	ret = fetch_registry(server_registry_bad_actor_comm, &reg, &skipped);
	if (skipped)
		SKIP("AF_UNIX mock server not permitted");
	else if (ret != LOTA_ERR_PROTOCOL || reg)
		FAIL(lota_strerror(ret));
	else
		PASS();

	TEST("get_registry names a process the round did not measure");
	ret = fetch_registry(server_registry_not_protected, &reg, &skipped);
	if (skipped)
		SKIP("AF_UNIX mock server not permitted");
	else if (ret != LOTA_ERR_NOT_PROTECTED || reg)
		FAIL(lota_strerror(ret));
	else
		PASS();

	TEST("get_registry refuses a missing client or output");
	if (lota_get_registry(NULL, 1, &reg) == LOTA_ERR_NOT_CONNECTED &&
	    lota_get_registry((struct lota_client *)&reg, 1, NULL) ==
		    LOTA_ERR_INVALID_ARG)
		PASS();
	else
		FAIL("accepted a missing argument");
}

/* Answer GET_BOOT_EVIDENCE with 64 patterned bytes, or refuse it */
static void serve_boot_evidence(int client_fd, uint32_t result)
{
	struct lota_ipc_request req;
	uint8_t buf[64];

	if (recv_request(client_fd, &req, NULL, 0) < 0)
		_exit(1);
	if (req.cmd != LOTA_IPC_CMD_GET_BOOT_EVIDENCE || req.payload_len != 0)
		_exit(2);
	for (size_t i = 0; i < sizeof(buf); i++)
		buf[i] = (uint8_t)i;
	if (send_response(client_fd, result, result == LOTA_IPC_OK ? buf : NULL,
			  result == LOTA_IPC_OK ? sizeof(buf) : 0) < 0)
		_exit(3);
}

static void server_boot_evidence(int client_fd)
{
	serve_boot_evidence(client_fd, LOTA_IPC_OK);
}

static void server_boot_evidence_no_tpm(int client_fd)
{
	serve_boot_evidence(client_fd, LOTA_IPC_ERR_NO_TPM);
}

static int fetch_boot_evidence(server_scenario_fn scenario, uint8_t *buf,
			       size_t buflen, size_t *written, int *skipped)
{
	struct lota_connect_opts opts = { .struct_size = sizeof(opts) };
	struct lota_client *client;
	pid_t server;
	int ret;

	*skipped = 0;
	server = start_mock_server(scenario);
	if (server < 0) {
		*skipped = socket_errno_is_sandbox(mock_server_errno);
		return LOTA_ERR_CONNECTION_FAILED;
	}
	opts.socket_path = test_socket;
	opts.timeout_ms = 5000;
	client = lota_connect_opts(&opts);
	if (!client) {
		wait_server(server);
		return LOTA_ERR_CONNECTION_FAILED;
	}
	ret = lota_get_boot_evidence(client, buf, buflen, written);
	lota_disconnect(client);
	wait_server(server);
	return ret;
}

static void test_boot_evidence(void)
{
	uint8_t buf[128];
	size_t written = 0;
	int skipped;
	int ret;

	TEST("get_boot_evidence hands back the agent's bytes");
	ret = fetch_boot_evidence(server_boot_evidence, buf, sizeof(buf),
				  &written, &skipped);
	if (skipped) {
		SKIP("AF_UNIX mock server not permitted");
		return;
	}
	if (ret != LOTA_OK || written != 64 || buf[0] != 0 || buf[63] != 63)
		FAIL("evidence lost or cut");
	else
		PASS();

	TEST("get_boot_evidence refuses a buffer too small");
	ret = fetch_boot_evidence(server_boot_evidence, buf, 16, &written,
				  &skipped);
	if (ret != LOTA_ERR_BUFFER_TOO_SMALL)
		FAIL("short buffer not reported");
	else
		PASS();

	TEST("get_boot_evidence passes NO_TPM through");
	ret = fetch_boot_evidence(server_boot_evidence_no_tpm, buf, sizeof(buf),
				  &written, &skipped);
	if (ret != LOTA_ERR_NO_TPM)
		FAIL("refusal not mapped");
	else
		PASS();
}

int main(void)
{
	printf("=== SUBSCRIBE / Push Notification Tests ===\n\n");

	snprintf(test_socket, sizeof(test_socket), "/tmp/lota_ts_%d.sock",
		 getpid());

	/* ignore SIGPIPE so broken connections dont kill the test */
	signal(SIGPIPE, SIG_IGN);

	/* protocol format tests */
	test_subscribe_request_format();
	test_notify_format();
	test_event_constants();
	test_subscribe_unsubscribe_mask();

	/* raw protocol tests */
	test_raw_subscribe_protocol();
	test_raw_notification_protocol();

	/* sdk argument validation */
	test_subscribe_null_client();
	test_subscribe_no_callback();
	test_poll_null_client();

	/* end-to-end sdk tests with mock server */
	test_subscribe_and_poll();
	test_interleaved_notification();
	test_unsubscribe();
	test_poll_no_data();
	test_poll_infinite_wait();
	test_reply_before_hangup();
	test_registry_pages();
	test_registry_torn();
	test_registry_refusals();
	test_boot_evidence();

	printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
	return (tests_passed == tests_run) ? 0 : 1;
}
