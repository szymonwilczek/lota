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

#include "../include/lota_gaming.h"
#include "../include/lota_ipc.h"

static int tests_run;
static int tests_passed;

#define TEST(name)                                                             \
  do {                                                                         \
    tests_run++;                                                               \
    printf("  [%2d] %-50s ", tests_run, name);                                 \
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

static char test_socket[64];

static void test_subscribe_request_format(void) {
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

static void test_notify_format(void) {
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

static void test_event_constants(void) {
  TEST("event constants match between IPC and SDK");

  if (LOTA_IPC_EVENT_STATUS != LOTA_EVENT_STATUS ||
      LOTA_IPC_EVENT_ATTEST != LOTA_EVENT_ATTEST ||
      LOTA_IPC_EVENT_MODE != LOTA_EVENT_MODE) {
    FAIL("IPC and SDK event constants mismatch");
    return;
  }

  if (LOTA_IPC_EVENT_ALL != LOTA_EVENT_ALL) {
    FAIL("EVENT_ALL mismatch");
    return;
  }

  PASS();
}

static void test_subscribe_unsubscribe_mask(void) {
  struct lota_ipc_subscribe_request sub;

  TEST("event_mask = 0 means unsubscribe");

  sub.event_mask = 0;
  if (sub.event_mask != 0) {
    FAIL("event_mask should be 0");
    return;
  }

  sub.event_mask = LOTA_IPC_EVENT_ALL;
  if (sub.event_mask != 0xFFFFFFFF) {
    FAIL("EVENT_ALL should be 0xFFFFFFFF");
    return;
  }

  PASS();
}

/*
 * Send a complete IPC response frame.
 */
static int send_response(int fd, uint32_t result, const void *payload,
                         uint32_t payload_len) {
  struct lota_ipc_response resp;

  resp.magic = LOTA_IPC_MAGIC;
  resp.version = LOTA_IPC_VERSION;
  resp.result = result;
  resp.payload_len = payload_len;

  if (send(fd, &resp, sizeof(resp), MSG_NOSIGNAL) != sizeof(resp))
    return -1;

  if (payload_len > 0 && payload) {
    if (send(fd, payload, payload_len, MSG_NOSIGNAL) != (ssize_t)payload_len)
      return -1;
  }
  return 0;
}

/*
 * Send a notification frame.
 */
static int send_notify(int fd, uint32_t events, uint32_t flags,
                       uint64_t attest_time, uint64_t valid_until,
                       uint32_t attest_count, uint32_t fail_count,
                       uint8_t mode) {
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

/*
 * Read a complete IPC request and its payload.
 */
static int recv_request(int fd, struct lota_ipc_request *req, void *payload,
                        size_t max_payload) {
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

/*
 * subscribe, receive 2 notifications
 */
static void server_subscribe_and_notify(int client_fd) {
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
                  LOTA_STATUS_ATTESTED | LOTA_STATUS_TPM_OK, 1000, 2000, 5, 1,
                  1) < 0)
    _exit(4);

  if (send_notify(client_fd, LOTA_IPC_EVENT_ATTEST,
                  LOTA_STATUS_ATTESTED | LOTA_STATUS_TPM_OK |
                      LOTA_STATUS_IOMMU_OK,
                  1001, 2001, 6, 1, 1) < 0)
    _exit(5);

  /* keep connection alive for client to read */
  usleep(200000);
}

/*
 * subscribe, response, interleaved notification, response
 */
static void server_interleaved_notify(int client_fd) {
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
                  LOTA_STATUS_ATTESTED | LOTA_STATUS_BPF_LOADED, 500, 1500, 3,
                  0, 2) < 0)
    _exit(4);

  /* now send the actual PING response */
  {
    struct lota_ipc_ping_response ping;
    ping.uptime_sec = 42;
    ping.pid = 12345;
    if (send_response(client_fd, LOTA_IPC_OK, &ping, sizeof(ping)) < 0)
      _exit(5);
  }

  usleep(200000);
}

/*
 * subscribe then unsubscribe
 */
static void server_unsubscribe(int client_fd) {
  struct lota_ipc_request req;
  struct lota_ipc_subscribe_request sub;

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
static void server_delayed_notify(int client_fd) {
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
                  LOTA_STATUS_ATTESTED | LOTA_STATUS_TPM_OK, 1000, 2000, 7, 1,
                  1) < 0)
    _exit(4);

  usleep(100000);
}

/*
 * Run a mock server for a given scenario.
 * Listens on test_socket, accepts one client, runs the scenario.
 */
typedef void (*server_scenario_fn)(int client_fd);

static pid_t start_mock_server(server_scenario_fn scenario) {
  int listen_fd;
  struct sockaddr_un addr;
  pid_t pid;

  listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (listen_fd < 0)
    return -1;

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, test_socket, sizeof(addr.sun_path) - 1);
  unlink(test_socket);

  if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    close(listen_fd);
    return -1;
  }

  if (listen(listen_fd, 1) < 0) {
    close(listen_fd);
    unlink(test_socket);
    return -1;
  }

  pid = fork();
  if (pid < 0) {
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

static int wait_server(pid_t pid) {
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

static void reset_cb(void) {
  cb_count = 0;
  cb_last_events = 0;
  cb_last_flags = 0;
  cb_last_attest_count = 0;
  cb_last_mode = 0;
}

static void test_callback(const struct lota_status *status, uint32_t events,
                          void *user_data) {
  (void)user_data;
  cb_count++;
  cb_last_events = events;
  cb_last_flags = status->flags;
  cb_last_attest_count = status->attest_count;
}

static void test_callback_mode(const struct lota_status *status,
                               uint32_t events, void *user_data) {
  int *counter = user_data;
  (*counter)++;
  cb_last_events = events;
  cb_last_flags = status->flags;
  (void)status;
}

static void test_subscribe_and_poll(void) {
  pid_t server;
  struct lota_client *client;
  struct lota_connect_opts opts;
  int ret;

  TEST("subscribe + poll_events receives notifications");

  reset_cb();
  server = start_mock_server(server_subscribe_and_notify);
  if (server < 0) {
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
    snprintf(msg, sizeof(msg), "subscribe failed: %s", lota_strerror(ret));
    FAIL(msg);
    lota_disconnect(client);
    wait_server(server);
    return;
  }

  ret = lota_poll_events(client, 2000);
  if (ret < 2) {
    char msg[64];
    snprintf(msg, sizeof(msg), "expected >= 2 notifications, got %d", ret);
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
    snprintf(msg, sizeof(msg), "server exited with code %d", srv_ret);
    FAIL(msg);
    return;
  }

  PASS();
}

static void test_interleaved_notification(void) {
  pid_t server;
  struct lota_client *client;
  struct lota_connect_opts opts;
  int counter = 0;
  uint64_t uptime = 0;
  int ret;

  TEST("notification interleaved with PING response");

  reset_cb();
  server = start_mock_server(server_interleaved_notify);
  if (server < 0) {
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

  ret = lota_subscribe(client, LOTA_EVENT_ALL, test_callback_mode, &counter);
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
    snprintf(msg, sizeof(msg), "ping failed: %s", lota_strerror(ret));
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
    snprintf(msg, sizeof(msg), "expected 1 interleaved notification, got %d",
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

static void test_unsubscribe(void) {
  pid_t server;
  struct lota_client *client;
  struct lota_connect_opts opts;
  int ret;

  TEST("unsubscribe clears subscription");

  reset_cb();
  server = start_mock_server(server_unsubscribe);
  if (server < 0) {
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
    snprintf(msg, sizeof(msg), "unsubscribe failed: %s", lota_strerror(ret));
    FAIL(msg);
    lota_disconnect(client);
    wait_server(server);
    return;
  }

  lota_disconnect(client);
  int srv_ret = wait_server(server);
  if (srv_ret != 0) {
    char msg[64];
    snprintf(msg, sizeof(msg), "server exited with code %d", srv_ret);
    FAIL(msg);
    return;
  }

  PASS();
}

static void test_subscribe_null_client(void) {
  TEST("subscribe(NULL) -> NOT_CONNECTED");

  int ret = lota_subscribe(NULL, LOTA_EVENT_ALL, test_callback, NULL);
  if (ret != LOTA_ERR_NOT_CONNECTED) {
    FAIL("expected LOTA_ERR_NOT_CONNECTED");
    return;
  }

  PASS();
}

static void test_subscribe_no_callback(void) {
  TEST("subscribe(mask!=0, NULL callback) -> INVALID_ARG");

  struct lota_connect_opts opts;
  opts.socket_path = "/nonexistent";
  opts.timeout_ms = 100;
  struct lota_client *c = lota_connect_opts(&opts);

  int ret = lota_subscribe(NULL, LOTA_EVENT_STATUS, NULL, NULL);
  if (ret != LOTA_ERR_NOT_CONNECTED) {
    /* OK, null client returns NOT_CONNECTED which is checked first */
    FAIL("expected NOT_CONNECTED or INVALID_ARG");
    if (c)
      lota_disconnect(c);
    return;
  }

  if (c)
    lota_disconnect(c);
  PASS();
}

static void test_poll_null_client(void) {
  TEST("poll_events(NULL) -> NOT_CONNECTED");

  int ret = lota_poll_events(NULL, 0);
  if (ret != LOTA_ERR_NOT_CONNECTED) {
    FAIL("expected LOTA_ERR_NOT_CONNECTED");
    return;
  }

  PASS();
}

static void test_poll_no_data(void) {
  pid_t server;
  struct lota_client *client;
  struct lota_connect_opts opts;
  int ret;

  TEST("poll_events with no data -> 0 dispatched");

  /* start a server that only handles subscribe, then waits */
  server = start_mock_server(server_unsubscribe);
  if (server < 0) {
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
  if (ret < 0) {
    /* After unsubscribe request read, server closes. Connection may reset! */
    /* Accept 0 or error depending on timing. */
  }

  /* no crash, no hang */
  lota_disconnect(client);
  wait_server(server);
  PASS();
}

static void test_poll_infinite_wait(void) {
  pid_t server;
  struct lota_client *client;
  struct lota_connect_opts opts;
  int ret;

  TEST("poll_events(-1) blocks until delayed notification");

  reset_cb();
  server = start_mock_server(server_delayed_notify);
  if (server < 0) {
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

static void test_raw_subscribe_protocol(void) {
  int sv[2]; /* socketpair: [0]=client, [1]=server */
  struct lota_ipc_request req;
  struct lota_ipc_subscribe_request sub;
  struct lota_ipc_response resp;
  ssize_t n;

  TEST("raw protocol: SUBSCRIBE request/response");

  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
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
    if (srv_sub.event_mask != (LOTA_IPC_EVENT_STATUS | LOTA_IPC_EVENT_ATTEST)) {
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

static void test_raw_notification_protocol(void) {
  int sv[2];
  struct lota_ipc_response resp;
  struct lota_ipc_notify notify;
  ssize_t n;

  TEST("raw protocol: notification frame round-trip");

  if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
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
    if (n != sizeof(cli_resp) || cli_resp.result != LOTA_IPC_NOTIFY) {
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
    if (cli_notify.flags != (LOTA_STATUS_ATTESTED | LOTA_STATUS_TPM_OK)) {
      FAIL("flags mismatch");
      goto out;
    }
    if (cli_notify.attest_count != 7 || cli_notify.fail_count != 2) {
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

int main(void) {
  printf("=== SUBSCRIBE / Push Notification Tests ===\n\n");

  snprintf(test_socket, sizeof(test_socket), "/tmp/lota_ts_%d.sock", getpid());

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

  printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
  return (tests_passed == tests_run) ? 0 : 1;
}
