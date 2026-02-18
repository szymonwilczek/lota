/* SPDX-License-Identifier: MIT */
/*
 * LOTA Gaming SDK - Implementation
 *
 * Client library for games to query local attestation status.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "../../include/lota_gaming.h"
#include "../../include/lota_ipc.h"
#include "../../include/lota_token.h"

#define DEFAULT_TIMEOUT_MS 5000

/*
 * Maximum number of candidate socket paths to try during autodiscovery.
 */
#define MAX_DISCOVERY_PATHS 4
#define VERSION_STRING "1.0.0"

/*
 * Client context
 */
struct lota_client {
  int fd;
  int timeout_ms;
  lota_status_callback_fn callback;
  void *user_data;
};

/*
 * Send all data, handling partial writes
 */
static int send_all(int fd, const void *buf, size_t len) {
  const char *p = buf;
  size_t remaining = len;
  ssize_t n;

  while (remaining > 0) {
    n = send(fd, p, remaining, MSG_NOSIGNAL);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      return -errno;
    }
    if (n == 0)
      return -EIO;
    p += n;
    remaining -= n;
  }
  return 0;
}

/*
 * Set socket to non-blocking mode
 */
static int set_nonblock(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);

  if (flags < 0)
    return -1;
  return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

/*
 * Restore socket to blocking mode after non-blocking connect completes.
 */
static int clear_nonblock(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);

  if (flags < 0)
    return -1;
  return fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
}

/*
 * Wait for socket to be readable/writable with timeout
 */
static int wait_for_socket(int fd, int events, int timeout_ms) {
  struct pollfd pfd = {
      .fd = fd,
      .events = (short)events,
  };
  int ret;

  ret = poll(&pfd, 1, timeout_ms);
  if (ret < 0)
    return -errno;
  if (ret == 0)
    return -ETIMEDOUT;
  if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
    return -ECONNRESET;

  return 0;
}

/*
 * Send request with timeout
 */
static int send_request(struct lota_client *client,
                        const struct lota_ipc_request *req, const void *payload,
                        size_t payload_len) {
  int ret;

  ret = wait_for_socket(client->fd, POLLOUT, client->timeout_ms);
  if (ret < 0)
    return ret;

  /* send header */
  ret = send_all(client->fd, req, sizeof(*req));
  if (ret < 0)
    return ret;

  /* send payload if present */
  if (payload && payload_len > 0) {
    ret = send_all(client->fd, payload, payload_len);
    if (ret < 0)
      return ret;
  }

  return 0;
}

/* for helpers used by recv_response */
static int dispatch_notification(struct lota_client *client,
                                 const void *payload, size_t payload_len);
static void drain_payload(int fd, size_t remaining);

/*
 * Receive response with timeout
 */
static int recv_response(struct lota_client *client,
                         struct lota_ipc_response *resp, void *payload,
                         size_t payload_size, size_t *payload_len) {
  ssize_t n;
  int ret;

  /*
   * Loop until LOTA receive a command response (not a notification!).
   * Server-push notifications that arrive while waiting for a
   * response are dispatched via the callback and skipped.
   */
  for (;;) {
    ret = wait_for_socket(client->fd, POLLIN, client->timeout_ms);
    if (ret < 0)
      return ret;

    n = recv(client->fd, resp, sizeof(*resp), MSG_WAITALL);
    if (n != sizeof(*resp))
      return (n < 0) ? -errno : -EIO;

    if (resp->magic != LOTA_IPC_MAGIC)
      return LOTA_ERR_PROTOCOL;

    if (resp->result == LOTA_IPC_NOTIFY && resp->payload_len > 0) {
      uint8_t nbuf[sizeof(struct lota_ipc_notify)];
      size_t nlen =
          resp->payload_len < sizeof(nbuf) ? resp->payload_len : sizeof(nbuf);

      ret = wait_for_socket(client->fd, POLLIN, client->timeout_ms);
      if (ret < 0)
        return ret;

      n = recv(client->fd, nbuf, nlen, MSG_WAITALL);
      if (n != (ssize_t)nlen)
        return (n < 0) ? -errno : -EIO;

      if (resp->payload_len > sizeof(nbuf))
        drain_payload(client->fd, resp->payload_len - sizeof(nbuf));

      dispatch_notification(client, nbuf, nlen);
      continue;
    }

    break; /* got a real response */
  }

  /* receive payload if present */
  if (resp->payload_len > 0) {
    if (resp->payload_len > payload_size) {
      drain_payload(client->fd, resp->payload_len);
      return LOTA_ERR_BUFFER_TOO_SMALL;
    }

    ret = wait_for_socket(client->fd, POLLIN, client->timeout_ms);
    if (ret < 0)
      return ret;

    n = recv(client->fd, payload, resp->payload_len, MSG_WAITALL);
    if (n != (ssize_t)resp->payload_len)
      return (n < 0) ? -errno : -EIO;

    if (payload_len)
      *payload_len = resp->payload_len;
  } else {
    if (payload_len)
      *payload_len = 0;
  }

  return 0;
}

/*
 * Map IPC result to SDK error code
 */
static int ipc_result_to_error(uint32_t result) {
  switch (result) {
  case LOTA_IPC_OK:
    return LOTA_OK;
  case LOTA_IPC_ERR_NOT_ATTESTED:
    return LOTA_ERR_NOT_ATTESTED;
  case LOTA_IPC_ERR_UNKNOWN_CMD:
  case LOTA_IPC_ERR_BAD_REQUEST:
    return LOTA_ERR_PROTOCOL;
  case LOTA_IPC_ERR_RATE_LIMITED:
    return LOTA_ERR_RATE_LIMITED;
  case LOTA_IPC_ERR_ACCESS_DENIED:
    return LOTA_ERR_ACCESS_DENIED;
  case LOTA_IPC_ERR_TPM_FAILURE:
  case LOTA_IPC_ERR_INTERNAL:
  default:
    return LOTA_ERR_AGENT_ERROR;
  }
}

/*
 * Dispatch a server-push notification via the client's callback.
 * Returns 1 if dispatched, 0 if no callback registered.
 */
static int dispatch_notification(struct lota_client *client,
                                 const void *payload, size_t payload_len) {
  const struct lota_ipc_notify *notify;
  struct lota_status status;

  if (!client->callback)
    return 0;

  if (payload_len < sizeof(*notify))
    return 0;

  notify = payload;
  status.flags = notify->flags;
  status.last_attest_time = notify->last_attest_time;
  status.valid_until = notify->valid_until;
  status.attest_count = notify->attest_count;
  status.fail_count = notify->fail_count;

  client->callback(&status, notify->events, client->user_data);
  return 1;
}

/*
 * Drain and discard a response payload from the socket.
 */
static void drain_payload(int fd, size_t remaining) {
  char discard[256];

  while (remaining > 0) {
    size_t chunk = remaining < sizeof(discard) ? remaining : sizeof(discard);
    ssize_t n = recv(fd, discard, chunk, 0);

    if (n <= 0)
      break;
    remaining -= (size_t)n;
  }
}

struct lota_client *lota_connect(void) { return lota_connect_opts(NULL); }

/*
 * Try to connect to a specific socket path.
 *
 * Returns a connected fd on success, -1 on failure.
 */
static int try_connect_path(const char *path, int timeout_ms) {
  struct sockaddr_un addr;
  int fd, ret;

  fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0)
    return -1;

  if (set_nonblock(fd) < 0) {
    close(fd);
    return -1;
  }

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

  ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
  if (ret < 0 && errno != EINPROGRESS) {
    close(fd);
    return -1;
  }

  if (ret < 0) {
    ret = wait_for_socket(fd, POLLOUT, timeout_ms);
    if (ret < 0) {
      close(fd);
      return -1;
    }

    int err = 0;
    socklen_t len = sizeof(err);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
    if (err != 0) {
      close(fd);
      return -1;
    }
  }

  /* restore blocking mode so recv(MSG_WAITALL) works correctly */
  if (clear_nonblock(fd) < 0) {
    close(fd);
    return -1;
  }

  return fd;
}

/*
 * Build the list of candidate socket paths for autodiscovery.
 *
 * Discovery order:
 *   1. LOTA_IPC_SOCKET env var (explicit override)
 *   2. /run/lota/lota.sock (primary agent socket)
 *   3. $XDG_RUNTIME_DIR/lota/lota.sock (container-accessible)
 */
static int build_discovery_paths(char paths[][PATH_MAX], int max) {
  const char *env;
  int n = 0;

  /* explicit override via environment */
  env = getenv("LOTA_IPC_SOCKET");
  if (env && env[0] && n < max) {
    snprintf(paths[n], PATH_MAX, "%s", env);
    n++;
  }

  /* primary path */
  if (n < max) {
    snprintf(paths[n], PATH_MAX, "%s", LOTA_IPC_SOCKET_PATH);
    n++;
  }

  /* container-accessible path via XDG_RUNTIME_DIR */
  env = getenv("XDG_RUNTIME_DIR");
  if (env && env[0] && n < max) {
    snprintf(paths[n], PATH_MAX, "%s/lota/lota.sock", env);
    n++;
  }

  return n;
}

struct lota_client *lota_connect_opts(const struct lota_connect_opts *opts) {
  struct lota_client *client;
  char discovery[MAX_DISCOVERY_PATHS][PATH_MAX];
  int timeout_ms;
  int fd = -1;

  timeout_ms =
      (opts && opts->timeout_ms > 0) ? opts->timeout_ms : DEFAULT_TIMEOUT_MS;

  /*
   * if the caller provided an explicit socket path, use only that
   * otherwise, try autodiscovery across known paths
   */
  if (opts && opts->socket_path) {
    fd = try_connect_path(opts->socket_path, timeout_ms);
  } else {
    int count = build_discovery_paths(discovery, MAX_DISCOVERY_PATHS);

    for (int i = 0; i < count; i++) {
      /* quick existence check to avoid blocking connect on missing sockets */
      struct stat st;
      if (stat(discovery[i], &st) != 0)
        continue;

      fd = try_connect_path(discovery[i], timeout_ms);
      if (fd >= 0)
        break;
    }
  }

  if (fd < 0)
    return NULL;

  client = calloc(1, sizeof(*client));
  if (!client) {
    close(fd);
    return NULL;
  }

  client->fd = fd;
  client->timeout_ms = timeout_ms;

  return client;
}

void lota_disconnect(struct lota_client *client) {
  if (!client)
    return;

  if (client->fd >= 0)
    close(client->fd);

  free(client);
}

int lota_get_fd(struct lota_client *client) {
  if (!client)
    return -1;
  return client->fd;
}

int lota_ping(struct lota_client *client, uint64_t *uptime_sec) {
  struct lota_ipc_request req;
  struct lota_ipc_response resp;
  struct lota_ipc_ping_response ping;
  size_t payload_len;
  int ret;

  if (!client)
    return LOTA_ERR_NOT_CONNECTED;

  /* build request */
  memset(&req, 0, sizeof(req));
  req.magic = LOTA_IPC_MAGIC;
  req.version = LOTA_IPC_VERSION;
  req.cmd = LOTA_IPC_CMD_PING;
  req.payload_len = 0;

  ret = send_request(client, &req, NULL, 0);
  if (ret < 0)
    return (ret == -ETIMEDOUT) ? LOTA_ERR_TIMEOUT : LOTA_ERR_PROTOCOL;

  ret = recv_response(client, &resp, &ping, sizeof(ping), &payload_len);
  if (ret < 0)
    return (ret == -ETIMEDOUT) ? LOTA_ERR_TIMEOUT : LOTA_ERR_PROTOCOL;

  if (resp.result != LOTA_IPC_OK)
    return ipc_result_to_error(resp.result);

  if (uptime_sec && payload_len >= sizeof(ping))
    *uptime_sec = ping.uptime_sec;

  return LOTA_OK;
}

int lota_get_status(struct lota_client *client, struct lota_status *status) {
  struct lota_ipc_request req;
  struct lota_ipc_response resp;
  struct lota_ipc_status ipc_status;
  size_t payload_len;
  int ret;

  if (!client)
    return LOTA_ERR_NOT_CONNECTED;
  if (!status)
    return LOTA_ERR_INVALID_ARG;

  /* build request */
  memset(&req, 0, sizeof(req));
  req.magic = LOTA_IPC_MAGIC;
  req.version = LOTA_IPC_VERSION;
  req.cmd = LOTA_IPC_CMD_GET_STATUS;
  req.payload_len = 0;

  ret = send_request(client, &req, NULL, 0);
  if (ret < 0)
    return (ret == -ETIMEDOUT) ? LOTA_ERR_TIMEOUT : LOTA_ERR_PROTOCOL;

  ret = recv_response(client, &resp, &ipc_status, sizeof(ipc_status),
                      &payload_len);
  if (ret < 0)
    return (ret == -ETIMEDOUT) ? LOTA_ERR_TIMEOUT : LOTA_ERR_PROTOCOL;

  if (resp.result != LOTA_IPC_OK)
    return ipc_result_to_error(resp.result);

  /* copy to output */
  if (payload_len >= sizeof(ipc_status)) {
    status->flags = ipc_status.flags;
    status->last_attest_time = ipc_status.last_attest_time;
    status->valid_until = ipc_status.valid_until;
    status->attest_count = ipc_status.attest_count;
    status->fail_count = ipc_status.fail_count;
  } else {
    memset(status, 0, sizeof(*status));
  }

  return LOTA_OK;
}

int lota_is_attested(struct lota_client *client) {
  struct lota_status status;
  int ret;

  ret = lota_get_status(client, &status);
  if (ret != LOTA_OK)
    return 0;

  return (status.flags & LOTA_FLAG_ATTESTED) ? 1 : 0;
}

int lota_get_token(struct lota_client *client, const uint8_t *nonce,
                   struct lota_token *token) {
  struct lota_ipc_request req;
  struct lota_ipc_response resp;
  struct lota_ipc_token_request token_req;
  uint8_t buf[LOTA_IPC_TOKEN_MAX_SIZE];
  struct lota_ipc_token *ipc_token;
  uint8_t *data_ptr;
  size_t payload_len;
  int ret;

  if (!client)
    return LOTA_ERR_NOT_CONNECTED;
  if (!token)
    return LOTA_ERR_INVALID_ARG;

  /* initialize token */
  memset(token, 0, sizeof(*token));

  /* build request */
  memset(&req, 0, sizeof(req));
  req.magic = LOTA_IPC_MAGIC;
  req.version = LOTA_IPC_VERSION;
  req.cmd = LOTA_IPC_CMD_GET_TOKEN;

  if (nonce) {
    memset(&token_req, 0, sizeof(token_req));
    memcpy(token_req.nonce, nonce, 32);
    req.payload_len = sizeof(token_req);
  } else {
    req.payload_len = 0;
  }

  ret = send_request(client, &req, nonce ? &token_req : NULL,
                     nonce ? sizeof(token_req) : 0);
  if (ret < 0)
    return (ret == -ETIMEDOUT) ? LOTA_ERR_TIMEOUT : LOTA_ERR_PROTOCOL;

  ret = recv_response(client, &resp, buf, sizeof(buf), &payload_len);
  if (ret < 0)
    return (ret == -ETIMEDOUT) ? LOTA_ERR_TIMEOUT : LOTA_ERR_PROTOCOL;

  if (resp.result != LOTA_IPC_OK)
    return ipc_result_to_error(resp.result);

  if (payload_len < LOTA_IPC_TOKEN_HEADER_SIZE)
    return LOTA_ERR_PROTOCOL;

  /* parse token header */
  ipc_token = (struct lota_ipc_token *)buf;

  token->valid_until = ipc_token->valid_until;
  token->flags = ipc_token->flags;
  memcpy(token->nonce, ipc_token->client_nonce, 32);
  token->sig_alg = ipc_token->sig_alg;
  token->hash_alg = ipc_token->hash_alg;
  token->pcr_mask = ipc_token->pcr_mask;

  /* validate sizes */
  if (ipc_token->attest_size > LOTA_IPC_TOKEN_MAX_ATTEST ||
      ipc_token->sig_size > LOTA_IPC_TOKEN_MAX_SIG)
    return LOTA_ERR_PROTOCOL;

  size_t expected_len =
      LOTA_IPC_TOKEN_HEADER_SIZE + ipc_token->attest_size + ipc_token->sig_size;
  if (payload_len < expected_len)
    return LOTA_ERR_PROTOCOL;

  data_ptr = buf + LOTA_IPC_TOKEN_HEADER_SIZE;

  /* copy attest_data if present */
  if (ipc_token->attest_size > 0) {
    token->attest_data = malloc(ipc_token->attest_size);
    if (!token->attest_data)
      return LOTA_ERR_NO_MEMORY;

    memcpy(token->attest_data, data_ptr, ipc_token->attest_size);
    token->attest_size = ipc_token->attest_size;
    data_ptr += ipc_token->attest_size;
  }

  /* copy signature if present */
  if (ipc_token->sig_size > 0) {
    token->signature = malloc(ipc_token->sig_size);
    if (!token->signature) {
      free(token->attest_data);
      token->attest_data = NULL;
      return LOTA_ERR_NO_MEMORY;
    }

    memcpy(token->signature, data_ptr, ipc_token->sig_size);
    token->signature_len = ipc_token->sig_size;
  }

  return LOTA_OK;
}

void lota_token_free(struct lota_token *token) {
  if (!token)
    return;

  free(token->attest_data);
  token->attest_data = NULL;
  token->attest_size = 0;

  free(token->signature);
  token->signature = NULL;
  token->signature_len = 0;
}

/*
 * Serialization using shared definitions
 */
size_t lota_token_serialized_size(const struct lota_token *token) {
  if (!token)
    return 0;
  if (token->attest_size > 1024 || token->signature_len > 512)
    return 0;

  return LOTA_TOKEN_HEADER_SIZE + token->attest_size + token->signature_len;
}

int lota_token_serialize(const struct lota_token *token, uint8_t *buf,
                         size_t buflen, size_t *written) {
  if (!token || !buf)
    return LOTA_ERR_INVALID_ARG;

  size_t total = lota_token_serialized_size(token);
  if (total == 0)
    return LOTA_ERR_INVALID_ARG;
  if (buflen < total)
    return LOTA_ERR_BUFFER_TOO_SMALL;

  /* populate header struct */
  struct lota_token_wire wire;
  memset(&wire, 0, sizeof(wire));

  wire.magic = LOTA_TOKEN_MAGIC;
  wire.version = LOTA_TOKEN_VERSION;
  wire.total_size = (uint16_t)total;

  wire.valid_until = token->valid_until;
  wire.flags = token->flags;
  memcpy(wire.nonce, token->nonce, 32);
  wire.sig_alg = token->sig_alg;
  wire.hash_alg = token->hash_alg;
  wire.pcr_mask = token->pcr_mask;
  wire.attest_size = (uint16_t)token->attest_size;
  wire.sig_size = (uint16_t)token->signature_len;

  /* write header */
  memcpy(buf, &wire, sizeof(wire));
  size_t off = sizeof(wire);

  /* write attest_data */
  if (token->attest_size > 0 && token->attest_data) {
    memcpy(buf + off, token->attest_data, token->attest_size);
    off += token->attest_size;
  }

  /* write signature */
  if (token->signature_len > 0 && token->signature) {
    memcpy(buf + off, token->signature, token->signature_len);
    off += token->signature_len;
  }

  if (written)
    *written = off;

  return LOTA_OK;
}

int lota_subscribe(struct lota_client *client, uint32_t event_mask,
                   lota_status_callback_fn callback, void *user_data) {
  struct lota_ipc_request req;
  struct lota_ipc_response resp;
  struct lota_ipc_subscribe_request sub;
  size_t payload_len;
  int ret;

  if (!client)
    return LOTA_ERR_NOT_CONNECTED;
  if (event_mask != 0 && !callback)
    return LOTA_ERR_INVALID_ARG;

  memset(&req, 0, sizeof(req));
  req.magic = LOTA_IPC_MAGIC;
  req.version = LOTA_IPC_VERSION;
  req.cmd = LOTA_IPC_CMD_SUBSCRIBE;
  req.payload_len = sizeof(sub);

  sub.event_mask = event_mask;

  ret = send_request(client, &req, &sub, sizeof(sub));
  if (ret < 0)
    return (ret == -ETIMEDOUT) ? LOTA_ERR_TIMEOUT : LOTA_ERR_PROTOCOL;

  ret = recv_response(client, &resp, NULL, 0, &payload_len);
  if (ret < 0)
    return (ret == -ETIMEDOUT) ? LOTA_ERR_TIMEOUT : LOTA_ERR_PROTOCOL;

  if (resp.result != LOTA_IPC_OK)
    return ipc_result_to_error(resp.result);

  client->callback = callback;
  client->user_data = user_data;

  return LOTA_OK;
}

int lota_unsubscribe(struct lota_client *client) {
  int ret;

  ret = lota_subscribe(client, 0, NULL, NULL);
  if (ret == LOTA_OK) {
    client->callback = NULL;
    client->user_data = NULL;
  }
  return ret;
}

int lota_poll_events(struct lota_client *client, int timeout_ms) {
  struct lota_ipc_response resp;
  uint8_t buf[sizeof(struct lota_ipc_notify)];
  ssize_t n;
  int ret;
  int dispatched = 0;

  if (!client)
    return LOTA_ERR_NOT_CONNECTED;

  for (;;) {
    ret = wait_for_socket(client->fd, POLLIN, timeout_ms);
    if (ret == -ETIMEDOUT)
      break;
    if (ret < 0)
      return LOTA_ERR_PROTOCOL;

    n = recv(client->fd, &resp, sizeof(resp), MSG_WAITALL);
    if (n == 0)
      return LOTA_ERR_NOT_CONNECTED;
    if (n != sizeof(resp))
      return LOTA_ERR_PROTOCOL;

    if (resp.magic != LOTA_IPC_MAGIC)
      return LOTA_ERR_PROTOCOL;

    if (resp.result != LOTA_IPC_NOTIFY) {
      /* unexpected non-notification -> drain and skip */
      if (resp.payload_len > 0)
        drain_payload(client->fd, resp.payload_len);
      continue;
    }

    if (resp.payload_len > 0) {
      size_t nlen =
          resp.payload_len < sizeof(buf) ? resp.payload_len : sizeof(buf);

      ret = wait_for_socket(client->fd, POLLIN,
                            timeout_ms > 0 ? timeout_ms : 1000);
      if (ret < 0)
        break;

      n = recv(client->fd, buf, nlen, MSG_WAITALL);
      if (n != (ssize_t)nlen)
        return LOTA_ERR_PROTOCOL;

      if (resp.payload_len > sizeof(buf))
        drain_payload(client->fd, resp.payload_len - sizeof(buf));

      dispatched += dispatch_notification(client, buf, nlen);
    }

    /* switch to non-blocking to drain queue */
    timeout_ms = 0;
  }

  return dispatched;
}

const char *lota_strerror(int error) {
  switch (error) {
  case LOTA_OK:
    return "Success";
  case LOTA_ERR_NOT_CONNECTED:
    return "Not connected to agent";
  case LOTA_ERR_CONNECTION_FAILED:
    return "Connection to agent failed";
  case LOTA_ERR_TIMEOUT:
    return "Operation timed out";
  case LOTA_ERR_PROTOCOL:
    return "Protocol error";
  case LOTA_ERR_NOT_ATTESTED:
    return "System not attested";
  case LOTA_ERR_INVALID_ARG:
    return "Invalid argument";
  case LOTA_ERR_BUFFER_TOO_SMALL:
    return "Buffer too small";
  case LOTA_ERR_AGENT_ERROR:
    return "Agent returned error";
  case LOTA_ERR_NO_MEMORY:
    return "Out of memory";
  case LOTA_ERR_RATE_LIMITED:
    return "Request rate limited";
  case LOTA_ERR_ACCESS_DENIED:
    return "Access denied";
  default:
    return "Unknown error";
  }
}

const char *lota_sdk_version(void) { return VERSION_STRING; }

int lota_flags_to_string(uint32_t flags, char *buf, size_t buflen) {
  static const struct {
    uint32_t flag;
    const char *name;
  } flag_names[] = {
      {LOTA_FLAG_ATTESTED, "ATTESTED"},
      {LOTA_FLAG_TPM_OK, "TPM_OK"},
      {LOTA_FLAG_IOMMU_OK, "IOMMU_OK"},
      {LOTA_FLAG_BPF_LOADED, "BPF_LOADED"},
      {LOTA_FLAG_SECURE_BOOT, "SECURE_BOOT"},
  };
  size_t pos = 0;
  int first = 1;

  if (!buf || buflen == 0)
    return LOTA_ERR_INVALID_ARG;

  buf[0] = '\0';

  for (size_t i = 0; i < sizeof(flag_names) / sizeof(flag_names[0]); i++) {
    if (!(flags & flag_names[i].flag))
      continue;

    size_t name_len = strlen(flag_names[i].name);
    size_t needed = name_len + (first ? 0 : 1);

    if (pos + needed >= buflen)
      return LOTA_ERR_BUFFER_TOO_SMALL;

    if (!first)
      buf[pos++] = ',';

    memcpy(buf + pos, flag_names[i].name, name_len);
    pos += name_len;
    first = 0;
  }

  buf[pos] = '\0';
  return (int)pos;
}
