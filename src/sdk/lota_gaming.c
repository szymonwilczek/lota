/* SPDX-License-Identifier: MIT */
/*
 * LOTA Gaming SDK - Implementation
 *
 * Client library for games to query local attestation status.
 */

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "../../include/lota_gaming.h"
#include "../../include/lota_ipc.h"

#define DEFAULT_TIMEOUT_MS 5000
#define VERSION_STRING "1.0.0"

/*
 * Client context
 */
struct lota_client {
  int fd;
  int timeout_ms;
};

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
  ssize_t n;
  int ret;

  ret = wait_for_socket(client->fd, POLLOUT, client->timeout_ms);
  if (ret < 0)
    return ret;

  /* send header */
  n = send(client->fd, req, sizeof(*req), MSG_NOSIGNAL);
  if (n != sizeof(*req))
    return (n < 0) ? -errno : -EIO;

  /* send payload if present */
  if (payload && payload_len > 0) {
    n = send(client->fd, payload, payload_len, MSG_NOSIGNAL);
    if (n != (ssize_t)payload_len)
      return (n < 0) ? -errno : -EIO;
  }

  return 0;
}

/*
 * Receive response with timeout
 */
static int recv_response(struct lota_client *client,
                         struct lota_ipc_response *resp, void *payload,
                         size_t payload_size, size_t *payload_len) {
  ssize_t n;
  int ret;

  ret = wait_for_socket(client->fd, POLLIN, client->timeout_ms);
  if (ret < 0)
    return ret;

  /* receive header */
  n = recv(client->fd, resp, sizeof(*resp), MSG_WAITALL);
  if (n != sizeof(*resp))
    return (n < 0) ? -errno : -EIO;

  if (resp->magic != LOTA_IPC_MAGIC)
    return LOTA_ERR_PROTOCOL;

  /* receive payload if present */
  if (resp->payload_len > 0) {
    if (resp->payload_len > payload_size) {
      char discard[256];
      size_t remaining = resp->payload_len;

      while (remaining > 0) {
        size_t chunk =
            remaining < sizeof(discard) ? remaining : sizeof(discard);
        n = recv(client->fd, discard, chunk, 0);
        if (n <= 0)
          break;
        remaining -= (size_t)n;
      }
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
  case LOTA_IPC_ERR_TPM_FAILURE:
  case LOTA_IPC_ERR_INTERNAL:
  default:
    return LOTA_ERR_AGENT_ERROR;
  }
}

struct lota_client *lota_connect(void) { return lota_connect_opts(NULL); }

struct lota_client *lota_connect_opts(const struct lota_connect_opts *opts) {
  struct lota_client *client;
  struct sockaddr_un addr;
  const char *path;
  int timeout_ms;
  int fd;
  int ret;

  path = (opts && opts->socket_path) ? opts->socket_path : LOTA_IPC_SOCKET_PATH;
  timeout_ms =
      (opts && opts->timeout_ms > 0) ? opts->timeout_ms : DEFAULT_TIMEOUT_MS;

  fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0)
    return NULL;

  if (set_nonblock(fd) < 0) {
    close(fd);
    return NULL;
  }

  /* connect */
  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, path, sizeof(addr.sun_path) - 1);

  ret = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
  if (ret < 0 && errno != EINPROGRESS) {
    close(fd);
    return NULL;
  }

  if (ret < 0) {
    /* wait for connection to complete */
    ret = wait_for_socket(fd, POLLOUT, timeout_ms);
    if (ret < 0) {
      close(fd);
      return NULL;
    }

    /* check for connection error */
    int err = 0;
    socklen_t len = sizeof(err);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
    if (err != 0) {
      close(fd);
      return NULL;
    }
  }

  client = malloc(sizeof(*client));
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
  uint8_t buf[sizeof(struct lota_ipc_token) + LOTA_IPC_TOKEN_MAX_SIG];
  struct lota_ipc_token *ipc_token;
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

  if (payload_len < sizeof(struct lota_ipc_token))
    return LOTA_ERR_PROTOCOL;

  /* parse token */
  ipc_token = (struct lota_ipc_token *)buf;
  token->issued_at = ipc_token->issued_at;
  token->valid_until = ipc_token->valid_until;
  token->flags = ipc_token->flags;
  memcpy(token->nonce, ipc_token->client_nonce, 32);
  memcpy(token->agent_nonce, ipc_token->agent_nonce, 32);

  /* copy signature if present */
  if (ipc_token->signature_len > 0) {
    if (ipc_token->signature_len > LOTA_IPC_TOKEN_MAX_SIG)
      return LOTA_ERR_PROTOCOL;

    size_t expected_len =
        sizeof(struct lota_ipc_token) + ipc_token->signature_len;
    if (payload_len < expected_len)
      return LOTA_ERR_PROTOCOL;

    token->signature = malloc(ipc_token->signature_len);
    if (!token->signature)
      return LOTA_ERR_NO_MEMORY;

    memcpy(token->signature, buf + sizeof(struct lota_ipc_token),
           ipc_token->signature_len);
    token->signature_len = ipc_token->signature_len;
  }

  return LOTA_OK;
}

void lota_token_free(struct lota_token *token) {
  if (!token)
    return;

  free(token->signature);
  token->signature = NULL;
  token->signature_len = 0;
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
