/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - IPC Server Implementation
 * Unix socket server for local attestation queries.
 */

#include "ipc.h"
#include "../../include/lota.h"
#include "../../include/lota_ipc.h"
#include "dbus.h"
#include "journal.h"
#include "quote.h"
#include "tpm.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define MAX_EVENTS 64
#define MAX_CONNECTED_CLIENTS 2048
#define SOCKET_DIR "/run/lota"
#define LOTA_GROUP_NAME "lota"

/* Rate limiting: max GET_TOKEN requests per UID per window */
#define TOKEN_RATE_LIMIT 10      /* requests */
#define TOKEN_RATE_WINDOW_SEC 60 /* per minute */

/*
 * Per-UID rate limiter
 */
struct uid_rate {
  uid_t uid;
  int count;
  time_t window_start;
};

#define MAX_RATE_ENTRIES 256
static struct uid_rate rate_table[MAX_RATE_ENTRIES];
static int rate_count = 0;

/*
 * Check and update rate limit for a UID.
 * Returns 0 if allowed, -1 if rate limited.
 */
static int check_rate_limit(uid_t uid) {
  time_t now = time(NULL);

  /* existing entry */
  for (int i = 0; i < rate_count; i++) {
    if (rate_table[i].uid == uid) {
      /* reset window if expired */
      if (now - rate_table[i].window_start >= TOKEN_RATE_WINDOW_SEC) {
        rate_table[i].count = 1;
        rate_table[i].window_start = now;
        return 0;
      }
      /* within window: check limit */
      if (rate_table[i].count >= TOKEN_RATE_LIMIT)
        return -1;
      rate_table[i].count++;
      return 0;
    }
  }

  /* new entry */
  if (rate_count < MAX_RATE_ENTRIES) {
    rate_table[rate_count].uid = uid;
    rate_table[rate_count].count = 1;
    rate_table[rate_count].window_start = now;
    rate_count++;
    return 0;
  }

  /* table full - LRU */
  int oldest = 0;
  for (int i = 1; i < rate_count; i++) {
    if (rate_table[i].window_start < rate_table[oldest].window_start)
      oldest = i;
  }
  rate_table[oldest].uid = uid;
  rate_table[oldest].count = 1;
  rate_table[oldest].window_start = now;
  return 0;
}

/*
 * Client connection state
 *
 * recv_buf and send_buf are sized to hold exactly one maximum-size
 * IPC message. The payload_len cap in handle_client_read() ensures
 * untrusted clients cannot trigger allocations beyond these buffers.
 */
struct ipc_client {
  int fd;
  uid_t peer_uid; /* authenticated peer UID via SO_PEERCRED */
  gid_t peer_gid; /* authenticated peer GID */
  pid_t peer_pid; /* authenticated peer PID */
  uint8_t recv_buf[LOTA_IPC_REQUEST_SIZE + LOTA_IPC_MAX_PAYLOAD];
  size_t recv_len;
  uint8_t send_buf[LOTA_IPC_RESPONSE_SIZE + LOTA_IPC_MAX_PAYLOAD];
  size_t send_len;
  size_t send_offset;
  bool subscribed;         /* client subscribed to notifications */
  uint32_t event_mask;     /* LOTA_IPC_EVENT_* subscription mask */
  bool notify_pending;     /* notification queued behind current send */
  uint32_t pending_events; /* accumulated LOTA_IPC_EVENT_* while busy */
  struct ipc_client *next;
};

_Static_assert(
    LOTA_IPC_MAX_PAYLOAD <= 65536,
    "IPC payload cap must be bounded to prevent excessive memory use");

static struct ipc_client *client_list = NULL;
static int client_count = 0;

/*
 * Set socket to non-blocking mode
 */
static int set_nonblocking(int fd) {
  int flags = fcntl(fd, F_GETFL, 0);
  if (flags < 0)
    return -errno;
  if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
    return -errno;
  return 0;
}

/*
 * Create socket directory if needed
 */
static int ensure_socket_dir(void) {
  struct stat st;

  if (stat(SOCKET_DIR, &st) == 0) {
    if (!S_ISDIR(st.st_mode))
      return -ENOTDIR;
    return 0;
  }

  if (mkdir(SOCKET_DIR, 0750) < 0)
    return -errno;

  /* set socket directory group to 'lota' if the group exists */
  struct group *grp = getgrnam(LOTA_GROUP_NAME);
  if (grp) {
    if (chown(SOCKET_DIR, 0, grp->gr_gid) < 0)
      lota_warn("chown(%s) failed: %s", SOCKET_DIR, strerror(errno));
  }

  return 0;
}

/*
 * Find or create client slot
 */
static struct ipc_client *client_create(int fd, uid_t uid, gid_t gid,
                                        pid_t pid) {
  struct ipc_client *client;

  if (client_count >= MAX_CONNECTED_CLIENTS) {
    lota_warn("Max clients (%d) reached, rejecting connection",
              MAX_CONNECTED_CLIENTS);
    return NULL;
  }

  client = calloc(1, sizeof(*client));
  if (!client)
    return NULL;

  client->fd = fd;
  client->peer_uid = uid;
  client->peer_gid = gid;
  client->peer_pid = pid;

  client->next = client_list;
  client_list = client;
  client_count++;

  return client;
}

/*
 * Find client by fd
 */
static struct ipc_client *client_find(int fd) {
  struct ipc_client *c = client_list;
  while (c) {
    if (c->fd == fd)
      return c;
    c = c->next;
  }
  return NULL;
}

/*
 * Remove and free client
 */
static void client_destroy(struct ipc_client *client) {
  struct ipc_client **pp = &client_list;

  while (*pp) {
    if (*pp == client) {
      *pp = client->next;
      client_count--;
      close(client->fd);
      free(client);
      return;
    }
    pp = &(*pp)->next;
  }
}

/*
 * Build error response
 */
static void build_error_response(struct ipc_client *client, uint32_t result) {
  struct lota_ipc_response *resp = (void *)client->send_buf;

  resp->magic = LOTA_IPC_MAGIC;
  resp->version = LOTA_IPC_VERSION;
  resp->result = result;
  resp->payload_len = 0;

  client->send_len = LOTA_IPC_RESPONSE_SIZE;
  client->send_offset = 0;
}

/*
 * Build a notification frame in the client's send buffer.
 */
static void build_notification(struct ipc_context *ctx,
                               struct ipc_client *client, uint32_t events) {
  struct lota_ipc_response *resp = (void *)client->send_buf;
  struct lota_ipc_notify *notify;

  resp->magic = LOTA_IPC_MAGIC;
  resp->version = LOTA_IPC_VERSION;
  resp->result = LOTA_IPC_NOTIFY;
  resp->payload_len = sizeof(*notify);

  notify = (void *)(client->send_buf + LOTA_IPC_RESPONSE_SIZE);
  notify->events = events;
  notify->flags = ctx->status_flags;
  notify->last_attest_time = ctx->last_attest_time;
  notify->valid_until = ctx->valid_until;
  notify->attest_count = ctx->attest_count;
  notify->fail_count = ctx->fail_count;
  notify->mode = ctx->mode;
  memset(notify->reserved, 0, sizeof(notify->reserved));

  client->send_len = LOTA_IPC_RESPONSE_SIZE + sizeof(*notify);
  client->send_offset = 0;
}

/*
 * Push notification to a single subscriber.
 */
static void push_notify(struct ipc_context *ctx, struct ipc_client *client,
                        uint32_t events) {
  uint32_t relevant = events & client->event_mask;

  if (!relevant)
    return;

  if (client->send_len > client->send_offset) {
    /* send in progress -> accumulate */
    client->notify_pending = true;
    client->pending_events |= relevant;
    return;
  }

  build_notification(ctx, client, relevant);
}

/*
 * Notify all subscribers about an event.
 */
static void notify_subscribers(struct ipc_context *ctx, uint32_t events) {
  struct ipc_client *c = client_list;
  while (c) {
    if (c->subscribed)
      push_notify(ctx, c, events);
    c = c->next;
  }
}

/*
 * Handle PING command
 */
static void handle_ping(struct ipc_context *ctx, struct ipc_client *client) {
  struct lota_ipc_response *resp = (void *)client->send_buf;
  struct lota_ipc_ping_response *ping;

  resp->magic = LOTA_IPC_MAGIC;
  resp->version = LOTA_IPC_VERSION;
  resp->result = LOTA_IPC_OK;
  resp->payload_len = sizeof(*ping);

  ping = (void *)(client->send_buf + LOTA_IPC_RESPONSE_SIZE);
  ping->uptime_sec = (uint64_t)(time(NULL) - ctx->start_time);
  ping->pid = (uint32_t)getpid();

  client->send_len = LOTA_IPC_RESPONSE_SIZE + sizeof(*ping);
  client->send_offset = 0;
}

/*
 * Handle GET_STATUS command
 */
static void handle_get_status(struct ipc_context *ctx,
                              struct ipc_client *client) {
  struct lota_ipc_response *resp = (void *)client->send_buf;
  struct lota_ipc_status *status;

  resp->magic = LOTA_IPC_MAGIC;
  resp->version = LOTA_IPC_VERSION;
  resp->result = LOTA_IPC_OK;
  resp->payload_len = sizeof(*status);

  status = (void *)(client->send_buf + LOTA_IPC_RESPONSE_SIZE);
  status->flags = ctx->status_flags;
  status->last_attest_time = ctx->last_attest_time;
  status->valid_until = ctx->valid_until;
  status->attest_count = ctx->attest_count;
  status->fail_count = ctx->fail_count;
  status->mode = ctx->mode;
  memset(status->reserved, 0, sizeof(status->reserved));

  client->send_len = LOTA_IPC_RESPONSE_SIZE + sizeof(*status);
  client->send_offset = 0;
}

/*
 * Write little-endian uint32 into buffer
 */
static void write_le32(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v);
  p[1] = (uint8_t)(v >> 8);
  p[2] = (uint8_t)(v >> 16);
  p[3] = (uint8_t)(v >> 24);
}

/*
 * Write little-endian uint64 into buffer
 */
static void write_le64(uint8_t *p, uint64_t v) {
  write_le32(p, (uint32_t)v);
  write_le32(p + 4, (uint32_t)(v >> 32));
}

/*
 * Compute binding nonce for token
 *
 * Creates a SHA-256 hash of token header fields to use as TPM quote nonce.
 * This binds the TPM signature to the specific token data.
 * All integers are encoded in little-endian to match the wire format.
 */
static int compute_token_nonce(uint64_t issued_at, uint64_t valid_until,
                               uint32_t flags, const uint8_t *client_nonce,
                               uint8_t *out_nonce) {
  EVP_MD_CTX *mdctx;
  unsigned int len;
  uint8_t le_buf[20]; /* 8 + 8 + 4 */

  write_le64(le_buf, issued_at);
  write_le64(le_buf + 8, valid_until);
  write_le32(le_buf + 16, flags);

  mdctx = EVP_MD_CTX_new();
  if (!mdctx)
    return -ENOMEM;

  if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1 ||
      EVP_DigestUpdate(mdctx, le_buf, 8) != 1 ||
      EVP_DigestUpdate(mdctx, le_buf + 8, 8) != 1 ||
      EVP_DigestUpdate(mdctx, le_buf + 16, 4) != 1 ||
      EVP_DigestUpdate(mdctx, client_nonce, 32) != 1 ||
      EVP_DigestFinal_ex(mdctx, out_nonce, &len) != 1) {
    EVP_MD_CTX_free(mdctx);
    return -EIO;
  }

  EVP_MD_CTX_free(mdctx);
  return 0;
}

/*
 * Handle GET_TOKEN command
 *
 * Generates a signed attestation token using TPM Quote.
 * The TPM signs over a hash of (token_header + client_nonce),
 * binding the signature to both the attestation state and the
 * client's challenge.
 */
static void handle_get_token(struct ipc_context *ctx, struct ipc_client *client,
                             const uint8_t *payload, uint32_t payload_len) {
  struct lota_ipc_response *resp = (void *)client->send_buf;
  struct lota_ipc_token *token;
  const struct lota_ipc_token_request *req = NULL;
  uint8_t binding_nonce[LOTA_NONCE_SIZE];
  struct tpm_quote_response quote;
  uint8_t *data_ptr;
  size_t total_size;
  int ret;

  if (!(ctx->status_flags & LOTA_STATUS_ATTESTED)) {
    build_error_response(client, LOTA_IPC_ERR_NOT_ATTESTED);
    return;
  }

  /* rate limit GET_TOKEN per peer UID */
  if (check_rate_limit(client->peer_uid) < 0) {
    lota_warn("rate limited GET_TOKEN for uid=%d pid=%d", client->peer_uid,
              client->peer_pid);
    build_error_response(client, LOTA_IPC_ERR_RATE_LIMITED);
    return;
  }

  if (payload_len >= sizeof(*req))
    req = (const void *)payload;

  /* build token header */
  token = (void *)(client->send_buf + LOTA_IPC_RESPONSE_SIZE);
  token->issued_at = (uint64_t)time(NULL);
  token->valid_until = ctx->valid_until;
  token->flags = ctx->status_flags;

  if (req)
    memcpy(token->client_nonce, req->nonce, 32);
  else
    memset(token->client_nonce, 0, 32);

  /* TPM context is required - refuse to issue unsigned tokens */
  if (!ctx->tpm) {
    build_error_response(client, LOTA_IPC_ERR_TPM_FAILURE);
    return;
  }

  ret = compute_token_nonce(token->issued_at, token->valid_until, token->flags,
                            token->client_nonce, binding_nonce);
  if (ret < 0) {
    lota_err("compute_token_nonce failed: %s", strerror(-ret));
    build_error_response(client, LOTA_IPC_ERR_INTERNAL);
    return;
  }

  ret = tpm_quote(ctx->tpm, binding_nonce, ctx->quote_pcr_mask, &quote);
  if (ret < 0) {
    lota_err("tpm_quote failed: %s", strerror(-ret));
    build_error_response(client, LOTA_IPC_ERR_TPM_FAILURE);
    return;
  }

  /* check buffer space */
  total_size =
      LOTA_IPC_TOKEN_HEADER_SIZE + quote.attest_size + quote.signature_size;
  if (total_size > LOTA_IPC_MAX_PAYLOAD) {
    lota_err("token too large (%zu bytes)", total_size);
    build_error_response(client, LOTA_IPC_ERR_INTERNAL);
    return;
  }

  token->attest_size = quote.attest_size;
  token->sig_size = quote.signature_size;
  token->sig_alg = quote.sig_alg;
  token->hash_alg = quote.hash_alg;
  token->pcr_mask = quote.pcr_mask;

  /* copy attest data and signature */
  data_ptr =
      client->send_buf + LOTA_IPC_RESPONSE_SIZE + LOTA_IPC_TOKEN_HEADER_SIZE;
  memcpy(data_ptr, quote.attest_data, quote.attest_size);
  data_ptr += quote.attest_size;
  memcpy(data_ptr, quote.signature, quote.signature_size);

  /* build response */
  resp->magic = LOTA_IPC_MAGIC;
  resp->version = LOTA_IPC_VERSION;
  resp->result = LOTA_IPC_OK;
  resp->payload_len = (uint32_t)total_size;

  client->send_len = LOTA_IPC_RESPONSE_SIZE + total_size;
  client->send_offset = 0;
}

/*
 * Handle SUBSCRIBE command
 *
 * Registers or cancels per-connection push notifications.
 * event_mask = 0 cancels any existing subscription.
 */
static void handle_subscribe(struct ipc_context *ctx, struct ipc_client *client,
                             const uint8_t *payload, uint32_t payload_len) {
  struct lota_ipc_response *resp = (void *)client->send_buf;
  const struct lota_ipc_subscribe_request *sub;
  (void)ctx;

  if (payload_len < sizeof(*sub)) {
    build_error_response(client, LOTA_IPC_ERR_BAD_REQUEST);
    return;
  }

  sub = (const void *)payload;

  if (sub->event_mask == 0) {
    client->subscribed = false;
    client->event_mask = 0;
    client->notify_pending = false;
    client->pending_events = 0;
  } else {
    client->subscribed = true;
    client->event_mask = sub->event_mask;
  }

  resp->magic = LOTA_IPC_MAGIC;
  resp->version = LOTA_IPC_VERSION;
  resp->result = LOTA_IPC_OK;
  resp->payload_len = 0;

  client->send_len = LOTA_IPC_RESPONSE_SIZE;
  client->send_offset = 0;
}

/*
 * Process complete request
 */
static void process_request(struct ipc_context *ctx,
                            struct ipc_client *client) {
  struct lota_ipc_request *req = (void *)client->recv_buf;
  uint8_t *payload = client->recv_buf + LOTA_IPC_REQUEST_SIZE;
  uint32_t payload_len = req->payload_len;

  if (req->magic != LOTA_IPC_MAGIC) {
    build_error_response(client, LOTA_IPC_ERR_BAD_REQUEST);
    return;
  }

  if (req->version != LOTA_IPC_VERSION) {
    build_error_response(client, LOTA_IPC_ERR_BAD_VERSION);
    return;
  }

  /* dispatch command */
  switch (req->cmd) {
  case LOTA_IPC_CMD_PING:
    handle_ping(ctx, client);
    break;

  case LOTA_IPC_CMD_GET_STATUS:
    handle_get_status(ctx, client);
    break;

  case LOTA_IPC_CMD_GET_TOKEN:
    handle_get_token(ctx, client, payload, payload_len);
    break;

  case LOTA_IPC_CMD_SUBSCRIBE:
    handle_subscribe(ctx, client, payload, payload_len);
    break;

  default:
    build_error_response(client, LOTA_IPC_ERR_UNKNOWN_CMD);
    break;
  }
}

/*
 * Handle client read event
 */
static int handle_client_read(struct ipc_context *ctx,
                              struct ipc_client *client) {
  ssize_t n;
  size_t need;
  struct lota_ipc_request *req;

  /*
   * Check if the buffer already contains a complete request from a
   * previous read (pipelined leftover)
   */
  if (client->recv_len < LOTA_IPC_REQUEST_SIZE)
    goto do_recv;

  req = (void *)client->recv_buf;

  if (req->payload_len > LOTA_IPC_MAX_PAYLOAD) {
    lota_warn("oversized payload from pid=%d uid=%d (len=%u)", client->peer_pid,
              client->peer_uid, req->payload_len);
    return -1; /* close: cannot recover from protocol desync */
  }

  need = LOTA_IPC_REQUEST_SIZE + req->payload_len;
  if (client->recv_len >= need)
    goto have_request;

do_recv:
  /* read as much as possible */
  need = sizeof(client->recv_buf) - client->recv_len;
  n = recv(client->fd, client->recv_buf + client->recv_len, need, 0);

  if (n < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK)
      return 0;
    return -errno;
  }

  if (n == 0)
    return -ECONNRESET; /* client disconnected */

  client->recv_len += n;

  /* complete header? */
  if (client->recv_len < LOTA_IPC_REQUEST_SIZE)
    return 0;

  req = (void *)client->recv_buf;

  if (req->payload_len > LOTA_IPC_MAX_PAYLOAD) {
    lota_warn("oversized payload from pid=%d uid=%d (len=%u)", client->peer_pid,
              client->peer_uid, req->payload_len);
    return -1; /* close: cannot recover from protocol desync */
  }

  /* complete request? */
  need = LOTA_IPC_REQUEST_SIZE + req->payload_len;
  if (client->recv_len < need)
    return 0;

have_request:
  /* defer if a previous response is still pending */
  if (client->send_len > 0)
    return 0;
  process_request(ctx, client);

  /* arm EPOLLOUT so the event loop will drive the send */
  if (client->send_len > 0) {
    struct epoll_event ev;
    ev.events = EPOLLIN | EPOLLOUT;
    ev.data.fd = client->fd;
    epoll_ctl(ctx->epoll_fd, EPOLL_CTL_MOD, client->fd, &ev);
  }

  /* preserve any leftover bytes from the next pipelined request */
  {
    size_t consumed = LOTA_IPC_REQUEST_SIZE + req->payload_len;
    if (client->recv_len > consumed) {
      memmove(client->recv_buf, client->recv_buf + consumed,
              client->recv_len - consumed);
      client->recv_len -= consumed;
    } else {
      client->recv_len = 0;
    }
  }

  return 1; /* response ready */
}

/*
 * Handle client write event
 */
static int handle_client_write(struct ipc_context *ctx,
                               struct ipc_client *client) {
  ssize_t n;
  size_t remaining;

  if (client->send_len == 0)
    return 0;

  while (client->send_offset < client->send_len) {
    remaining = client->send_len - client->send_offset;
    n = send(client->fd, client->send_buf + client->send_offset, remaining,
             MSG_NOSIGNAL);

    if (n < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
        return 0; /* yield to event loop, EPOLLOUT will re-fire */
      return -errno;
    }

    client->send_offset += n;
  }

  if (client->send_offset >= client->send_len) {
    /* response complete, reset */
    client->send_len = 0;
    client->send_offset = 0;

    /*
     * deliver pending notification that accumulated
     * while the previous send was in progress
     */
    if (client->subscribed && client->notify_pending) {
      uint32_t pending = client->pending_events;
      client->notify_pending = false;
      client->pending_events = 0;
      build_notification(ctx, client, pending);
    }

    /* disarm EPOLLOUT if nothing left to send */
    if (client->send_len == 0) {
      struct epoll_event ev;
      ev.events = EPOLLIN;
      ev.data.fd = client->fd;
      epoll_ctl(ctx->epoll_fd, EPOLL_CTL_MOD, client->fd, &ev);
    }
  }

  return 0;
}

/*
 * Accept new client with peer credential authentication
 */
static int accept_client(struct ipc_context *ctx, int listen_fd) {
  struct sockaddr_un addr;
  socklen_t len = sizeof(addr);
  struct ipc_client *client;
  struct epoll_event ev;
  struct ucred cred;
  socklen_t cred_len = sizeof(cred);
  int fd;
  int ret;

  fd = accept(listen_fd, (struct sockaddr *)&addr, &len);
  if (fd < 0) {
    if (errno == EAGAIN || errno == EWOULDBLOCK)
      return 0;
    return -errno;
  }

  /* retrieve peer credentials */
  if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) < 0) {
    lota_err("SO_PEERCRED failed: %s", strerror(errno));
    close(fd);
    return -errno;
  }

  lota_dbg("client connected pid=%d uid=%d gid=%d", cred.pid, cred.uid,
           cred.gid);

  ret = set_nonblocking(fd);
  if (ret < 0) {
    close(fd);
    return ret;
  }

  client = client_create(fd, cred.uid, cred.gid, cred.pid);
  if (!client) {
    close(fd);
    return -ENOMEM;
  }

  ev.events = EPOLLIN;
  ev.data.fd = fd;
  if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
    client_destroy(client);
    return -errno;
  }

  return 0;
}

/*
 * Initialize IPC server
 */
int ipc_init(struct ipc_context *ctx) {
  struct sockaddr_un addr;
  struct epoll_event ev;
  int ret;

  memset(ctx, 0, sizeof(*ctx));
  ctx->listen_fd = -1;
  ctx->epoll_fd = -1;
  ctx->start_time = time(NULL);

  for (int i = 0; i < IPC_MAX_EXTRA_LISTENERS; i++)
    ctx->extra[i].fd = -1;
  ctx->extra_count = 0;

  ret = ensure_socket_dir();
  if (ret < 0) {
    lota_err("failed to create %s: %s", SOCKET_DIR, strerror(-ret));
    return ret;
  }

  unlink(LOTA_IPC_SOCKET_PATH);

  ctx->listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (ctx->listen_fd < 0) {
    ret = -errno;
    lota_err("socket() failed: %s", strerror(-ret));
    return ret;
  }

  ret = set_nonblocking(ctx->listen_fd);
  if (ret < 0) {
    lota_err("set_nonblocking() failed: %s", strerror(-ret));
    goto err_close;
  }

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, LOTA_IPC_SOCKET_PATH, sizeof(addr.sun_path) - 1);

  /*
   * Restrict socket access to owner (root) and 'lota' group
   */
  {
    mode_t old_umask = umask(0117);
    ret = bind(ctx->listen_fd, (struct sockaddr *)&addr, sizeof(addr));
    umask(old_umask);
  }
  if (ret < 0) {
    ret = -errno;
    lota_err("bind(%s) failed: %s", LOTA_IPC_SOCKET_PATH, strerror(-ret));
    goto err_close;
  }
  {
    struct group *grp = getgrnam(LOTA_GROUP_NAME);
    if (grp) {
      if (chown(LOTA_IPC_SOCKET_PATH, 0, grp->gr_gid) < 0)
        lota_warn("chown(%s, 0, %d) failed: %s", LOTA_IPC_SOCKET_PATH,
                  grp->gr_gid, strerror(errno));
    } else {
      lota_warn("group '%s' not found, socket accessible to current group only",
                LOTA_GROUP_NAME);
    }
  }

  if (listen(ctx->listen_fd, 16) < 0) {
    ret = -errno;
    lota_err("listen() failed: %s", strerror(-ret));
    goto err_unlink;
  }

  ctx->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  if (ctx->epoll_fd < 0) {
    ret = -errno;
    lota_err("epoll_create1() failed: %s", strerror(-ret));
    goto err_unlink;
  }

  ev.events = EPOLLIN;
  ev.data.fd = ctx->listen_fd;
  if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, ctx->listen_fd, &ev) < 0) {
    ret = -errno;
    lota_err("epoll_ctl() failed: %s", strerror(-ret));
    goto err_epoll;
  }

  ctx->running = true;
  ctx->status_flags = 0;

  lota_info("IPC listening on %s", LOTA_IPC_SOCKET_PATH);
  return 0;

err_epoll:
  close(ctx->epoll_fd);
err_unlink:
  unlink(LOTA_IPC_SOCKET_PATH);
err_close:
  close(ctx->listen_fd);
  ctx->listen_fd = -1;
  ctx->epoll_fd = -1;
  return ret;
}

/*
 * just set it non-blocking, create an epoll, and register it
 * no bind/listen is needed because systemd already did that
 */
int ipc_init_activated(struct ipc_context *ctx, int fd) {
  struct epoll_event ev;
  int ret;

  if (!ctx || fd < 0)
    return -EINVAL;

  memset(ctx, 0, sizeof(*ctx));
  ctx->listen_fd = -1;
  ctx->epoll_fd = -1;
  ctx->start_time = time(NULL);

  for (int i = 0; i < IPC_MAX_EXTRA_LISTENERS; i++)
    ctx->extra[i].fd = -1;
  ctx->extra_count = 0;

  ret = set_nonblocking(fd);
  if (ret < 0) {
    lota_err("set_nonblocking(activated fd) failed: %s", strerror(-ret));
    return ret;
  }

  ctx->listen_fd = fd;
  ctx->activated = true;

  ctx->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  if (ctx->epoll_fd < 0) {
    ret = -errno;
    lota_err("epoll_create1() failed: %s", strerror(-ret));
    ctx->listen_fd = -1;
    return ret;
  }

  ev.events = EPOLLIN;
  ev.data.fd = ctx->listen_fd;
  if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, ctx->listen_fd, &ev) < 0) {
    ret = -errno;
    lota_err("epoll_ctl() failed: %s", strerror(-ret));
    close(ctx->epoll_fd);
    ctx->epoll_fd = -1;
    ctx->listen_fd = -1;
    return ret;
  }

  ctx->running = true;
  ctx->status_flags = 0;

  lota_info("IPC using socket-activated fd %d", fd);
  return 0;
}

/*
 * Cleanup IPC server
 */
void ipc_cleanup(struct ipc_context *ctx) {
  ctx->running = false;

  /* close all clients */
  /* close all clients */
  while (client_list) {
    client_destroy(client_list);
  }
  client_count = 0;

  if (ctx->epoll_fd >= 0) {
    close(ctx->epoll_fd);
    ctx->epoll_fd = -1;
  }

  if (ctx->listen_fd >= 0) {
    close(ctx->listen_fd);
    ctx->listen_fd = -1;
  }

  if (!ctx->activated)
    unlink(LOTA_IPC_SOCKET_PATH);

  /* close extra listener sockets */
  for (int i = 0; i < IPC_MAX_EXTRA_LISTENERS; i++) {
    if (ctx->extra[i].fd >= 0) {
      close(ctx->extra[i].fd);
      ctx->extra[i].fd = -1;
      if (ctx->extra[i].path[0]) {
        unlink(ctx->extra[i].path);
        ctx->extra[i].path[0] = '\0';
      }
    }
  }
  ctx->extra_count = 0;

  lota_dbg("IPC cleaned up");
}

/*
 * Process IPC events
 */
int ipc_process(struct ipc_context *ctx, int timeout_ms) {
  struct epoll_event events[MAX_EVENTS];
  int nfds;
  int processed = 0;

  if (!ctx->running || ctx->epoll_fd < 0)
    return -EINVAL;

  nfds = epoll_wait(ctx->epoll_fd, events, MAX_EVENTS, timeout_ms);
  if (nfds < 0) {
    if (errno == EINTR)
      return 0;
    return -errno;
  }

  for (int i = 0; i < nfds; i++) {
    int fd = events[i].data.fd;

    if (fd == ctx->listen_fd || ipc_is_listener(ctx, fd)) {
      /* new connection on primary or extra listener */
      accept_client(ctx, fd);
      processed++;
    } else {
      /* client event */
      struct ipc_client *client = client_find(fd);
      if (!client)
        continue;

      int ret = 0;

      if (events[i].events & EPOLLIN) {
        ret = handle_client_read(ctx, client);
      }

      if (events[i].events & EPOLLOUT) {
        if (handle_client_write(ctx, client) < 0)
          ret = -1;
      }

      if ((events[i].events & (EPOLLERR | EPOLLHUP)) || ret < 0) {
        epoll_ctl(ctx->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
        client_destroy(client);
      }

      processed++;
    }
  }

  return processed;
}

/*
 * Get epoll fd
 */
int ipc_get_fd(struct ipc_context *ctx) { return ctx->epoll_fd; }

/*
 * Update status
 */
void ipc_update_status(struct ipc_context *ctx, uint32_t flags,
                       uint64_t valid_until) {
  if (!ctx->running)
    return;

  uint32_t old_flags = ctx->status_flags;

  ctx->status_flags = flags;
  ctx->valid_until = valid_until;
  ctx->last_attest_time = (uint64_t)time(NULL);

  if (old_flags != flags) {
    notify_subscribers(ctx, LOTA_IPC_EVENT_STATUS);
    dbus_emit_status_changed(ctx->dbus, flags);
  }
}

/*
 * Record attestation attempt
 */
void ipc_record_attestation(struct ipc_context *ctx, bool success) {
  if (success)
    ctx->attest_count++;
  else
    ctx->fail_count++;

  notify_subscribers(ctx, LOTA_IPC_EVENT_ATTEST);
  dbus_emit_attestation_result(ctx->dbus, success);
}

/*
 * Set mode
 */
void ipc_set_mode(struct ipc_context *ctx, uint8_t mode) {
  uint8_t old_mode = ctx->mode;

  ctx->mode = mode;

  if (old_mode != mode) {
    notify_subscribers(ctx, LOTA_IPC_EVENT_MODE);
    dbus_emit_mode_changed(ctx->dbus, mode);
  }
}

/*
 * Set TPM context for token signing
 */
void ipc_set_tpm(struct ipc_context *ctx, struct tpm_context *tpm,
                 uint32_t pcr_mask) {
  ctx->tpm = tpm;
  ctx->quote_pcr_mask = pcr_mask;
}

/*
 * Add extra listener socket.
 *
 * Creates a new Unix stream socket at the given path, registers it
 * with epoll, and stores it in the extra[] array for cleanup on
 * shutdown. Connections accepted on this socket are handled
 * identically to the primary listener.
 */
int ipc_add_listener(struct ipc_context *ctx, const char *socket_path) {
  struct sockaddr_un addr;
  struct epoll_event ev;
  int fd, ret, slot;

  if (!ctx || !socket_path || !socket_path[0])
    return -EINVAL;

  if (ctx->epoll_fd < 0)
    return -EINVAL;

  if (ctx->extra_count >= IPC_MAX_EXTRA_LISTENERS)
    return -ENOSPC;

  /* find free slot */
  slot = -1;
  for (int i = 0; i < IPC_MAX_EXTRA_LISTENERS; i++) {
    if (ctx->extra[i].fd < 0) {
      slot = i;
      break;
    }
  }
  if (slot < 0)
    return -ENOSPC;

  /* remove stale socket file */
  unlink(socket_path);

  fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) {
    ret = -errno;
    lota_err("extra socket() failed: %s", strerror(-ret));
    return ret;
  }

  ret = set_nonblocking(fd);
  if (ret < 0) {
    close(fd);
    return ret;
  }

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

  {
    mode_t old_umask = umask(0117);
    ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    umask(old_umask);
  }

  if (ret < 0) {
    ret = -errno;
    lota_err("bind(%s) failed: %s", socket_path, strerror(-ret));
    close(fd);
    return ret;
  }
  {
    struct group *grp = getgrnam(LOTA_GROUP_NAME);
    if (grp) {
      if (chown(socket_path, 0, grp->gr_gid) < 0)
        lota_warn("chown(%s) failed: %s", socket_path, strerror(errno));
    }
  }

  if (listen(fd, 16) < 0) {
    ret = -errno;
    close(fd);
    unlink(socket_path);
    return ret;
  }

  ev.events = EPOLLIN;
  ev.data.fd = fd;
  if (epoll_ctl(ctx->epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
    ret = -errno;
    close(fd);
    unlink(socket_path);
    return ret;
  }

  ctx->extra[slot].fd = fd;
  snprintf(ctx->extra[slot].path, sizeof(ctx->extra[slot].path), "%s",
           socket_path);
  ctx->extra_count++;

  lota_info("IPC extra listener on %s", socket_path);
  return 0;
}

/*
 * Check if fd is any listener socket (primary or extra).
 */
int ipc_is_listener(struct ipc_context *ctx, int fd) {
  if (fd == ctx->listen_fd)
    return 1;
  for (int i = 0; i < IPC_MAX_EXTRA_LISTENERS; i++) {
    if (ctx->extra[i].fd >= 0 && ctx->extra[i].fd == fd)
      return 1;
  }
  return 0;
}

void ipc_set_dbus(struct ipc_context *ctx, struct dbus_context *dbus) {
  if (ctx)
    ctx->dbus = dbus;
}
