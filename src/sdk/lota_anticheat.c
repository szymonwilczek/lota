/* SPDX-License-Identifier: MIT */
/*
 * LOTA Anti-Cheat Compatibility Layer
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <openssl/evp.h>

#include "lota_anticheat.h"
#include "lota_gaming.h"
#include "lota_server.h"
#include "lota_snapshot.h"

_Static_assert(sizeof(struct lota_ac_heartbeat_wire) == LOTA_AC_HEADER_SIZE,
               "heartbeat wire header must be exactly 74 bytes");

static ssize_t read_file_buf(const char *path, void *buf, size_t buflen);

struct lota_ac_session {
  enum lota_ac_provider provider;
  enum lota_ac_state state;

  uint8_t session_id[LOTA_AC_SESSION_ID_SIZE];
  char game_id[LOTA_AC_MAX_GAME_ID];
  uint8_t game_id_hash[LOTA_AC_GAME_HASH_SIZE];

  uint64_t session_start;
  uint64_t last_heartbeat;
  uint32_t heartbeat_seq;
  uint32_t heartbeat_interval;
  uint32_t required_flags;
  uint32_t lota_flags;

  /* direct SDK mode */
  int direct;
  struct lota_client *client;

  /* file mode */
  char token_dir[256];
  char status_path[512];
  char token_path[512];
  char snapshot_path[512];
  int snapshot_warned;

  /* cached token (wire format) */
  uint8_t token_buf[LOTA_AC_MAX_TOKEN];
  size_t token_len;
};

static uint16_t read_le16_u(const uint8_t *p) {
  return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t read_le32_u(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}

static int read_snapshot(struct lota_ac_session *session) {
  uint8_t buf[LOTA_SNAPSHOT_HEADER_SIZE + LOTA_AC_MAX_TOKEN];
  ssize_t n = read_file_buf(session->snapshot_path, buf, sizeof(buf));
  if (n < 0)
    return (int)n;
  if (n < LOTA_SNAPSHOT_HEADER_SIZE)
    return -EIO;

  if (read_le32_u(buf + 0) != LOTA_SNAPSHOT_MAGIC)
    return -EIO;
  if (read_le16_u(buf + 4) != (uint16_t)LOTA_SNAPSHOT_VERSION)
    return -EIO;
  if (read_le16_u(buf + 6) != 0)
    return -EIO;

  uint32_t flags = read_le32_u(buf + 8);
  uint32_t token_size = read_le32_u(buf + 12);
  if (token_size == 0 || token_size > LOTA_AC_MAX_TOKEN)
    return -EIO;
  if ((size_t)n < LOTA_SNAPSHOT_HEADER_SIZE + (size_t)token_size)
    return -EIO;

  session->lota_flags = flags;
  memcpy(session->token_buf, buf + LOTA_SNAPSHOT_HEADER_SIZE, token_size);
  session->token_len = (size_t)token_size;
  return 0;
}

static int sha256_hash(const void *data, size_t len, uint8_t out[32]) {
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx)
    return -ENOMEM;

  unsigned int out_len = 32;
  int ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) &&
           EVP_DigestUpdate(ctx, data, len) &&
           EVP_DigestFinal_ex(ctx, out, &out_len);

  EVP_MD_CTX_free(ctx);
  return ok ? 0 : -EIO;
}

static int generate_session_id(uint8_t id[LOTA_AC_SESSION_ID_SIZE]) {
  ssize_t n = getrandom(id, LOTA_AC_SESSION_ID_SIZE, 0);
  if (n != LOTA_AC_SESSION_ID_SIZE)
    return -errno;
  return 0;
}

static ssize_t read_file_buf(const char *path, void *buf, size_t buflen) {
  int fd = open(path, O_RDONLY);
  if (fd < 0)
    return -errno;

  ssize_t total = 0;
  while ((size_t)total < buflen) {
    ssize_t n = read(fd, (uint8_t *)buf + total, buflen - (size_t)total);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      int err = errno;
      close(fd);
      return -err;
    }
    if (n == 0)
      break;
    total += n;
  }

  close(fd);
  return total;
}

/*
 * Parse lota-status file for LOTA_FLAGS=0x... line.
 * Returns the flags value, or 0 on parse failure.
 */
static uint32_t parse_status_flags(const char *path) {
  char buf[512];
  ssize_t n = read_file_buf(path, buf, sizeof(buf) - 1);
  if (n <= 0)
    return 0;

  buf[n] = '\0';
  const char *p = strstr(buf, "LOTA_FLAGS=");
  if (!p)
    return 0;

  p += sizeof("LOTA_FLAGS=") - 1;
  return (uint32_t)strtoul(p, NULL, 0);
}

/*
 * Resolve token directory for file mode.
 * Priority: cfg->token_dir > $LOTA_HOOK_TOKEN_DIR > $XDG_RUNTIME_DIR/lota
 */
static int resolve_token_dir(const struct lota_ac_config *cfg, char *out,
                             size_t outlen) {
  const char *dir = cfg->token_dir;
  if (!dir)
    dir = getenv("LOTA_HOOK_TOKEN_DIR");

  if (!dir) {
    const char *xdg = getenv("XDG_RUNTIME_DIR");
    if (xdg) {
      int ret = snprintf(out, outlen, "%s/lota", xdg);
      if (ret < 0 || (size_t)ret >= outlen)
        return -ENAMETOOLONG;
      return 0;
    }
    return -ENOENT;
  }

  if (strlen(dir) >= outlen)
    return -ENAMETOOLONG;
  strncpy(out, dir, outlen - 1);
  out[outlen - 1] = '\0';
  return 0;
}

static int is_trusted(uint32_t flags, uint32_t required) {
  if (required)
    return (flags & required) == required;
  return flags != 0;
}

struct lota_ac_session *lota_ac_init(const struct lota_ac_config *cfg) {
  if (!cfg)
    return NULL;
  if (!cfg->game_id || cfg->game_id[0] == '\0')
    return NULL;
  if (strlen(cfg->game_id) >= LOTA_AC_MAX_GAME_ID)
    return NULL;
  if (cfg->provider != LOTA_AC_PROVIDER_EAC &&
      cfg->provider != LOTA_AC_PROVIDER_BATTLEYE)
    return NULL;

  struct lota_ac_session *s = calloc(1, sizeof(*s));
  if (!s)
    return NULL;

  s->provider = cfg->provider;
  s->state = LOTA_AC_STATE_IDLE;
  strncpy(s->game_id, cfg->game_id, LOTA_AC_MAX_GAME_ID - 1);
  s->heartbeat_interval = cfg->heartbeat_interval_sec
                              ? cfg->heartbeat_interval_sec
                              : LOTA_AC_DEFAULT_HEARTBEAT_SEC;
  s->required_flags = cfg->required_flags;
  s->direct = cfg->direct;

  if (generate_session_id(s->session_id) < 0) {
    free(s);
    return NULL;
  }
  if (sha256_hash(s->game_id, strlen(s->game_id), s->game_id_hash) < 0) {
    free(s);
    return NULL;
  }

  s->session_start = (uint64_t)time(NULL);

  if (cfg->direct) {
    if (cfg->socket_path) {
      struct lota_connect_opts opts = {0};
      opts.socket_path = cfg->socket_path;
      opts.timeout_ms = 5000;
      s->client = lota_connect_opts(&opts);
    } else {
      s->client = lota_connect();
    }
    if (!s->client)
      s->state = LOTA_AC_STATE_ERROR;
    else
      s->state = LOTA_AC_STATE_RUNNING;
  } else {
    if (resolve_token_dir(cfg, s->token_dir, sizeof(s->token_dir)) < 0) {
      s->state = LOTA_AC_STATE_ERROR;
    } else {
      snprintf(s->status_path, sizeof(s->status_path), "%s/lota-status",
               s->token_dir);
      snprintf(s->token_path, sizeof(s->token_path), "%s/lota-token.bin",
               s->token_dir);
      snprintf(s->snapshot_path, sizeof(s->snapshot_path), "%s/%s",
               s->token_dir, LOTA_SNAPSHOT_FILE_NAME);
      s->state = LOTA_AC_STATE_RUNNING;
    }
  }

  /* initial tick to populate state */
  if (s->state == LOTA_AC_STATE_RUNNING)
    lota_ac_tick(s);

  return s;
}

void lota_ac_shutdown(struct lota_ac_session *session) {
  if (!session)
    return;

  if (session->client) {
    lota_disconnect(session->client);
    session->client = NULL;
  }

  session->state = LOTA_AC_STATE_IDLE;
  free(session);
}

enum lota_ac_state lota_ac_get_state(const struct lota_ac_session *session) {
  if (!session)
    return LOTA_AC_STATE_IDLE;
  return session->state;
}

int lota_ac_get_info(const struct lota_ac_session *session,
                     struct lota_ac_info *info) {
  if (!session || !info)
    return -EINVAL;

  info->provider = session->provider;
  info->state = session->state;
  memcpy(info->session_id, session->session_id, LOTA_AC_SESSION_ID_SIZE);
  info->session_start = session->session_start;
  info->last_heartbeat = session->last_heartbeat;
  info->heartbeat_seq = session->heartbeat_seq;
  info->lota_flags = session->lota_flags;
  info->trusted = is_trusted(session->lota_flags, session->required_flags);

  return 0;
}

int lota_ac_tick(struct lota_ac_session *session) {
  if (!session)
    return -EINVAL;
  if (session->state == LOTA_AC_STATE_IDLE)
    return -EINVAL;

  if (session->direct) {
    /* direct SDK mode */
    if (!session->client) {
      session->state = LOTA_AC_STATE_ERROR;
      return -ENOTCONN;
    }

    struct lota_status status;
    int ret = lota_get_status(session->client, &status);
    if (ret != LOTA_OK) {
      session->state = LOTA_AC_STATE_ERROR;
      return -EIO;
    }
    session->lota_flags = status.flags;

    struct lota_token token;
    ret = lota_get_token(session->client, NULL, &token);
    if (ret == LOTA_OK) {
      size_t sz = lota_token_serialized_size(&token);
      if (sz <= LOTA_AC_MAX_TOKEN)
        lota_token_serialize(&token, session->token_buf, LOTA_AC_MAX_TOKEN,
                             &session->token_len);
      lota_token_free(&token);
    } else {
      session->token_len = 0;
    }
  } else {
    int sret = read_snapshot(session);
    if (sret == -ENOENT) {
      /* legacy fallback: separate status + token files */
      session->lota_flags = parse_status_flags(session->status_path);

      ssize_t n = read_file_buf(session->token_path, session->token_buf,
                                LOTA_AC_MAX_TOKEN);
      session->token_len = n > 0 ? (size_t)n : 0;
    } else if (sret < 0) {
      if (!session->snapshot_warned) {
        fprintf(stderr, "lota-ac: snapshot read failed (%s): %s\n",
                session->snapshot_path, strerror(-sret));
        session->snapshot_warned = 1;
      }
      session->lota_flags = 0;
      session->token_len = 0;
    }
  }

  /* update state machine */
  if (session->token_len > 0 || session->lota_flags != 0)
    session->state = is_trusted(session->lota_flags, session->required_flags)
                         ? LOTA_AC_STATE_TRUSTED
                         : LOTA_AC_STATE_UNTRUSTED;
  else
    session->state = LOTA_AC_STATE_ERROR;

  return 0;
}

int lota_ac_heartbeat(struct lota_ac_session *session, uint8_t *buf,
                      size_t buflen, size_t *written) {
  if (!session || !buf || !written)
    return -EINVAL;

  int ret = lota_ac_tick(session);
  if (ret < 0 && session->token_len == 0)
    return -ENODATA;

  if (session->token_len == 0)
    return -ENODATA;

  size_t total = LOTA_AC_HEADER_SIZE + session->token_len;
  if (buflen < total)
    return -ENOSPC;

  struct lota_ac_heartbeat_wire hdr = {
      .magic = LOTA_AC_MAGIC,
      .version = LOTA_AC_VERSION,
      .provider = (uint8_t)session->provider,
      .total_size = (uint16_t)total,
      .sequence = session->heartbeat_seq,
      .lota_flags = session->lota_flags,
      .timestamp = (uint64_t)time(NULL),
      .token_size = (uint16_t)session->token_len,
  };
  memcpy(hdr.session_id, session->session_id, LOTA_AC_SESSION_ID_SIZE);
  memcpy(hdr.game_id_hash, session->game_id_hash, LOTA_AC_GAME_HASH_SIZE);

  memcpy(buf, &hdr, LOTA_AC_HEADER_SIZE);
  memcpy(buf + LOTA_AC_HEADER_SIZE, session->token_buf, session->token_len);

  session->heartbeat_seq++;
  session->last_heartbeat = hdr.timestamp;

  *written = total;
  return 0;
}

int lota_ac_verify_heartbeat(const uint8_t *data, size_t len,
                             const uint8_t *aik_pub_der, size_t aik_pub_len,
                             struct lota_ac_info *info) {
  if (!data || !info)
    return LOTA_SERVER_ERR_INVALID_ARG;

  if (len < LOTA_AC_HEADER_SIZE)
    return LOTA_SERVER_ERR_BAD_TOKEN;

  /* memcpy to avoid unaligned access on packed struct */
  struct lota_ac_heartbeat_wire hdr;
  memcpy(&hdr, data, LOTA_AC_HEADER_SIZE);

  if (hdr.magic != LOTA_AC_MAGIC)
    return LOTA_SERVER_ERR_BAD_TOKEN;
  if (hdr.version != LOTA_AC_VERSION)
    return LOTA_SERVER_ERR_BAD_VERSION;
  if (hdr.total_size > len)
    return LOTA_SERVER_ERR_BAD_TOKEN;
  if (hdr.total_size != LOTA_AC_HEADER_SIZE + hdr.token_size)
    return LOTA_SERVER_ERR_BAD_TOKEN;
  if (hdr.token_size == 0 || hdr.token_size > LOTA_AC_MAX_TOKEN)
    return LOTA_SERVER_ERR_BAD_TOKEN;
  if (hdr.provider != LOTA_AC_PROVIDER_EAC &&
      hdr.provider != LOTA_AC_PROVIDER_BATTLEYE)
    return LOTA_SERVER_ERR_BAD_TOKEN;

  const uint8_t *token = data + LOTA_AC_HEADER_SIZE;
  uint16_t token_size = hdr.token_size;

  struct lota_server_claims claims;
  int ret;

  if (aik_pub_der)
    ret = lota_server_verify_token(token, token_size, aik_pub_der, aik_pub_len,
                                   NULL, &claims);
  else
    ret = lota_server_parse_token(token, token_size, &claims);

  if (ret != LOTA_SERVER_OK)
    return ret;

  info->provider = (enum lota_ac_provider)hdr.provider;
  memcpy(info->session_id, hdr.session_id, LOTA_AC_SESSION_ID_SIZE);
  info->session_start = 0; /* not available from a single heartbeat */
  info->last_heartbeat = hdr.timestamp;
  info->heartbeat_seq = hdr.sequence;
  info->lota_flags = hdr.lota_flags;
  info->trusted = !claims.expired && (claims.flags != 0);
  info->state = info->trusted ? LOTA_AC_STATE_TRUSTED : LOTA_AC_STATE_UNTRUSTED;

  return 0;
}

const char *lota_ac_state_str(enum lota_ac_state state) {
  switch (state) {
  case LOTA_AC_STATE_IDLE:
    return "idle";
  case LOTA_AC_STATE_RUNNING:
    return "running";
  case LOTA_AC_STATE_TRUSTED:
    return "trusted";
  case LOTA_AC_STATE_UNTRUSTED:
    return "untrusted";
  case LOTA_AC_STATE_ERROR:
    return "error";
  }
  return "unknown";
}

const char *lota_ac_provider_str(enum lota_ac_provider provider) {
  switch (provider) {
  case LOTA_AC_PROVIDER_EAC:
    return "EAC";
  case LOTA_AC_PROVIDER_BATTLEYE:
    return "BattlEye";
  }
  return "unknown";
}
