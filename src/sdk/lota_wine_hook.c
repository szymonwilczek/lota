/* SPDX-License-Identifier: MIT */
/*
 * LOTA Wine/Proton Hook - LD_PRELOAD Integration
 *
 * Shared library loaded via LD_PRELOAD into Wine/Proton processes
 * to transparently bridge LOTA attestation into Windows games.
 *
 * Lifecycle:
 *   1. Constructor: connect to agent, write initial status/token,
 *      start background refresh thread.
 *   2. Background thread: periodically re-query agent, atomically
 *      update the status and token files.
 *   3. Destructor: stop thread, disconnect, remove files.
 *
 * The hook is self-contained -- the Gaming SDK is linked statically
 * into the .so!
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "../../include/lota_gaming.h"
#include "../../include/lota_wine_hook.h"

/* log levels */
enum hook_log_level {
  HOOK_LOG_DEBUG = 0,
  HOOK_LOG_INFO = 1,
  HOOK_LOG_WARN = 2,
  HOOK_LOG_ERROR = 3,
  HOOK_LOG_SILENT = 4,
};

/* global state */
static struct {
  struct lota_client *client;
  pthread_t thread;
  atomic_int running;
  atomic_int thread_started;
  int log_level;
  int refresh_sec;
  char token_dir[PATH_MAX - 64]; /* leave room for filename suffix */
  char socket_path[PATH_MAX];    /* empty -> default */
  char status_path[PATH_MAX];
  char token_path[PATH_MAX];
  pid_t init_pid;
} g_hook;

#define HOOK_PREFIX "lota-hook"

#define HOOK_LOG(level, fmt, ...)                                              \
  do {                                                                         \
    if ((level) >= g_hook.log_level)                                           \
      fprintf(stderr, HOOK_PREFIX ": " fmt "\n", ##__VA_ARGS__);               \
  } while (0)

#define LOG_DBG(fmt, ...) HOOK_LOG(HOOK_LOG_DEBUG, fmt, ##__VA_ARGS__)
#define LOG_INF(fmt, ...) HOOK_LOG(HOOK_LOG_INFO, fmt, ##__VA_ARGS__)
#define LOG_WRN(fmt, ...) HOOK_LOG(HOOK_LOG_WARN, fmt, ##__VA_ARGS__)
#define LOG_ERR(fmt, ...) HOOK_LOG(HOOK_LOG_ERROR, fmt, ##__VA_ARGS__)

/*
 * Parse log level string. Returns HOOK_LOG_WARN for NULL or
 * unrecognised values (safe default for LD_PRELOAD context).
 */
static int parse_log_level(const char *s) {
  if (!s)
    return HOOK_LOG_WARN;
  if (strcmp(s, "debug") == 0)
    return HOOK_LOG_DEBUG;
  if (strcmp(s, "info") == 0)
    return HOOK_LOG_INFO;
  if (strcmp(s, "warn") == 0)
    return HOOK_LOG_WARN;
  if (strcmp(s, "error") == 0)
    return HOOK_LOG_ERROR;
  if (strcmp(s, "silent") == 0)
    return HOOK_LOG_SILENT;
  return HOOK_LOG_WARN;
}

/*
 * Determine the token output directory.
 *
 * Priority:
 *   1. LOTA_HOOK_TOKEN_DIR   (explicit override)
 *   2. $XDG_RUNTIME_DIR/lota (standard runtime directory)
 *   3. /tmp/lota-<uid>       (fallback)
 *
 * Writes result into g_hook.token_dir
 */
static void resolve_token_dir(void) {
  const char *env;

  env = getenv(LOTA_HOOK_ENV_TOKEN_DIR);
  if (env && env[0]) {
    snprintf(g_hook.token_dir, sizeof(g_hook.token_dir), "%s", env);
    return;
  }

  env = getenv("XDG_RUNTIME_DIR");
  if (env && env[0]) {
    snprintf(g_hook.token_dir, sizeof(g_hook.token_dir), "%s/lota", env);
    return;
  }

  snprintf(g_hook.token_dir, sizeof(g_hook.token_dir), "/tmp/lota-%u",
           (unsigned)getuid());
}

/*
 * Create the token directory if it does not exist.
 * Mode 0700: only the owning user can read attestation data.
 *
 * Attempts mkdir first, then validates the result with lstat.
 * This avoids the TOCTOU race of check-then-create in shared
 * directories like /tmp.
 *
 * Returns 0 on success, negative errno on failure.
 */
static int ensure_token_dir(void) {
  struct stat st;

  /* try to create; EEXIST is fine */
  if (mkdir(g_hook.token_dir, 0700) < 0 && errno != EEXIST) {
    LOG_ERR("mkdir %s: %s", g_hook.token_dir, strerror(errno));
    return -errno;
  }

  /* validate what actually sits at the path */
  if (lstat(g_hook.token_dir, &st) != 0) {
    LOG_ERR("lstat %s: %s", g_hook.token_dir, strerror(errno));
    return -errno;
  }
  if (S_ISLNK(st.st_mode)) {
    LOG_ERR("token dir is a symlink (possible attack): %s", g_hook.token_dir);
    return -ELOOP;
  }
  if (!S_ISDIR(st.st_mode)) {
    LOG_ERR("token dir exists but is not a directory: %s", g_hook.token_dir);
    return -ENOTDIR;
  }
  if (st.st_uid != getuid()) {
    LOG_ERR("token dir owned by uid %u, expected %u: %s", (unsigned)st.st_uid,
            (unsigned)getuid(), g_hook.token_dir);
    return -EACCES;
  }

  return 0;
}

/*
 * Write data to a file atomically.
 *
 * Writes to a PID-tagged temporary file, fsyncs, then renames
 * over the target path. This guarantees readers never see a
 * partially written file.
 */
static int atomic_write(const char *path, const void *data, size_t len) {
  char tmp[PATH_MAX];
  int fd, err;
  ssize_t n;

  snprintf(tmp, sizeof(tmp), "%s.tmp.%d", path, (int)getpid());

  fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (fd < 0)
    return -errno;

  n = write(fd, data, len);
  if (n != (ssize_t)len) {
    err = (n < 0) ? errno : EIO;
    close(fd);
    unlink(tmp);
    return -err;
  }

  if (fsync(fd) < 0) {
    err = errno;
    close(fd);
    unlink(tmp);
    return -err;
  }

  close(fd);

  if (rename(tmp, path) < 0) {
    err = errno;
    unlink(tmp);
    return -err;
  }

  return 0;
}

/*
 * Write the text status file.
 *
 * Format: key=value, one per line, no quoting.
 * Parseable from C, Python, shell, and Wine-side code.
 */
static int write_status(const struct lota_status *status) {
  char buf[512];
  int len;

  len = snprintf(buf, sizeof(buf),
                 "LOTA_ATTESTED=%d\n"
                 "LOTA_FLAGS=0x%08x\n"
                 "LOTA_VALID_UNTIL=%lu\n"
                 "LOTA_ATTEST_COUNT=%u\n"
                 "LOTA_FAIL_COUNT=%u\n"
                 "LOTA_UPDATED=%lu\n"
                 "LOTA_PID=%d\n",
                 (status->flags & LOTA_FLAG_ATTESTED) ? 1 : 0, status->flags,
                 (unsigned long)status->valid_until, status->attest_count,
                 status->fail_count, (unsigned long)time(NULL), (int)getpid());

  if (len < 0 || (size_t)len >= sizeof(buf))
    return -ENOMEM;

  return atomic_write(g_hook.status_path, buf, (size_t)len);
}

/* Runtime-only: refresh, thread, fork safety, constructor/destructor */
#ifndef LOTA_HOOK_TESTING

/*
 * Fetch and write the binary token file.
 *
 * Requests a token without a client nonce (nonce = NULL).
 * The resulting token is still TPM-signed and proves attestation
 * at a point in time; it is just not bound to a specific server
 * challenge. Games requiring challenge-response freshness should
 * use the SDK directly.
 */
static int write_token(struct lota_client *client) {
  struct lota_token token;
  uint8_t wire[2048];
  size_t written;
  int ret;

  ret = lota_get_token(client, NULL, &token);
  if (ret != LOTA_OK) {
    LOG_DBG("get_token: %s", lota_strerror(ret));
    unlink(g_hook.token_path);
    return ret;
  }

  ret = lota_token_serialize(&token, wire, sizeof(wire), &written);
  lota_token_free(&token);

  if (ret != LOTA_OK) {
    LOG_WRN("token_serialize: %s", lota_strerror(ret));
    return ret;
  }

  return atomic_write(g_hook.token_path, wire, written);
}

/*
 * Connect (or reconnect) to the LOTA agent.
 */
static struct lota_client *hook_connect(void) {
  struct lota_connect_opts opts;

  memset(&opts, 0, sizeof(opts));

  if (g_hook.socket_path[0])
    opts.socket_path = g_hook.socket_path;
  opts.timeout_ms = LOTA_HOOK_CONNECT_TIMEOUT_MS;

  return lota_connect_opts(&opts);
}

/*
 * Perform one refresh cycle.
 *
 * Reconnects to the agent if needed, queries status, writes files.
 * All failures are handled gracefully -- the hook never aborts
 * the host process.
 */
static void refresh_once(void) {
  struct lota_status status;
  int ret;

  if (!g_hook.client) {
    g_hook.client = hook_connect();
    if (!g_hook.client) {
      LOG_DBG("agent not available");
      return;
    }
    LOG_DBG("connected to agent");
  }

  ret = lota_get_status(g_hook.client, &status);
  if (ret != LOTA_OK) {
    LOG_DBG("get_status: %s -> reconnecting", lota_strerror(ret));
    lota_disconnect(g_hook.client);
    g_hook.client = NULL;
    return;
  }

  ret = write_status(&status);
  if (ret < 0)
    LOG_WRN("write_status: %s", strerror(-ret));

  if (status.flags & LOTA_FLAG_ATTESTED) {
    ret = write_token(g_hook.client);
    if (ret < 0 && ret != LOTA_ERR_NOT_ATTESTED)
      LOG_DBG("write_token: %s", lota_strerror(ret));
  } else {
    unlink(g_hook.token_path);
  }
}

/*
 * Periodically refresh status and token files.
 *
 * Blocks all signals to avoid interfering with Wine's aggressive
 * signal handling.
 */
static void *refresh_thread_fn(void *arg) {
  sigset_t all;
  int i;

  (void)arg;

  sigfillset(&all);
  pthread_sigmask(SIG_BLOCK, &all, NULL);

  /*
   * initial sleep: the constructor already wrote the first
   * snapshot, so wait one full interval before the first
   * background refresh
   */
  for (i = 0; i < g_hook.refresh_sec && g_hook.running; i++)
    sleep(1);

  while (g_hook.running) {
    refresh_once();

    for (i = 0; i < g_hook.refresh_sec && g_hook.running; i++)
      sleep(1);
  }

  return NULL;
}

/*
 * Reset state so the child does not try to join a non-existent thread.
 */
static void hook_child_after_fork(void) {
  g_hook.thread_started = 0;
  g_hook.running = 0;
  g_hook.client = NULL;
  g_hook.init_pid = 0;
}

__attribute__((constructor)) static void lota_wine_hook_init(void) {
  const char *env;

  /* check disable flag */
  env = getenv(LOTA_HOOK_ENV_DISABLE);
  if (env && (strcmp(env, "1") == 0 || strcmp(env, "true") == 0))
    return;

  /* parse configuration from environment */
  g_hook.log_level = parse_log_level(getenv(LOTA_HOOK_ENV_LOG_LEVEL));

  env = getenv(LOTA_HOOK_ENV_SOCKET);
  if (env && env[0])
    snprintf(g_hook.socket_path, sizeof(g_hook.socket_path), "%s", env);

  env = getenv(LOTA_HOOK_ENV_REFRESH_SEC);
  g_hook.refresh_sec =
      (env && atoi(env) > 0) ? atoi(env) : LOTA_HOOK_DEFAULT_REFRESH_SEC;

  /* resolve and create token directory */
  resolve_token_dir();

  if (ensure_token_dir() < 0)
    return;

  snprintf(g_hook.status_path, sizeof(g_hook.status_path), "%s/%s",
           g_hook.token_dir, LOTA_HOOK_STATUS_FILE);
  snprintf(g_hook.token_path, sizeof(g_hook.token_path), "%s/%s",
           g_hook.token_dir, LOTA_HOOK_TOKEN_FILE);

  /* export token directory for wine-side discovery */
  setenv(LOTA_HOOK_ENV_TOKEN_DIR, g_hook.token_dir, 0);

  LOG_INF("initializing (token_dir=%s, refresh=%ds)", g_hook.token_dir,
          g_hook.refresh_sec);

  g_hook.init_pid = getpid();
  pthread_atfork(NULL, NULL, hook_child_after_fork);

  g_hook.client = hook_connect();
  if (!g_hook.client) {
    LOG_WRN("agent not available (will retry in background)");
  } else {
    LOG_INF("connected to agent");
    refresh_once();
  }

  /* background refresh thread */
  g_hook.running = 1;
  if (pthread_create(&g_hook.thread, NULL, refresh_thread_fn, NULL) != 0) {
    LOG_ERR("pthread_create: %s", strerror(errno));
    g_hook.running = 0;
    return;
  }
  g_hook.thread_started = 1;

  LOG_INF("hook active (pid=%d)", (int)getpid());
}

/*
 * Safely unlink a path after verifying it is a regular file
 * owned by the current user (not a symlink).
 */
static void safe_unlink(const char *path) {
  struct stat st;

  if (lstat(path, &st) < 0)
    return;
  if (S_ISLNK(st.st_mode) || st.st_uid != getuid())
    return;
  unlink(path);
}

__attribute__((destructor)) static void lota_wine_hook_fini(void) {
  if (g_hook.init_pid != getpid())
    return;

  if (!g_hook.thread_started && !g_hook.client)
    return;

  LOG_DBG("shutting down");

  g_hook.running = 0;

  if (g_hook.thread_started) {
    pthread_join(g_hook.thread, NULL);
    g_hook.thread_started = 0;
  }

  if (g_hook.client) {
    lota_disconnect(g_hook.client);
    g_hook.client = NULL;
  }

  if (g_hook.status_path[0])
    safe_unlink(g_hook.status_path);
  if (g_hook.token_path[0])
    safe_unlink(g_hook.token_path);

  LOG_INF("hook detached");
}

#endif /* !LOTA_HOOK_TESTING */

/* exported query functions */

int lota_hook_active(void) { return g_hook.thread_started && g_hook.running; }

const char *lota_hook_status_path(void) {
  if (!g_hook.status_path[0])
    return NULL;
  return g_hook.status_path;
}

const char *lota_hook_token_path(void) {
  if (!g_hook.token_path[0])
    return NULL;
  return g_hook.token_path;
}
