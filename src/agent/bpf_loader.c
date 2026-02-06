/* SPDX-License-Identifier: MIT */
/*
 * LOTA - BPF Program Loader
 * Implementation using libbpf
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "../../include/lota.h"
#include "bpf_loader.h"

/* Stats map indices - must match BPF program */
#define STAT_TOTAL_EXECS 0
#define STAT_EVENTS_SENT 1
#define STAT_ERRORS 2
#define STAT_RINGBUF_DROPS 3
#define STAT_MODULES_BLOCKED 4
#define STAT_MMAP_EXECS 5
#define STAT_MMAP_BLOCKED 6
#define STAT_PTRACE_ATTEMPTS 7
#define STAT_PTRACE_BLOCKED 8
#define STAT_SETUID_EVENTS 9

/*
 * libbpf print callback - redirect to stderr with prefix
 */
static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
  if (level == LIBBPF_DEBUG)
    return 0;

  return vfprintf(stderr, format, args);
}

int bpf_loader_init(struct bpf_loader_ctx *ctx) {
  if (!ctx)
    return -EINVAL;

  memset(ctx, 0, sizeof(*ctx));

  libbpf_set_print(libbpf_print_fn);
  libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

  return 0;
}

int bpf_loader_load(struct bpf_loader_ctx *ctx, const char *bpf_obj_path) {
  struct bpf_program *prog;
  struct bpf_link *link;
  int err;

  if (!ctx || !bpf_obj_path)
    return -EINVAL;

  if (ctx->loaded)
    return -EALREADY;

  ctx->obj = bpf_object__open_file(bpf_obj_path, NULL);
  if (!ctx->obj) {
    err = -errno;
    fprintf(stderr, "Failed to open BPF object: %s\n", bpf_obj_path);
    return err;
  }

  err = bpf_object__load(ctx->obj);
  if (err) {
    fprintf(stderr, "Failed to load BPF object: %d\n", err);
    goto err_close;
  }

  /*
   * Attach all LSM programs.
   */
  bpf_object__for_each_program(prog, ctx->obj) {
    if (bpf_program__type(prog) != BPF_PROG_TYPE_LSM)
      continue;

    link = bpf_program__attach(prog);
    if (!link) {
      err = -errno;
      fprintf(stderr, "Failed to attach program %s: %d\n",
              bpf_program__name(prog), err);
      goto err_close;
    }

    fprintf(stderr, "Attached LSM program: %s\n", bpf_program__name(prog));
  }

  /* Get ring buffer map fd */
  ctx->ringbuf_fd = bpf_object__find_map_fd_by_name(ctx->obj, "events");
  if (ctx->ringbuf_fd < 0) {
    err = ctx->ringbuf_fd;
    fprintf(stderr, "Failed to find events map\n");
    goto err_close;
  }

  /* Get stats map fd */
  ctx->stats_fd = bpf_object__find_map_fd_by_name(ctx->obj, "stats");
  if (ctx->stats_fd < 0) {
    ctx->stats_fd = -1; // stats map is optional
  }

  ctx->config_fd = bpf_object__find_map_fd_by_name(ctx->obj, "lota_config");
  if (ctx->config_fd < 0) {
    ctx->config_fd = -1;
  }

  /* Get trusted libraries map fd */
  ctx->trusted_libs_fd =
      bpf_object__find_map_fd_by_name(ctx->obj, "trusted_libs");
  if (ctx->trusted_libs_fd < 0) {
    ctx->trusted_libs_fd = -1; /* optional map */
  }

  /* Get protected PIDs map fd */
  ctx->protected_pids_fd =
      bpf_object__find_map_fd_by_name(ctx->obj, "protected_pids");
  if (ctx->protected_pids_fd < 0) {
    ctx->protected_pids_fd = -1; /* optional map */
  }

  ctx->loaded = true;
  return 0;

err_close:
  bpf_object__close(ctx->obj);
  ctx->obj = NULL;
  return err;
}

int bpf_loader_setup_ringbuf(struct bpf_loader_ctx *ctx,
                             bpf_event_handler_t handler, void *handler_ctx) {
  if (!ctx || !ctx->loaded || !handler)
    return -EINVAL;

  if (ctx->ringbuf)
    return -EALREADY;

  /*
   * Create ring buffer manager.
   * The handler will be called for each event.
   */
  ctx->ringbuf = ring_buffer__new(
      ctx->ringbuf_fd, (ring_buffer_sample_fn)handler, handler_ctx, NULL);
  if (!ctx->ringbuf) {
    fprintf(stderr, "Failed to create ring buffer\n");
    return -errno;
  }

  return 0;
}

int bpf_loader_poll(struct bpf_loader_ctx *ctx, int timeout_ms) {
  if (!ctx || !ctx->ringbuf)
    return -EINVAL;

  return ring_buffer__poll(ctx->ringbuf, timeout_ms);
}

int bpf_loader_get_stats(struct bpf_loader_ctx *ctx, uint64_t *total_execs,
                         uint64_t *events_sent, uint64_t *errors,
                         uint64_t *drops) {
  uint64_t value;
  uint32_t key;
  int err;

  if (!ctx || !ctx->loaded || ctx->stats_fd < 0)
    return -EINVAL;

  if (total_execs) {
    key = STAT_TOTAL_EXECS;
    err = bpf_map_lookup_elem(ctx->stats_fd, &key, &value);
    *total_execs = (err == 0) ? value : 0;
  }

  if (events_sent) {
    key = STAT_EVENTS_SENT;
    err = bpf_map_lookup_elem(ctx->stats_fd, &key, &value);
    *events_sent = (err == 0) ? value : 0;
  }

  if (errors) {
    key = STAT_ERRORS;
    err = bpf_map_lookup_elem(ctx->stats_fd, &key, &value);
    *errors = (err == 0) ? value : 0;
  }

  if (drops) {
    key = STAT_RINGBUF_DROPS;
    err = bpf_map_lookup_elem(ctx->stats_fd, &key, &value);
    *drops = (err == 0) ? value : 0;
  }

  return 0;
}

void bpf_loader_cleanup(struct bpf_loader_ctx *ctx) {
  if (!ctx)
    return;

  if (ctx->ringbuf) {
    ring_buffer__free(ctx->ringbuf);
    ctx->ringbuf = NULL;
  }

  if (ctx->obj) {
    bpf_object__close(ctx->obj);
    ctx->obj = NULL;
  }

  ctx->loaded = false;
  ctx->ringbuf_fd = -1;
  ctx->stats_fd = -1;
  ctx->config_fd = -1;
  ctx->trusted_libs_fd = -1;
  ctx->protected_pids_fd = -1;
}

int bpf_loader_set_mode(struct bpf_loader_ctx *ctx, uint32_t mode) {
  uint32_t key = LOTA_CFG_MODE;

  if (!ctx || !ctx->loaded || ctx->config_fd < 0)
    return -EINVAL;

  if (mode > LOTA_MODE_MAINTENANCE)
    return -EINVAL;

  return bpf_map_update_elem(ctx->config_fd, &key, &mode, BPF_ANY);
}

int bpf_loader_get_mode(struct bpf_loader_ctx *ctx, uint32_t *mode) {
  uint32_t key = LOTA_CFG_MODE;
  uint32_t value;
  int err;

  if (!ctx || !ctx->loaded || ctx->config_fd < 0 || !mode)
    return -EINVAL;

  err = bpf_map_lookup_elem(ctx->config_fd, &key, &value);
  if (err < 0)
    return err;

  *mode = value;
  return 0;
}

int bpf_loader_set_config(struct bpf_loader_ctx *ctx, uint32_t key,
                          uint32_t value) {
  if (!ctx || !ctx->loaded || ctx->config_fd < 0)
    return -EINVAL;

  return bpf_map_update_elem(ctx->config_fd, &key, &value, BPF_ANY);
}

int bpf_loader_protect_pid(struct bpf_loader_ctx *ctx, uint32_t pid) {
  uint32_t value = 1;

  if (!ctx || !ctx->loaded)
    return -EINVAL;

  if (ctx->protected_pids_fd < 0)
    return -ENOTSUP;

  return bpf_map_update_elem(ctx->protected_pids_fd, &pid, &value, BPF_ANY);
}

int bpf_loader_unprotect_pid(struct bpf_loader_ctx *ctx, uint32_t pid) {
  if (!ctx || !ctx->loaded)
    return -EINVAL;

  if (ctx->protected_pids_fd < 0)
    return -ENOTSUP;

  return bpf_map_delete_elem(ctx->protected_pids_fd, &pid);
}

int bpf_loader_trust_lib(struct bpf_loader_ctx *ctx, const char *path) {
  char key[LOTA_MAX_PATH_LEN];
  uint32_t value = 1;
  size_t len;

  if (!ctx || !ctx->loaded || !path)
    return -EINVAL;

  if (ctx->trusted_libs_fd < 0)
    return -ENOTSUP;

  len = strlen(path);
  if (len == 0 || len >= LOTA_MAX_PATH_LEN)
    return -EINVAL;

  memset(key, 0, sizeof(key));
  memcpy(key, path, len);

  return bpf_map_update_elem(ctx->trusted_libs_fd, key, &value, BPF_ANY);
}

int bpf_loader_untrust_lib(struct bpf_loader_ctx *ctx, const char *path) {
  char key[LOTA_MAX_PATH_LEN];
  size_t len;

  if (!ctx || !ctx->loaded || !path)
    return -EINVAL;

  if (ctx->trusted_libs_fd < 0)
    return -ENOTSUP;

  len = strlen(path);
  if (len == 0 || len >= LOTA_MAX_PATH_LEN)
    return -EINVAL;

  memset(key, 0, sizeof(key));
  memcpy(key, path, len);

  return bpf_map_delete_elem(ctx->trusted_libs_fd, key);
}

/*
 * read a single stat counter from the stats map
 */
static int read_stat(int stats_fd, uint32_t key, uint64_t *out) {
  uint64_t value;
  int err;

  err = bpf_map_lookup_elem(stats_fd, &key, &value);
  *out = (err == 0) ? value : 0;
  return 0;
}

int bpf_loader_get_extended_stats(
    struct bpf_loader_ctx *ctx, uint64_t *total_execs, uint64_t *events_sent,
    uint64_t *errors, uint64_t *drops, uint64_t *modules_blocked,
    uint64_t *mmap_execs, uint64_t *mmap_blocked, uint64_t *ptrace_attempts,
    uint64_t *ptrace_blocked, uint64_t *setuid_events) {
  if (!ctx || !ctx->loaded || ctx->stats_fd < 0)
    return -EINVAL;

  if (total_execs)
    read_stat(ctx->stats_fd, STAT_TOTAL_EXECS, total_execs);
  if (events_sent)
    read_stat(ctx->stats_fd, STAT_EVENTS_SENT, events_sent);
  if (errors)
    read_stat(ctx->stats_fd, STAT_ERRORS, errors);
  if (drops)
    read_stat(ctx->stats_fd, STAT_RINGBUF_DROPS, drops);
  if (modules_blocked)
    read_stat(ctx->stats_fd, STAT_MODULES_BLOCKED, modules_blocked);
  if (mmap_execs)
    read_stat(ctx->stats_fd, STAT_MMAP_EXECS, mmap_execs);
  if (mmap_blocked)
    read_stat(ctx->stats_fd, STAT_MMAP_BLOCKED, mmap_blocked);
  if (ptrace_attempts)
    read_stat(ctx->stats_fd, STAT_PTRACE_ATTEMPTS, ptrace_attempts);
  if (ptrace_blocked)
    read_stat(ctx->stats_fd, STAT_PTRACE_BLOCKED, ptrace_blocked);
  if (setuid_events)
    read_stat(ctx->stats_fd, STAT_SETUID_EVENTS, setuid_events);

  return 0;
}
