/* SPDX-License-Identifier: MIT */
/*
 * LOTA - BPF Program Loader
 * Implementation using libbpf
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <sys/ioctl.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <linux/fsverity.h>

#include "../../include/lota.h"
#include "bpf_loader.h"
#include "journal.h"

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
#define STAT_BPF_SYSCALL_BLOCKED 13

struct protected_pid_entry {
  uint64_t start_time_ticks;
};

struct lota_identity_entry {
  uint32_t tgid;
  uint32_t pad;
  uint64_t start_time_ticks;
};

/*
 * Read /proc/<pid>/stat field 22 (starttime in clock ticks since boot).
 */
static int read_pid_start_time_ticks(uint32_t pid, uint64_t *start_time_ticks) {
  char path[64];
  FILE *fp;
  char line[4096];
  char *rparen;
  char *field;
  char *saveptr = NULL;
  int field_index = 3;

  if (!start_time_ticks)
    return -EINVAL;

  snprintf(path, sizeof(path), "/proc/%u/stat", pid);
  fp = fopen(path, "r");
  if (!fp)
    return -errno;

  if (!fgets(line, sizeof(line), fp)) {
    int err = ferror(fp) ? -errno : -EIO;
    fclose(fp);
    return err;
  }
  fclose(fp);

  rparen = strrchr(line, ')');
  if (!rparen)
    return -EINVAL;

  field = rparen + 2; /* skip ") " before field 3 */
  if (*field == '\0')
    return -EINVAL;

  for (char *tok = strtok_r(field, " ", &saveptr); tok;
       tok = strtok_r(NULL, " ", &saveptr), field_index++) {
    if (field_index == 22) {
      char *end = NULL;
      unsigned long long val;

      errno = 0;
      val = strtoull(tok, &end, 10);
      if (errno != 0 || end == tok || (end && *end != '\0'))
        return -EINVAL;

      *start_time_ticks = (uint64_t)val;
      return 0;
    }
  }

  return -EINVAL;
}

/*
 * libbpf print callback - redirect to stderr with prefix
 */
static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
  if (level == LIBBPF_DEBUG)
    return 0;

  fprintf(stderr, "libbpf: ");
  int n = vfprintf(stderr, format, args);
  return n;
}

/*
 * Resolve kernel symbol address from /proc/kallsyms.
 * Returns 0 on failure.
 */
unsigned long resolve_kernel_symbol(const char *name) {
  FILE *f;
  char line[512];
  unsigned long addr = 0;

  f = fopen("/proc/kallsyms", "r");
  if (!f) {
    lota_warn("Failed to open /proc/kallsyms: %s", strerror(errno));
    return 0;
  }

  while (fgets(line, sizeof(line), f)) {
    char sym_name[256];
    char type;
    unsigned long a;

    if (sscanf(line, "%lx %c %s", &a, &type, sym_name) == 3) {
      if (strcmp(name, sym_name) == 0) {
        addr = a;
        break;
      }
    }
  }

  fclose(f);
  return addr;
}

int bpf_loader_init(struct bpf_loader_ctx *ctx) {
  if (!ctx)
    return -EINVAL;

  memset(ctx, 0, sizeof(*ctx));
  ctx->ringbuf_fd = -1;
  ctx->stats_fd = -1;
  ctx->config_fd = -1;
  ctx->bpf_admin_tgid_fd = -1;
  ctx->agent_identity_fd = -1;
  ctx->trusted_libs_fd = -1;
  ctx->protected_pids_fd = -1;
  ctx->allow_verity_digest_fd = -1;

  libbpf_set_print(libbpf_print_fn);
  libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

  return 0;
}

int bpf_loader_load(struct bpf_loader_ctx *ctx, const char *bpf_obj_path) {
  struct bpf_program *prog;
  struct bpf_link *link;
  int err;
  int ret;

  if (!ctx || !bpf_obj_path)
    return -EINVAL;

  if (ctx->loaded)
    return -EALREADY;

  struct bpf_object_open_opts opts = {
      .sz = sizeof(struct bpf_object_open_opts),
      .kernel_log_level = 1,
  };

  ctx->obj = bpf_object__open_file(bpf_obj_path, &opts);
  if (!ctx->obj) {
    lota_err("Failed to open BPF object %s: %s", bpf_obj_path, strerror(errno));
    return -errno;
  }

  bpf_object__for_each_program(prog, ctx->obj) {
    bpf_program__set_log_level(prog, 2);
  }

  err = bpf_object__load(ctx->obj);
  if (err) {
    lota_err("Failed to load BPF object: %d", err);
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
      lota_err("Failed to attach program %s: %d", bpf_program__name(prog), err);
      goto err_close;
    }

    if (ctx->link_count < BPF_MAX_LSM_LINKS) {
      ctx->links[ctx->link_count++] = link;
    } else {
      lota_err("Too many LSM programs, increase BPF_MAX_LSM_LINKS");
      bpf_link__destroy(link);
      err = -E2BIG;
      goto err_close;
    }

    lota_info("Attached LSM program: %s", bpf_program__name(prog));
  }

  /* Get ring buffer map fd */
  ctx->ringbuf_fd = bpf_object__find_map_fd_by_name(ctx->obj, "events");
  if (ctx->ringbuf_fd < 0) {
    err = ctx->ringbuf_fd;
    lota_err("Failed to find events map");
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

  ctx->bpf_admin_tgid_fd =
      bpf_object__find_map_fd_by_name(ctx->obj, "bpf_admin_tgid");
  if (ctx->bpf_admin_tgid_fd >= 0) {
    uint32_t key = 0;
    struct lota_identity_entry admin = {0};

    admin.tgid = (uint32_t)getpid();
    ret = read_pid_start_time_ticks(admin.tgid, &admin.start_time_ticks);
    if (ret < 0 || admin.start_time_ticks == 0) {
      lota_err("Failed to read bpf admin start time for pid %u", admin.tgid);
      err = ret < 0 ? ret : -EINVAL;
      goto err_close;
    }

    if (bpf_map_update_elem(ctx->bpf_admin_tgid_fd, &key, &admin, BPF_ANY) <
        0) {
      lota_err("Failed to set bpf admin identity: %s", strerror(errno));
      err = -errno;
      goto err_close;
    }
  } else {
    lota_warn("bpf_admin_tgid map not found in BPF object");
  }

  ctx->agent_identity_fd =
      bpf_object__find_map_fd_by_name(ctx->obj, "lota_agent_identity");
  if (ctx->agent_identity_fd < 0) {
    err = ctx->agent_identity_fd;
    lota_err("Failed to find lota_agent_identity map");
    goto err_close;
  }

  /* Integrity config map */
  ctx->integrity_fd =
      bpf_object__find_map_fd_by_name(ctx->obj, "integrity_config");
  if (ctx->integrity_fd >= 0) {
    unsigned long sig_enforce = resolve_kernel_symbol("sig_enforce");
    unsigned long lockdown = resolve_kernel_symbol("lockdown_state");

    if (!lockdown) {
      /* fallback for kernels exposing internal lockdown state symbol */
      lockdown = resolve_kernel_symbol("kernel_locked_down");
    }

    if (!lockdown) {
      /* fallback for older kernels */
      lockdown = resolve_kernel_symbol("security_lockdown_enabled");
    }

    lota_info("Resolved kernel symbols: sig_enforce=0x%lx, lockdown=0x%lx",
              sig_enforce, lockdown);

    uint32_t key = 0;
    struct {
      uint64_t sig_enforce_addr;
      uint64_t lockdown_addr;
    } cfg = {
        .sig_enforce_addr = sig_enforce,
        .lockdown_addr = lockdown,
    };

    if (bpf_map_update_elem(ctx->integrity_fd, &key, &cfg, BPF_ANY) < 0) {
      lota_err("Failed to update integrity_config map: %s", strerror(errno));
    }
  } else {
    lota_warn("integrity_config map not found in BPF object");
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

  /* Get fs-verity allowlist map fd */
  ctx->allow_verity_digest_fd =
      bpf_object__find_map_fd_by_name(ctx->obj, "allow_verity_digest");
  if (ctx->allow_verity_digest_fd < 0) {
    ctx->allow_verity_digest_fd = -1; /* optional map */
  }

  ctx->loaded = true;
  return 0;

err_close:
  for (int i = 0; i < ctx->link_count; i++) {
    bpf_link__destroy(ctx->links[i]);
    ctx->links[i] = NULL;
  }
  ctx->link_count = 0;
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
    lota_err("Failed to create ring buffer");
    return -errno;
  }

  return 0;
}

int bpf_loader_poll(struct bpf_loader_ctx *ctx, int timeout_ms) {
  if (!ctx || !ctx->ringbuf)
    return -EINVAL;

  return ring_buffer__poll(ctx->ringbuf, timeout_ms);
}

int bpf_loader_get_event_fd(struct bpf_loader_ctx *ctx) {
  if (!ctx || !ctx->ringbuf)
    return -EINVAL;
  return ring_buffer__epoll_fd(ctx->ringbuf);
}

int bpf_loader_consume(struct bpf_loader_ctx *ctx) {
  if (!ctx || !ctx->ringbuf)
    return -EINVAL;
  return ring_buffer__consume(ctx->ringbuf);
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

  for (int i = 0; i < ctx->link_count; i++) {
    bpf_link__destroy(ctx->links[i]);
    ctx->links[i] = NULL;
  }
  ctx->link_count = 0;

  if (ctx->obj) {
    bpf_object__close(ctx->obj);
    ctx->obj = NULL;
  }

  ctx->loaded = false;
  ctx->ringbuf_fd = -1;
  ctx->stats_fd = -1;
  ctx->config_fd = -1;
  ctx->bpf_admin_tgid_fd = -1;
  ctx->agent_identity_fd = -1;
  ctx->integrity_fd = -1;
  ctx->trusted_libs_fd = -1;
  ctx->protected_pids_fd = -1;
  ctx->allow_verity_digest_fd = -1;
}

int bpf_loader_allow_verity_digest(struct bpf_loader_ctx *ctx,
                                   const uint8_t digest[32]) {
  uint32_t value = 1;

  if (!ctx || !ctx->loaded || !digest)
    return -EINVAL;

  if (ctx->allow_verity_digest_fd < 0)
    return -ENOTSUP;

  if (bpf_map_update_elem(ctx->allow_verity_digest_fd, digest, &value,
                          BPF_ANY) < 0)
    return -errno;

  return 0;
}

static int measure_fsverity_digest(const char *path, uint8_t out[32]) {
  int fd;
  struct stat st;
  int ret = 0;

  if (!path || !out)
    return -EINVAL;

  fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0)
    return -errno;

  if (fstat(fd, &st) != 0) {
    ret = -errno;
    close(fd);
    return ret;
  }

  if (!S_ISREG(st.st_mode)) {
    close(fd);
    return -EINVAL;
  }

  /* fsverity_digest has a flexible array; allocate space for SHA-256 */
  {
    struct {
      struct fsverity_digest hdr;
      uint8_t digest[64];
    } d;

    memset(&d, 0, sizeof(d));
    d.hdr.digest_size = (uint16_t)sizeof(d.digest);

    if (ioctl(fd, FS_IOC_MEASURE_VERITY, &d) != 0) {
      ret = -errno;
      close(fd);
      return ret;
    }

    if (d.hdr.digest_size != 32) {
      close(fd);
      return -EINVAL;
    }

    memcpy(out, d.digest, 32);
  }

  close(fd);
  return 0;
}

int bpf_loader_measure_verity_digest(const char *path, uint8_t out[32]) {
  return measure_fsverity_digest(path, out);
}

int bpf_loader_allow_verity_path(struct bpf_loader_ctx *ctx, const char *path) {
  uint8_t digest[32];
  int ret;

  if (!ctx || !ctx->loaded || !path)
    return -EINVAL;

  if (ctx->allow_verity_digest_fd < 0)
    return -ENOTSUP;

  ret = measure_fsverity_digest(path, digest);
  if (ret < 0)
    return ret;

  return bpf_loader_allow_verity_digest(ctx, digest);
}

int bpf_loader_disallow_verity_digest(struct bpf_loader_ctx *ctx,
                                      const uint8_t digest[32]) {
  if (!ctx || !ctx->loaded || !digest)
    return -EINVAL;

  if (ctx->allow_verity_digest_fd < 0)
    return -ENOTSUP;

  if (bpf_map_delete_elem(ctx->allow_verity_digest_fd, digest) < 0)
    return -errno;

  return 0;
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

int bpf_loader_set_agent_pid(struct bpf_loader_ctx *ctx, uint32_t pid) {
  uint32_t key = 0;
  struct lota_identity_entry agent = {0};
  int ret;

  if (!ctx || !ctx->loaded || pid == 0)
    return -EINVAL;

  if (ctx->agent_identity_fd < 0)
    return -ENOTSUP;

  agent.tgid = pid;
  ret = read_pid_start_time_ticks(pid, &agent.start_time_ticks);
  if (ret < 0)
    return ret;
  if (agent.start_time_ticks == 0)
    return -EINVAL;

  if (bpf_map_update_elem(ctx->agent_identity_fd, &key, &agent, BPF_ANY) < 0)
    return -errno;

  return 0;
}

int bpf_loader_protect_pid(struct bpf_loader_ctx *ctx, uint32_t pid) {
  struct protected_pid_entry value = {0};
  int ret;

  if (!ctx || !ctx->loaded)
    return -EINVAL;

  if (ctx->protected_pids_fd < 0)
    return -ENOTSUP;

  ret = read_pid_start_time_ticks(pid, &value.start_time_ticks);
  if (ret < 0)
    return ret;

  if (value.start_time_ticks == 0)
    return -EINVAL;

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

int bpf_loader_get_extended_stats(struct bpf_loader_ctx *ctx,
                                  struct bpf_extended_stats *stats) {
  if (!ctx || !stats || !ctx->loaded || ctx->stats_fd < 0)
    return -EINVAL;

  read_stat(ctx->stats_fd, STAT_TOTAL_EXECS, &stats->total_execs);
  read_stat(ctx->stats_fd, STAT_EVENTS_SENT, &stats->events_sent);
  read_stat(ctx->stats_fd, STAT_ERRORS, &stats->errors);
  read_stat(ctx->stats_fd, STAT_RINGBUF_DROPS, &stats->drops);
  read_stat(ctx->stats_fd, STAT_MODULES_BLOCKED, &stats->modules_blocked);
  read_stat(ctx->stats_fd, STAT_MMAP_EXECS, &stats->mmap_execs);
  read_stat(ctx->stats_fd, STAT_MMAP_BLOCKED, &stats->mmap_blocked);
  read_stat(ctx->stats_fd, STAT_PTRACE_ATTEMPTS, &stats->ptrace_attempts);
  read_stat(ctx->stats_fd, STAT_PTRACE_BLOCKED, &stats->ptrace_blocked);
  read_stat(ctx->stats_fd, STAT_SETUID_EVENTS, &stats->setuid_events);
  read_stat(ctx->stats_fd, STAT_BPF_SYSCALL_BLOCKED,
            &stats->bpf_syscall_blocked);

  return 0;
}
