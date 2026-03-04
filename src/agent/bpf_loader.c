/* SPDX-License-Identifier: MIT */
/*
 * LOTA - BPF Program Loader
 * Implementation using libbpf
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <sys/ioctl.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <linux/fsverity.h>
#include <linux/openat2.h>

#include "../../include/lota.h"
#include "bpf_loader.h"
#include "journal.h"
#include "policy_sign.h"

#define BPF_OBJECT_MAX_FILE_SIZE (4 * 1024 * 1024)

#ifndef EAUTH
#define EAUTH 80
#endif

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

struct lota_task_auth_entry {
  uint32_t flags;
  uint32_t pad;
};

#define LOTA_TASK_AUTH_ADMIN (1U << 0)
#define LOTA_TASK_AUTH_AGENT (1U << 1)

struct trusted_lib_key {
  uint64_t dev;
  uint64_t ino;
};

static int harden_fd_cloexec(int fd, const char *label) {
  int flags;

  if (fd < 0)
    return -EINVAL;

  flags = fcntl(fd, F_GETFD, 0);
  if (flags < 0)
    return -errno;

  if ((flags & FD_CLOEXEC) != 0)
    return 0;

  if (fcntl(fd, F_SETFD, flags | FD_CLOEXEC) < 0)
    return -errno;

  lota_info("Applied FD_CLOEXEC hardening on %s fd=%d", label ? label : "fd",
            fd);
  return 0;
}

/*
 * Returns 1 in initial PID namespace, 0 in nested PID namespace, <0 on error.
 */
static int running_in_initial_pidns(void) {
  FILE *fp;
  char line[512];
  int nspid_count = 0;

  fp = fopen("/proc/self/status", "r");
  if (!fp)
    return -errno;

  while (fgets(line, sizeof(line), fp)) {
    if (strncmp(line, "NSpid:\t", 7) != 0)
      continue;

    char *p = line + 7;
    while (*p != '\0') {
      char *end = NULL;
      unsigned long v;

      while (*p == ' ' || *p == '\t')
        p++;
      if (*p == '\0' || *p == '\n')
        break;

      errno = 0;
      v = strtoul(p, &end, 10);
      if (errno != 0 || end == p)
        break;
      (void)v;
      nspid_count++;
      p = end;
    }
    break;
  }

  fclose(fp);

  if (nspid_count <= 0)
    return -EINVAL;

  return (nspid_count == 1) ? 1 : 0;
}

/*
 * Read /proc/<pid>/stat field 22 (starttime in clock ticks since boot).
 */
static int read_pid_start_time_ticks(uint32_t pid, uint64_t *start_time_ticks) {
  static int pidns_state = -1;
  char path[64];
  FILE *fp;
  char line[4096];
  char *rparen;
  char *field;
  char *saveptr = NULL;
  int field_index = 3;

  if (!start_time_ticks)
    return -EINVAL;

  if (pidns_state < 0)
    pidns_state = running_in_initial_pidns();
  if (pidns_state <= 0)
    return (pidns_state < 0) ? pidns_state : -EOPNOTSUPP;

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

static int set_task_auth_flags(int task_auth_fd, pid_t pid, uint32_t flags) {
  int pidfd;
  struct lota_task_auth_entry value = {0};

  if (task_auth_fd < 0 || pid <= 0 || flags == 0)
    return -EINVAL;

#ifndef SYS_pidfd_open
  return -ENOTSUP;
#else
  pidfd = (int)syscall(SYS_pidfd_open, pid, 0);
  if (pidfd < 0)
    return -errno;

  value.flags = flags;
  if (bpf_map_update_elem(task_auth_fd, &pidfd, &value, BPF_ANY) < 0) {
    int err = -errno;
    close(pidfd);
    return err;
  }

  close(pidfd);
  return 0;
#endif
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

static unsigned long resolve_lockdown_symbol(void) {
  unsigned long lockdown = resolve_kernel_symbol("lockdown_state");

  if (!lockdown) {
    lockdown = resolve_kernel_symbol("kernel_locked_down");
  }

  if (!lockdown) {
    lockdown = resolve_kernel_symbol("security_lockdown_enabled");
  }

  return lockdown;
}

static void build_expected_integrity_config(struct integrity_data *cfg) {
  if (!cfg)
    return;

  memset(cfg, 0, sizeof(*cfg));
  cfg->sig_enforce_addr = resolve_kernel_symbol("sig_enforce");
  cfg->lockdown_addr = resolve_lockdown_symbol();
}

static int read_text_file(const char *path, char *buf, size_t buf_size,
                          size_t *out_len) {
  int fd;
  ssize_t n;

  if (!path || !buf || buf_size < 2)
    return -EINVAL;

  fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0)
    return -errno;

  n = read(fd, buf, buf_size - 1);
  if (n < 0) {
    int err = -errno;
    close(fd);
    return err;
  }

  close(fd);
  buf[n] = '\0';
  if (out_len)
    *out_len = (size_t)n;
  return 0;
}

static int kernel_lockdown_restrictive(void) {
  char buf[256];
  size_t len = 0;
  char *lb;
  char *rb;

  int ret =
      read_text_file("/sys/kernel/security/lockdown", buf, sizeof(buf), &len);
  if (ret < 0)
    return ret;

  if (len == 0)
    return -EIO;

  lb = strchr(buf, '[');
  rb = lb ? strchr(lb + 1, ']') : NULL;
  if (!lb || !rb || rb <= lb + 1)
    return -EPERM;

  *rb = '\0';
  if (strcmp(lb + 1, "integrity") == 0 ||
      strcmp(lb + 1, "confidentiality") == 0)
    return 0;

  return -EPERM;
}

static int kernel_ima_appraisal_enabled(void) {
  char buf[8192];
  int ret =
      read_text_file("/sys/kernel/security/ima/policy", buf, sizeof(buf), NULL);
  if (ret < 0)
    return ret;

  if (!strstr(buf, "appraise"))
    return -EPERM;

  return 0;
}

int bpf_loader_verify_kernel_runtime_hardening(void) {
  int ret;

  ret = kernel_lockdown_restrictive();
  if (ret < 0) {
    lota_err("Kernel lockdown is not in restrictive mode "
             "(integrity/confidentiality required)");
    return ret;
  }

  ret = kernel_ima_appraisal_enabled();
  if (ret < 0) {
    lota_err("IMA appraisal policy is required for anti-tamper startup");
    return ret;
  }

  return 0;
}

int bpf_loader_init(struct bpf_loader_ctx *ctx) {
  if (!ctx)
    return -EINVAL;

  memset(ctx, 0, sizeof(*ctx));
  ctx->ringbuf_fd = -1;
  ctx->stats_fd = -1;
  ctx->config_fd = -1;
  ctx->task_auth_fd = -1;
  ctx->trusted_libs_fd = -1;
  ctx->trusted_lib_mnt_fd = -1;
  ctx->protected_pids_fd = -1;
  ctx->allow_verity_digest_fd = -1;

  libbpf_set_print(libbpf_print_fn);
  libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

  return 0;
}

static int verify_bpf_object_signature(const char *bpf_obj_path,
                                       const char *bpf_pubkey_pem_path) {
  char *sig_path = NULL;
  size_t sig_path_len;
  uint8_t *obj_data = NULL;
  size_t obj_len = 0;
  uint8_t sig[POLICY_SIG_SIZE];
  FILE *f = NULL;
  long fsize;
  size_t nread;
  int ret;

  if (!bpf_obj_path || !bpf_pubkey_pem_path || bpf_pubkey_pem_path[0] == '\0')
    return -EINVAL;

  f = fopen(bpf_obj_path, "rb");
  if (!f)
    return -errno;

  if (fseek(f, 0, SEEK_END) != 0) {
    ret = -errno;
    goto out;
  }

  fsize = ftell(f);
  if (fsize < 0) {
    ret = -EIO;
    goto out;
  }

  if ((size_t)fsize > BPF_OBJECT_MAX_FILE_SIZE) {
    ret = -EFBIG;
    goto out;
  }

  if (fseek(f, 0, SEEK_SET) != 0) {
    ret = -errno;
    goto out;
  }

  obj_data = malloc((size_t)fsize);
  if (!obj_data) {
    ret = -ENOMEM;
    goto out;
  }

  nread = fread(obj_data, 1, (size_t)fsize, f);
  if (nread != (size_t)fsize) {
    ret = -EIO;
    goto out;
  }
  obj_len = (size_t)fsize;

  fclose(f);
  f = NULL;

  sig_path_len = strlen(bpf_obj_path) + 5; /* ".sig" + NUL */
  sig_path = calloc(sig_path_len, 1);
  if (!sig_path) {
    ret = -ENOMEM;
    goto out;
  }

  snprintf(sig_path, sig_path_len, "%s.sig", bpf_obj_path);

  f = fopen(sig_path, "rb");
  if (!f) {
    ret = -errno ? -errno : -ENOENT;
    goto out;
  }

  nread = fread(sig, 1, POLICY_SIG_SIZE, f);
  if (nread != POLICY_SIG_SIZE) {
    ret = -EAUTH;
    goto out;
  }

  ret = policy_verify_buffer(obj_data, obj_len, bpf_pubkey_pem_path, sig);

out:
  if (f)
    fclose(f);
  free(sig_path);
  free(obj_data);
  return ret;
}

int bpf_loader_load(struct bpf_loader_ctx *ctx, const char *bpf_obj_path,
                    const char *bpf_pubkey_pem_path) {
  struct bpf_program *prog;
  struct bpf_link *link;
  int err;
  int ret;

  if (!ctx || !bpf_obj_path)
    return -EINVAL;

  if (!bpf_pubkey_pem_path || bpf_pubkey_pem_path[0] == '\0') {
    lota_err("BPF public key is required to verify %s signature", bpf_obj_path);
    return -EINVAL;
  }

  if (ctx->loaded)
    return -EALREADY;

  ret = verify_bpf_object_signature(bpf_obj_path, bpf_pubkey_pem_path);
  if (ret < 0) {
    lota_err("BPF object signature verification failed for %s: %s",
             bpf_obj_path, strerror(-ret));
    return ret;
  }

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
   * Attach all supported runtime enforcement programs.
   *
   * LOTA currently uses LSM hooks and a tracing fallback (fmod_ret) for
   * __ptrace_may_access to cover process_vm_* access paths. This will be
   * properly done in the future.
   */
  bpf_object__for_each_program(prog, ctx->obj) {
    enum bpf_prog_type prog_type = bpf_program__type(prog);

    if (prog_type != BPF_PROG_TYPE_LSM && prog_type != BPF_PROG_TYPE_TRACING)
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
      lota_err("Too many attached BPF programs, increase BPF_MAX_LSM_LINKS");
      bpf_link__destroy(link);
      err = -E2BIG;
      goto err_close;
    }

    lota_info("Attached BPF program: %s", bpf_program__name(prog));
  }

  /* Get ring buffer map fd */
  ctx->ringbuf_fd = bpf_object__find_map_fd_by_name(ctx->obj, "events");
  if (ctx->ringbuf_fd < 0) {
    err = ctx->ringbuf_fd;
    lota_err("Failed to find events map");
    goto err_close;
  }
  err = harden_fd_cloexec(ctx->ringbuf_fd, "events map");
  if (err < 0) {
    lota_err("Failed to harden events map fd: %s", strerror(-err));
    goto err_close;
  }

  /* Get stats map fd */
  ctx->stats_fd = bpf_object__find_map_fd_by_name(ctx->obj, "stats");
  if (ctx->stats_fd < 0) {
    ctx->stats_fd = -1; // stats map is optional
  } else {
    err = harden_fd_cloexec(ctx->stats_fd, "stats map");
    if (err < 0) {
      lota_err("Failed to harden stats map fd: %s", strerror(-err));
      goto err_close;
    }
  }

  ctx->config_fd = bpf_object__find_map_fd_by_name(ctx->obj, "lota_config");
  if (ctx->config_fd < 0) {
    ctx->config_fd = -1;
  } else {
    err = harden_fd_cloexec(ctx->config_fd, "lota_config map");
    if (err < 0) {
      lota_err("Failed to harden lota_config map fd: %s", strerror(-err));
      goto err_close;
    }
  }

  ctx->task_auth_fd =
      bpf_object__find_map_fd_by_name(ctx->obj, "lota_task_auth");
  if (ctx->task_auth_fd < 0) {
    err = ctx->task_auth_fd;
    lota_err("Failed to find lota_task_auth map");
    goto err_close;
  }
  err = harden_fd_cloexec(ctx->task_auth_fd, "lota_task_auth map");
  if (err < 0) {
    lota_err("Failed to harden lota_task_auth map fd: %s", strerror(-err));
    goto err_close;
  }

  ret = set_task_auth_flags(ctx->task_auth_fd, getpid(),
                            LOTA_TASK_AUTH_ADMIN | LOTA_TASK_AUTH_AGENT);
  if (ret < 0) {
    lota_err("Failed to register task auth flags: %s", strerror(-ret));
    err = ret;
    goto err_close;
  }

  if (bpf_map_freeze(ctx->task_auth_fd) < 0) {
    err = -errno;
    lota_err("Failed to freeze lota_task_auth map: %s", strerror(errno));
    goto err_close;
  }

  if (ctx->config_fd >= 0) {
    uint32_t lock_key = LOTA_CFG_LOCK_BPF;
    uint32_t lock_val = 1;

    if (bpf_map_update_elem(ctx->config_fd, &lock_key, &lock_val, BPF_ANY) <
        0) {
      lota_err("Failed to enable early LOCK_BPF: %s", strerror(errno));
      err = -errno;
      goto err_close;
    }
    lota_info("Early BPF map lock enabled during loader init");
  } else {
    lota_warn("lota_config map unavailable, early LOCK_BPF not applied");
  }

  /* Integrity config map */
  ctx->integrity_fd =
      bpf_object__find_map_fd_by_name(ctx->obj, "integrity_config");
  if (ctx->integrity_fd >= 0) {
    err = harden_fd_cloexec(ctx->integrity_fd, "integrity_config map");
    if (err < 0) {
      lota_err("Failed to harden integrity_config map fd: %s", strerror(-err));
      goto err_close;
    }

    struct integrity_data cfg = {0};

    build_expected_integrity_config(&cfg);

    lota_info("Resolved kernel symbols: sig_enforce=0x%lx, lockdown=0x%lx",
              (unsigned long)cfg.sig_enforce_addr,
              (unsigned long)cfg.lockdown_addr);

    uint32_t key = 0;
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
  } else {
    err = harden_fd_cloexec(ctx->trusted_libs_fd, "trusted_libs map");
    if (err < 0) {
      lota_err("Failed to harden trusted_libs map fd: %s", strerror(-err));
      goto err_close;
    }
  }

  /* Get trusted parent mountpoint map fd */
  ctx->trusted_lib_mnt_fd =
      bpf_object__find_map_fd_by_name(ctx->obj, "trusted_lib_mnt");
  if (ctx->trusted_lib_mnt_fd < 0) {
    ctx->trusted_lib_mnt_fd = -1; /* optional map */
  } else {
    err = harden_fd_cloexec(ctx->trusted_lib_mnt_fd, "trusted_lib_mnt map");
    if (err < 0) {
      lota_err("Failed to harden trusted_lib_mnt map fd: %s", strerror(-err));
      goto err_close;
    }
  }

  /* Get protected PIDs map fd */
  ctx->protected_pids_fd =
      bpf_object__find_map_fd_by_name(ctx->obj, "protected_pids");
  if (ctx->protected_pids_fd < 0) {
    ctx->protected_pids_fd = -1; /* optional map */
  } else {
    err = harden_fd_cloexec(ctx->protected_pids_fd, "protected_pids map");
    if (err < 0) {
      lota_err("Failed to harden protected_pids map fd: %s", strerror(-err));
      goto err_close;
    }
  }

  /* Get fs-verity allowlist map fd */
  ctx->allow_verity_digest_fd =
      bpf_object__find_map_fd_by_name(ctx->obj, "allow_verity_digest");
  if (ctx->allow_verity_digest_fd < 0) {
    ctx->allow_verity_digest_fd = -1; /* optional map */
  } else {
    err = harden_fd_cloexec(ctx->allow_verity_digest_fd,
                            "allow_verity_digest map");
    if (err < 0) {
      lota_err("Failed to harden allow_verity_digest map fd: %s",
               strerror(-err));
      goto err_close;
    }
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
  ctx->task_auth_fd = -1;
  ctx->integrity_fd = -1;
  ctx->trusted_libs_fd = -1;
  ctx->trusted_lib_mnt_fd = -1;
  ctx->protected_pids_fd = -1;
  ctx->allow_verity_digest_fd = -1;
}

int bpf_loader_allow_verity_digest(struct bpf_loader_ctx *ctx,
                                   const struct lota_verity_digest_key *key) {
  uint32_t value = 1;

  if (!ctx || !ctx->loaded || !key)
    return -EINVAL;

  if (key->len != LOTA_VERITY_DIGEST_SHA512_SIZE)
    return -EINVAL;

  if (ctx->allow_verity_digest_fd < 0)
    return -ENOTSUP;

  if (bpf_map_update_elem(ctx->allow_verity_digest_fd, key, &value, BPF_ANY) <
      0)
    return -errno;

  return 0;
}

static int open_regular_file_nofollow(const char *path) {
  int fd = -1;

  if (!path)
    return -EINVAL;

  if (path[0] == '\0')
    return -EINVAL;

#ifndef O_NOFOLLOW
  return -ENOTSUP;
#else
  if (path[0] != '/')
    return -EINVAL;

  {
    struct open_how how = {
        .flags = O_RDONLY | O_CLOEXEC,
        .resolve = RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
    };

    fd = (int)syscall(SYS_openat2, AT_FDCWD, path, &how, sizeof(how));
    if (fd < 0 && errno != ENOSYS && errno != EINVAL)
      return -errno;
  }

  if (fd < 0) {
    int dirfd = -1;
    const char *p = path;

    dirfd = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (dirfd < 0)
      return -errno;

    while (*p == '/')
      p++;

    while (*p != '\0') {
      char name[NAME_MAX + 1];
      const char *slash = strchr(p, '/');
      size_t n = slash ? (size_t)(slash - p) : strlen(p);
      int nextfd;

      if (n == 0) {
        p++;
        continue;
      }
      if (n > NAME_MAX) {
        close(dirfd);
        return -ENAMETOOLONG;
      }

      memcpy(name, p, n);
      name[n] = '\0';

      if (slash) {
        nextfd =
            openat(dirfd, name, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        close(dirfd);
        if (nextfd < 0)
          return -errno;
        dirfd = nextfd;

        p = slash + 1;
        while (*p == '/')
          p++;
        continue;
      }

      fd = openat(dirfd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
      close(dirfd);
      if (fd < 0)
        return -errno;
      break;
    }

    if (fd < 0)
      return -EINVAL;
  }

  return fd;
#endif
}

static int measure_fsverity_digest(const char *path,
                                   struct lota_verity_digest_key *out) {
  int fd;
  struct stat st;
  int ret = 0;

  if (!path || !out)
    return -EINVAL;

  fd = open_regular_file_nofollow(path);
  if (fd < 0)
    return fd;

  if (fstat(fd, &st) != 0) {
    ret = -errno;
    close(fd);
    return ret;
  }

  if (!S_ISREG(st.st_mode)) {
    close(fd);
    return -EINVAL;
  }

  /* fsverity_digest has a flexible array; reserve max supported size */
  {
    struct {
      struct fsverity_digest hdr;
      uint8_t digest[LOTA_VERITY_DIGEST_MAX_SIZE];
    } d;

    memset(&d, 0, sizeof(d));
    d.hdr.digest_size = (uint16_t)sizeof(d.digest);

    if (ioctl(fd, FS_IOC_MEASURE_VERITY, &d) != 0) {
      ret = -errno;
      close(fd);
      return ret;
    }

    if (d.hdr.digest_size != LOTA_VERITY_DIGEST_SHA512_SIZE) {
      close(fd);
      return -EINVAL;
    }

    memset(out, 0, sizeof(*out));
    out->len = d.hdr.digest_size;
    memcpy(out->digest, d.digest, (size_t)out->len);
  }

  close(fd);
  return 0;
}

int bpf_loader_measure_verity_digest(const char *path,
                                     struct lota_verity_digest_key *out) {
  return measure_fsverity_digest(path, out);
}

int bpf_loader_allow_verity_path(struct bpf_loader_ctx *ctx, const char *path) {
  struct lota_verity_digest_key key = {0};
  int ret;

  if (!ctx || !ctx->loaded || !path)
    return -EINVAL;

  if (ctx->allow_verity_digest_fd < 0)
    return -ENOTSUP;

  ret = measure_fsverity_digest(path, &key);
  if (ret < 0)
    return ret;

  return bpf_loader_allow_verity_digest(ctx, &key);
}

int bpf_loader_disallow_verity_digest(
    struct bpf_loader_ctx *ctx, const struct lota_verity_digest_key *key) {
  if (!ctx || !ctx->loaded || !key)
    return -EINVAL;

  if (key->len != LOTA_VERITY_DIGEST_SHA512_SIZE)
    return -EINVAL;

  if (ctx->allow_verity_digest_fd < 0)
    return -ENOTSUP;

  if (bpf_map_delete_elem(ctx->allow_verity_digest_fd, key) < 0)
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

int bpf_loader_verify_integrity_config(struct bpf_loader_ctx *ctx) {
  uint32_t key = 0;
  struct integrity_data current = {0};
  struct integrity_data expected = {0};

  if (!ctx || !ctx->loaded)
    return -EINVAL;

  if (ctx->integrity_fd < 0)
    return -ENOTSUP;

  if (bpf_map_lookup_elem(ctx->integrity_fd, &key, &current) < 0)
    return -errno;

  build_expected_integrity_config(&expected);

  if (current.sig_enforce_addr != expected.sig_enforce_addr ||
      current.lockdown_addr != expected.lockdown_addr) {
    lota_err(
        "integrity_config mismatch: map(sig_enforce=0x%llx lockdown=0x%llx) "
        "expected(sig_enforce=0x%llx lockdown=0x%llx)",
        (unsigned long long)current.sig_enforce_addr,
        (unsigned long long)current.lockdown_addr,
        (unsigned long long)expected.sig_enforce_addr,
        (unsigned long long)expected.lockdown_addr);
    return -EPERM;
  }

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

  if (bpf_map_update_elem(ctx->protected_pids_fd, &pid, &value, BPF_ANY) < 0)
    return -errno;

  return 0;
}

int bpf_loader_unprotect_pid(struct bpf_loader_ctx *ctx, uint32_t pid) {
  if (!ctx || !ctx->loaded)
    return -EINVAL;

  if (ctx->protected_pids_fd < 0)
    return -ENOTSUP;

  if (bpf_map_delete_elem(ctx->protected_pids_fd, &pid) < 0)
    return -errno;

  return 0;
}

static int stat_regular_file_nofollow(const char *path, struct stat *st) {
  int fd = -1;
  int ret = 0;

  if (!path || !st)
    return -EINVAL;

  if (path[0] == '\0')
    return -EINVAL;

  fd = open_regular_file_nofollow(path);
  if (fd < 0)
    return fd;

  if (fstat(fd, st) != 0) {
    ret = -errno;
    close(fd);
    return ret;
  }

  close(fd);
  if (!S_ISREG(st->st_mode))
    return -EINVAL;

  return 0;
}

static int stat_dir_nofollow(const char *path, struct stat *st) {
  int fd = -1;
  int ret = 0;

  if (!path || !st)
    return -EINVAL;

  if (path[0] != '/')
    return -EINVAL;

  {
    struct open_how how = {
        .flags = O_PATH | O_DIRECTORY | O_CLOEXEC,
        .resolve = RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
    };

    fd = (int)syscall(SYS_openat2, AT_FDCWD, path, &how, sizeof(how));
    if (fd < 0 && errno != ENOSYS && errno != EINVAL)
      return -errno;
  }

  if (fd < 0) {
    int dirfd = -1;
    const char *p = path;

    dirfd = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (dirfd < 0)
      return -errno;

    while (*p == '/')
      p++;

    if (*p == '\0') {
      fd = dirfd;
      dirfd = -1;
    }

    while (fd < 0 && *p != '\0') {
      char name[NAME_MAX + 1];
      const char *slash = strchr(p, '/');
      size_t n = slash ? (size_t)(slash - p) : strlen(p);
      int nextfd;

      if (n == 0) {
        p++;
        continue;
      }
      if (n > NAME_MAX) {
        close(dirfd);
        return -ENAMETOOLONG;
      }

      memcpy(name, p, n);
      name[n] = '\0';

      nextfd =
          openat(dirfd, name, O_PATH | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
      close(dirfd);
      if (nextfd < 0)
        return -errno;
      dirfd = nextfd;

      if (!slash) {
        fd = dirfd;
        dirfd = -1;
        break;
      }

      p = slash + 1;
      while (*p == '/')
        p++;
    }

    if (dirfd >= 0)
      close(dirfd);

    if (fd < 0)
      return -EINVAL;
  }

  if (fstat(fd, st) != 0) {
    ret = -errno;
    close(fd);
    return ret;
  }

  close(fd);
  if (!S_ISDIR(st->st_mode))
    return -EINVAL;

  return 0;
}

static int update_trusted_mountpoint_ref(struct bpf_loader_ctx *ctx,
                                         const char *dir_path, int add) {
  struct trusted_lib_key key = {0};
  struct stat st;
  uint32_t refcnt = 0;
  int ret;

  if (!ctx || !dir_path)
    return -EINVAL;

  if (ctx->trusted_lib_mnt_fd < 0)
    return 0;

  ret = stat_dir_nofollow(dir_path, &st);
  if (ret < 0)
    return ret;

  key.dev = (uint64_t)st.st_dev;
  key.ino = (uint64_t)st.st_ino;
  if (key.dev == 0 || key.ino == 0)
    return -EINVAL;

  if (bpf_map_lookup_elem(ctx->trusted_lib_mnt_fd, &key, &refcnt) < 0) {
    if (errno != ENOENT)
      return -errno;
    refcnt = 0;
  }

  if (add) {
    if (refcnt == UINT32_MAX)
      return -EOVERFLOW;
    refcnt++;
    if (bpf_map_update_elem(ctx->trusted_lib_mnt_fd, &key, &refcnt, BPF_ANY) <
        0)
      return -errno;
    return 0;
  }

  if (refcnt == 0)
    return 0;

  if (refcnt == 1) {
    if (bpf_map_delete_elem(ctx->trusted_lib_mnt_fd, &key) < 0 &&
        errno != ENOENT)
      return -errno;
    return 0;
  }

  refcnt--;
  if (bpf_map_update_elem(ctx->trusted_lib_mnt_fd, &key, &refcnt, BPF_ANY) < 0)
    return -errno;

  return 0;
}

static int update_trusted_parent_mountpoints(struct bpf_loader_ctx *ctx,
                                             const char *lib_path, int add) {
  char dir_path[PATH_MAX];
  char prefix[PATH_MAX];
  size_t len;
  size_t prefix_len = 0;
  char *slash;
  char *p;
  uint32_t applied = 0;

  if (!ctx || !lib_path)
    return -EINVAL;

  if (ctx->trusted_lib_mnt_fd < 0)
    return 0;

  len = strnlen(lib_path, sizeof(dir_path));
  if (len == 0 || len >= sizeof(dir_path))
    return -EINVAL;

  memcpy(dir_path, lib_path, len + 1);

  while (len > 1 && dir_path[len - 1] == '/') {
    dir_path[len - 1] = '\0';
    len--;
  }

  slash = strrchr(dir_path, '/');
  if (!slash)
    return -EINVAL;
  if (slash == dir_path)
    return 0; /* parent is /, skip global mountpoint lock */
  *slash = '\0';

  p = dir_path + 1; /* skip leading slash */
  while (*p != '\0') {
    const char *next = strchr(p, '/');
    size_t comp_len = next ? (size_t)(next - p) : strlen(p);

    if (comp_len == 0) {
      p++;
      continue;
    }

    if (prefix_len == 0) {
      if (1 + comp_len >= sizeof(prefix))
        return -ENAMETOOLONG;
      prefix[0] = '/';
      memcpy(prefix + 1, p, comp_len);
      prefix_len = 1 + comp_len;
    } else {
      if (prefix_len + 1 + comp_len >= sizeof(prefix))
        return -ENAMETOOLONG;
      prefix[prefix_len] = '/';
      memcpy(prefix + prefix_len + 1, p, comp_len);
      prefix_len += 1 + comp_len;
    }

    prefix[prefix_len] = '\0';

    int ret = update_trusted_mountpoint_ref(ctx, prefix, add);
    if (ret < 0) {
      if (add && applied > 0) {
        size_t rollback_prefix_len = 0;
        char rollback_prefix[PATH_MAX];
        char *rp = dir_path + 1;
        uint32_t remaining = applied;

        while (remaining > 0 && *rp != '\0') {
          const char *rnext = strchr(rp, '/');
          size_t rlen = rnext ? (size_t)(rnext - rp) : strlen(rp);

          if (rlen == 0) {
            rp++;
            continue;
          }

          if (rollback_prefix_len == 0) {
            rollback_prefix[0] = '/';
            memcpy(rollback_prefix + 1, rp, rlen);
            rollback_prefix_len = 1 + rlen;
          } else {
            rollback_prefix[rollback_prefix_len] = '/';
            memcpy(rollback_prefix + rollback_prefix_len + 1, rp, rlen);
            rollback_prefix_len += 1 + rlen;
          }

          rollback_prefix[rollback_prefix_len] = '\0';
          (void)update_trusted_mountpoint_ref(ctx, rollback_prefix, 0);
          remaining--;

          if (!rnext)
            break;
          rp = (char *)rnext + 1;
        }
      }
      return ret;
    }

    applied++;

    if (!next)
      break;
    p = (char *)next + 1;
  }

  return 0;
}

int bpf_loader_trust_lib(struct bpf_loader_ctx *ctx, const char *path) {
  struct trusted_lib_key key = {0};
  struct stat st;
  uint32_t value = 1;
  int ret;

  if (!ctx || !ctx->loaded || !path)
    return -EINVAL;

  if (ctx->trusted_libs_fd < 0)
    return -ENOTSUP;

  ret = stat_regular_file_nofollow(path, &st);
  if (ret < 0)
    return ret;

  key.dev = (uint64_t)st.st_dev;
  key.ino = (uint64_t)st.st_ino;
  if (key.dev == 0 || key.ino == 0)
    return -EINVAL;

  if (bpf_map_update_elem(ctx->trusted_libs_fd, &key, &value, BPF_ANY) < 0)
    return -errno;

  ret = update_trusted_parent_mountpoints(ctx, path, 1);
  if (ret < 0) {
    (void)bpf_map_delete_elem(ctx->trusted_libs_fd, &key);
    return ret;
  }

  return 0;
}

int bpf_loader_untrust_lib(struct bpf_loader_ctx *ctx, const char *path) {
  struct trusted_lib_key key = {0};
  struct stat st;
  int ret;

  if (!ctx || !ctx->loaded || !path)
    return -EINVAL;

  if (ctx->trusted_libs_fd < 0)
    return -ENOTSUP;

  ret = stat_regular_file_nofollow(path, &st);
  if (ret < 0)
    return ret;

  key.dev = (uint64_t)st.st_dev;
  key.ino = (uint64_t)st.st_ino;
  if (key.dev == 0 || key.ino == 0)
    return -EINVAL;

  if (bpf_map_delete_elem(ctx->trusted_libs_fd, &key) < 0 && errno != ENOENT)
    return -errno;

  ret = update_trusted_parent_mountpoints(ctx, path, 0);
  if (ret < 0)
    return ret;

  return 0;
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
