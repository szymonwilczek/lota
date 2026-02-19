/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent
 * Minimalist C daemon for Linux remote attestation
 *
 * Copyright (C) 2026 Szymon Wilczek
 *
 * Usage:
 *   lota-agent [options]
 *
 * Options:
 *   --test-tpm      Test TPM operations and exit
 *   --test-iommu    Test IOMMU verification and exit
 *   --bpf PATH      Path to BPF object file
 *   --server HOST   Remote attestation server
 *   --daemon        Run as daemon
 */
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/random.h>
#include <sys/signalfd.h>
#include <time.h>
#include <unistd.h>

#include "../../include/attestation.h"
#include "../../include/lota.h"
#include "../../include/lota_ipc.h"
#include "agent.h"
#include "attest.h"
#include "bpf_loader.h"
#include "config.h"
#include "daemon.h"
#include "dbus.h"
#include "event.h"
#include "hash_verify.h"
#include "iommu.h"
#include "ipc.h"
#include "journal.h"
#include "main_utils.h"
#include "net.h"
#include "policy.h"
#include "quote.h"
#include "reload.h"
#include "sdnotify.h"
#include "selftest.h"
#include "startup_policy.h"
#include "steam_runtime.h"
#include "test_servers.h"
#include "tpm.h"

#define DEFAULT_BPF_PATH "/usr/lib/lota/lota_lsm.bpf.o"
#define DEFAULT_VERIFIER_PORT 8443

/* Default AIK TTL */
#define DEFAULT_AIK_TTL 0 /* 0 -> use TPM_AIK_DEFAULT_TTL_SEC */

/*
 * Safe integer parser.
 * Returns 0 on success, -1 on error (overflow, empty, trailing garbage).
 */
static int safe_parse_long(const char *s, long *out) {
  char *end;
  errno = 0;
  long v = strtol(s, &end, 10);
  if (errno != 0 || end == s || *end != '\0')
    return -1;
  *out = v;
  return 0;
}

/* Global state */
volatile sig_atomic_t g_running = 1;
static volatile sig_atomic_t g_reload = 0;
struct tpm_context g_tpm_ctx;
struct bpf_loader_ctx g_bpf_ctx;
struct ipc_context g_ipc_ctx;
struct hash_verify_ctx g_hash_ctx;
struct dbus_context *g_dbus_ctx;
int g_mode = LOTA_MODE_MONITOR;

/* Runtime config from CLI */
static uint32_t *g_protect_pids = NULL;
static int g_protect_pid_count = 0;
static char g_trust_libs[LOTA_CONFIG_MAX_LIBS][PATH_MAX];
static int g_trust_lib_count;
static int g_no_hash_cache;

/*
 * Main daemon loop
 */

static int run_daemon(const char *bpf_path, int mode, bool strict_mmap,
                      bool block_ptrace, bool strict_modules,
                      bool block_anon_exec, const char *config_path,
                      struct lota_config *cfg) {
  int ret, epoll_fd, sfd;
  uint32_t status_flags = 0;
  uint64_t wd_usec = 0;
  bool wd_enabled;
  sigset_t mask;
  struct epoll_event ev, events[16];
  int nfds;

  lota_info("LOTA agent starting");

  /* detect watchdog interval */
  wd_enabled = sdnotify_watchdog_enabled(&wd_usec);
  if (wd_enabled)
    lota_info("Watchdog enabled, interval %lu us", (unsigned long)wd_usec);

  /* setup signalfd for synchronous signal handling */
  sigemptyset(&mask);
  sigaddset(&mask, SIGTERM);
  sigaddset(&mask, SIGINT);
  sigaddset(&mask, SIGHUP);

  if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
    lota_err("Failed to block signals: %s", strerror(errno));
    return -errno;
  }

  sfd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
  if (sfd < 0) {
    lota_err("Failed to create signalfd: %s", strerror(errno));
    return -errno;
  }

  epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  if (epoll_fd < 0) {
    lota_err("Failed to create epoll instance: %s", strerror(errno));
    close(sfd);
    return -errno;
  }

  ev.events = EPOLLIN;
  ev.data.fd = sfd;
  if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, sfd, &ev) < 0) {
    lota_err("Failed to add signalfd to epoll: %s", strerror(errno));
    close(sfd);
    close(epoll_fd);
    return -errno;
  }

  ret =
      hash_verify_init(&g_hash_ctx, g_no_hash_cache ? HASH_CACHE_DISABLED : 0);
  if (ret < 0) {
    lota_err("Failed to initialize hash cache: %s", strerror(-ret));
    close(sfd);
    close(epoll_fd);
    return ret;
  }
  if (g_no_hash_cache)
    lota_info("Hash cache disabled (--no-hash-cache)");
  else
    lota_info("Hash verification cache ready");

  lota_info("Starting IPC server");
  ret = ipc_init_or_activate(&g_ipc_ctx);
  if (ret < 0) {
    lota_err("Failed to initialize IPC: %s", strerror(-ret));
    goto cleanup_epoll;
  } else {
    ipc_set_mode(&g_ipc_ctx, (uint8_t)mode);
    setup_container_listener(&g_ipc_ctx);
    setup_dbus(&g_ipc_ctx);

    /* IPC epoll fd to main loop */
    int ipc_fd = ipc_get_fd(&g_ipc_ctx);
    if (ipc_fd >= 0) {
      ev.events = EPOLLIN;
      ev.data.fd = ipc_fd;
      epoll_ctl(epoll_fd, EPOLL_CTL_ADD, ipc_fd, &ev);
    }

    if (g_dbus_ctx) {
      int dbus_fd = dbus_get_fd(g_dbus_ctx);
      if (dbus_fd >= 0) {
        ev.events = EPOLLIN;
        ev.data.fd = dbus_fd;
        epoll_ctl(epoll_fd, EPOLL_CTL_ADD, dbus_fd, &ev);
      }
    }
  }

  lota_info("Verifying IOMMU");
  ret = test_iommu();
  if (ret != 0) {
    lota_warn("IOMMU verification failed");
  } else {
    status_flags |= LOTA_STATUS_IOMMU_OK;
  }

  lota_info("Initializing TPM");
  ret = tpm_init(&g_tpm_ctx);
  if (ret < 0) {
    lota_err("Failed to initialize TPM: %s", strerror(-ret));
    goto cleanup_tpm;
  } else {
    lota_info("TPM initialized");
    status_flags |= LOTA_STATUS_TPM_OK;

    lota_info("Provisioning AIK");
    ret = tpm_provision_aik(&g_tpm_ctx);
    if (ret < 0) {
      lota_err("AIK provisioning failed: %s", strerror(-ret));
      goto cleanup_tpm;
    } else {
      ipc_set_tpm(&g_ipc_ctx, &g_tpm_ctx,
                  (1U << 0) | (1U << 1) | (1U << LOTA_PCR_SELF));
      lota_info("AIK ready, signed tokens enabled");

      ret = tpm_aik_load_metadata(&g_tpm_ctx);
      if (ret < 0) {
        lota_warn("Failed to load AIK metadata: %s", strerror(-ret));
      } else {
        int64_t age = tpm_aik_age(&g_tpm_ctx);
        lota_info("AIK generation: %lu, age: %ld seconds",
                  (unsigned long)g_tpm_ctx.aik_meta.generation, (long)age);
      }
    }

    lota_info("Performing self-measurement");
    ret = self_measure(&g_tpm_ctx);
    if (ret < 0) {
      lota_err("Self-measurement failed: %s", strerror(-ret));
      goto cleanup_tpm;
    } else {
      lota_info("Self-measurement complete (PCR %d extended)", LOTA_PCR_SELF);
    }
  }

  lota_info("Loading BPF program from: %s", bpf_path);
  ret = bpf_loader_init(&g_bpf_ctx);
  if (ret < 0) {
    lota_err("Failed to initialize BPF loader: %s", strerror(-ret));
    goto cleanup_tpm;
  }

  ret = bpf_loader_load(&g_bpf_ctx, bpf_path);
  if (ret < 0) {
    lota_err("Failed to load BPF program: %s", strerror(-ret));
    goto cleanup_bpf;
  }
  lota_info("BPF program loaded");
  status_flags |= LOTA_STATUS_BPF_LOADED;

  /* BPF event fd to epoll */
  int bpf_fd = bpf_loader_get_event_fd(&g_bpf_ctx);
  if (bpf_fd >= 0) {
    ev.events = EPOLLIN;
    ev.data.fd = bpf_fd;
    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, bpf_fd, &ev);
  }

  ret = agent_apply_startup_policy(
      mode, strict_mmap, block_ptrace, strict_modules, block_anon_exec,
      g_protect_pids, g_protect_pid_count, g_trust_libs, g_trust_lib_count);
  if (ret < 0)
    goto cleanup_bpf;

  ret = bpf_loader_setup_ringbuf(&g_bpf_ctx, handle_exec_event, NULL);
  if (ret < 0) {
    lota_err("Failed to setup ring buffer: %s", strerror(-ret));
    goto cleanup_bpf;
  }
  lota_info("Ring buffer ready");

  ipc_update_status(&g_ipc_ctx, status_flags, 0);

  sdnotify_ready();
  sdnotify_status("Monitoring, mode=%s", mode_to_string(mode));
  lota_info("Monitoring binary executions (event-driven)");

  /* main loop */
  while (g_running) {
    int timeout = -1;
    if (wd_enabled && wd_usec > 0)
      timeout = (int)(wd_usec / 2000); /* usec -> ms, /2 for safety */

    nfds = epoll_wait(epoll_fd, events, 16, timeout);

    if (nfds < 0) {
      if (errno == EINTR)
        continue;
      lota_err("epoll_wait failed: %s", strerror(errno));
      break;
    }

    if (nfds == 0 && wd_enabled) {
      sdnotify_watchdog_ping();
      continue;
    }

    for (int i = 0; i < nfds; i++) {
      if (events[i].data.fd == sfd) {
        struct signalfd_siginfo fdsi;
        ssize_t s = read(sfd, &fdsi, sizeof(struct signalfd_siginfo));
        if (s != sizeof(struct signalfd_siginfo))
          continue;

        if (fdsi.ssi_signo == SIGTERM || fdsi.ssi_signo == SIGINT) {
          lota_info("Signal received, stopping...");
          g_running = 0;
        } else if (fdsi.ssi_signo == SIGHUP) {
          /* reload */
          sdnotify_reloading();
          lota_info("SIGHUP received, reloading configuration");

          (void)agent_reload_config(
              config_path, cfg, &mode, &strict_mmap, &block_ptrace,
              &strict_modules, &block_anon_exec, &g_protect_pids,
              &g_protect_pid_count, g_trust_libs, &g_trust_lib_count);
        }
      } else if (events[i].data.fd == ipc_get_fd(&g_ipc_ctx)) {
        ipc_process(&g_ipc_ctx, 0);
      } else if (g_dbus_ctx && events[i].data.fd == dbus_get_fd(g_dbus_ctx)) {
        dbus_process(g_dbus_ctx, 0);
      } else if (events[i].data.fd == bpf_loader_get_event_fd(&g_bpf_ctx)) {
        bpf_loader_consume(&g_bpf_ctx);
      }
    }

    if (wd_enabled)
      sdnotify_watchdog_ping();
  }

  /* clean shutdown via signal - do not propagate EINTR as failure */
  if (!g_running)
    ret = 0;

  sdnotify_stopping();

  uint64_t total, sent, errs, drops;
  uint64_t mblocked, mmexec, mmblock, ptratt, ptrblk, setuid_ev;
  if (bpf_loader_get_extended_stats(&g_bpf_ctx, &total, &sent, &errs, &drops,
                                    &mblocked, &mmexec, &mmblock, &ptratt,
                                    &ptrblk, &setuid_ev) == 0) {
    lota_info("Shutdown statistics: exec=%lu sent=%lu err=%lu drops=%lu "
              "mod_blocked=%lu mmap_exec=%lu mmap_blocked=%lu "
              "ptrace=%lu ptrace_blocked=%lu setuid=%lu",
              total, sent, errs, drops, mblocked, mmexec, mmblock, ptratt,
              ptrblk, setuid_ev);
  }

  {
    uint64_t h_hits, h_misses, h_errors;
    hash_verify_stats(&g_hash_ctx, &h_hits, &h_misses, &h_errors);
    lota_info("Hash cache: hits=%lu misses=%lu errors=%lu", h_hits, h_misses,
              h_errors);
  }

cleanup_bpf:
  bpf_loader_cleanup(&g_bpf_ctx);
cleanup_tpm:
  tpm_cleanup(&g_tpm_ctx);
  dbus_cleanup(g_dbus_ctx);
  ipc_cleanup(&g_ipc_ctx);
cleanup_epoll:
  hash_verify_cleanup(&g_hash_ctx);
  close(sfd);
  close(epoll_fd);
  return ret;
}

int main(int argc, char *argv[]) {
  int opt;
  int test_tpm_flag = 0;
  int test_iommu_flag = 0;
  int test_ipc_flag = 0;
  int test_signed_flag = 0;

  if (daemon_install_signals(&g_running, &g_reload) < 0) {
    fprintf(stderr, "Failed to install signal handlers: %s\n", strerror(errno));
    return 1;
  }

  int export_policy_flag = 0;
  int attest_flag = 0;
  const char *gen_signing_key_prefix = NULL;
  const char *sign_policy_file = NULL;
  const char *verify_policy_file = NULL;
  const char *signing_key_path = NULL;
  const char *policy_pubkey_path = NULL;
  int attest_interval = 0; /* 0 = one-shot, >0 = continuous */
  uint32_t aik_ttl = DEFAULT_AIK_TTL;
  int mode = LOTA_MODE_MONITOR;
  bool strict_mmap = false;
  bool block_ptrace = false;
  bool strict_modules = false;
  bool block_anon_exec = false;
  int daemon_flag = 0;
  const char *pid_file_path = NULL;
  int pid_fd = -1;
  const char *bpf_path = DEFAULT_BPF_PATH;
  const char *server_addr = "localhost";
  int server_port = DEFAULT_VERIFIER_PORT;
  const char *ca_cert_path = NULL;
  int no_verify_tls = 0;
  const char *pin_sha256_hex = NULL;
  uint8_t pin_sha256_bin[NET_PIN_SHA256_LEN];
  int has_pin = 0;
  static struct lota_config cfg;
  const char *config_path = NULL;
  int dump_config_flag = 0;

  static struct option long_options[] = {
      {"config", required_argument, 0, 'f'},
      {"dump-config", no_argument, 0, 'Z'},
      {"test-tpm", no_argument, 0, 't'},
      {"test-iommu", no_argument, 0, 'i'},
      {"test-ipc", no_argument, 0, 'c'},
      {"test-signed", no_argument, 0, 'S'},
      {"export-policy", no_argument, 0, 'E'},
      {"attest", no_argument, 0, 'a'},
      {"attest-interval", required_argument, 0, 'I'},
      {"server", required_argument, 0, 's'},
      {"port", required_argument, 0, 'p'},
      {"ca-cert", required_argument, 0, 'C'},
      {"no-verify-tls", no_argument, 0, 'K'},
      {"pin-sha256", required_argument, 0, 'F'},
      {"bpf", required_argument, 0, 'b'},
      {"mode", required_argument, 0, 'm'},
      {"strict-mmap", no_argument, 0, 'M'},
      {"block-ptrace", no_argument, 0, 'P'},
      {"strict-modules", no_argument, 0, 'J'},
      {"block-anon-exec", no_argument, 0, 'X'},
      {"protect-pid", required_argument, 0, 'R'},
      {"trust-lib", required_argument, 0, 'L'},
      {"daemon", no_argument, 0, 'd'},
      {"pid-file", required_argument, 0, 'D'},
      {"aik-ttl", required_argument, 0, 'T'},
      {"gen-signing-key", required_argument, 0, 'G'},
      {"sign-policy", required_argument, 0, 'g'},
      {"verify-policy", required_argument, 0, 'V'},
      {"signing-key", required_argument, 0, 'k'},
      {"policy-pubkey", required_argument, 0, 'Q'},
      {"no-hash-cache", no_argument, 0, 'H'},
      {"help", no_argument, 0, 'h'},
      {0, 0, 0, 0}};

  config_init(&cfg);

  journal_init("lota-agent");

  for (int i = 1; i < argc; i++) {
    if ((strcmp(argv[i], "--config") == 0 || strcmp(argv[i], "-f") == 0) &&
        i + 1 < argc) {
      config_path = argv[++i];
    }
  }

  {
    int cfg_ret = config_load(&cfg, config_path);
    if (cfg_ret == -ENOENT && !config_path) {
      /* default config file does not exist -> not an error */
    } else if (cfg_ret == -ENOENT) {
      fprintf(stderr, "Config file not found: %s\n", config_path);
      return 1;
    } else if (cfg_ret < 0) {
      fprintf(stderr, "Failed to load config %s: %s\n",
              config_path ? config_path : LOTA_CONFIG_DEFAULT_PATH,
              strerror(-cfg_ret));
      return 1;
    }
  }

  server_addr = cfg.server;
  server_port = cfg.port;
  ca_cert_path = cfg.ca_cert[0] ? cfg.ca_cert : NULL;
  pin_sha256_hex = cfg.pin_sha256[0] ? cfg.pin_sha256 : NULL;
  bpf_path = cfg.bpf_path;
  {
    int cfg_mode = parse_mode(cfg.mode);
    if (cfg_mode >= 0)
      mode = cfg_mode;
  }
  strict_mmap = cfg.strict_mmap;
  block_ptrace = cfg.block_ptrace;
  strict_modules = cfg.strict_modules;
  block_anon_exec = cfg.block_anon_exec;
  attest_interval = cfg.attest_interval;
  aik_ttl = cfg.aik_ttl;
  g_tpm_ctx.aik_handle = cfg.aik_handle;
  daemon_flag = cfg.daemon ? 1 : 0;
  pid_file_path = cfg.pid_file;
  signing_key_path = cfg.signing_key[0] ? cfg.signing_key : NULL;
  policy_pubkey_path = cfg.policy_pubkey[0] ? cfg.policy_pubkey : NULL;

  g_protect_pid_count = 0;
  if (cfg.protect_pid_count > 0) {
    uint32_t *new_pids =
        realloc(g_protect_pids, cfg.protect_pid_count * sizeof(uint32_t));
    if (!new_pids) {
      fprintf(stderr, "Memory allocation failed while loading protected PIDs "
                      "from config\n");
      return 1;
    }
    g_protect_pids = new_pids;
    for (int i = 0; i < cfg.protect_pid_count; i++)
      g_protect_pids[i] = cfg.protect_pids[i];
    g_protect_pid_count = cfg.protect_pid_count;
  }
  g_trust_lib_count = cfg.trust_lib_count;
  for (int i = 0; i < cfg.trust_lib_count; i++)
    snprintf(g_trust_libs[i], sizeof(g_trust_libs[i]), "%s", cfg.trust_libs[i]);

  while ((opt = getopt_long(argc, argv,
                            "f:ZticSEaI:s:p:C:KF:b:m:MPJXR:L:dD:T:G:g:V:k:Q:Hh",
                            long_options, NULL)) != -1) {
    switch (opt) {
    case 't':
      test_tpm_flag = 1;
      break;
    case 'i':
      test_iommu_flag = 1;
      break;
    case 'c':
      test_ipc_flag = 1;
      break;
    case 'S':
      test_signed_flag = 1;
      break;
    case 'E':
      export_policy_flag = 1;
      break;
    case 'a':
      attest_flag = 1;
      break;
    case 'I':
      attest_flag = 1;
      {
        long v;
        if (safe_parse_long(optarg, &v) < 0 || v < 0 || v > INT_MAX) {
          fprintf(stderr, "Invalid interval: %s\n", optarg);
          return 1;
        }
        attest_interval = (int)v;
      }
      if (attest_interval != 0 && attest_interval < MIN_ATTEST_INTERVAL) {
        fprintf(stderr,
                "Warning: interval %d too low, using minimum %d seconds\n",
                attest_interval, MIN_ATTEST_INTERVAL);
        attest_interval = MIN_ATTEST_INTERVAL;
      }
      break;
    case 's':
      server_addr = optarg;
      break;
    case 'p': {
      long v;
      if (safe_parse_long(optarg, &v) < 0 || v <= 0 || v > 65535) {
        fprintf(stderr, "Invalid port: %s\n", optarg);
        return 1;
      }
      server_port = (int)v;
    } break;
    case 'C':
      ca_cert_path = optarg;
      break;
    case 'K':
      no_verify_tls = 1;
      break;
    case 'F':
      pin_sha256_hex = optarg;
      break;
    case 'b':
      bpf_path = optarg;
      break;
    case 'm':
      mode = parse_mode(optarg);
      if (mode < 0) {
        fprintf(stderr, "Invalid mode: %s\n", optarg);
        fprintf(stderr, "Valid modes: monitor, enforce, maintenance\n");
        return 1;
      }
      break;
    case 'M':
      strict_mmap = true;
      break;
    case 'P':
      block_ptrace = true;
      break;
    case 'J':
      strict_modules = true;
      break;
    case 'X':
      block_anon_exec = true;
      break;
    case 'R': {
      long v;
      if (safe_parse_long(optarg, &v) < 0 || v <= 0 || v > UINT32_MAX) {
        fprintf(stderr, "Invalid PID: %s\n", optarg);
        return 1;
      }
      if (g_protect_pid_count >= LOTA_MAX_PROTECTED_PIDS) {
        fprintf(stderr, "Too many --protect-pid entries (max %d)\n",
                LOTA_MAX_PROTECTED_PIDS);
        return 1;
      }
      uint32_t *new_pids =
          realloc(g_protect_pids, (g_protect_pid_count + 1) * sizeof(uint32_t));
      if (!new_pids) {
        fprintf(stderr, "Memory allocation failed for protected PID\n");
        return 1;
      }
      g_protect_pids = new_pids;
      g_protect_pids[g_protect_pid_count++] = (uint32_t)v;
    } break;
    case 'L':
      if (g_trust_lib_count < LOTA_CONFIG_MAX_LIBS) {
        snprintf(g_trust_libs[g_trust_lib_count],
                 sizeof(g_trust_libs[g_trust_lib_count]), "%s", optarg);
        g_trust_lib_count++;
      } else {
        fprintf(stderr, "Too many --trust-lib entries (max %d)\n",
                LOTA_CONFIG_MAX_LIBS);
        return 1;
      }
      break;
    case 'd':
      daemon_flag = 1;
      break;
    case 'D':
      pid_file_path = optarg;
      break;
    case 'T': {
      long v;
      if (safe_parse_long(optarg, &v) < 0 || v < 0 || v > UINT32_MAX) {
        fprintf(stderr, "Invalid AIK TTL: %s\n", optarg);
        return 1;
      }
      aik_ttl = (uint32_t)v;
    }
      if (aik_ttl > 0 && aik_ttl < 3600) {
        fprintf(stderr, "Warning: AIK TTL %u too low, using 3600s (1 hour)\n",
                aik_ttl);
        aik_ttl = 3600;
      }
      break;
    case 'G':
      gen_signing_key_prefix = optarg;
      break;
    case 'g':
      sign_policy_file = optarg;
      break;
    case 'V':
      verify_policy_file = optarg;
      break;
    case 'k':
      signing_key_path = optarg;
      break;
    case 'Q':
      policy_pubkey_path = optarg;
      break;
    case 'H':
      g_no_hash_cache = 1;
      break;
    case 'f':
      /* --config: handled in pre-scan above */
      break;
    case 'Z':
      dump_config_flag = 1;
      break;
    case 'h':
    default:
      print_usage(argv[0], DEFAULT_BPF_PATH, DEFAULT_VERIFIER_PORT);
      return (opt == 'h') ? 0 : 1;
    }
  }

  if (dump_config_flag) {
    if (server_addr != cfg.server)
      snprintf(cfg.server, sizeof(cfg.server), "%s", server_addr);
    cfg.port = server_port;
    if (ca_cert_path) {
      if (ca_cert_path != cfg.ca_cert)
        snprintf(cfg.ca_cert, sizeof(cfg.ca_cert), "%s", ca_cert_path);
    } else {
      cfg.ca_cert[0] = '\0';
    }
    if (pin_sha256_hex) {
      if (pin_sha256_hex != cfg.pin_sha256)
        snprintf(cfg.pin_sha256, sizeof(cfg.pin_sha256), "%s", pin_sha256_hex);
    } else {
      cfg.pin_sha256[0] = '\0';
    }

    if (bpf_path != cfg.bpf_path)
      snprintf(cfg.bpf_path, sizeof(cfg.bpf_path), "%s", bpf_path);
    if (mode == LOTA_MODE_ENFORCE)
      snprintf(cfg.mode, sizeof(cfg.mode), "enforce");
    else if (mode == LOTA_MODE_MAINTENANCE)
      snprintf(cfg.mode, sizeof(cfg.mode), "maintenance");
    else
      snprintf(cfg.mode, sizeof(cfg.mode), "monitor");

    cfg.strict_mmap = strict_mmap;
    cfg.block_ptrace = block_ptrace;
    cfg.strict_modules = strict_modules;
    cfg.block_anon_exec = block_anon_exec;
    cfg.attest_interval = attest_interval;
    cfg.aik_ttl = aik_ttl;
    cfg.aik_handle = g_tpm_ctx.aik_handle;
    cfg.daemon = daemon_flag ? true : false;
    if (pid_file_path != cfg.pid_file)
      snprintf(cfg.pid_file, sizeof(cfg.pid_file), "%s", pid_file_path);

    if (signing_key_path) {
      if (signing_key_path != cfg.signing_key)
        snprintf(cfg.signing_key, sizeof(cfg.signing_key), "%s",
                 signing_key_path);
    } else {
      cfg.signing_key[0] = '\0';
    }

    if (policy_pubkey_path) {
      if (policy_pubkey_path != cfg.policy_pubkey)
        snprintf(cfg.policy_pubkey, sizeof(cfg.policy_pubkey), "%s",
                 policy_pubkey_path);
    } else {
      cfg.policy_pubkey[0] = '\0';
    }

    cfg.trust_lib_count = g_trust_lib_count;
    for (int i = 0; i < g_trust_lib_count; i++) {
      snprintf(cfg.trust_libs[i], sizeof(cfg.trust_libs[i]), "%s",
               g_trust_libs[i]);
    }

    free(cfg.protect_pids);
    cfg.protect_pids = NULL;
    cfg.protect_pid_count = 0;
    if (g_protect_pid_count > 0) {
      cfg.protect_pids = malloc(g_protect_pid_count * sizeof(uint32_t));
      if (!cfg.protect_pids) {
        fprintf(
            stderr,
            "Warning: failed to allocate protect_pid list for dump-config\n");
      } else {
        memcpy(cfg.protect_pids, g_protect_pids,
               g_protect_pid_count * sizeof(uint32_t));
        cfg.protect_pid_count = g_protect_pid_count;
      }
    }

    config_dump(&cfg, stdout);
    return 0;
  }

  /* parse certificate pin if provided */
  if (pin_sha256_hex) {
    if (net_parse_pin_sha256(pin_sha256_hex, pin_sha256_bin) < 0) {
      fprintf(stderr,
              "Invalid --pin-sha256 value: '%s'\n"
              "Expected 64 hex characters (colons/spaces allowed).\n"
              "Example: openssl x509 -in cert.pem "
              "-fingerprint -sha256 -noout\n",
              pin_sha256_hex);
      return 1;
    }
    has_pin = 1;
    if (no_verify_tls) {
      fprintf(stderr,
              "Warning: --pin-sha256 with --no-verify-tls: PKI validation\n"
              "is disabled but certificate pinning remains active.\n");
    }
  }

  /* policy signing operations */
  {
    int ret = handle_policy_ops(gen_signing_key_prefix, sign_policy_file,
                                verify_policy_file, signing_key_path,
                                policy_pubkey_path);
    if (ret != -1)
      return ret;
  }

  if (test_tpm_flag)
    return test_tpm();

  if (test_iommu_flag)
    return test_iommu();

  if (export_policy_flag)
    return export_policy(mode);

  if (test_ipc_flag)
    return run_ipc_test_server();

  if (test_signed_flag)
    return run_signed_ipc_test_server();

  if (attest_flag) {
    if (no_verify_tls && ca_cert_path) {
      fprintf(stderr,
              "Warning: --ca-cert ignored when --no-verify-tls is set\n");
    }
    if (attest_interval > 0)
      return do_continuous_attest(
          server_addr, server_port, ca_cert_path, no_verify_tls,
          has_pin ? pin_sha256_bin : NULL, attest_interval, aik_ttl);
    else
      return do_attest(server_addr, server_port, ca_cert_path, no_verify_tls,
                       has_pin ? pin_sha256_bin : NULL);
  }

  if (daemon_flag) {
    int dret = daemonize();
    if (dret < 0) {
      fprintf(stderr, "Failed to daemonize: %s\n", strerror(-dret));
      return 1;
    }
  }

  pid_fd = pidfile_create(pid_file_path);
  if (pid_fd == -EEXIST) {
    fprintf(stderr, "Another instance is already running (PID file locked)\n");
    return 1;
  }
  if (pid_fd < 0) {
    fprintf(stderr, "Warning: Failed to create PID file: %s\n",
            strerror(-pid_fd));
    /* non-fatal: continue without PID file */
    pid_fd = -1;
  }

  {
    int ret = run_daemon(bpf_path, mode, strict_mmap, block_ptrace,
                         strict_modules, block_anon_exec, config_path, &cfg);
    pidfile_remove(pid_file_path, pid_fd);
    return ret;
  }
}
