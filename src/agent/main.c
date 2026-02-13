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
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
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
#include "net.h"
#include "policy.h"
#include "policy_sign.h"
#include "quote.h"
#include "sdnotify.h"
#include "selftest.h"
#include "steam_runtime.h"
#include "tpm.h"

#ifndef EAUTH
#define EAUTH 80
#endif

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
static uint32_t g_protect_pids[64];
static int g_protect_pid_count;
static const char *g_trust_libs[64];
static int g_trust_lib_count;

static const char *mode_to_string(int mode);
static int parse_mode(const char *mode_str);

/*
 * Set up a container-accessible extra listener socket.
 *
 * Failures are non-fatal: the primary socket still works for
 * host-side clients.
 */
void setup_container_listener(struct ipc_context *ctx) {
  char dir[PATH_MAX];
  char path[PATH_MAX];
  struct steam_runtime_info rt_info;
  int ret;

  ret = steam_runtime_container_socket_dir(dir, sizeof(dir));
  if (ret < 0)
    return; /* XDG_RUNTIME_DIR not set, nothing to do */

  ret = steam_runtime_container_socket_path(path, sizeof(path));
  if (ret < 0)
    return;

  if (strcmp(path, LOTA_IPC_SOCKET_PATH) == 0)
    return;

  ret = steam_runtime_ensure_socket_dir(dir);
  if (ret < 0) {
    fprintf(stderr, "Warning: cannot create container socket dir %s: %s\n", dir,
            strerror(-ret));
    return;
  }

  ret = ipc_add_listener(ctx, path);
  if (ret < 0) {
    fprintf(stderr, "Warning: container listener %s: %s\n", path,
            strerror(-ret));
    return;
  }

  /* log detected Steam Runtime environment */
  ret = steam_runtime_detect(&rt_info);
  if (ret == 0 && (rt_info.env_flags & STEAM_ENV_STEAM_ACTIVE))
    steam_runtime_log_info(&rt_info);
}

/*
 * Set up D-Bus interface on the system bus.
 *
 * Non-fatal: if D-Bus is unavailable the agent continues with Unix socket IPC
 * only.
 */
void setup_dbus(struct ipc_context *ctx) {
  g_dbus_ctx = dbus_init(ctx);
  if (g_dbus_ctx)
    ipc_set_dbus(ctx, g_dbus_ctx);
  else
    lota_warn("D-Bus unavailable, using socket IPC only");
}

/*
 * Initialize IPC, preferring a systemd socket-activated fd.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int ipc_init_or_activate(struct ipc_context *ctx) {
  int n, fd, ret;

  n = sdnotify_listen_fds();
  if (n > 0) {
    for (fd = SD_LISTEN_FDS_START; fd < SD_LISTEN_FDS_START + n; fd++) {
      if (sdnotify_is_unix_socket(fd)) {
        lota_info("Using socket-activated fd %d", fd);
        ret = ipc_init_activated(ctx, fd);
        if (ret == 0)
          return 0;
        lota_warn("Failed to use activated fd %d: %s", fd, strerror(-ret));
      }
    }
    lota_warn("No suitable activated socket, creating own");
  }

  return ipc_init(ctx);
}

/*
 * Self-measurement: hash own binary and extend into PCR 14.
 * This provides tamper evidence - if agent is modified, attestation fails.
 *
 * Returns: 0 on success, negative errno on failure
 */
int self_measure(struct tpm_context *ctx) {
  char exe_path[LOTA_MAX_PATH_LEN];
  uint8_t self_hash[LOTA_HASH_SIZE];
  ssize_t len;
  int ret;

  if (!ctx || !ctx->initialized)
    return -EINVAL;

  /*
   * Get path to own executable via /proc/self/exe.
   * This symlink points to the actual binary on disk.
   */
  len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
  if (len < 0) {
    return -errno;
  }
  exe_path[len] = '\0';

  /*
   * Hash the binary using SHA-256.
   * This captures the complete executable state.
   */
  ret = tpm_hash_file(exe_path, self_hash);
  if (ret < 0) {
    return ret;
  }

  /*
   * Extend hash into PCR 14.
   * PCR 14 is in the range (8-15) typically reserved for OS use.
   */
  ret = tpm_pcr_extend(ctx, LOTA_PCR_SELF, self_hash);
  if (ret < 0) {
    return ret;
  }

  return 0;
}

/*
 * Main daemon loop
 */
static const char *mode_to_string(int mode) {
  switch (mode) {
  case LOTA_MODE_MAINTENANCE:
    return "MAINTENANCE";
  case LOTA_MODE_MONITOR:
    return "MONITOR";
  case LOTA_MODE_ENFORCE:
    return "ENFORCE";
  default:
    return "UNKNOWN";
  }
}

static int run_daemon(const char *bpf_path, int mode, bool strict_mmap,
                      bool block_ptrace, const char *config_path,
                      struct lota_config *cfg) {
  int ret;
  uint32_t status_flags = 0;
  uint64_t wd_usec = 0;
  bool wd_enabled;

  lota_info("LOTA agent starting");

  /* detect watchdog interval */
  wd_enabled = sdnotify_watchdog_enabled(&wd_usec);
  if (wd_enabled)
    lota_info("Watchdog enabled, interval %lu us", (unsigned long)wd_usec);

  ret = hash_verify_init(&g_hash_ctx, 0);
  if (ret < 0) {
    lota_err("Failed to initialize hash cache: %s", strerror(-ret));
    return ret;
  }
  lota_info("Hash verification cache ready");

  lota_info("Starting IPC server");
  ret = ipc_init_or_activate(&g_ipc_ctx);
  if (ret < 0) {
    lota_err("Failed to initialize IPC: %s", strerror(-ret));
    lota_warn("Continuing without IPC support");
  } else {
    ipc_set_mode(&g_ipc_ctx, (uint8_t)mode);
    setup_container_listener(&g_ipc_ctx);
    setup_dbus(&g_ipc_ctx);
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
    lota_warn("Continuing without TPM support");
  } else {
    lota_info("TPM initialized");
    status_flags |= LOTA_STATUS_TPM_OK;

    lota_info("Provisioning AIK");
    ret = tpm_provision_aik(&g_tpm_ctx);
    if (ret < 0) {
      lota_warn("AIK provisioning failed: %s", strerror(-ret));
      lota_warn("Signed tokens will not be available");
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
      lota_warn("Continuing without self-measurement");
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

  ret = bpf_loader_set_mode(&g_bpf_ctx, mode);
  if (ret < 0) {
    lota_warn("Failed to set mode: %s", strerror(-ret));
  } else {
    lota_info("Mode: %s", mode_to_string(mode));
  }
  g_mode = mode;
  if (mode == LOTA_MODE_ENFORCE) {
    lota_notice("ENFORCE mode active - module loading BLOCKED");
  }

  /* apply runtime config flags */
  if (strict_mmap) {
    ret = bpf_loader_set_config(&g_bpf_ctx, LOTA_CFG_STRICT_MMAP, 1);
    if (ret < 0)
      lota_warn("Failed to enable strict mmap: %s", strerror(-ret));
    else
      lota_info("Strict mmap enforcement: ON");
  }

  if (block_ptrace) {
    ret = bpf_loader_set_config(&g_bpf_ctx, LOTA_CFG_BLOCK_PTRACE, 1);
    if (ret < 0)
      lota_warn("Failed to enable ptrace blocking: %s", strerror(-ret));
    else
      lota_info("Global ptrace blocking: ON");
  }

  /* apply protected PIDs from CLI */
  for (int i = 0; i < g_protect_pid_count; i++) {
    ret = bpf_loader_protect_pid(&g_bpf_ctx, g_protect_pids[i]);
    if (ret < 0) {
      lota_warn("Failed to protect PID %u: %s", g_protect_pids[i],
                strerror(-ret));
    } else {
      lota_dbg("Protected PID: %u", g_protect_pids[i]);
    }
  }

  /* apply trusted libraries from CLI */
  for (int i = 0; i < g_trust_lib_count; i++) {
    ret = bpf_loader_trust_lib(&g_bpf_ctx, g_trust_libs[i]);
    if (ret < 0) {
      lota_warn("Failed to trust lib %s: %s", g_trust_libs[i], strerror(-ret));
    } else {
      lota_dbg("Trusted lib: %s", g_trust_libs[i]);
    }
  }

  ret = bpf_loader_setup_ringbuf(&g_bpf_ctx, handle_exec_event, NULL);
  if (ret < 0) {
    lota_err("Failed to setup ring buffer: %s", strerror(-ret));
    goto cleanup_bpf;
  }
  lota_info("Ring buffer ready");

  ipc_update_status(&g_ipc_ctx, status_flags, 0);

  sdnotify_ready();
  sdnotify_status("Monitoring, mode=%s", mode_to_string(mode));
  lota_info("Monitoring binary executions");

  /* main loop */
  while (g_running) {
    if (g_reload) {
      g_reload = 0;
      sdnotify_reloading();
      lota_info("SIGHUP received, reloading configuration");

      struct lota_config new_cfg;
      config_init(&new_cfg);
      int reload_ret = config_load(&new_cfg, config_path);
      if (reload_ret < 0 && reload_ret != -ENOENT) {
        lota_err("Failed to reload config: %s", strerror(-reload_ret));
        sdnotify_ready();
      } else {
        int new_mode = parse_mode(new_cfg.mode);
        if (new_mode >= 0 && new_mode != mode) {
          if (bpf_loader_set_mode(&g_bpf_ctx, new_mode) == 0) {
            lota_info("Mode changed: %s -> %s", mode_to_string(mode),
                      mode_to_string(new_mode));
            mode = new_mode;
            g_mode = new_mode;
          } else {
            lota_warn("Failed to apply new mode");
          }
        }

        if (new_cfg.strict_mmap != strict_mmap) {
          bpf_loader_set_config(&g_bpf_ctx, LOTA_CFG_STRICT_MMAP,
                                new_cfg.strict_mmap ? 1 : 0);
          strict_mmap = new_cfg.strict_mmap;
          lota_info("Strict mmap: %s", strict_mmap ? "ON" : "OFF");
        }

        if (new_cfg.block_ptrace != block_ptrace) {
          bpf_loader_set_config(&g_bpf_ctx, LOTA_CFG_BLOCK_PTRACE,
                                new_cfg.block_ptrace ? 1 : 0);
          block_ptrace = new_cfg.block_ptrace;
          lota_info("Block ptrace: %s", block_ptrace ? "ON" : "OFF");
        }

        if (new_cfg.log_level[0] &&
            strcmp(new_cfg.log_level, cfg->log_level) != 0) {
          int lvl = LOG_DEBUG;
          if (strcmp(new_cfg.log_level, "error") == 0)
            lvl = LOG_ERR;
          else if (strcmp(new_cfg.log_level, "warn") == 0)
            lvl = LOG_WARNING;
          else if (strcmp(new_cfg.log_level, "info") == 0)
            lvl = LOG_INFO;
          journal_set_level(lvl);
          lota_info("Log level changed to %s", new_cfg.log_level);
        }

        *cfg = new_cfg;
        sdnotify_ready();
        sdnotify_status("Monitoring, mode=%s", mode_to_string(mode));
        lota_info("Configuration reloaded");
      }
    }

    /* non-blocking */
    ipc_process(&g_ipc_ctx, 0);
    dbus_process(g_dbus_ctx, 0);

    if (wd_enabled)
      sdnotify_watchdog_ping();

    ret = bpf_loader_poll(&g_bpf_ctx, 100); /* 100ms timeout */
    if (ret < 0 && ret != -EINTR) {
      lota_err("Poll error: %s", strerror(-ret));
      break;
    }
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
    printf("\n=== Statistics ===\n");
    printf("Total executions: %lu\n", total);
    printf("Events sent: %lu\n", sent);
    printf("Errors: %lu\n", errs);
    printf("Ring buffer drops: %lu\n", drops);
    printf("Modules blocked: %lu\n", mblocked);
    printf("Executable mmaps: %lu\n", mmexec);
    printf("Mmaps blocked: %lu\n", mmblock);
    printf("Ptrace attempts: %lu\n", ptratt);
    printf("Ptrace blocked: %lu\n", ptrblk);
    printf("Setuid transitions: %lu\n", setuid_ev);
  }

  {
    uint64_t h_hits, h_misses, h_errors;
    hash_verify_stats(&g_hash_ctx, &h_hits, &h_misses, &h_errors);
    printf("Hash cache hits: %lu\n", h_hits);
    printf("Hash cache misses: %lu\n", h_misses);
    printf("Hash errors: %lu\n", h_errors);
  }

cleanup_bpf:
  bpf_loader_cleanup(&g_bpf_ctx);
cleanup_tpm:
  tpm_cleanup(&g_tpm_ctx);
  dbus_cleanup(g_dbus_ctx);
  ipc_cleanup(&g_ipc_ctx);
  hash_verify_cleanup(&g_hash_ctx);
  return ret;
}

static void print_usage(const char *prog) {
  printf("Usage: %s [options]\n", prog);
  printf("\n");
  printf("Options:\n");
  printf("  --config PATH     Configuration file path\n");
  printf("                    (default: %s)\n", LOTA_CONFIG_DEFAULT_PATH);
  printf("  --dump-config     Print loaded configuration and exit\n");
  printf("  --test-tpm        Test TPM operations and exit\n");
  printf("  --test-iommu      Test IOMMU verification and exit\n");
  printf("  --test-ipc        Run IPC server with simulated attested state\n");
  printf("                    (unsigned tokens, for protocol testing)\n");
  printf("  --test-signed     Run IPC server with TPM-signed tokens\n");
  printf(
      "                    (requires TPM, for token verification testing)\n");
  printf("  --export-policy   Export complete YAML policy from live system\n");
  printf("                    (verifier-ready, pipe to file)\n");
  printf("  --attest          Perform remote attestation and exit\n");
  printf("  --attest-interval SECS\n");
  printf("                    Continuous attestation interval in seconds\n");
  printf("                    (default: 0=one-shot, min: %d for continuous)\n",
         MIN_ATTEST_INTERVAL);
  printf("  --server HOST     Verifier server address (default: localhost)\n");
  printf("  --port PORT       Verifier server port (default: %d)\n",
         DEFAULT_VERIFIER_PORT);
  printf("  --ca-cert PATH    CA certificate for verifier TLS verification\n");
  printf("                    (default: use system CA store)\n");
  printf(
      "  --no-verify-tls   Disable TLS certificate verification (INSECURE)\n");
  printf("                    Only for development/testing!\n");
  printf("  --pin-sha256 HEX  Pin verifier certificate by SHA-256 "
         "fingerprint\n");
  printf("                    (64 hex chars, colons/spaces allowed)\n");
  printf("  --bpf PATH        Path to BPF object file\n");
  printf("                    (default: %s)\n", DEFAULT_BPF_PATH);
  printf("  --mode MODE       Set enforcement mode:\n");
  printf("                      monitor     - log events only (default)\n");
  printf("                      enforce     - block unauthorized modules\n");
  printf("                      maintenance - allow all, minimal logging\n");
  printf("  --strict-mmap     Block mmap(PROT_EXEC) of untrusted libraries\n");
  printf("                    (requires --mode enforce)\n");
  printf("  --block-ptrace    Block all ptrace attach attempts\n");
  printf("                    (requires --mode enforce)\n");
  printf("  --protect-pid PID Add PID to protected set (ptrace blocked)\n");
  printf("  --trust-lib PATH  Add library path to trusted whitelist\n");
  printf("  --daemon          Fork to background (not needed under systemd)\n");
  printf("  --pid-file PATH   PID file location\n");
  printf("                    (default: %s)\n", DAEMON_DEFAULT_PID_FILE);
  printf("  --aik-ttl SECS    AIK key lifetime in seconds before rotation\n");
  printf("                    (default: 30 days, min: 3600)\n");
  printf("\nPolicy signing:\n");
  printf("  --gen-signing-key PREFIX\n");
  printf("                    Generate Ed25519 keypair: PREFIX.key + "
         "PREFIX.pub\n");
  printf("  --sign-policy FILE --signing-key KEY\n");
  printf("                    Sign policy YAML, write detached FILE.sig\n");
  printf("  --verify-policy FILE --policy-pubkey PUB\n");
  printf("                    Verify detached Ed25519 signature on FILE\n");
  printf("  --signing-key PATH   Ed25519 private key (PEM) for signing\n");
  printf("  --policy-pubkey PATH Ed25519 public key (PEM) for verification\n");
  printf("\n");
  printf("  --help            Show this help\n");
}

static int parse_mode(const char *mode_str) {
  if (strcmp(mode_str, "monitor") == 0)
    return LOTA_MODE_MONITOR;
  if (strcmp(mode_str, "enforce") == 0)
    return LOTA_MODE_ENFORCE;
  if (strcmp(mode_str, "maintenance") == 0)
    return LOTA_MODE_MAINTENANCE;
  return -1;
}

int main(int argc, char *argv[]) {
  int opt;
  int test_tpm_flag = 0;
  int test_iommu_flag = 0;
  int test_ipc_flag = 0;
  int test_signed_flag = 0;
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
  struct lota_config cfg;
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
      {"help", no_argument, 0, 'h'},
      {0, 0, 0, 0}};

  config_init(&cfg);

  journal_init("lota-agent");

  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
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
  no_verify_tls = cfg.no_verify_tls ? 1 : 0;
  pin_sha256_hex = cfg.pin_sha256[0] ? cfg.pin_sha256 : NULL;
  bpf_path = cfg.bpf_path;
  {
    int cfg_mode = parse_mode(cfg.mode);
    if (cfg_mode >= 0)
      mode = cfg_mode;
  }
  strict_mmap = cfg.strict_mmap;
  block_ptrace = cfg.block_ptrace;
  attest_interval = cfg.attest_interval;
  aik_ttl = cfg.aik_ttl;
  g_tpm_ctx.aik_handle = cfg.aik_handle;
  daemon_flag = cfg.daemon ? 1 : 0;
  pid_file_path = cfg.pid_file;
  signing_key_path = cfg.signing_key[0] ? cfg.signing_key : NULL;
  policy_pubkey_path = cfg.policy_pubkey[0] ? cfg.policy_pubkey : NULL;

  g_protect_pid_count = cfg.protect_pid_count;
  for (int i = 0; i < cfg.protect_pid_count; i++)
    g_protect_pids[i] = cfg.protect_pids[i];
  g_trust_lib_count = cfg.trust_lib_count;
  for (int i = 0; i < cfg.trust_lib_count; i++)
    g_trust_libs[i] = cfg.trust_libs[i];

  while ((opt = getopt_long(argc, argv,
                            "f:ZticSEaI:s:p:C:KF:b:m:MPR:L:dD:T:G:g:V:k:Q:h",
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
    case 'R':
      if (g_protect_pid_count < 64) {
        long v;
        if (safe_parse_long(optarg, &v) < 0 || v <= 0 || v > UINT32_MAX) {
          fprintf(stderr, "Invalid PID: %s\n", optarg);
          return 1;
        }
        g_protect_pids[g_protect_pid_count++] = (uint32_t)v;
      } else {
        fprintf(stderr, "Too many --protect-pid entries (max 64)\n");
      }
      break;
    case 'L':
      if (g_trust_lib_count < 64) {
        g_trust_libs[g_trust_lib_count++] = optarg;
      } else {
        fprintf(stderr, "Too many --trust-lib entries (max 64)\n");
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
    case 'f':
      /* --config: handled in pre-scan above */
      break;
    case 'Z':
      dump_config_flag = 1;
      break;
    case 'h':
    default:
      print_usage(argv[0]);
      return (opt == 'h') ? 0 : 1;
    }
  }

  if (dump_config_flag) {
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

  /* signal handlers: SIGTERM/SIGINT -> shutdown, SIGHUP -> reload */
  {
    int sig_ret = daemon_install_signals(&g_running, &g_reload);
    if (sig_ret < 0) {
      fprintf(stderr, "Failed to install signal handlers: %s\n",
              strerror(-sig_ret));
      return 1;
    }
  }

  /* policy signing operations */
  if (gen_signing_key_prefix) {
    char priv_path[PATH_MAX];
    char pub_path[PATH_MAX];
    int ret;

    snprintf(priv_path, sizeof(priv_path), "%s.key", gen_signing_key_prefix);
    snprintf(pub_path, sizeof(pub_path), "%s.pub", gen_signing_key_prefix);

    ret = policy_sign_generate_keypair(priv_path, pub_path);
    if (ret < 0) {
      fprintf(stderr, "Failed to generate keypair: %s\n", strerror(-ret));
      return 1;
    }
    printf("Generated Ed25519 keypair:\n");
    printf("  Private key: %s\n", priv_path);
    printf("  Public key:  %s\n", pub_path);
    return 0;
  }

  if (sign_policy_file) {
    char sig_path[PATH_MAX];
    int ret;

    if (!signing_key_path) {
      fprintf(stderr, "--sign-policy requires --signing-key\n");
      return 1;
    }

    snprintf(sig_path, sizeof(sig_path), "%s.sig", sign_policy_file);

    ret = policy_sign_file(sign_policy_file, signing_key_path, sig_path);
    if (ret < 0) {
      fprintf(stderr, "Failed to sign policy: %s\n", strerror(-ret));
      return 1;
    }
    printf("Signed: %s\n", sign_policy_file);
    printf("Signature: %s\n", sig_path);
    return 0;
  }

  if (verify_policy_file) {
    char sig_path[PATH_MAX];
    int ret;

    if (!policy_pubkey_path) {
      fprintf(stderr, "--verify-policy requires --policy-pubkey\n");
      return 1;
    }

    snprintf(sig_path, sizeof(sig_path), "%s.sig", verify_policy_file);

    ret = policy_verify_file(verify_policy_file, policy_pubkey_path, sig_path);
    if (ret == 0) {
      printf("Signature valid: %s\n", verify_policy_file);
      return 0;
    } else if (ret == -EAUTH) {
      fprintf(stderr, "Signature INVALID: %s\n", verify_policy_file);
      return 1;
    } else {
      fprintf(stderr, "Verification failed: %s\n", strerror(-ret));
      return 1;
    }
  }

  if (test_tpm_flag)
    return test_tpm();

  if (test_iommu_flag)
    return test_iommu();

  if (export_policy_flag)
    return export_policy();

  if (test_ipc_flag) {
    int ret;
    uint64_t valid_until;
    printf("=== IPC Test Server (Unsigned) ===\n\n");
    printf("Starting IPC server for testing...\n");
    ret = ipc_init_or_activate(&g_ipc_ctx);
    if (ret < 0) {
      fprintf(stderr, "Failed to initialize IPC: %s\n", strerror(-ret));
      return 1;
    }
    setup_container_listener(&g_ipc_ctx);
    setup_dbus(&g_ipc_ctx);

    valid_until = (uint64_t)(time(NULL) + 3600);
    ipc_update_status(&g_ipc_ctx,
                      LOTA_STATUS_ATTESTED | LOTA_STATUS_TPM_OK |
                          LOTA_STATUS_IOMMU_OK | LOTA_STATUS_BPF_LOADED,
                      valid_until);
    ipc_set_mode(&g_ipc_ctx, LOTA_MODE_MONITOR);
    ipc_record_attestation(&g_ipc_ctx, true);

    printf("IPC server running (simulated ATTESTED state, no TPM).\n");
    printf("Tokens will be UNSIGNED.\n");
    printf("Press Ctrl+C to stop.\n\n");

    sdnotify_ready();

    while (g_running) {
      ipc_process(&g_ipc_ctx, 1000);
      dbus_process(g_dbus_ctx, 0);
    }

    sdnotify_stopping();
    printf("\nShutting down IPC test server...\n");
    dbus_cleanup(g_dbus_ctx);
    ipc_cleanup(&g_ipc_ctx);
    return 0;
  }

  if (test_signed_flag) {
    int ret;
    uint64_t valid_until;
    printf("=== IPC Test Server (Signed Tokens) ===\n\n");

    printf("Initializing TPM...\n");
    ret = tpm_init(&g_tpm_ctx);
    if (ret < 0) {
      fprintf(stderr, "Failed to initialize TPM: %s\n", strerror(-ret));
      return 1;
    }
    printf("TPM initialized\n");

    printf("Provisioning AIK...\n");
    ret = tpm_provision_aik(&g_tpm_ctx);
    if (ret < 0) {
      fprintf(stderr, "Failed to provision AIK: %s\n", strerror(-ret));
      tpm_cleanup(&g_tpm_ctx);
      return 1;
    }
    printf("AIK ready\n\n");

    printf("Starting IPC server...\n");
    ret = ipc_init_or_activate(&g_ipc_ctx);
    if (ret < 0) {
      fprintf(stderr, "Failed to initialize IPC: %s\n", strerror(-ret));
      tpm_cleanup(&g_tpm_ctx);
      return 1;
    }
    setup_container_listener(&g_ipc_ctx);
    setup_dbus(&g_ipc_ctx);

    /* enable signed tokens with PCRs 0, 1, 14 */
    ipc_set_tpm(&g_ipc_ctx, &g_tpm_ctx,
                (1U << 0) | (1U << 1) | (1U << LOTA_PCR_SELF));

    valid_until = (uint64_t)(time(NULL) + 3600);
    ipc_update_status(&g_ipc_ctx,
                      LOTA_STATUS_ATTESTED | LOTA_STATUS_TPM_OK |
                          LOTA_STATUS_IOMMU_OK | LOTA_STATUS_BPF_LOADED,
                      valid_until);
    ipc_set_mode(&g_ipc_ctx, LOTA_MODE_MONITOR);
    ipc_record_attestation(&g_ipc_ctx, true);

    printf("IPC server running (simulated ATTESTED state).\n");
    printf("Tokens will be SIGNED by TPM AIK!\n");
    printf("Press Ctrl+C to stop.\n\n");

    sdnotify_ready();

    while (g_running) {
      ipc_process(&g_ipc_ctx, 1000);
      dbus_process(g_dbus_ctx, 0);
    }

    sdnotify_stopping();
    printf("\nShutting down...\n");
    dbus_cleanup(g_dbus_ctx);
    ipc_cleanup(&g_ipc_ctx);
    tpm_cleanup(&g_tpm_ctx);
    return 0;
  }

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
    int ret = run_daemon(bpf_path, mode, strict_mmap, block_ptrace, config_path,
                         &cfg);
    pidfile_remove(pid_file_path, pid_fd);
    return ret;
  }
}
