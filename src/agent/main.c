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
#include <time.h>
#include <unistd.h>

#include "../../include/attestation.h"
#include "../../include/lota.h"
#include "../../include/lota_ipc.h"
#include "bpf_loader.h"
#include "daemon.h"
#include "hash_verify.h"
#include "iommu.h"
#include "ipc.h"
#include "net.h"
#include "policy.h"
#include "policy_sign.h"
#include "quote.h"
#include "tpm.h"

#ifndef EAUTH
#define EAUTH 80
#endif

#define DEFAULT_BPF_PATH "/usr/lib/lota/lota_lsm.bpf.o"
#define DEFAULT_VERIFIER_PORT 8443
#define DEFAULT_ATTEST_INTERVAL 300 /* 5 minutes */
#define MIN_ATTEST_INTERVAL 10      /* 10 seconds */
#define MAX_BACKOFF_SECONDS 300     /* Max retry delay */

/* Default AIK TTL */
#define DEFAULT_AIK_TTL 0 /* 0 -> use TPM_AIK_DEFAULT_TTL_SEC */

/* PCR index for LOTA agent self-measurement */
#define LOTA_PCR_SELF 14

/* Global state */
static volatile sig_atomic_t g_running = 1;
static volatile sig_atomic_t g_reload = 0;
static struct tpm_context g_tpm_ctx;
static struct bpf_loader_ctx g_bpf_ctx;
static struct ipc_context g_ipc_ctx;
static struct hash_verify_ctx g_hash_ctx;
static int g_mode = LOTA_MODE_MONITOR;

/* Runtime config from CLI */
static uint32_t g_protect_pids[64];
static int g_protect_pid_count;
static const char *g_trust_libs[64];
static int g_trust_lib_count;

static uint32_t check_module_security(void);
static int self_measure(struct tpm_context *ctx);

/*
 * Print hex dump of buffer
 */
static void print_hex(const char *label, const uint8_t *data, size_t len) {
  size_t i;
  printf("%s: ", label);
  for (i = 0; i < len && i < 32; i++)
    printf("%02x", data[i]);
  if (len > 32)
    printf("...");
  printf("\n");
}

/*
 * Self-measurement: hash own binary and extend into PCR 14.
 * This provides tamper evidence - if agent is modified, attestation fails.
 *
 * Returns: 0 on success, negative errno on failure
 */
static int self_measure(struct tpm_context *ctx) {
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
 * Test TPM operations
 */
static int test_tpm(void) {
  int ret;
  uint8_t pcr_value[LOTA_HASH_SIZE];
  uint8_t kernel_hash[LOTA_HASH_SIZE];
  char kernel_path[256];
  char exe_path[LOTA_MAX_PATH_LEN];
  uint8_t self_hash[LOTA_HASH_SIZE];
  ssize_t len;

  printf("=== TPM Test ===\n\n");

  printf("Initializing TPM context...\n");
  ret = tpm_init(&g_tpm_ctx);
  if (ret < 0) {
    fprintf(stderr, "Failed to initialize TPM: %s\n", strerror(-ret));
    return ret;
  }
  printf("TPM initialized successfully\n\n");

  printf("Running TPM self-test...\n");
  ret = tpm_self_test(&g_tpm_ctx);
  if (ret < 0) {
    fprintf(stderr, "TPM self-test failed: %s\n", strerror(-ret));
  } else {
    printf("TPM self-test passed\n");
  }
  printf("\n");

  printf("Reading PCR 0 (SRTM)...\n");
  ret = tpm_read_pcr(&g_tpm_ctx, 0, TPM2_ALG_SHA256, pcr_value);
  if (ret < 0) {
    fprintf(stderr, "Failed to read PCR 0: %s\n", strerror(-ret));
  } else {
    print_hex("PCR 0", pcr_value, LOTA_HASH_SIZE);
  }

  printf("\nReading PCR 1 (BIOS config/IOMMU)...\n");
  ret = tpm_read_pcr(&g_tpm_ctx, 1, TPM2_ALG_SHA256, pcr_value);
  if (ret < 0) {
    fprintf(stderr, "Failed to read PCR 1: %s\n", strerror(-ret));
  } else {
    print_hex("PCR 1", pcr_value, LOTA_HASH_SIZE);
  }

  printf("\nReading PCR 10 (IMA)...\n");
  ret = tpm_read_pcr(&g_tpm_ctx, 10, TPM2_ALG_SHA256, pcr_value);
  if (ret < 0) {
    fprintf(stderr, "Failed to read PCR 10: %s\n", strerror(-ret));
  } else {
    print_hex("PCR 10", pcr_value, LOTA_HASH_SIZE);
  }

  /* hash kernel image */
  printf("\nFinding current kernel...\n");
  ret = tpm_get_current_kernel_path(kernel_path, sizeof(kernel_path));
  if (ret < 0) {
    fprintf(stderr, "Failed to find kernel: %s\n", strerror(-ret));
  } else {
    printf("Kernel: %s\n", kernel_path);
    printf("Hashing kernel image...\n");
    ret = tpm_hash_file(kernel_path, kernel_hash);
    if (ret < 0) {
      fprintf(stderr, "Failed to hash kernel: %s\n", strerror(-ret));
    } else {
      print_hex("Kernel SHA-256", kernel_hash, LOTA_HASH_SIZE);
    }
  }

  /* self-measurement test */
  printf("\n=== Self-Measurement Test ===\n\n");

  len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
  if (len < 0) {
    fprintf(stderr, "Failed to read /proc/self/exe: %s\n", strerror(errno));
  } else {
    exe_path[len] = '\0';
    printf("Agent binary: %s\n", exe_path);

    ret = tpm_hash_file(exe_path, self_hash);
    if (ret < 0) {
      fprintf(stderr, "Failed to hash agent: %s\n", strerror(-ret));
    } else {
      print_hex("Agent SHA-256", self_hash, LOTA_HASH_SIZE);
    }
  }

  printf("\nReading PCR %d before extend...\n", LOTA_PCR_SELF);
  ret = tpm_read_pcr(&g_tpm_ctx, LOTA_PCR_SELF, TPM2_ALG_SHA256, pcr_value);
  if (ret < 0) {
    fprintf(stderr, "Failed to read PCR %d: %s\n", LOTA_PCR_SELF,
            strerror(-ret));
  } else {
    print_hex("PCR 14 (before)", pcr_value, LOTA_HASH_SIZE);
  }

  printf("\nExtending self-hash into PCR %d...\n", LOTA_PCR_SELF);
  ret = self_measure(&g_tpm_ctx);
  if (ret < 0) {
    fprintf(stderr, "Self-measurement failed: %s\n", strerror(-ret));
  } else {
    printf("Self-measurement successful\n");
  }

  printf("\nReading PCR %d after extend...\n", LOTA_PCR_SELF);
  ret = tpm_read_pcr(&g_tpm_ctx, LOTA_PCR_SELF, TPM2_ALG_SHA256, pcr_value);
  if (ret < 0) {
    fprintf(stderr, "Failed to read PCR %d: %s\n", LOTA_PCR_SELF,
            strerror(-ret));
  } else {
    print_hex("PCR 14 (after)", pcr_value, LOTA_HASH_SIZE);
  }

  /* AIK provisioning test */
  printf("\n=== AIK Provisioning Test ===\n\n");

  printf("Checking/provisioning AIK at handle 0x%08X...\n", TPM_AIK_HANDLE);
  ret = tpm_provision_aik(&g_tpm_ctx);
  if (ret < 0) {
    fprintf(stderr, "AIK provisioning failed: %s\n", strerror(-ret));
    fprintf(stderr, "Note: May require owner hierarchy authorization\n");
  } else {
    printf("AIK ready\n");
  }

  /* TPM Quote test */
  printf("\n=== TPM Quote Test ===\n\n");

  if (ret == 0) {
    struct tpm_quote_response quote_resp;
    uint8_t test_nonce[LOTA_NONCE_SIZE];
    uint32_t quote_pcr_mask;

    /* Generate random nonce (TODO: from server) */
    printf("Generating test nonce...\n");
    for (size_t j = 0; j < LOTA_NONCE_SIZE; j++) {
      test_nonce[j] = (uint8_t)(rand() & 0xFF);
    }
    print_hex("Nonce", test_nonce, LOTA_NONCE_SIZE);

    /* quote pcrs: 0,1,14 */
    quote_pcr_mask = (1U << 0) | (1U << 1) | (1U << LOTA_PCR_SELF);
    printf("\nRequesting quote for PCRs 0, 1, %d...\n", LOTA_PCR_SELF);

    ret = tpm_quote(&g_tpm_ctx, test_nonce, quote_pcr_mask, &quote_resp);
    if (ret < 0) {
      fprintf(stderr, "TPM Quote failed: %s\n", strerror(-ret));
    } else {
      printf("Quote generated successfully!\n\n");
      printf("Attestation data size: %u bytes\n", quote_resp.attest_size);
      printf("Signature algorithm: 0x%04X\n", quote_resp.sig_alg);
      printf("Signature size: %u bytes\n", quote_resp.signature_size);
      print_hex("Signature", quote_resp.signature, quote_resp.signature_size);
      printf("\nPCR values in quote:\n");
      print_hex("  PCR 0", quote_resp.pcr_values[0], LOTA_HASH_SIZE);
      print_hex("  PCR 1", quote_resp.pcr_values[1], LOTA_HASH_SIZE);
      print_hex("  PCR 14", quote_resp.pcr_values[LOTA_PCR_SELF],
                LOTA_HASH_SIZE);
    }
  }

  tpm_cleanup(&g_tpm_ctx);
  printf("\nTPM test complete\n");
  return 0;
}

/*
 * Test IOMMU verification
 */
static int test_iommu(void) {
  struct iommu_status status;
  char buf[1024];
  bool ok;

  printf("=== IOMMU Test ===\n\n");

  ok = iommu_verify_full(&status);

  iommu_status_to_string(&status, buf, sizeof(buf));
  printf("%s\n", buf);

  if (ok) {
    printf("IOMMU verification: PASSED\n");
    return 0;
  } else {
    printf("IOMMU verification: FAILED\n");
    printf("\nRecommendations:\n");
    if (!(status.flags & IOMMU_FLAG_SYSFS_PRESENT)) {
      printf("  - Enable VT-d/AMD-Vi in BIOS\n");
    }
    if (!(status.flags & IOMMU_FLAG_CMDLINE_SET)) {
      printf(
          "  - Add 'intel_iommu=on' or 'amd_iommu=force' to kernel cmdline\n");
    }
    if (!(status.flags & IOMMU_FLAG_DMA_REMAP)) {
      printf("  - Check dmesg for IOMMU initialization errors\n");
    }
    return 1;
  }
}

/*
 * Format SHA-256 hex string into buffer.
 * buf must be at least 65 bytes (64 hex + NUL).
 */
static void format_sha256(const uint8_t hash[LOTA_HASH_SIZE], char *buf) {
  for (int i = 0; i < LOTA_HASH_SIZE; i++)
    snprintf(buf + i * 2, 3, "%02x", hash[i]);
}

/*
 * Ring buffer event handler.
 *
 * For file-bearing events (EXEC, MODULE, MMAP), computes the SHA-256
 * content hash via the hash verification cache and logs it alongside
 * the event metadata.
 */
static int handle_exec_event(void *ctx, void *data, size_t len) {
  struct lota_exec_event *event = data;
  const char *event_type_str;
  uint8_t content_hash[LOTA_HASH_SIZE];
  char hash_hex[LOTA_HASH_SIZE * 2 + 1];
  int has_file = 0;
  int hash_ret;
  (void)ctx;

  if (len < sizeof(*event))
    return 0;

  switch (event->event_type) {
  case LOTA_EVENT_EXEC:
    event_type_str = "EXEC";
    has_file = 1;
    break;
  case LOTA_EVENT_MODULE_LOAD:
    event_type_str = "MODULE";
    has_file = 1;
    break;
  case LOTA_EVENT_MODULE_BLOCKED:
    event_type_str = "BLOCKED";
    has_file = 1;
    break;
  case LOTA_EVENT_MMAP_EXEC:
    event_type_str = "MMAP_EXEC";
    has_file = 1;
    break;
  case LOTA_EVENT_MMAP_BLOCKED:
    event_type_str = "MMAP_BLOCKED";
    has_file = 1;
    break;
  case LOTA_EVENT_PTRACE:
    event_type_str = "PTRACE";
    printf("[%llu] %s %s -> pid=%u: %s (pid=%u, uid=%u)\n",
           (unsigned long long)event->timestamp_ns, event_type_str, event->comm,
           event->target_pid, event->filename, event->pid, event->uid);
    return 0;
  case LOTA_EVENT_PTRACE_BLOCKED:
    event_type_str = "PTRACE_BLOCKED";
    printf("[%llu] %s %s -> pid=%u: %s (pid=%u, uid=%u)\n",
           (unsigned long long)event->timestamp_ns, event_type_str, event->comm,
           event->target_pid, event->filename, event->pid, event->uid);
    return 0;
  case LOTA_EVENT_SETUID:
    printf("[%llu] SETUID %s: uid %u -> %u (pid=%u)\n",
           (unsigned long long)event->timestamp_ns, event->comm, event->uid,
           event->target_pid, event->pid);
    return 0;
  case LOTA_EVENT_ANON_EXEC:
    event_type_str = "ANON_EXEC";
    break;
  case LOTA_EVENT_ANON_EXEC_BLOCKED:
    event_type_str = "ANON_EXEC_BLOCKED";
    break;
  default:
    event_type_str = "UNKNOWN";
    break;
  }

  /*
   * For events with a file path, attempt to resolve the content
   * SHA-256 hash. This uses the LRU cache so unchanged files
   * are not re-hashed on every event.
   */
  if (has_file && event->filename[0] == '/') {
    hash_ret = hash_verify_event(&g_hash_ctx, event, content_hash);
    if (hash_ret == 0) {
      format_sha256(content_hash, hash_hex);
      printf("[%llu] %s %s: %s sha256=%s (pid=%u, uid=%u)\n",
             (unsigned long long)event->timestamp_ns, event_type_str,
             event->comm, event->filename, hash_hex, event->pid, event->uid);
      return 0;
    }
    /* hash failed -> fall through to log without hash */
  }

  printf("[%llu] %s %s: %s (pid=%u, uid=%u)\n",
         (unsigned long long)event->timestamp_ns, event_type_str, event->comm,
         event->filename, event->pid, event->uid);

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
                      bool block_ptrace) {
  int ret;
  uint32_t status_flags = 0;

  printf("=== LOTA Agent ===\n\n");

  ret = hash_verify_init(&g_hash_ctx, 0);
  if (ret < 0) {
    fprintf(stderr, "Failed to initialize hash cache: %s\n", strerror(-ret));
    return ret;
  }
  printf("Hash verification cache ready\n");

  printf("Starting IPC server...\n");
  ret = ipc_init(&g_ipc_ctx);
  if (ret < 0) {
    fprintf(stderr, "Failed to initialize IPC: %s\n", strerror(-ret));
    fprintf(stderr, "Continuing without IPC support\n");
  } else {
    ipc_set_mode(&g_ipc_ctx, (uint8_t)mode);
  }
  printf("\n");

  printf("Verifying IOMMU...\n");
  ret = test_iommu();
  if (ret != 0) {
    fprintf(stderr, "Warning: IOMMU verification failed\n");
    /* continue anyway for testing - ill handle it later */
  } else {
    status_flags |= LOTA_STATUS_IOMMU_OK;
  }
  printf("\n");

  printf("Initializing TPM...\n");
  ret = tpm_init(&g_tpm_ctx);
  if (ret < 0) {
    fprintf(stderr, "Failed to initialize TPM: %s\n", strerror(-ret));
    fprintf(stderr, "Continuing without TPM support\n");
  } else {
    printf("TPM initialized\n");
    status_flags |= LOTA_STATUS_TPM_OK;

    printf("Provisioning AIK...\n");
    ret = tpm_provision_aik(&g_tpm_ctx);
    if (ret < 0) {
      fprintf(stderr, "Warning: AIK provisioning failed: %s\n", strerror(-ret));
      fprintf(stderr, "Signed tokens will not be available\n");
    } else {
      ipc_set_tpm(&g_ipc_ctx, &g_tpm_ctx,
                  (1U << 0) | (1U << 1) | (1U << LOTA_PCR_SELF));
      printf("AIK ready, signed tokens enabled\n");

      ret = tpm_aik_load_metadata(&g_tpm_ctx);
      if (ret < 0) {
        fprintf(stderr, "Warning: Failed to load AIK metadata: %s\n",
                strerror(-ret));
      } else {
        int64_t age = tpm_aik_age(&g_tpm_ctx);
        printf("AIK generation: %lu, age: %ld seconds\n",
               (unsigned long)g_tpm_ctx.aik_meta.generation, (long)age);
      }
    }

    printf("Performing self-measurement...\n");
    ret = self_measure(&g_tpm_ctx);
    if (ret < 0) {
      fprintf(stderr, "Self-measurement failed: %s\n", strerror(-ret));
      fprintf(stderr, "Warning: Continuing without self-measurement\n");
    } else {
      printf("Self-measurement complete (PCR %d extended)\n", LOTA_PCR_SELF);
    }
  }
  printf("\n");

  printf("Loading BPF program from: %s\n", bpf_path);
  ret = bpf_loader_init(&g_bpf_ctx);
  if (ret < 0) {
    fprintf(stderr, "Failed to initialize BPF loader: %s\n", strerror(-ret));
    goto cleanup_tpm;
  }

  ret = bpf_loader_load(&g_bpf_ctx, bpf_path);
  if (ret < 0) {
    fprintf(stderr, "Failed to load BPF program: %s\n", strerror(-ret));
    goto cleanup_bpf;
  }
  printf("BPF program loaded\n");
  status_flags |= LOTA_STATUS_BPF_LOADED;

  ret = bpf_loader_set_mode(&g_bpf_ctx, mode);
  if (ret < 0) {
    fprintf(stderr, "Warning: Failed to set mode: %s\n", strerror(-ret));
  } else {
    printf("Mode: %s\n", mode_to_string(mode));
  }
  g_mode = mode;
  if (mode == LOTA_MODE_ENFORCE) {
    printf("\n*** WARNING: ENFORCE mode active - module loading BLOCKED ***\n");
  }

  /* apply runtime config flags */
  if (strict_mmap) {
    ret = bpf_loader_set_config(&g_bpf_ctx, LOTA_CFG_STRICT_MMAP, 1);
    if (ret < 0)
      fprintf(stderr, "Warning: Failed to enable strict mmap: %s\n",
              strerror(-ret));
    else
      printf("Strict mmap enforcement: ON\n");
  }

  if (block_ptrace) {
    ret = bpf_loader_set_config(&g_bpf_ctx, LOTA_CFG_BLOCK_PTRACE, 1);
    if (ret < 0)
      fprintf(stderr, "Warning: Failed to enable ptrace blocking: %s\n",
              strerror(-ret));
    else
      printf("Global ptrace blocking: ON\n");
  }

  /* apply protected PIDs from CLI */
  for (int i = 0; i < g_protect_pid_count; i++) {
    ret = bpf_loader_protect_pid(&g_bpf_ctx, g_protect_pids[i]);
    if (ret < 0) {
      fprintf(stderr, "Warning: Failed to protect PID %u: %s\n",
              g_protect_pids[i], strerror(-ret));
    } else {
      printf("Protected PID: %u\n", g_protect_pids[i]);
    }
  }

  /* apply trusted libraries from CLI */
  for (int i = 0; i < g_trust_lib_count; i++) {
    ret = bpf_loader_trust_lib(&g_bpf_ctx, g_trust_libs[i]);
    if (ret < 0) {
      fprintf(stderr, "Warning: Failed to trust lib %s: %s\n", g_trust_libs[i],
              strerror(-ret));
    } else {
      printf("Trusted lib: %s\n", g_trust_libs[i]);
    }
  }

  ret = bpf_loader_setup_ringbuf(&g_bpf_ctx, handle_exec_event, NULL);
  if (ret < 0) {
    fprintf(stderr, "Failed to setup ring buffer: %s\n", strerror(-ret));
    goto cleanup_bpf;
  }
  printf("Ring buffer ready\n\n");

  ipc_update_status(&g_ipc_ctx, status_flags, 0);

  printf("Monitoring binary executions (Ctrl+C to stop)...\n\n");

  /* main loop */
  while (g_running) {
    if (g_reload) {
      g_reload = 0;
      printf("SIGHUP received, reloading configuration\n");
      /*
       * TODO: re-read configuration, refresh BPF maps,
       * rotate hash cache, etc.
       * For now, I'm just logging the event so systemctl reload lota-agent no
       * longer kills the process.
       */
    }

    /* non-blocking */
    ipc_process(&g_ipc_ctx, 0);

    ret = bpf_loader_poll(&g_bpf_ctx, 100); /* 100ms timeout */
    if (ret < 0 && ret != -EINTR) {
      fprintf(stderr, "Poll error: %s\n", strerror(-ret));
      break;
    }
  }

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
  ipc_cleanup(&g_ipc_ctx);
  hash_verify_cleanup(&g_hash_ctx);
  return ret;
}

static void print_usage(const char *prog) {
  printf("Usage: %s [options]\n", prog);
  printf("\n");
  printf("Options:\n");
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
  printf("                    (default: %d, min: %d, 0=one-shot)\n",
         DEFAULT_ATTEST_INTERVAL, MIN_ATTEST_INTERVAL);
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

/*
 * Export a complete YAML policy from the current system state.
 *
 * Collects PCR values, binary hashes, and security feature flags,
 * then emits a verifier-ready YAML document via policy_emit().
 *
 * The output can be piped directly to a file:
 *   sudo lota-agent --export-policy > my-policy.yaml
 *   lota-verifier --policy my-policy.yaml
 *
 * Exported PCRs:
 *   PCR 0:  Firmware/SRTM measurement
 *   PCR 1:  BIOS configuration
 *   PCR 7:  Secure Boot state
 *   PCR 14: LOTA self-measurement
 */
static int export_policy(void) {
  struct policy_snapshot snap;
  int ret;
  ssize_t len;
  time_t now;
  struct tm tm_buf;

  static const int pcrs_to_export[] = {POLICY_PCR_0, POLICY_PCR_1, POLICY_PCR_7,
                                       POLICY_PCR_14};

  memset(&snap, 0, sizeof(snap));

  if (gethostname(snap.hostname, sizeof(snap.hostname) - 1) != 0)
    snprintf(snap.hostname, sizeof(snap.hostname), "unknown");

  now = time(NULL);
  if (gmtime_r(&now, &tm_buf))
    strftime(snap.timestamp, sizeof(snap.timestamp), "%Y-%m-%dT%H:%M:%SZ",
             &tm_buf);

  {
    size_t hlen = strlen(snap.hostname);
    if (hlen + sizeof("-baseline") <= sizeof(snap.name))
      snprintf(snap.name, sizeof(snap.name), "%s-baseline", snap.hostname);
    else
      snprintf(snap.name, sizeof(snap.name), "%.54s-baseline", snap.hostname);
  }
  snprintf(snap.description, sizeof(snap.description),
           "Auto-generated policy from %s", snap.hostname);

  fprintf(stderr, "Initializing TPM...\n");
  ret = tpm_init(&g_tpm_ctx);
  if (ret < 0) {
    fprintf(stderr, "Failed to initialize TPM: %s\n", strerror(-ret));
    return ret;
  }

  fprintf(stderr, "Performing self-measurement...\n");
  ret = self_measure(&g_tpm_ctx);
  if (ret < 0) {
    fprintf(stderr, "Warning: Self-measurement failed: %s\n", strerror(-ret));
    fprintf(stderr, "PCR 14 may not contain agent measurement.\n");
  }

  /* PCR values */
  snap.pcr_count = (int)(sizeof(pcrs_to_export) / sizeof(pcrs_to_export[0]));
  for (int i = 0; i < snap.pcr_count; i++) {
    snap.pcrs[i].index = pcrs_to_export[i];
    ret = tpm_read_pcr(&g_tpm_ctx, pcrs_to_export[i], TPM2_ALG_SHA256,
                       snap.pcrs[i].value);
    if (ret == 0) {
      snap.pcrs[i].valid = true;
    } else {
      fprintf(stderr, "Warning: Failed to read PCR %d: %s\n", pcrs_to_export[i],
              strerror(-ret));
    }
  }

  /* Kernel image hash */
  ret = tpm_get_current_kernel_path(snap.kernel_path, sizeof(snap.kernel_path));
  if (ret == 0) {
    ret = tpm_hash_file(snap.kernel_path, snap.kernel_hash);
    if (ret == 0) {
      snap.kernel_hash_valid = true;
    } else {
      fprintf(stderr, "Warning: Failed to hash kernel: %s\n", strerror(-ret));
    }
  } else {
    fprintf(stderr, "Warning: Failed to find kernel: %s\n", strerror(-ret));
  }

  /* Agent binary hash */
  len =
      readlink("/proc/self/exe", snap.agent_path, sizeof(snap.agent_path) - 1);
  if (len > 0) {
    snap.agent_path[len] = '\0';
    ret = tpm_hash_file(snap.agent_path, snap.agent_hash);
    if (ret == 0) {
      snap.agent_hash_valid = true;
    } else {
      fprintf(stderr, "Warning: Failed to hash agent: %s\n", strerror(-ret));
    }
  } else {
    fprintf(stderr, "Warning: Failed to read agent path.\n");
  }

  /* Security feature detection */
  {
    uint32_t flags = check_module_security();
    struct iommu_status iommu_status;

    snap.iommu_enabled = iommu_verify_full(&iommu_status);
    snap.enforce_mode = (g_mode == LOTA_MODE_ENFORCE);
    snap.module_sig = (flags & LOTA_REPORT_FLAG_MODULE_SIG) != 0;
    snap.secureboot = (flags & LOTA_REPORT_FLAG_SECUREBOOT) != 0;
    snap.lockdown = (flags & LOTA_REPORT_FLAG_LOCKDOWN) != 0;
  }

  tpm_cleanup(&g_tpm_ctx);

  ret = policy_emit(&snap, stdout);
  if (ret < 0) {
    fprintf(stderr, "Failed to write policy: %s\n", strerror(-ret));
    return ret;
  }

  fprintf(stderr, "\nPolicy export complete.\n");
  return 0;
}

/*
 * Check kernel module security status.
 * Returns: bitmask of LOTA_REPORT_FLAG_* for module security
 *
 * Checks:
 *   - /sys/module/module/parameters/sig_enforce - module signature enforcement
 *   - /sys/kernel/security/lockdown - kernel lockdown mode
 *   - /sys/firmware/efi/efivars or dmesg for Secure Boot
 */
static uint32_t check_module_security(void) {
  uint32_t flags = 0;
  char buf[64];
  FILE *f;
  ssize_t n;

  f = fopen("/sys/module/module/parameters/sig_enforce", "r");
  if (f) {
    if (fgets(buf, sizeof(buf), f)) {
      if (buf[0] == 'Y' || buf[0] == '1') {
        flags |= LOTA_REPORT_FLAG_MODULE_SIG;
      }
    }
    fclose(f);
  }

  f = fopen("/sys/kernel/security/lockdown", "r");
  if (f) {
    if (fgets(buf, sizeof(buf), f)) {
      if (strstr(buf, "[integrity]") || strstr(buf, "[confidentiality]")) {
        flags |= LOTA_REPORT_FLAG_LOCKDOWN;
      }
    }
    fclose(f);
  }

  /* secure boot status via efi variable */
  f = fopen("/sys/firmware/efi/efivars/"
            "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c",
            "rb");
  if (f) {
    uint8_t efi_buf[5];
    n = fread(efi_buf, 1, sizeof(efi_buf), f);
    if (n == 5 && efi_buf[4] == 1) {
      flags |= LOTA_REPORT_FLAG_SECUREBOOT;
    }
    fclose(f);
  }

  return flags;
}

/*
 * Build attestation report for verifier
 */
static int build_attestation_report(const struct verifier_challenge *challenge,
                                    struct lota_attestation_report *report) {
  struct tpm_quote_response quote_resp;
  struct iommu_status iommu_status;
  char kernel_path[LOTA_MAX_PATH_LEN];
  int ret;

  memset(report, 0, sizeof(*report));

  report->header.magic = LOTA_MAGIC;
  report->header.version = LOTA_VERSION;
  report->header.report_size = sizeof(*report);

  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  report->header.timestamp = ts.tv_sec;
  report->header.timestamp_ns = ts.tv_nsec;

  /* nonce from challenge */
  memcpy(report->tpm.nonce, challenge->nonce, LOTA_NONCE_SIZE);
  report->tpm.pcr_mask = challenge->pcr_mask;

  /*
   * Get hardware identity (SHA-256 of EK public key).
   * This provides a unique, immutable identifier for this TPM.
   * Used by verifier to detect unauthorized hardware changes.
   */
  ret = tpm_get_hardware_id(&g_tpm_ctx, report->tpm.hardware_id);
  if (ret < 0) {
    fprintf(stderr, "Warning: Failed to get hardware ID: %s\n", strerror(-ret));
    /* continue with zero hardware ID - verifier may reject */
    memset(report->tpm.hardware_id, 0, sizeof(report->tpm.hardware_id));
  } else {
    printf("Hardware ID derived from %s\n",
           ret == 1 ? "AIK (EK not available)" : "EK");
  }

  ret =
      tpm_quote(&g_tpm_ctx, challenge->nonce, challenge->pcr_mask, &quote_resp);
  if (ret < 0) {
    fprintf(stderr, "TPM Quote failed: %s\n", strerror(-ret));
    return ret;
  }
  printf("TPM quote generated (sig: %u bytes, attest: %u bytes)\n",
         quote_resp.signature_size, quote_resp.attest_size);

  /* copy TPM evidence */
  memcpy(report->tpm.pcr_values, quote_resp.pcr_values,
         sizeof(report->tpm.pcr_values));
  report->tpm.quote_sig_size = quote_resp.signature_size;
  if (quote_resp.signature_size <= LOTA_MAX_SIG_SIZE) {
    memcpy(report->tpm.quote_signature, quote_resp.signature,
           quote_resp.signature_size);
  }

  /*
   * Copy raw TPMS_ATTEST blob for signature verification.
   * Verifier will: 1) verify signature over this data
   *                2) parse extraData to extract nonce
   *                3) compare with challenge nonce
   */
  report->tpm.attest_size = quote_resp.attest_size;
  if (quote_resp.attest_size <= LOTA_MAX_ATTEST_SIZE) {
    memcpy(report->tpm.attest_data, quote_resp.attest_data,
           quote_resp.attest_size);
  }

  /*
   * Export AIK public key for TOFU registration.
   * Verifier stores this on first attestation and uses it
   * to verify signatures on subsequent attestations.
   */
  {
    size_t aik_size = 0;
    ret = tpm_get_aik_public(&g_tpm_ctx, report->tpm.aik_public,
                             LOTA_MAX_AIK_PUB_SIZE, &aik_size);
    if (ret == 0) {
      report->tpm.aik_public_size = (uint16_t)aik_size;
      printf("AIK public key exported (%zu bytes, DER SPKI)\n", aik_size);
    } else {
      fprintf(stderr, "Warning: Failed to export AIK public key: %s\n",
              strerror(-ret));
      report->tpm.aik_public_size = 0;
    }
  }

  /* AIK rotation metadata */
  if (g_tpm_ctx.aik_meta_loaded) {
    report->tpm.aik_generation = g_tpm_ctx.aik_meta.generation;

    if (tpm_aik_in_grace_period(&g_tpm_ctx)) {
      size_t prev_size = 0;
      ret = tpm_aik_get_prev_public(&g_tpm_ctx, report->tpm.prev_aik_public,
                                    LOTA_MAX_AIK_PUB_SIZE, &prev_size);
      if (ret == 0) {
        report->tpm.prev_aik_public_size = (uint16_t)prev_size;
        printf("Previous AIK included (grace period, %zu bytes)\n", prev_size);
      }
    }
  }

  report->header.flags |= LOTA_REPORT_FLAG_TPM_QUOTE_OK;

  /* system info: kernel hash */
  ret = tpm_get_current_kernel_path(kernel_path, sizeof(kernel_path));
  if (ret == 0) {
    size_t kpath_len = strlen(kernel_path);
    if (kpath_len >= sizeof(report->system.kernel_path))
      kpath_len = sizeof(report->system.kernel_path) - 1;
    memcpy(report->system.kernel_path, kernel_path, kpath_len);
    report->system.kernel_path[kpath_len] = '\0';

    ret = tpm_hash_file(kernel_path, report->system.kernel_hash);
    if (ret == 0) {
      report->header.flags |= LOTA_REPORT_FLAG_KERNEL_HASH_OK;
    } else {
      fprintf(stderr, "Warning: Failed to hash kernel\n");
    }
  }

  /*
   * Agent self-hash: hash LOTA own binary for integrity verification.
   * Verifier can compare this against known-good agent hashes.
   */
  {
    char agent_path[256];
    ssize_t len =
        readlink("/proc/self/exe", agent_path, sizeof(agent_path) - 1);
    if (len > 0) {
      agent_path[len] = '\0';
      ret = tpm_hash_file(agent_path, report->system.agent_hash);
      if (ret == 0) {
        printf("Agent binary hashed: %s\n", agent_path);
      } else {
        fprintf(stderr, "Warning: Failed to hash agent binary\n");
      }
    }
  }

  if (iommu_verify_full(&iommu_status)) {
    report->header.flags |= LOTA_REPORT_FLAG_IOMMU_OK;
  }
  memcpy(&report->system.iommu, &iommu_status, sizeof(report->system.iommu));

  report->header.flags |= check_module_security();

  /* report LSM enforcement mode */
  if (g_mode == LOTA_MODE_ENFORCE) {
    report->header.flags |= LOTA_REPORT_FLAG_ENFORCE;
  }

  return 0;
}

/*
 * Perform remote attestation
 */
/*
 * Perform single attestation round.
 * TPM and network must be initialized before calling.
 * Returns: 0 on success, negative errno on failure
 */
static int attest_once(const char *server, int port, const char *ca_cert,
                       int skip_verify, const uint8_t *pin_sha256,
                       int verbose) {
  struct net_context net_ctx;
  struct verifier_challenge challenge;
  struct verifier_result result;
  struct lota_attestation_report report;
  uint8_t *event_log = NULL;
  size_t event_log_size = 0;
  uint8_t *wire_buf = NULL;
  ssize_t wire_size;
  int ret;

  if (verbose)
    printf("Connecting to verifier at %s:%d...\n", server, port);

  ret = net_context_init(&net_ctx, server, port, ca_cert, skip_verify,
                         pin_sha256);
  if (ret < 0) {
    if (verbose)
      fprintf(stderr, "Failed to initialize connection: %s\n", strerror(-ret));
    return ret;
  }

  ret = net_connect(&net_ctx);
  if (ret < 0) {
    if (verbose)
      fprintf(stderr, "Failed to connect to verifier: %s\n", strerror(-ret));
    net_context_cleanup(&net_ctx);
    return ret;
  }

  if (verbose)
    printf("Connected, waiting for challenge...\n");

  ret = net_recv_challenge(&net_ctx, &challenge);
  if (ret < 0) {
    if (verbose)
      fprintf(stderr, "Failed to receive challenge: %s\n", strerror(-ret));
    goto cleanup;
  }

  if (verbose) {
    printf("Challenge received (PCR mask: 0x%08X)\n", challenge.pcr_mask);
    print_hex("  Nonce", challenge.nonce, LOTA_NONCE_SIZE);
  }

  ret = build_attestation_report(&challenge, &report);
  if (ret < 0) {
    if (verbose)
      fprintf(stderr, "Failed to build report: %s\n", strerror(-ret));
    goto cleanup;
  }

  /* read TPM event log for verifier PCR reconstruction */
  event_log = malloc(TPM_MAX_EVENT_LOG_SIZE);
  if (event_log) {
    ret =
        tpm_read_event_log(event_log, TPM_MAX_EVENT_LOG_SIZE, &event_log_size);
    if (ret < 0) {
      if (verbose)
        fprintf(stderr, "Warning: Failed to read TPM event log: %s\n",
                strerror(-ret));
      event_log_size = 0;
    } else if (verbose) {
      printf("TPM event log read (%zu bytes)\n", event_log_size);
    }
  }

  /* serialize report with variable-length sections */
  {
    size_t total = calculate_report_size(0, (uint32_t)event_log_size);
    wire_buf = malloc(total);
    if (!wire_buf) {
      fprintf(stderr, "Failed to allocate serialization buffer\n");
      ret = -ENOMEM;
      goto cleanup;
    }

    report.header.report_size = (uint32_t)total;
    wire_size = serialize_report(&report, NULL, 0, event_log,
                                 (uint32_t)event_log_size, wire_buf, total);
    if (wire_size < 0) {
      fprintf(stderr, "Failed to serialize report: %s\n",
              strerror((int)-wire_size));
      ret = (int)wire_size;
      goto cleanup;
    }
  }

  if (verbose)
    printf("Sending report (%zd bytes, event_log: %zu)...\n", wire_size,
           event_log_size);

  ret = net_send_report(&net_ctx, wire_buf, (size_t)wire_size);
  if (ret < 0) {
    if (verbose)
      fprintf(stderr, "Failed to send report: %s\n", strerror(-ret));
    goto cleanup;
  }

  ret = net_recv_result(&net_ctx, &result);
  if (ret < 0) {
    if (verbose)
      fprintf(stderr, "Failed to receive result: %s\n", strerror(-ret));
    goto cleanup;
  }

  if (verbose) {
    printf("Result: %s\n", net_result_str(result.result));
    if (result.result == VERIFY_OK) {
      printf("Valid until: %lu\n", (unsigned long)result.valid_until);
    }
  }

  ret = (result.result == VERIFY_OK) ? 0 : 1;

cleanup:
  free(wire_buf);
  free(event_log);
  net_context_cleanup(&net_ctx);
  return ret;
}

/*
 * One-shot remote attestation
 */
static int do_attest(const char *server, int port, const char *ca_cert,
                     int skip_verify, const uint8_t *pin_sha256) {
  int ret;

  printf("=== Remote Attestation ===\n\n");

  ret = net_init();
  if (ret < 0) {
    fprintf(stderr, "Failed to initialize network: %s\n", strerror(-ret));
    return ret;
  }

  printf("Initializing TPM...\n");
  ret = tpm_init(&g_tpm_ctx);
  if (ret < 0) {
    fprintf(stderr, "Failed to initialize TPM: %s\n", strerror(-ret));
    net_cleanup();
    return ret;
  }

  printf("Performing self-measurement...\n");
  ret = self_measure(&g_tpm_ctx);
  if (ret < 0) {
    fprintf(stderr, "Warning: Self-measurement failed: %s\n", strerror(-ret));
  }

  printf("Checking AIK...\n");
  ret = tpm_provision_aik(&g_tpm_ctx);
  if (ret < 0) {
    fprintf(stderr, "Failed to provision AIK: %s\n", strerror(-ret));
    tpm_cleanup(&g_tpm_ctx);
    net_cleanup();
    return ret;
  }

  ret = attest_once(server, port, ca_cert, skip_verify, pin_sha256, 1);

  printf("\n=== Attestation %s ===\n", ret == 0 ? "Successful" : "Failed");

  tpm_cleanup(&g_tpm_ctx);
  net_cleanup();
  return ret;
}

/*
 * Continuous attestation loop.
 * Re-attests every interval_sec seconds with exponential backoff on failure.
 */
static int do_continuous_attest(const char *server, int port,
                                const char *ca_cert, int skip_verify,
                                const uint8_t *pin_sha256, int interval_sec,
                                uint32_t aik_ttl) {
  int ret;
  int consecutive_failures = 0;
  int backoff_sec = 0;
  time_t last_success = 0;
  time_t now;
  uint32_t status_flags = 0;
  uint64_t valid_until = 0;

  printf("=== Continuous Attestation ===\n");
  printf("Server: %s:%d\n", server, port);
  printf("Interval: %d seconds\n\n", interval_sec);

  printf("Starting IPC server...\n");
  ret = ipc_init(&g_ipc_ctx);
  if (ret < 0) {
    fprintf(stderr, "Warning: IPC init failed: %s\n", strerror(-ret));
    fprintf(stderr, "Gaming clients will not be able to query status\n");
  }
  printf("\n");

  ret = net_init();
  if (ret < 0) {
    fprintf(stderr, "Failed to initialize network: %s\n", strerror(-ret));
    ipc_cleanup(&g_ipc_ctx);
    return ret;
  }

  printf("Initializing TPM...\n");
  ret = tpm_init(&g_tpm_ctx);
  if (ret < 0) {
    fprintf(stderr, "Failed to initialize TPM: %s\n", strerror(-ret));
    net_cleanup();
    ipc_cleanup(&g_ipc_ctx);
    return ret;
  }
  status_flags |= LOTA_STATUS_TPM_OK;

  printf("Performing self-measurement...\n");
  ret = self_measure(&g_tpm_ctx);
  if (ret < 0) {
    fprintf(stderr, "Warning: Self-measurement failed: %s\n", strerror(-ret));
  }

  printf("Checking AIK...\n");
  ret = tpm_provision_aik(&g_tpm_ctx);
  if (ret < 0) {
    fprintf(stderr, "Failed to provision AIK: %s\n", strerror(-ret));
    tpm_cleanup(&g_tpm_ctx);
    net_cleanup();
    ipc_cleanup(&g_ipc_ctx);
    return ret;
  }

  ipc_set_tpm(&g_ipc_ctx, &g_tpm_ctx,
              (1U << 0) | (1U << 1) | (1U << LOTA_PCR_SELF));

  ret = tpm_aik_load_metadata(&g_tpm_ctx);
  if (ret < 0) {
    fprintf(stderr, "Warning: Failed to load AIK metadata: %s\n",
            strerror(-ret));
  } else {
    int64_t age = tpm_aik_age(&g_tpm_ctx);
    printf("AIK generation: %lu, age: %ld seconds\n",
           (unsigned long)g_tpm_ctx.aik_meta.generation, (long)age);
  }

  ipc_update_status(&g_ipc_ctx, status_flags, 0);

  printf("Starting attestation loop (Ctrl+C to stop)...\n\n");

  while (g_running) {
    now = time(NULL);

    /* check if AIK rotation is due */
    if (g_tpm_ctx.aik_meta_loaded) {
      int needs = tpm_aik_needs_rotation(&g_tpm_ctx, aik_ttl);
      if (needs == 1) {
        printf("[%ld] AIK rotation due (gen %lu, age %ld s)\n", (long)now,
               (unsigned long)g_tpm_ctx.aik_meta.generation,
               (long)tpm_aik_age(&g_tpm_ctx));
        ret = tpm_rotate_aik(&g_tpm_ctx);
        if (ret < 0) {
          fprintf(stderr, "[%ld] AIK rotation failed: %s\n", (long)now,
                  strerror(-ret));
        } else {
          printf("[%ld] AIK rotated -> generation %lu\n", (long)now,
                 (unsigned long)g_tpm_ctx.aik_meta.generation);
        }
      }
    }

    printf("[%ld] Attestation round starting...\n", (long)now);
    ret = attest_once(server, port, ca_cert, skip_verify, pin_sha256, 0);

    if (ret == 0) {
      printf("[%ld] Attestation successful\n", (long)now);
      consecutive_failures = 0;
      backoff_sec = 0;
      last_success = now;

      /* update ipc: attestation successful */
      status_flags |= LOTA_STATUS_ATTESTED;
      valid_until = (uint64_t)(now + interval_sec + 60); /* buffer */
      ipc_update_status(&g_ipc_ctx, status_flags, valid_until);
      ipc_record_attestation(&g_ipc_ctx, true);
    } else {
      consecutive_failures++;
      /* exponential backoff: 10, 20, 40, 80, ... up to max */
      backoff_sec = MIN_ATTEST_INTERVAL * (1 << (consecutive_failures - 1));
      if (backoff_sec > MAX_BACKOFF_SECONDS)
        backoff_sec = MAX_BACKOFF_SECONDS;

      fprintf(stderr, "[%ld] Attestation FAILED (attempt %d, backoff %ds)\n",
              (long)now, consecutive_failures, backoff_sec);

      if (last_success > 0) {
        fprintf(stderr, "[%ld] Last success: %ld seconds ago\n", (long)now,
                (long)(now - last_success));
      }

      /* update ipc: clear attested flag after multiple failures */
      if (consecutive_failures >= 3) {
        status_flags &= ~LOTA_STATUS_ATTESTED;
        ipc_update_status(&g_ipc_ctx, status_flags, 0);
      }
      ipc_record_attestation(&g_ipc_ctx, false);
    }

    int sleep_time = (ret == 0) ? interval_sec : backoff_sec;
    printf("[%ld] Next attestation in %d seconds\n\n", (long)now, sleep_time);

    for (int i = 0; i < sleep_time && g_running; i++) {
      ipc_process(&g_ipc_ctx, 100); /* 100ms timeout */
      usleep(900000);
    }
  }

  printf("\nShutting down continuous attestation...\n");
  tpm_cleanup(&g_tpm_ctx);
  net_cleanup();
  ipc_cleanup(&g_ipc_ctx);
  return 0;
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

  static struct option long_options[] = {
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

  while ((opt = getopt_long(argc, argv,
                            "ticSEaI:s:p:C:KF:b:m:MPR:L:dD:T:G:g:V:k:Q:h",
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
      attest_interval = atoi(optarg);
      if (attest_interval < MIN_ATTEST_INTERVAL) {
        fprintf(stderr,
                "Warning: interval %d too low, using minimum %d seconds\n",
                attest_interval, MIN_ATTEST_INTERVAL);
        attest_interval = MIN_ATTEST_INTERVAL;
      }
      break;
    case 's':
      server_addr = optarg;
      break;
    case 'p':
      server_port = atoi(optarg);
      break;
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
        g_protect_pids[g_protect_pid_count++] = (uint32_t)atoi(optarg);
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
    case 'T':
      aik_ttl = (uint32_t)atoi(optarg);
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
    case 'h':
    default:
      print_usage(argv[0]);
      return (opt == 'h') ? 0 : 1;
    }
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
    ret = ipc_init(&g_ipc_ctx);
    if (ret < 0) {
      fprintf(stderr, "Failed to initialize IPC: %s\n", strerror(-ret));
      return 1;
    }

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

    while (g_running) {
      ipc_process(&g_ipc_ctx, 1000);
    }

    printf("\nShutting down IPC test server...\n");
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
    ret = ipc_init(&g_ipc_ctx);
    if (ret < 0) {
      fprintf(stderr, "Failed to initialize IPC: %s\n", strerror(-ret));
      tpm_cleanup(&g_tpm_ctx);
      return 1;
    }

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

    while (g_running) {
      ipc_process(&g_ipc_ctx, 1000);
    }

    printf("\nShutting down...\n");
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
    int ret = run_daemon(bpf_path, mode, strict_mmap, block_ptrace);
    pidfile_remove(pid_file_path, pid_fd);
    return ret;
  }
}
