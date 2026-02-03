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
#include "iommu.h"
#include "ipc.h"
#include "net.h"
#include "quote.h"
#include "tpm.h"

#define DEFAULT_BPF_PATH "/usr/lib/lota/lota_lsm.bpf.o"
#define DEFAULT_VERIFIER_PORT 8443
#define DEFAULT_ATTEST_INTERVAL 300 /* 5 minutes */
#define MIN_ATTEST_INTERVAL 10      /* 10 seconds */
#define MAX_BACKOFF_SECONDS 300     /* Max retry delay */

/* PCR index for LOTA agent self-measurement */
#define LOTA_PCR_SELF 14

/* Global state */
static volatile sig_atomic_t g_running = 1;
static struct tpm_context g_tpm_ctx;
static struct bpf_loader_ctx g_bpf_ctx;
static struct ipc_context g_ipc_ctx;

/*
 * Signal handler for graceful shutdown
 */
static void signal_handler(int sig) {
  (void)sig;
  g_running = 0;
}

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
 * Ring buffer event handler
 */
static int handle_exec_event(void *ctx, void *data, size_t len) {
  struct lota_exec_event *event = data;
  const char *event_type_str;
  (void)ctx;

  if (len < sizeof(*event))
    return 0;

  switch (event->event_type) {
  case LOTA_EVENT_EXEC:
    event_type_str = "EXEC";
    break;
  case LOTA_EVENT_MODULE_LOAD:
    event_type_str = "MODULE";
    break;
  case LOTA_EVENT_MODULE_BLOCKED:
    event_type_str = "BLOCKED";
    break;
  default:
    event_type_str = "UNKNOWN";
    break;
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

static int run_daemon(const char *bpf_path, int mode) {
  int ret;
  uint32_t status_flags = 0;

  printf("=== LOTA Agent ===\n\n");

  /* IPC server first */
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
  if (mode == LOTA_MODE_ENFORCE) {
    printf("\n*** WARNING: ENFORCE mode active - module loading BLOCKED ***\n");
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
    /* non-blocking */
    ipc_process(&g_ipc_ctx, 0);

    ret = bpf_loader_poll(&g_bpf_ctx, 100); /* 100ms timeout */
    if (ret < 0 && ret != -EINTR) {
      fprintf(stderr, "Poll error: %s\n", strerror(-ret));
      break;
    }
  }

  uint64_t total, sent, errs, drops;
  if (bpf_loader_get_stats(&g_bpf_ctx, &total, &sent, &errs, &drops) == 0) {
    printf("\n=== Statistics ===\n");
    printf("Total executions: %lu\n", total);
    printf("Events sent: %lu\n", sent);
    printf("Errors: %lu\n", errs);
    printf("Ring buffer drops: %lu\n", drops);
  }

cleanup_bpf:
  bpf_loader_cleanup(&g_bpf_ctx);
cleanup_tpm:
  tpm_cleanup(&g_tpm_ctx);
  ipc_cleanup(&g_ipc_ctx);
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
  printf("  --attest          Perform remote attestation and exit\n");
  printf("  --attest-interval SECS\n");
  printf("                    Continuous attestation interval in seconds\n");
  printf("                    (default: %d, min: %d, 0=one-shot)\n",
         DEFAULT_ATTEST_INTERVAL, MIN_ATTEST_INTERVAL);
  printf("  --server HOST     Verifier server address (default: localhost)\n");
  printf("  --port PORT       Verifier server port (default: %d)\n",
         DEFAULT_VERIFIER_PORT);
  printf("  --bpf PATH        Path to BPF object file\n");
  printf("                    (default: %s)\n", DEFAULT_BPF_PATH);
  printf("  --mode MODE       Set enforcement mode:\n");
  printf("                      monitor     - log events only (default)\n");
  printf("                      enforce     - block unauthorized modules\n");
  printf("                      maintenance - allow all, minimal logging\n");
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
static int attest_once(const char *server, int port, int verbose) {
  struct net_context net_ctx;
  struct verifier_challenge challenge;
  struct verifier_result result;
  struct lota_attestation_report report;
  int ret;

  if (verbose)
    printf("Connecting to verifier at %s:%d...\n", server, port);

  ret = net_context_init(&net_ctx, server, port, NULL);
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

  if (verbose)
    printf("Sending report (%u bytes)...\n", report.header.report_size);

  ret = net_send_report(&net_ctx, &report, sizeof(report));
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
  net_context_cleanup(&net_ctx);
  return ret;
}

/*
 * One-shot remote attestation
 */
static int do_attest(const char *server, int port) {
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

  ret = attest_once(server, port, 1);

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
                                int interval_sec) {
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

  ipc_update_status(&g_ipc_ctx, status_flags, 0);

  printf("Starting attestation loop (Ctrl+C to stop)...\n\n");

  while (g_running) {
    now = time(NULL);

    printf("[%ld] Attestation round starting...\n", (long)now);
    ret = attest_once(server, port, 0);

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
  int attest_flag = 0;
  int attest_interval = 0; /* 0 = one-shot, >0 = continuous */
  int mode = LOTA_MODE_MONITOR;
  const char *bpf_path = DEFAULT_BPF_PATH;
  const char *server_addr = "localhost";
  int server_port = DEFAULT_VERIFIER_PORT;

  static struct option long_options[] = {
      {"test-tpm", no_argument, 0, 't'},
      {"test-iommu", no_argument, 0, 'i'},
      {"test-ipc", no_argument, 0, 'c'},
      {"test-signed", no_argument, 0, 'S'},
      {"attest", no_argument, 0, 'a'},
      {"attest-interval", required_argument, 0, 'I'},
      {"server", required_argument, 0, 's'},
      {"port", required_argument, 0, 'p'},
      {"bpf", required_argument, 0, 'b'},
      {"mode", required_argument, 0, 'm'},
      {"help", no_argument, 0, 'h'},
      {0, 0, 0, 0}};

  while ((opt = getopt_long(argc, argv, "ticSaI:s:p:b:m:h", long_options,
                            NULL)) != -1) {
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
    case 'h':
    default:
      print_usage(argv[0]);
      return (opt == 'h') ? 0 : 1;
    }
  }

  /* signal handlers */
  signal(SIGINT, signal_handler);
  signal(SIGTERM, signal_handler);

  if (test_tpm_flag)
    return test_tpm();

  if (test_iommu_flag)
    return test_iommu();

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
    if (attest_interval > 0)
      return do_continuous_attest(server_addr, server_port, attest_interval);
    else
      return do_attest(server_addr, server_port);
  }

  return run_daemon(bpf_path, mode);
}
