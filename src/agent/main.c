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
#include "bpf_loader.h"
#include "iommu.h"
#include "tpm.h"

#define DEFAULT_BPF_PATH "/usr/lib/lota/lota_lsm.bpf.o"

/* Global state */
static volatile sig_atomic_t g_running = 1;
static struct tpm_context g_tpm_ctx;
static struct bpf_loader_ctx g_bpf_ctx;

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
 * Test TPM operations
 */
static int test_tpm(void) {
  int ret;
  uint8_t pcr_value[LOTA_HASH_SIZE];
  uint8_t kernel_hash[LOTA_HASH_SIZE];
  char kernel_path[256];

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
  (void)ctx;

  if (len < sizeof(*event))
    return 0;

  printf("[%llu] %s: %s (pid=%u, uid=%u)\n",
         (unsigned long long)event->timestamp_ns, event->comm, event->filename,
         event->pid, event->uid);

  return 0;
}

/*
 * Main daemon loop
 */
static int run_daemon(const char *bpf_path) {
  int ret;

  printf("=== LOTA Agent ===\n\n");

  printf("Verifying IOMMU...\n");
  ret = test_iommu();
  if (ret != 0) {
    fprintf(stderr, "Warning: IOMMU verification failed\n");
    /* continue anyway for testing - ill handle it later */
  }
  printf("\n");

  printf("Initializing TPM...\n");
  ret = tpm_init(&g_tpm_ctx);
  if (ret < 0) {
    fprintf(stderr, "Failed to initialize TPM: %s\n", strerror(-ret));
    fprintf(stderr, "Continuing without TPM support\n");
  } else {
    printf("TPM initialized\n");
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

  ret = bpf_loader_setup_ringbuf(&g_bpf_ctx, handle_exec_event, NULL);
  if (ret < 0) {
    fprintf(stderr, "Failed to setup ring buffer: %s\n", strerror(-ret));
    goto cleanup_bpf;
  }
  printf("Ring buffer ready\n\n");

  printf("Monitoring binary executions (Ctrl+C to stop)...\n\n");

  /* main loop */
  while (g_running) {
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
  return ret;
}

static void print_usage(const char *prog) {
  printf("Usage: %s [options]\n", prog);
  printf("\n");
  printf("Options:\n");
  printf("  --test-tpm      Test TPM operations and exit\n");
  printf("  --test-iommu    Test IOMMU verification and exit\n");
  printf("  --bpf PATH      Path to BPF object file\n");
  printf("                  (default: %s)\n", DEFAULT_BPF_PATH);
  printf("  --help          Show this help\n");
}

int main(int argc, char *argv[]) {
  int opt;
  int test_tpm_flag = 0;
  int test_iommu_flag = 0;
  const char *bpf_path = DEFAULT_BPF_PATH;

  static struct option long_options[] = {{"test-tpm", no_argument, 0, 't'},
                                         {"test-iommu", no_argument, 0, 'i'},
                                         {"bpf", required_argument, 0, 'b'},
                                         {"help", no_argument, 0, 'h'},
                                         {0, 0, 0, 0}};

  while ((opt = getopt_long(argc, argv, "tib:h", long_options, NULL)) != -1) {
    switch (opt) {
    case 't':
      test_tpm_flag = 1;
      break;
    case 'i':
      test_iommu_flag = 1;
      break;
    case 'b':
      bpf_path = optarg;
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

  return run_daemon(bpf_path);
}
