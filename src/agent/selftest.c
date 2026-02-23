/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - Self-test commands
 * TPM and IOMMU diagnostic test subcommands
 */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <unistd.h>

#include "../../include/lota.h"
#include "agent.h"
#include "iommu.h"
#include "quote.h"
#include "selftest.h"
#include "tpm.h"

/*
 * Print hex dump of buffer
 */
void print_hex(const char *label, const uint8_t *data, size_t len) {
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
int test_tpm(void) {
  int ret;
  uint8_t pcr_value[LOTA_HASH_SIZE];
  uint8_t kernel_hash[LOTA_HASH_SIZE];
  char kernel_path[256];
  char exe_path[LOTA_MAX_PATH_LEN];
  uint8_t self_hash[LOTA_HASH_SIZE];
  ssize_t len;

  printf("=== TPM Test ===\n\n");

  printf("Initializing TPM context...\n");
  ret = tpm_init(&g_agent.tpm_ctx);
  if (ret < 0) {
    fprintf(stderr, "Failed to initialize TPM: %s\n", strerror(-ret));
    return ret;
  }
  printf("TPM initialized successfully\n\n");

  printf("Running TPM self-test...\n");
  ret = tpm_self_test(&g_agent.tpm_ctx);
  if (ret < 0) {
    fprintf(stderr, "TPM self-test failed: %s\n", strerror(-ret));
  } else {
    printf("TPM self-test passed\n");
  }
  printf("\n");

  printf("Reading PCR 0 (SRTM)...\n");
  ret = tpm_read_pcr(&g_agent.tpm_ctx, 0, TPM2_ALG_SHA256, pcr_value);
  if (ret < 0) {
    fprintf(stderr, "Failed to read PCR 0: %s\n", strerror(-ret));
  } else {
    print_hex("PCR 0", pcr_value, LOTA_HASH_SIZE);
  }

  printf("\nReading PCR 1 (BIOS config/IOMMU)...\n");
  ret = tpm_read_pcr(&g_agent.tpm_ctx, 1, TPM2_ALG_SHA256, pcr_value);
  if (ret < 0) {
    fprintf(stderr, "Failed to read PCR 1: %s\n", strerror(-ret));
  } else {
    print_hex("PCR 1", pcr_value, LOTA_HASH_SIZE);
  }

  printf("\nReading PCR 10 (IMA)...\n");
  ret = tpm_read_pcr(&g_agent.tpm_ctx, 10, TPM2_ALG_SHA256, pcr_value);
  if (ret < 0) {
    fprintf(stderr, "Failed to read PCR 10: %s\n", strerror(-ret));
  } else {
    print_hex("PCR 10", pcr_value, LOTA_HASH_SIZE);
  }

  /* hash kernel image */
  printf("\nFinding current kernel...\n");
  {
    int k_err = tpm_get_current_kernel_path(&g_agent.tpm_ctx, kernel_path,
                                            sizeof(kernel_path));
    if (k_err < 0) {
      fprintf(stderr, "Failed to find kernel: %s\n", strerror(-k_err));
    } else {
      printf("Kernel: %s\n", kernel_path);
      printf("Hashing kernel image...\n");
      k_err = tpm_hash_file(kernel_path, kernel_hash);
      if (k_err < 0) {
        fprintf(stderr, "Failed to hash kernel: %s\n", strerror(-k_err));
      } else {
        print_hex("Kernel SHA-256", kernel_hash, LOTA_HASH_SIZE);
      }
    }
  }

  /* self-measurement test */
  printf("\n=== Self-Measurement Test ===\n\n");

  len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
  if (len < 0) {
    fprintf(stderr, "Failed to read /proc/self/exe: %s\n", strerror(errno));
  } else {
    int s_err;
    exe_path[len] = '\0';
    printf("Agent binary: %s\n", exe_path);

    s_err = tpm_hash_file(exe_path, self_hash);
    if (s_err < 0) {
      fprintf(stderr, "Failed to hash agent: %s\n", strerror(-s_err));
    } else {
      print_hex("Agent SHA-256", self_hash, LOTA_HASH_SIZE);
    }
  }

  printf("\nReading PCR %d before extend...\n", LOTA_PCR_SELF);
  ret =
      tpm_read_pcr(&g_agent.tpm_ctx, LOTA_PCR_SELF, TPM2_ALG_SHA256, pcr_value);
  if (ret < 0) {
    fprintf(stderr, "Failed to read PCR %d: %s\n", LOTA_PCR_SELF,
            strerror(-ret));
  } else {
    print_hex("PCR 14 (before)", pcr_value, LOTA_HASH_SIZE);
  }

  printf("\nExtending self-hash into PCR %d...\n", LOTA_PCR_SELF);
  ret = self_measure(&g_agent.tpm_ctx);
  if (ret < 0) {
    fprintf(stderr, "Self-measurement failed: %s\n", strerror(-ret));
  } else {
    printf("Self-measurement successful\n");
  }

  printf("\nReading PCR %d after extend...\n", LOTA_PCR_SELF);
  ret =
      tpm_read_pcr(&g_agent.tpm_ctx, LOTA_PCR_SELF, TPM2_ALG_SHA256, pcr_value);
  if (ret < 0) {
    fprintf(stderr, "Failed to read PCR %d: %s\n", LOTA_PCR_SELF,
            strerror(-ret));
  } else {
    print_hex("PCR 14 (after)", pcr_value, LOTA_HASH_SIZE);
  }

  /* AIK provisioning test */
  printf("\n=== AIK Provisioning Test ===\n\n");

  printf("Checking/provisioning AIK at handle 0x%08X...\n",
         g_agent.tpm_ctx.aik_handle);
  ret = tpm_provision_aik(&g_agent.tpm_ctx);
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

    /* Generate random test nonce (production path uses server challenge) */
    printf("Generating test nonce...\n");
    if (getrandom(test_nonce, LOTA_NONCE_SIZE, 0) != LOTA_NONCE_SIZE) {
      fprintf(stderr, "getrandom failed: %s\n", strerror(errno));
      tpm_cleanup(&g_agent.tpm_ctx);
      return -1;
    }
    print_hex("Nonce", test_nonce, LOTA_NONCE_SIZE);

    /* quote pcrs: 0,1,14 */
    quote_pcr_mask = (1U << 0) | (1U << 1) | (1U << LOTA_PCR_SELF);
    printf("\nRequesting quote for PCRs 0, 1, %d...\n", LOTA_PCR_SELF);

    ret = tpm_quote(&g_agent.tpm_ctx, test_nonce, quote_pcr_mask, &quote_resp);
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

  tpm_cleanup(&g_agent.tpm_ctx);
  printf("\nTPM test complete\n");
  return 0;
}

/*
 * Test IOMMU verification
 */
int test_iommu(void) {
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
