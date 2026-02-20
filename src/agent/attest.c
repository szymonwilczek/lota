/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - Remote attestation and policy export
 *
 * Handles remote attestation flow (challenge-response), continuous
 * attestation loop, and policy YAML export from live system state.
 */

#include <errno.h>
#include <limits.h>
#include <openssl/evp.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "../../include/attestation.h"
#include "../../include/lota.h"
#include "../../include/lota_ipc.h"
#include "agent.h"
#include "attest.h"
#include "bpf_loader.h"
#include "dbus.h"
#include "iommu.h"
#include "ipc.h"
#include "journal.h"
#include "net.h"
#include "policy.h"
#include "quote.h"
#include "sdnotify.h"
#include "selftest.h"
#include "tpm.h"

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
int export_policy(int mode) {
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
  ret = tpm_get_current_kernel_path(&g_tpm_ctx, snap.kernel_path,
                                    sizeof(snap.kernel_path));
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
    struct iommu_status iommu_status;

    snap.iommu_enabled = iommu_verify_full(&iommu_status);
    snap.enforce_mode = (mode == LOTA_MODE_ENFORCE);
    snap.module_sig = false;
    snap.secureboot = false;
    snap.lockdown = false;
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

  /* nonce from challenge */
  memcpy(report->tpm.nonce, challenge->nonce, LOTA_NONCE_SIZE);
  report->tpm.pcr_mask = challenge->pcr_mask;

  /*
   * report LSM enforcement mode
   * this flag is part of nonce binding (signed by TPM quote extraData)
   */
  if (g_mode == LOTA_MODE_ENFORCE)
    report->header.flags |= LOTA_REPORT_FLAG_ENFORCE;

  /*
   * report BPF LSM status
   * this flag is part of nonce binding (signed by TPM quote extraData)
   */
  if (g_bpf_ctx.loaded)
    report->header.flags |= LOTA_REPORT_FLAG_BPF_ACTIVE;

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

  /* system info: kernel hash */
  ret =
      tpm_get_current_kernel_path(&g_tpm_ctx, kernel_path, sizeof(kernel_path));
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
    char agent_path[PATH_MAX];
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

  if (iommu_verify_full(&iommu_status))
    report->header.flags |= LOTA_REPORT_FLAG_IOMMU_OK;
  memcpy(&report->system.iommu, &iommu_status, sizeof(report->system.iommu));

  /*
   * Compute binding nonce = SHA-256(
   *   challenge_nonce || hardware_id || signed_flags ||
   *   kernel_hash || agent_hash || iommu_status
   * ).
   */
  uint8_t binding_nonce[LOTA_NONCE_SIZE];
  {
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    unsigned int md_len;
    uint32_t signed_flags =
        report->header.flags & ~LOTA_REPORT_FLAG_TPM_QUOTE_OK;
    uint8_t flags_le[sizeof(signed_flags)];

    flags_le[0] = (uint8_t)(signed_flags);
    flags_le[1] = (uint8_t)(signed_flags >> 8);
    flags_le[2] = (uint8_t)(signed_flags >> 16);
    flags_le[3] = (uint8_t)(signed_flags >> 24);

    if (!md) {
      fprintf(stderr, "Failed to allocate EVP_MD_CTX\n");
      return -ENOMEM;
    }
    if (EVP_DigestInit_ex(md, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(md, challenge->nonce, LOTA_NONCE_SIZE) != 1 ||
        EVP_DigestUpdate(md, report->tpm.hardware_id, LOTA_HARDWARE_ID_SIZE) !=
            1 ||
        EVP_DigestUpdate(md, flags_le, sizeof(flags_le)) != 1 ||
        EVP_DigestUpdate(md, report->system.kernel_hash,
                         sizeof(report->system.kernel_hash)) != 1 ||
        EVP_DigestUpdate(md, report->system.agent_hash,
                         sizeof(report->system.agent_hash)) != 1 ||
        EVP_DigestUpdate(md, &report->system.iommu,
                         sizeof(report->system.iommu)) != 1 ||
        EVP_DigestFinal_ex(md, binding_nonce, &md_len) != 1) {
      EVP_MD_CTX_free(md);
      fprintf(stderr, "Failed to compute binding nonce\n");
      return -EIO;
    }
    EVP_MD_CTX_free(md);
  }

  ret = tpm_quote(&g_tpm_ctx, binding_nonce, challenge->pcr_mask, &quote_resp);
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
  if (quote_resp.signature_size > LOTA_MAX_SIG_SIZE) {
    fprintf(stderr, "TPM signature too large: %u > %u\n",
            quote_resp.signature_size, LOTA_MAX_SIG_SIZE);
    return -EOVERFLOW;
  }
  memcpy(report->tpm.quote_signature, quote_resp.signature,
         quote_resp.signature_size);

  /*
   * Copy raw TPMS_ATTEST blob for signature verification.
   * Verifier will: 1) verify signature over this data
   *                2) parse extraData to extract nonce
   *                3) compare with challenge nonce
   */
  report->tpm.attest_size = quote_resp.attest_size;
  if (quote_resp.attest_size > LOTA_MAX_ATTEST_SIZE) {
    fprintf(stderr, "TPMS_ATTEST too large: %u > %u\n", quote_resp.attest_size,
            LOTA_MAX_ATTEST_SIZE);
    return -EOVERFLOW;
  }
  memcpy(report->tpm.attest_data, quote_resp.attest_data,
         quote_resp.attest_size);

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

  /*
   * Export EK certificate (if available).
   */
  {
    size_t ek_cert_size = 0;
    ret = tpm_get_ek_cert(&g_tpm_ctx, report->tpm.ek_certificate,
                          LOTA_MAX_EK_CERT_SIZE, &ek_cert_size);
    if (ret == 0) {
      report->tpm.ek_cert_size = (uint16_t)ek_cert_size;
      printf("EK certificate exported (%zu bytes, DER X.509)\n", ek_cert_size);
    } else if (ret == -ENOENT) {
      printf("No EK certificate found (TOFU will require approval if strict "
             "mode)\n");
      report->tpm.ek_cert_size = 0;
    } else {
      fprintf(stderr, "Warning: Failed to read EK certificate: %s\n",
              strerror(-ret));
      report->tpm.ek_cert_size = 0;
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

  return 0;
}

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
int do_attest(const char *server, int port, const char *ca_cert,
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
int do_continuous_attest(const char *server, int port, const char *ca_cert,
                         int skip_verify, const uint8_t *pin_sha256,
                         int interval_sec, uint32_t aik_ttl) {
  int ret;
  int consecutive_failures = 0;
  int backoff_sec = 0;
  time_t last_success = 0;
  time_t now;
  uint32_t status_flags = 0;
  uint64_t valid_until = 0;
  uint64_t wd_usec = 0;
  bool wd_enabled;

  lota_info("Continuous attestation starting");
  lota_info("Server: %s:%d, interval: %d seconds", server, port, interval_sec);

  wd_enabled = sdnotify_watchdog_enabled(&wd_usec);

  lota_info("Starting IPC server");
  ret = ipc_init_or_activate(&g_ipc_ctx);
  if (ret < 0) {
    lota_warn("IPC init failed: %s", strerror(-ret));
    lota_warn("Gaming clients will not be able to query status");
  } else {
    setup_container_listener(&g_ipc_ctx);
    setup_dbus(&g_ipc_ctx);
  }

  ret = net_init();
  if (ret < 0) {
    lota_err("Failed to initialize network: %s", strerror(-ret));
    dbus_cleanup(g_dbus_ctx);
    ipc_cleanup(&g_ipc_ctx);
    return ret;
  }

  lota_info("Initializing TPM");
  ret = tpm_init(&g_tpm_ctx);
  if (ret < 0) {
    lota_err("Failed to initialize TPM: %s", strerror(-ret));
    net_cleanup();
    dbus_cleanup(g_dbus_ctx);
    ipc_cleanup(&g_ipc_ctx);
    return ret;
  }
  status_flags |= LOTA_STATUS_TPM_OK;

  lota_info("Performing self-measurement");
  ret = self_measure(&g_tpm_ctx);
  if (ret < 0) {
    lota_warn("Self-measurement failed: %s", strerror(-ret));
  }

  lota_info("Checking AIK");
  ret = tpm_provision_aik(&g_tpm_ctx);
  if (ret < 0) {
    lota_err("Failed to provision AIK: %s", strerror(-ret));
    tpm_cleanup(&g_tpm_ctx);
    net_cleanup();
    dbus_cleanup(g_dbus_ctx);
    ipc_cleanup(&g_ipc_ctx);
    return ret;
  }

  ipc_set_tpm(&g_ipc_ctx, &g_tpm_ctx,
              (1U << 0) | (1U << 1) | (1U << LOTA_PCR_SELF));

  ret = tpm_aik_load_metadata(&g_tpm_ctx);
  if (ret < 0) {
    lota_warn("Failed to load AIK metadata: %s", strerror(-ret));
  } else {
    int64_t age = tpm_aik_age(&g_tpm_ctx);
    lota_info("AIK generation: %lu, age: %ld seconds",
              (unsigned long)g_tpm_ctx.aik_meta.generation, (long)age);
  }

  ipc_update_status(&g_ipc_ctx, status_flags, 0);

  sdnotify_ready();
  sdnotify_status("Attesting to %s:%d", server, port);
  lota_info("Starting attestation loop");

  while (g_running) {
    now = time(NULL);

    /* check if AIK rotation is due */
    if (g_tpm_ctx.aik_meta_loaded) {
      int needs = tpm_aik_needs_rotation(&g_tpm_ctx, aik_ttl);
      if (needs == 1) {
        lota_info("AIK rotation due (gen %lu, age %ld s)",
                  (unsigned long)g_tpm_ctx.aik_meta.generation,
                  (long)tpm_aik_age(&g_tpm_ctx));
        ret = tpm_rotate_aik(&g_tpm_ctx);
        if (ret < 0) {
          lota_err("AIK rotation failed: %s", strerror(-ret));
        } else {
          lota_info("AIK rotated -> generation %lu",
                    (unsigned long)g_tpm_ctx.aik_meta.generation);
        }
      }
    }

    lota_dbg("Attestation round starting");
    ret = attest_once(server, port, ca_cert, skip_verify, pin_sha256, 0);

    if (ret == 0) {
      lota_info("Attestation successful");
      consecutive_failures = 0;
      backoff_sec = 0;
      last_success = now;

      /* update ipc: attestation successful */
      status_flags |= LOTA_STATUS_ATTESTED;
      valid_until = (uint64_t)(now + interval_sec + 60); /* buffer */
      ipc_update_status(&g_ipc_ctx, status_flags, valid_until);
      ipc_record_attestation(&g_ipc_ctx, true);
      sdnotify_status("Attested, valid until %lu", (unsigned long)valid_until);
    } else {
      consecutive_failures++;
      /* exponential backoff */
      {
        int shift = consecutive_failures - 1;
        if (shift > 5)
          shift = 5; /* 10 * 2^5 = 320 > MAX_BACKOFF_SECONDS */
        backoff_sec = MIN_ATTEST_INTERVAL * (1 << shift);
      }
      if (backoff_sec > MAX_BACKOFF_SECONDS)
        backoff_sec = MAX_BACKOFF_SECONDS;

      lota_err("Attestation FAILED (attempt %d, backoff %ds)",
               consecutive_failures, backoff_sec);

      if (last_success > 0) {
        lota_warn("Last success: %ld seconds ago", (long)(now - last_success));
      }

      /* update ipc: clear attested flag after multiple failures */
      if (consecutive_failures >= 3) {
        status_flags &= ~LOTA_STATUS_ATTESTED;
        ipc_update_status(&g_ipc_ctx, status_flags, 0);
      }
      ipc_record_attestation(&g_ipc_ctx, false);
      sdnotify_status("Attestation failed (%d consecutive)",
                      consecutive_failures);
    }

    int sleep_time = (ret == 0) ? interval_sec : backoff_sec;
    lota_dbg("Next attestation in %d seconds", sleep_time);

    struct timespec now_ts;
    clock_gettime(CLOCK_MONOTONIC, &now_ts);
    uint64_t target_ms = (uint64_t)now_ts.tv_sec * 1000 +
                         (uint64_t)now_ts.tv_nsec / 1000000 +
                         (uint64_t)sleep_time * 1000;

    while (g_running) {
      clock_gettime(CLOCK_MONOTONIC, &now_ts);
      uint64_t current_ms =
          (uint64_t)now_ts.tv_sec * 1000 + (uint64_t)now_ts.tv_nsec / 1000000;

      if (current_ms >= target_ms)
        break;

      int timeout_ms = (int)(target_ms - current_ms);

      if (wd_enabled && wd_usec > 0) {
        int wd_timeout_ms = (int)(wd_usec / 2000);
        if (timeout_ms > wd_timeout_ms)
          timeout_ms = wd_timeout_ms;
      }

      ipc_process(&g_ipc_ctx, timeout_ms);
      if (wd_enabled)
        sdnotify_watchdog_ping();
    }
  }

  lota_info("Shutting down continuous attestation");
  sdnotify_stopping();
  tpm_cleanup(&g_tpm_ctx);
  net_cleanup();
  dbus_cleanup(g_dbus_ctx);
  ipc_cleanup(&g_ipc_ctx);
  return 0;
}
