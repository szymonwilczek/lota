/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - Policy Auto-Generation
 *
 * Generates a complete YAML policy file from the current system state.
 * The output is directly consumable by lota-verifier --policy.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_POLICY_H
#define LOTA_POLICY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "../../include/lota.h"

/*
 * PCR indices exported by default.
 *
 *   PCR 0:  SRTM / firmware measurement
 *   PCR 1:  BIOS / UEFI configuration
 *   PCR 4:  Boot manager / loader stage
 *   PCR 7:  Secure Boot state
 *   PCR 8:  Boot config / command line measurements
 *   PCR 9:  Kernel/initrd measurements (bootloader-dependent)
 *   PCR 11: Unified Kernel Image (UKI) measurements
 *   PCR 14: LOTA agent self-measurement
 */
#define POLICY_PCR_0 0
#define POLICY_PCR_1 1
#define POLICY_PCR_4 4
#define POLICY_PCR_7 7
#define POLICY_PCR_8 8
#define POLICY_PCR_9 9
#define POLICY_PCR_11 11
#define POLICY_PCR_14 14

#define POLICY_MAX_PCRS 24
#define POLICY_MAX_HASHES 8

/*
 * Collected system snapshot for policy generation.
 */
struct policy_snapshot {
  /* Policy metadata */
  char name[64];
  char description[256];
  char hostname[64];
  char timestamp[32]; /* ISO-8601 */

  /* PCR values (SHA-256, LOTA_HASH_SIZE bytes each) */
  struct {
    int index;
    uint8_t value[LOTA_HASH_SIZE];
    bool valid;
  } pcrs[POLICY_MAX_PCRS];
  int pcr_count;

  /* Boot-chain measurement digest (kernel-relevant measured-boot PCR) */
  char kernel_path[LOTA_MAX_PATH_LEN];
  uint8_t kernel_hash[LOTA_HASH_SIZE];
  bool kernel_hash_valid;

  /* Agent binary hash */
  char agent_path[LOTA_MAX_PATH_LEN];
  uint8_t agent_hash[LOTA_HASH_SIZE];
  bool agent_hash_valid;

  /* Security feature detection */
  bool iommu_enabled;
  bool enforce_mode;
  bool module_sig;
  bool secureboot;
  bool lockdown;
};

/*
 * policy_emit - Serialize a policy snapshot to YAML
 *
 * @snap: System snapshot (from policy_collect or test fixture)
 * @out:  Output stream (stdout, file, or fmemopen buffer)
 *
 * Writes a complete, verifier-ready YAML policy document to @out.
 * The output can be used directly with lota-verifier --policy.
 *
 * Returns: 0 on success, negative errno on write failure
 */
int policy_emit(const struct policy_snapshot *snap, FILE *out);

/*
 * policy_emit_to_buf - Serialize a policy snapshot to a memory buffer
 *
 * @snap:     System snapshot
 * @buf:      Output buffer
 * @buf_size: Buffer capacity
 * @written:  Bytes written (excluding NUL terminator)
 *
 * Convenience wrapper around policy_emit() using fmemopen.
 *
 * Returns: 0 on success, -ENOSPC if buffer too small, negative errno otherwise
 */
int policy_emit_to_buf(const struct policy_snapshot *snap, char *buf,
                       size_t buf_size, size_t *written);

#endif /* LOTA_POLICY_H */
