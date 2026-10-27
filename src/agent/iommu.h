/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * LOTA - IOMMU Verification Module
 * Verifies VT-d (Intel) or AMD-Vi status for DMA attack protection
 */

#ifndef LOTA_IOMMU_H
#define LOTA_IOMMU_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "../../include/iommu_types.h"

/*
 * iommu_check_sysfs - Check /sys/class/iommu/ for active IOMMU units
 * @status: Output structure to populate
 * @root: Prefix the sysfs path is read under, NULL for the live machine
 *
 * Scans /sys/class/iommu/ for dmar* (Intel) or ivhd* (AMD) entries.
 * Sets IOMMU_FLAG_SYSFS_PRESENT and vendor type.
 *
 * Returns: Number of IOMMU units found, 0 if none
 */
int iommu_check_sysfs(struct iommu_status *status, const char *root);

/*
 * iommu_check_cmdline - Validate /proc/cmdline for IOMMU boot parameters
 * @status: Output structure to populate
 * @root: Prefix /proc/cmdline is read under, NULL for the live machine
 *
 * Looks for: intel_iommu=on, amd_iommu=on/force, iommu.strict=1
 * Sets IOMMU_FLAG_CMDLINE_SET if found.
 *
 * Returns: 0 if IOMMU param found, -1 if missing
 */
int iommu_check_cmdline(struct iommu_status *status, const char *root);

/*
 * iommu_check_domains - Read the domain each IOMMU group is in
 * @status: Output structure to populate
 * @root: Prefix the sysfs path is read under, NULL for the live machine
 *
 * Sets IOMMU_FLAG_DMA_REMAP when at least one group is in a translating
 * (DMA or DMA-FQ) domain; identity (passthrough) does not count.
 *
 * Returns: Number of translating groups, negative on error
 */
int iommu_check_domains(struct iommu_status *status, const char *root);

/*
 * iommu_check_irq_remap - Look for a remapped interrupt chip
 * @status: Output structure to populate
 * @root: Prefix /proc/interrupts is read under, NULL for the live machine
 *
 * Sets IOMMU_FLAG_IRQ_REMAP when an interrupt chip is named IR-*.
 *
 * Returns: 0 on success, -1 if the table could not be read
 */
int iommu_check_irq_remap(struct iommu_status *status, const char *root);

/*
 * iommu_verify_full - Complete IOMMU verification
 * @status: Output structure to populate
 *
 * Runs every check and aggregates results.
 * For attestation to pass, IOMMU_FLAG_SYSFS_PRESENT and
 * IOMMU_FLAG_DMA_REMAP must be set.
 *
 * Returns: true if IOMMU is properly enabled, false otherwise
 */
bool iommu_verify_full(struct iommu_status *status);

/*
 * iommu_verify_full_at - iommu_verify_full() with every path read under @root
 * (NULL for the live machine)
 */
bool iommu_verify_full_at(struct iommu_status *status, const char *root);

/*
 * iommu_status_to_string - Convert status flags to human-readable string
 * @status: IOMMU status structure
 * @buf: Output buffer
 * @buf_len: Buffer size
 *
 * Returns: Number of bytes written (excluding null terminator)
 */
int iommu_status_to_string(const struct iommu_status *status, char *buf,
			   size_t buf_len);

#endif /* LOTA_IOMMU_H */
