/* SPDX-License-Identifier: MIT */
/*
 * LOTA - IOMMU Verification Module
 * Verifies VT-d (Intel) or AMD-Vi status for DMA attack protection
 */

#ifndef LOTA_IOMMU_H
#define LOTA_IOMMU_H

#include <stdbool.h>
#include <stdint.h>

#include "../../include/iommu_types.h"

/*
 * iommu_check_sysfs - Check /sys/class/iommu/ for active IOMMU units
 * @status: Output structure to populate
 *
 * Scans /sys/class/iommu/ for dmar* (Intel) or ivhd* (AMD) entries.
 * Sets IOMMU_FLAG_SYSFS_PRESENT and vendor type.
 *
 * Returns: Number of IOMMU units found, 0 if none
 */
int iommu_check_sysfs(struct iommu_status *status);

/*
 * iommu_check_cmdline - Validate /proc/cmdline for IOMMU boot parameters
 * @status: Output structure to populate
 *
 * Looks for: intel_iommu=on, amd_iommu=on/force, iommu.strict=1
 * Sets IOMMU_FLAG_CMDLINE_SET if found.
 *
 * Returns: 0 if IOMMU param found, -1 if missing
 */
int iommu_check_cmdline(struct iommu_status *status);

/*
 * iommu_check_dmesg - Parse kernel ring buffer for IOMMU messages
 * @status: Output structure to populate
 *
 * Requires: CAP_SYSLOG capability or root privileges.
 * Uses klogctl(SYSLOG_ACTION_READ_ALL) to read kernel log.
 * Looks for "DMAR: IOMMU enabled", "AMD-Vi: Initialized", etc.
 *
 * Returns: 0 on success, -1 on error (permission denied, etc.)
 */
int iommu_check_dmesg(struct iommu_status *status);

/*
 * iommu_verify_full - Complete IOMMU verification
 * @status: Output structure to populate
 *
 * Runs all three checks and aggregates results.
 * For attestation to pass, at minimum IOMMU_FLAG_SYSFS_PRESENT
 * should be set.
 *
 * Returns: true if IOMMU is properly enabled, false otherwise
 */
bool iommu_verify_full(struct iommu_status *status);

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
