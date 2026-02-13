/* SPDX-License-Identifier: MIT */
/*
 * LOTA - IOMMU Type Definitions
 * Shared between attestation report and IOMMU verification module
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_IOMMU_TYPES_H
#define LOTA_IOMMU_TYPES_H

#include <stdint.h>

/* IOMMU vendor types */
enum iommu_vendor {
  IOMMU_VENDOR_NONE = 0,
  IOMMU_VENDOR_INTEL_VTD, /* Intel VT-d (DMAR) */
  IOMMU_VENDOR_AMD_VI,    /* AMD-Vi (IVRS/IVHD) */
};

/* IOMMU status flags - bitmask */
#define IOMMU_FLAG_SYSFS_PRESENT (1U << 0) /* /sys/class/iommu/ has entries */
#define IOMMU_FLAG_CMDLINE_SET (1U << 1)   /* Boot param explicitly set */
#define IOMMU_FLAG_DMA_REMAP (1U << 2)     /* DMA remapping active (dmesg) */
#define IOMMU_FLAG_IRQ_REMAP (1U << 3)     /* Interrupt remapping (dmesg) */
#define IOMMU_FLAG_STRICT (1U << 4)        /* Strict mode (no lazy unmap) */

/* Maximum length for cmdline parameter storage */
#define IOMMU_CMDLINE_PARAM_MAX 64

/*
 * IOMMU verification result.
 * This struct is included in the attestation report.
 */
struct iommu_status {
  enum iommu_vendor vendor;
  uint32_t flags;
  uint32_t unit_count;                         /* Number of IOMMU units found */
  char cmdline_param[IOMMU_CMDLINE_PARAM_MAX]; /* Actual param from cmdline */
} __attribute__((packed));

#endif /* LOTA_IOMMU_TYPES_H */
