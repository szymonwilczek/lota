/* SPDX-License-Identifier: MIT */
/*
 * IOMMU status, shared by the attestation report and the agent's IOMMU check.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_IOMMU_TYPES_H
#define LOTA_IOMMU_TYPES_H

#include <stdint.h>

enum iommu_vendor {
	IOMMU_VENDOR_NONE = 0,
	IOMMU_VENDOR_INTEL_VTD, /* Intel VT-d (DMAR) */
	IOMMU_VENDOR_AMD_VI, /* AMD-Vi (IVRS/IVHD) */
};

/* iommu_status.flags */
#define IOMMU_FLAG_SYSFS_PRESENT (1U << 0) /* /sys/class/iommu/ has entries */
#define IOMMU_FLAG_CMDLINE_SET (1U << 1) /* Boot param explicitly set */
#define IOMMU_FLAG_DMA_REMAP (1U << 2) /* A group is in a translating domain */
#define IOMMU_FLAG_IRQ_REMAP \
	(1U << 3) /* An interrupt goes through an IR- chip */
#define IOMMU_FLAG_STRICT (1U << 4) /* Strict mode (no lazy unmap) */

#define IOMMU_CMDLINE_PARAM_MAX 64

struct iommu_status {
	enum iommu_vendor vendor;
	uint32_t flags;
	uint32_t unit_count;
	char cmdline_param[IOMMU_CMDLINE_PARAM_MAX];
} __attribute__((packed));

#endif /* LOTA_IOMMU_TYPES_H */
