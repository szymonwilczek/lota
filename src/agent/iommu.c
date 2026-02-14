/* SPDX-License-Identifier: MIT */
/*
 * LOTA - IOMMU Verification Module
 * Verifies VT-d (Intel) or AMD-Vi status for DMA attack protection
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/klog.h>
#include <unistd.h>

#include "iommu.h"

/* Sysfs path for IOMMU class */
#define IOMMU_SYSFS_PATH "/sys/class/iommu"

/* Kernel log buffer size (1 MB, covers typical dmesg output) */
#define KLOG_BUF_SIZE (1 << 20)

/* klogctl actions */
#define SYSLOG_ACTION_READ_ALL 3

int iommu_check_sysfs(struct iommu_status *status) {
  DIR *dir;
  struct dirent *entry;
  int count = 0;

  if (!status)
    return -1;

  dir = opendir(IOMMU_SYSFS_PATH);
  if (!dir) {
    /* kernel might not support it */
    return 0;
  }

  while ((entry = readdir(dir)) != NULL) {
    if (entry->d_name[0] == '.')
      continue;

    /*
     * Intel VT-d: dmar0, dmar1, ...
     * AMD-Vi: ivhd0, ivhd1, ...
     */
    if (strncmp(entry->d_name, "dmar", 4) == 0) {
      status->vendor = IOMMU_VENDOR_INTEL_VTD;
      count++;
    } else if (strncmp(entry->d_name, "ivhd", 4) == 0) {
      status->vendor = IOMMU_VENDOR_AMD_VI;
      count++;
    }
  }

  closedir(dir);

  if (count > 0)
    status->flags |= IOMMU_FLAG_SYSFS_PRESENT;

  status->unit_count = (uint32_t)count;
  return count;
}

int iommu_check_cmdline(struct iommu_status *status) {
  int fd;
  char buf[4096];
  ssize_t n;
  int ret = -1;

  if (!status)
    return -1;

  fd = open("/proc/cmdline", O_RDONLY);
  if (fd < 0)
    return -1;

  n = read(fd, buf, sizeof(buf) - 1);
  close(fd);

  if (n <= 0)
    return -1;

  buf[n] = '\0';

  if (n > 0 && buf[n - 1] == '\n')
    buf[n - 1] = '\0';

  /*
   * Check for Intel IOMMU parameters
   * intel_iommu=on enables IOMMU
   */
  if (strstr(buf, "intel_iommu=on")) {
    status->flags |= IOMMU_FLAG_CMDLINE_SET;
    strncpy(status->cmdline_param, "intel_iommu=on",
            IOMMU_CMDLINE_PARAM_MAX - 1);
    status->cmdline_param[IOMMU_CMDLINE_PARAM_MAX - 1] = '\0';
    ret = 0;
  }

  /*
   * Check for AMD IOMMU parameters
   * amd_iommu=on or amd_iommu=force
   */
  if (strstr(buf, "amd_iommu=force")) {
    status->flags |= IOMMU_FLAG_CMDLINE_SET;
    strncpy(status->cmdline_param, "amd_iommu=force",
            IOMMU_CMDLINE_PARAM_MAX - 1);
    status->cmdline_param[IOMMU_CMDLINE_PARAM_MAX - 1] = '\0';
    ret = 0;
  } else if (strstr(buf, "amd_iommu=on")) {
    status->flags |= IOMMU_FLAG_CMDLINE_SET;
    strncpy(status->cmdline_param, "amd_iommu=on", IOMMU_CMDLINE_PARAM_MAX - 1);
    status->cmdline_param[IOMMU_CMDLINE_PARAM_MAX - 1] = '\0';
    ret = 0;
  }

  /*
   * Check for strict mode - disables lazy IOMMU TLB flush
   * More secure but slightly lower performance
   */
  if (strstr(buf, "iommu.strict=1") || strstr(buf, "iommu=strict")) {
    status->flags |= IOMMU_FLAG_STRICT;
  }

  return ret;
}

int iommu_check_dmesg(struct iommu_status *status) {
  char *log;
  int len;

  if (!status)
    return -1;

  log = malloc(KLOG_BUF_SIZE);
  if (!log)
    return -1;

  /*
   * Read kernel ring buffer using klogctl syscall.
   * Requires CAP_SYSLOG capability or root.
   */
  len = klogctl(SYSLOG_ACTION_READ_ALL, log, KLOG_BUF_SIZE);
  if (len < 0) {
    free(log);
    return -1;
  }

  if (len < KLOG_BUF_SIZE)
    log[len] = '\0';
  else
    log[KLOG_BUF_SIZE - 1] = '\0';

  /*
   * Intel VT-d indicators in dmesg:
   * - "DMAR: IOMMU enabled"
   * - "DMAR-IR: Enabled" (interrupt remapping)
   */
  if (strstr(log, "DMAR: IOMMU enabled") ||
      strstr(log, "DMAR: Intel(R) Virtualization Technology")) {
    status->flags |= IOMMU_FLAG_DMA_REMAP;
  }

  /*
   * AMD-Vi indicators in dmesg:
   * - "AMD-Vi: Initialized"
   * - "AMD-Vi: Interrupt remapping enabled"
   */
  if (strstr(log, "AMD-Vi: Initialized") ||
      strstr(log, "AMD-Vi: Found IOMMU") ||
      strstr(log, "pci 0000:00:00.2: AMD-Vi")) {
    status->flags |= IOMMU_FLAG_DMA_REMAP;
  }

  /*
   * Interrupt remapping indicators
   */
  if (strstr(log, "Interrupt remapping enabled") ||
      strstr(log, "DMAR-IR: Enabled") ||
      strstr(log, "AMD-Vi: Interrupt remapping enabled")) {
    status->flags |= IOMMU_FLAG_IRQ_REMAP;
  }

  free(log);
  return 0;
}

bool iommu_verify_full(struct iommu_status *status) {
  if (!status)
    return false;

  memset(status, 0, sizeof(*status));

  iommu_check_sysfs(status);
  iommu_check_cmdline(status);
  iommu_check_dmesg(status);

  /*
   * Minimum requirement: IOMMU must be present in sysfs and have
   * confirmed DMA remapping active.
   *
   * IOMMU_FLAG_CMDLINE_SET is not strictly required
   * on modern systems where UEFI enables IOMMU by default.
   */
  return (status->flags & IOMMU_FLAG_SYSFS_PRESENT) &&
         (status->flags & IOMMU_FLAG_DMA_REMAP);
}

int iommu_status_to_string(const struct iommu_status *status, char *buf,
                           size_t buf_len) {
  const char *vendor_str;
  int written;

  if (!status || !buf || buf_len == 0)
    return -1;

  switch (status->vendor) {
  case IOMMU_VENDOR_INTEL_VTD:
    vendor_str = "Intel VT-d";
    break;
  case IOMMU_VENDOR_AMD_VI:
    vendor_str = "AMD-Vi";
    break;
  case IOMMU_VENDOR_NONE:
  default:
    vendor_str = "None";
    break;
  }

  written = snprintf(buf, buf_len,
                     "IOMMU Status:\n"
                     "  Vendor: %s\n"
                     "  Units: %u\n"
                     "  Flags: 0x%08x\n"
                     "    Sysfs Present: %s\n"
                     "    Cmdline Set: %s (%s)\n"
                     "    DMA Remap: %s\n"
                     "    IRQ Remap: %s\n"
                     "    Strict Mode: %s\n",
                     vendor_str, status->unit_count, status->flags,
                     (status->flags & IOMMU_FLAG_SYSFS_PRESENT) ? "yes" : "no",
                     (status->flags & IOMMU_FLAG_CMDLINE_SET) ? "yes" : "no",
                     status->cmdline_param[0] ? status->cmdline_param : "none",
                     (status->flags & IOMMU_FLAG_DMA_REMAP) ? "yes" : "no",
                     (status->flags & IOMMU_FLAG_IRQ_REMAP) ? "yes" : "no",
                     (status->flags & IOMMU_FLAG_STRICT) ? "yes" : "no");

  return written;
}
