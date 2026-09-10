/* SPDX-License-Identifier: MIT */
/*
 * LOTA - IOMMU Verification Module
 * Verifies VT-d (Intel) or AMD-Vi status for DMA attack protection
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>

#include "iommu.h"
#include "iommu_types.h"

/* Sysfs path for IOMMU class */
#define IOMMU_SYSFS_PATH "/sys/class/iommu"

/* Where the kernel command line is read from */
#define IOMMU_CMDLINE_PATH "/proc/cmdline"

/* One directory per IOMMU group, with its domain type */
#define IOMMU_GROUPS_PATH "/sys/kernel/iommu_groups"

/* The kernel's interrupt table, where a remapped chip names itself */
#define IOMMU_INTERRUPTS_PATH "/proc/interrupts"

/* prefix @path with @root (NULL: live machine); -1 if truncated */
static int iommu_path(char *buf, size_t len, const char *root, const char *path)
{
	int n = snprintf(buf, len, "%s%s", root ? root : "", path);

	if (n < 0 || (size_t)n >= len)
		return -1;
	return 0;
}

static int path_append(char *buf, size_t len, const char *component)
{
	size_t used = strlen(buf);
	int n;

	if (used >= len)
		return -1;

	n = snprintf(buf + used, len - used, "/%s", component);
	if (n < 0 || (size_t)n >= len - used)
		return -1;
	return 0;
}

static void set_iommu_cmdline(struct iommu_status *status, const char *param)
{
	status->flags |= IOMMU_FLAG_CMDLINE_SET;
	snprintf(status->cmdline_param, IOMMU_CMDLINE_PARAM_MAX, "%s", param);
}

static bool cmdline_has_param(const char *cmdline, const char *param)
{
	size_t plen = strlen(param);
	const char *p = cmdline;

	while ((p = strstr(p, param)) != NULL) {
		if (p != cmdline && p[-1] != ' ') {
			p += plen;
			continue;
		}

		if (p[plen] != '\0' && p[plen] != ' ' && p[plen] != '\n') {
			p += plen;
			continue;
		}
		return true;
	}
	return false;
}

int iommu_check_sysfs(struct iommu_status *status, const char *root)
{
	char path[PATH_MAX];
	DIR *dir;
	struct dirent *entry;
	int count = 0;

	if (!status)
		return -1;

	if (iommu_path(path, sizeof(path), root, IOMMU_SYSFS_PATH) < 0)
		return -1;

	dir = opendir(path);
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

int iommu_check_cmdline(struct iommu_status *status, const char *root)
{
	int fd;
#define IOMMU_READ_BUF_SIZE 4096
	char buf[IOMMU_READ_BUF_SIZE];
	char path[PATH_MAX];
	ssize_t n;
	int ret = -1;

	if (!status)
		return -1;

	if (iommu_path(path, sizeof(path), root, IOMMU_CMDLINE_PATH) < 0)
		return -1;

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;

	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);

	if (n <= 0)
		return -1;

	buf[n] = '\0';

	if (buf[n - 1] == '\n')
		buf[n - 1] = '\0';

	/*
	 * first match wins so Intel host with both arch families pinned on the
	 * command line never sees AMD overwrite the recorded value
	 */
	if (cmdline_has_param(buf, "intel_iommu=on")) {
		set_iommu_cmdline(status, "intel_iommu=on");
		ret = 0;
	} else if (cmdline_has_param(buf, "amd_iommu=force")) {
		set_iommu_cmdline(status, "amd_iommu=force");
		ret = 0;
	} else if (cmdline_has_param(buf, "amd_iommu=on")) {
		set_iommu_cmdline(status, "amd_iommu=on");
		ret = 0;
	}

	/*
	 * Check for strict mode - disables lazy IOMMU TLB flush
	 * More secure but slightly lower performance
	 */
	if (cmdline_has_param(buf, "iommu.strict=1") ||
	    cmdline_has_param(buf, "iommu=strict")) {
		status->flags |= IOMMU_FLAG_STRICT;
	}

	return ret;
}

/*
 * DMA and DMA-FQ translate (they differ only in flush timing); identity is
 * passthrough and blocked reaches nothing.
 * Unit presence alone would call an iommu=pt host protected.
 */
int iommu_check_domains(struct iommu_status *status, const char *root)
{
	char path[PATH_MAX];
	DIR *dir;
	struct dirent *entry;
	int translating = 0;

	if (!status)
		return -1;

	if (iommu_path(path, sizeof(path), root, IOMMU_GROUPS_PATH) < 0)
		return -1;

	dir = opendir(path);
	if (!dir) {
		/* no groups directory is a kernel with no IOMMU driver */
		return 0;
	}

	while ((entry = readdir(dir)) != NULL) {
		char type_path[PATH_MAX];
		char type[32];
		FILE *f;

		if (entry->d_name[0] == '.')
			continue;

		if (iommu_path(type_path, sizeof(type_path), root,
			       IOMMU_GROUPS_PATH) < 0)
			continue;
		if (path_append(type_path, sizeof(type_path), entry->d_name) <
		    0)
			continue;
		if (path_append(type_path, sizeof(type_path), "type") < 0)
			continue;

		f = fopen(type_path, "r");
		if (!f)
			continue;
		if (fgets(type, sizeof(type), f) &&
		    strncmp(type, "DMA", 3) == 0)
			translating++;
		fclose(f);
	}

	closedir(dir);

	if (translating > 0)
		status->flags |= IOMMU_FLAG_DMA_REMAP;

	return translating;
}

/* remapped chips are named IR-IO-APIC, IR-PCI-MSI, ... on both vendors */
int iommu_check_irq_remap(struct iommu_status *status, const char *root)
{
	char path[PATH_MAX];
	char line[512];
	FILE *f;

	if (!status)
		return -1;

	if (iommu_path(path, sizeof(path), root, IOMMU_INTERRUPTS_PATH) < 0)
		return -1;

	f = fopen(path, "r");
	if (!f)
		return -1;

	while (fgets(line, sizeof(line), f)) {
		if (strstr(line, " IR-")) {
			status->flags |= IOMMU_FLAG_IRQ_REMAP;
			break;
		}
	}

	fclose(f);
	return 0;
}

bool iommu_verify_full(struct iommu_status *status)
{
	return iommu_verify_full_at(status, NULL);
}

bool iommu_verify_full_at(struct iommu_status *status, const char *root)
{
	if (!status)
		return false;

	memset(status, 0, sizeof(*status));

	iommu_check_sysfs(status, root);
	iommu_check_cmdline(status, root);
	iommu_check_domains(status, root);
	iommu_check_irq_remap(status, root);

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
			   size_t buf_len)
{
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

	written = snprintf(
		buf, buf_len,
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
