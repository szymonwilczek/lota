/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - IOMMU state of the host.
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

#define IOMMU_SYSFS_PATH "/sys/class/iommu"

#define IOMMU_CMDLINE_PATH "/proc/cmdline"

#define IOMMU_GROUPS_PATH "/sys/kernel/iommu_groups"

#define IOMMU_INTERRUPTS_PATH "/proc/interrupts"

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

static int cmdline_bool(const char *s)
{
	switch (s[0]) {
	case 'e':
	case 'E':
	case 'y':
	case 'Y':
	case 't':
	case 'T':
	case '1':
		return 1;
	case 'd':
	case 'D':
	case 'n':
	case 'N':
	case 'f':
	case 'F':
	case '0':
		return 0;
	case 'o':
	case 'O':
		if (s[1] == 'n' || s[1] == 'N')
			return 1;
		if (s[1] == 'f' || s[1] == 'F')
			return 0;
		return -1;
	default:
		return -1;
	}
}

static bool cmdline_option(const char *list, const char *opt)
{
	return strncmp(list, opt, strlen(opt)) == 0;
}

/* a dash in a parameter name reads as an underscore */
static bool cmdline_param(const char *word, const char *name)
{
	for (; *name; word++, name++) {
		char c = *word == '-' ? '_' : *word;

		if (c != *name)
			return false;
	}
	return true;
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
		return 0;
	}

	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_name[0] == '.')
			continue;

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
	const char *intel = NULL;
	const char *amd = NULL;
	bool amd_off = false;
	bool setup_strict = false;
	int strict = 0;

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

	for (char *save, *word = strtok_r(buf, " \t\n", &save); word;
	     word = strtok_r(NULL, " \t\n", &save)) {
		const char *v;

		if (strcmp(word, "--") == 0)
			break;

		if (cmdline_param(word, "intel_iommu=")) {
			for (v = word + 12; *v; v += strspn(v, ",")) {
				if (cmdline_option(v, "on"))
					intel = word;
				else if (cmdline_option(v, "off"))
					intel = NULL;
				else if (cmdline_option(v, "strict"))
					setup_strict = true;
				v += strcspn(v, ",");
			}
		} else if (cmdline_param(word, "amd_iommu=")) {
			for (v = word + 10; *v; v += strspn(v, ",")) {
				if (cmdline_option(v, "fullflush"))
					setup_strict = true;
				else if (cmdline_option(v, "force_enable"))
					amd = word;
				else if (cmdline_option(v, "off"))
					amd_off = true;
				v += strcspn(v, ",");
			}
		} else if (strncmp(word, "iommu.strict=", 13) == 0) {
			int on = cmdline_bool(word + 13);

			if (on >= 0)
				strict = on;
		}
	}

	if (intel) {
		set_iommu_cmdline(status, intel);
		ret = 0;
	} else if (amd && !amd_off) {
		set_iommu_cmdline(status, amd);
		ret = 0;
	}

	if (strict == 1 || setup_strict)
		status->flags |= IOMMU_FLAG_STRICT;

	return ret;
}

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
