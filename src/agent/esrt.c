/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - ESRT System Firmware entry.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include "esrt.h"
#include "attestation.h"

#define ESRT_DEFAULT_BASE "/sys/firmware/efi/esrt/entries"

#define ESRT_FW_TYPE_SYSTEM 1

static int read_sysfs_u32(const char *dir, const char *name, uint32_t *out)
{
	char path[512];
	FILE *f;
	unsigned long val;

	if (snprintf(path, sizeof(path), "%s/%s", dir, name) >=
	    (int)sizeof(path))
		return -ENAMETOOLONG;
	f = fopen(path, "re");
	if (!f)
		return -errno;
	if (fscanf(f, "%lu", &val) != 1) {
		fclose(f);
		return -EINVAL;
	}
	fclose(f);
	if (val > UINT32_MAX)
		return -ERANGE;
	*out = (uint32_t)val;
	return 0;
}

static int parse_guid(const char *dir, uint8_t out[16])
{
	char path[512];
	char text[64];
	const char *p = text;
	FILE *f;
	int n = 0;

	if (snprintf(path, sizeof(path), "%s/fw_class", dir) >=
	    (int)sizeof(path))
		return -ENAMETOOLONG;
	f = fopen(path, "re");
	if (!f)
		return -errno;
	if (!fgets(text, sizeof(text), f)) {
		fclose(f);
		return -EINVAL;
	}
	fclose(f);

	while (*p && n < 16) {
		unsigned int byte;
		if (*p == '-') {
			p++;
			continue;
		}
		if (!isxdigit((unsigned char)p[0]) ||
		    !isxdigit((unsigned char)p[1]))
			return -EINVAL;
		if (sscanf(p, "%2x", &byte) != 1)
			return -EINVAL;
		out[n++] = (uint8_t)byte;
		p += 2;
	}
	return n == 16 ? 0 : -EINVAL;
}

int esrt_read_system_firmware_path(const char *base, struct lota_esrt *out)
{
	DIR *d;
	struct dirent *de;
	int found = 0;

	if (!base || !out)
		return -EINVAL;

	memset(out, 0, sizeof(*out));

	d = opendir(base);
	if (!d)
		return 0;

	while (!found && (de = readdir(d)) != NULL) {
		char dir[512];
		uint32_t fw_type = 0, fw_version = 0, lowest = 0;
		uint8_t guid[16];

		if (de->d_name[0] == '.')
			continue;
		if (snprintf(dir, sizeof(dir), "%s/%s", base, de->d_name) >=
		    (int)sizeof(dir))
			continue;

		if (read_sysfs_u32(dir, "fw_type", &fw_type) != 0)
			continue;
		if (fw_type != ESRT_FW_TYPE_SYSTEM)
			continue;
		if (read_sysfs_u32(dir, "fw_version", &fw_version) != 0)
			continue;
		(void)read_sysfs_u32(dir, "lowest_supported_fw_version",
				     &lowest);

		out->present = 1;
		out->fw_version = fw_version;
		out->lowest_supported = lowest;
		if (parse_guid(dir, guid) == 0)
			memcpy(out->fw_class, guid, sizeof(out->fw_class));
		found = 1;
	}

	closedir(d);
	return 0;
}

int esrt_read_system_firmware(struct lota_esrt *out)
{
	return esrt_read_system_firmware_path(ESRT_DEFAULT_BASE, out);
}
