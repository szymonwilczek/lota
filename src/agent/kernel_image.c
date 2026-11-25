/* SPDX-License-Identifier: MIT */
/*
 * LOTA - the kernel image the bootloader measured
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "../../include/lota.h"
#include "kernel_image.h"
#include "tcg_log.h"

#define PCR_BOOT_FILES 9u

static bool names_kernel(const char *path, size_t len)
{
	static const char *const prefixes[] = { "vmlinuz", "kernel",
						"bzImage" };
	size_t base = 0;

	for (size_t i = 0; i < len; i++) {
		if (path[i] == '/' || path[i] == '\\')
			base = i + 1;
	}

	for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
		size_t n = strlen(prefixes[i]);

		if (len - base >= n && memcmp(path + base, prefixes[i], n) == 0)
			return true;
	}
	return false;
}

bool kernel_image_path_names_kernel(const char *path)
{
	return path && names_kernel(path, strlen(path));
}

int kernel_image_from_event_log(const uint8_t *log, size_t log_size,
				struct kernel_image *out)
{
	struct tcg_log c;
	struct tcg_event ev;
	struct kernel_image found = { .digest = { 0 }, .path = { 0 } };
	bool have_one = false;
	int ret;

	if (!log || !out)
		return -EINVAL;

	if (tcg_log_open(&c, log, log_size) < 0)
		return -EINVAL;

	while ((ret = tcg_log_next(&c, &ev)) > 0) {
		const uint8_t *sha256 = ev.sha256;
		char path[KERNEL_IMAGE_PATH_MAX];
		size_t len = 0;

		if (ev.pcr != PCR_BOOT_FILES || ev.type != TCG_EV_IPL)
			continue;
		while (len < ev.data_size && ev.data[len] != '\0')
			len++;
		if (!names_kernel((const char *)ev.data, len))
			continue;
		if (len >= sizeof(path))
			return -ENAMETOOLONG;
		if (!sha256)
			return -ENOMSG;
		memcpy(path, ev.data, len);
		path[len] = '\0';

		if (have_one) {
			if (strcmp(found.path, path) == 0 &&
			    memcmp(found.digest, sha256, LOTA_HASH_SIZE) == 0)
				continue;
			return -EEXIST;
		}

		memcpy(found.digest, sha256, LOTA_HASH_SIZE);
		memcpy(found.path, path, strlen(path) + 1);
		have_one = true;
	}
	if (ret < 0)
		return -EINVAL;

	if (have_one) {
		*out = found;
		return 0;
	}
	return -ENOENT;
}
