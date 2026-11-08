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

bool kernel_image_path_names_kernel(const char *path)
{
	static const char *const prefixes[] = { "vmlinuz", "kernel",
						"bzImage" };
	const char *base = path;

	if (!path)
		return false;

	for (const char *p = path; *p; p++) {
		if (*p == '/' || *p == '\\')
			base = p + 1;
	}

	for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); i++) {
		if (strncmp(base, prefixes[i], strlen(prefixes[i])) == 0)
			return true;
	}
	return false;
}

static bool ipl_path(const uint8_t *data, size_t size, char *out,
		     size_t out_size)
{
	size_t len = 0;

	while (len < size && data[len] != '\0')
		len++;
	if (len >= out_size)
		return false;

	memcpy(out, data, len);
	out[len] = '\0';
	return true;
}

int kernel_image_from_event_log(const uint8_t *log, size_t log_size,
				struct kernel_image *out)
{
	struct tcg_log c;
	struct tcg_event ev;
	struct kernel_image found = { .digest = { 0 }, .path = { 0 } };
	bool have_one = false;
	bool missing_sha256 = false;
	int ret;

	if (!log || !out)
		return -EINVAL;

	if (tcg_log_open(&c, log, log_size) < 0)
		return -EINVAL;

	while ((ret = tcg_log_next(&c, &ev)) > 0) {
		const uint8_t *sha256 = ev.sha256;
		char path[KERNEL_IMAGE_PATH_MAX];

		if (ev.pcr != PCR_BOOT_FILES || ev.type != TCG_EV_IPL)
			continue;
		if (!ipl_path(ev.data, ev.data_size, path, sizeof(path)))
			continue;
		if (!kernel_image_path_names_kernel(path))
			continue;

		if (!sha256) {
			missing_sha256 = true;
			continue;
		}

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
	return missing_sha256 ? -ENOMSG : -ENOENT;
}
