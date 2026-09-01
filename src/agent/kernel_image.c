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

/* TCG event types this reader names */
#define EV_NO_ACTION 0x00000003u
#define EV_IPL 0x0000000Du

/* TCG algorithm ids */
#define TCG_ALG_SHA1 0x0004u
#define TCG_ALG_SHA256 0x000Bu
#define TCG_ALG_SHA384 0x000Cu
#define TCG_ALG_SHA512 0x000Du

/*
 * The log comes from securityfs and is as long as the firmware made it,
 * so every count in it is read as a bound to check.
 * The caps match the verifier's.
 */
#define MAX_HEADER_DATA_SIZE (1u << 20)
#define MAX_EVENT_DATA_SIZE (1u << 20)
#define MAX_DIGEST_COUNT 16u

/* PCR 9 is where a bootloader records the files it read */
#define PCR_BOOT_FILES 9u

struct cursor {
	const uint8_t *data;
	size_t size;
	size_t off;
};

static bool take(struct cursor *c, size_t n, const uint8_t **out)
{
	if (n > c->size - c->off)
		return false;
	if (out)
		*out = c->data + c->off;
	c->off += n;
	return true;
}

static bool take_u16(struct cursor *c, uint16_t *out)
{
	const uint8_t *p;

	if (!take(c, sizeof(*out), &p))
		return false;
	*out = (uint16_t)((uint16_t)p[0] | (uint16_t)p[1] << 8);
	return true;
}

static bool take_u32(struct cursor *c, uint32_t *out)
{
	const uint8_t *p;

	if (!take(c, sizeof(*out), &p))
		return false;
	*out = (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 |
	       (uint32_t)p[3] << 24;
	return true;
}

static size_t alg_digest_size(uint16_t alg)
{
	switch (alg) {
	case TCG_ALG_SHA1:
		return 20;
	case TCG_ALG_SHA256:
		return 32;
	case TCG_ALG_SHA384:
		return 48;
	case TCG_ALG_SHA512:
		return 64;
	default:
		return 0;
	}
}

/*
 * The first record is the legacy TCG_PCR_EVENT that carries the Spec ID event:
 * PCR 0, EV_NO_ACTION, a SHA-1 digest field, then its data. Every record after
 * it is crypto-agile.
 */
static bool skip_legacy_header(struct cursor *c)
{
	uint32_t pcr, type, data_size;

	if (!take_u32(c, &pcr) || !take_u32(c, &type))
		return false;
	if (pcr != 0 || type != EV_NO_ACTION)
		return false;
	if (!take(c, 20, NULL))
		return false;
	if (!take_u32(c, &data_size))
		return false;
	if (data_size > MAX_HEADER_DATA_SIZE)
		return false;

	return take(c, data_size, NULL);
}

/*
 * Match the last path element against the verifier's kernel prefixes.
 * GRUB writes paths like (hd0,gpt2)/vmlinuz-6.19.4.
 */
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

/*
 * EV_IPL data is the path the bootloader read, NUL-terminated or not.
 * A path too long for out is refused.
 */
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
	struct cursor c = { .data = log, .size = log_size, .off = 0 };
	struct kernel_image found = { .digest = { 0 }, .path = { 0 } };
	bool have_one = false;
	bool missing_sha256 = false;

	if (!log || !out)
		return -EINVAL;

	if (!skip_legacy_header(&c))
		return -EINVAL;

	while (c.off < c.size) {
		uint32_t pcr, type, digest_count, data_size;
		const uint8_t *sha256 = NULL;
		const uint8_t *data;
		char path[KERNEL_IMAGE_PATH_MAX];

		if (!take_u32(&c, &pcr) || !take_u32(&c, &type) ||
		    !take_u32(&c, &digest_count))
			return -EINVAL;
		if (digest_count > MAX_DIGEST_COUNT)
			return -EINVAL;

		for (uint32_t i = 0; i < digest_count; i++) {
			uint16_t alg;
			size_t dsize;
			const uint8_t *digest;

			if (!take_u16(&c, &alg))
				return -EINVAL;
			dsize = alg_digest_size(alg);
			if (dsize == 0)
				return -EINVAL;
			if (!take(&c, dsize, &digest))
				return -EINVAL;
			if (alg == TCG_ALG_SHA256)
				sha256 = digest;
		}

		if (!take_u32(&c, &data_size))
			return -EINVAL;
		if (data_size > MAX_EVENT_DATA_SIZE)
			return -EINVAL;
		if (!take(&c, data_size, &data))
			return -EINVAL;

		if (pcr != PCR_BOOT_FILES || type != EV_IPL)
			continue;
		if (!ipl_path(data, data_size, path, sizeof(path)))
			continue;
		if (!kernel_image_path_names_kernel(path))
			continue;

		/*
		 * Kernel without a SHA-256 digest yields -ENOMSG only
		 * when no record with one is found
		 */
		if (!sha256) {
			missing_sha256 = true;
			continue;
		}

		if (have_one) {
			if (strcmp(found.path, path) == 0 &&
			    memcmp(found.digest, sha256, LOTA_HASH_SIZE) == 0)
				continue;
			/*
			 * Two kernels and the log does not say which ran.
			 * Every command line can be checked, but the digest
			 * names what booted, so there is none to return.
			 */
			return -EEXIST;
		}

		memcpy(found.digest, sha256, LOTA_HASH_SIZE);
		memcpy(found.path, path, strlen(path) + 1);
		have_one = true;
	}

	if (have_one) {
		*out = found;
		return 0;
	}
	return missing_sha256 ? -ENOMSG : -ENOENT;
}
