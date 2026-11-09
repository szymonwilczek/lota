/* SPDX-License-Identifier: MIT */
/*
 * LOTA - the kernel image the bootloader measured
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#ifndef LOTA_KERNEL_IMAGE_H
#define LOTA_KERNEL_IMAGE_H

#include <stddef.h>
#include <stdint.h>

#include "../../include/lota.h"

#define KERNEL_IMAGE_PATH_MAX 256

/**
 * struct kernel_image - The kernel image a TCG log measures.
 * @digest: its SHA-256 digest.
 * @path: the path the bootloader logged.
 */
struct kernel_image {
	uint8_t digest[LOTA_HASH_SIZE];
	char path[KERNEL_IMAGE_PATH_MAX];
};

/**
 * kernel_image_from_event_log() - Find the measured kernel image in a TCG log.
 * @log: a crypto-agile event log.
 * @log_size: its length.
 * @out: the image.
 *
 * Reads the PCR 9 EV_IPL records whose path names a kernel image.
 *
 * Return: 0 when the images agree, -EINVAL for a bad argument or a log that
 * does not parse, -ENOENT when no record names a kernel image, -EEXIST for two
 * such images that differ in path or digest, -ENOMSG for an image measured
 * without a SHA-256 digest, or -ENAMETOOLONG for an image path of
 * KERNEL_IMAGE_PATH_MAX bytes or more.
 */
int kernel_image_from_event_log(const uint8_t *log, size_t log_size,
				struct kernel_image *out);

/**
 * kernel_image_path_names_kernel() - Does a bootloader path name a kernel?
 * @path: the logged path, or NULL.
 *
 * Return: true when the last path element starts with vmlinuz, kernel or
 * bzImage.
 */
bool kernel_image_path_names_kernel(const char *path);

#endif /* LOTA_KERNEL_IMAGE_H */
