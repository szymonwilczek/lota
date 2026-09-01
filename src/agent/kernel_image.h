/* SPDX-License-Identifier: MIT */
/*
 * LOTA - the kernel image the bootloader measured
 *
 * The verifier pins the kernel by the digest the bootloader recorded for the
 * image, not by PCR 9: that register folds in every file GRUB read, grubenv
 * included, so it changes between boots of one kernel.
 *
 * The exporter uses this to write the value the verifier compares. The rules
 * mirror ExtractKernelImageDigest in src/verifier/verify/kernel_trust.go;
 * tests on both sides keep them in step.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#ifndef LOTA_KERNEL_IMAGE_H
#define LOTA_KERNEL_IMAGE_H

#include <stddef.h>
#include <stdint.h>

#include "../../include/lota.h"

/* Longest bootloader path this records, NUL included */
#define KERNEL_IMAGE_PATH_MAX 256

struct kernel_image {
	uint8_t digest[LOTA_HASH_SIZE];
	char path[KERNEL_IMAGE_PATH_MAX];
};

/*
 * kernel_image_from_event_log - find the measured kernel image in a TCG log
 *
 * Walks the PCR 9 EV_IPL records of a crypto-agile event log and returns the
 * SHA-256 digest of the one whose path names a kernel image.
 *
 * Returns 0 and fills @out when exactly one kernel image is measured.
 *
 *   -EINVAL   arguments, or a log this cannot parse
 *   -ENOENT   parsed, and no record names a kernel image
 *   -EEXIST   two different kernel images are measured, so the log does not
 *             say which one booted
 *   -ENOMSG   a kernel image is measured without a SHA-256 digest
 *
 * The four are separate because the caller says something different for each:
 * a log that does not parse is not a host that booted no kernel.
 */
int kernel_image_from_event_log(const uint8_t *log, size_t log_size,
				struct kernel_image *out);

/*
 * kernel_image_path_names_kernel - does this bootloader path name a kernel?
 *
 * Exposed for the tests that hold this file and the verifier's list together.
 */
bool kernel_image_path_names_kernel(const char *path);

#endif /* LOTA_KERNEL_IMAGE_H */
