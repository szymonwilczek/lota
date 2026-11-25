/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
#ifndef LOTA_AGENT_KERNEL_MEASURE_H
#define LOTA_AGENT_KERNEL_MEASURE_H

#include <stdint.h>

#include "../../include/lota.h"

/**
 * typedef kernel_pcr_reader - Read one SHA-256 PCR.
 * @ctx: the caller's context.
 * @pcr: the register.
 * @out: its value.
 *
 * Return: 0 with @out filled; any other value skips the register.
 */
typedef int (*kernel_pcr_reader)(void *ctx, int pcr,
				 uint8_t out[LOTA_HASH_SIZE]);

/**
 * kernel_measurement_select() - Take the kernel measurement from a PCR.
 * @read: reads one register.
 * @ctx: passed to @read.
 * @out_hash: the value of the first usable register.
 * @selected_pcr: the register taken, -1 when none; may be NULL.
 *
 * Tries PCR 11, 9, 8 and 4 in that order and skips a register that
 * cannot be read or reads as all zeros.
 *
 * Return: 0, -EINVAL for a NULL @read or @out_hash, or -ENOENT when no
 * register is usable.
 */
int kernel_measurement_select(kernel_pcr_reader read, void *ctx,
			      uint8_t out_hash[LOTA_HASH_SIZE],
			      int *selected_pcr);

#endif
