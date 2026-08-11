/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
#ifndef LOTA_AGENT_KERNEL_MEASURE_H
#define LOTA_AGENT_KERNEL_MEASURE_H

#include <stdint.h>

#include "../../include/lota.h"

/*
 * Which register carries the booted kernel depends on how the host boots,
 * so the agent tries several.
 * A register that exists is not a register that was extended: every TPM 2.0
 * answers for PCR 11 whether or not anything measured a unified kernel image
 * into it, and on a GRUB host it answers with zeros.
 *
 * Reading is a callback so the selection can be driven without a TPM.
 * Returns 0 and fills @out on success, negative on failure.
 */
typedef int (*kernel_pcr_reader)(void *ctx, int pcr,
				 uint8_t out[LOTA_HASH_SIZE]);

/*
 * kernel_measurement_select - take the kernel measurement from a PCR that has one
 *
 * Tries, in order: PCR 11 (UKI / systemd-stub), 9 (GRUB's kernel and initrd
 * measurements), 8 (GRUB command line), 4 (boot manager).
 * A register that cannot be read, or that reads as all zeros because nothing
 * extended it, is not a source.
 *
 * Returns 0 with @out_hash filled and @selected_pcr naming the register,
 * or -ENOENT when no candidate carries a measurement -- which is the answer
 * a caller must not report as a kernel hash of zeros.
 */
int kernel_measurement_select(kernel_pcr_reader read, void *ctx,
			      uint8_t out_hash[LOTA_HASH_SIZE],
			      int *selected_pcr);

#endif
