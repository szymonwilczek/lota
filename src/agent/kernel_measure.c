/* SPDX-License-Identifier: MIT */
/*
 * LOTA - selecting the PCR that carries the booted kernel
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "../../include/lota.h"
#include "kernel_measure.h"

static int digest_is_all_zero(const uint8_t digest[LOTA_HASH_SIZE])
{
	uint8_t acc = 0;

	for (size_t i = 0; i < LOTA_HASH_SIZE; i++)
		acc |= digest[i];

	return acc == 0;
}

int kernel_measurement_select(kernel_pcr_reader read, void *ctx,
			      uint8_t out_hash[LOTA_HASH_SIZE],
			      int *selected_pcr)
{
	static const int candidates[] = { 11, 9, 8, 4 };

	if (!read || !out_hash)
		return -EINVAL;

	for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]);
	     i++) {
		uint8_t digest[LOTA_HASH_SIZE];

		if (read(ctx, candidates[i], digest) != 0)
			continue;

		/*
		 * An unextended register reads as zeros. Reported as the kernel
		 * measurement, zeros make every host on the same boot path look
		 * identical, and an allow-list built from them admits all of them.
		 */
		if (digest_is_all_zero(digest))
			continue;

		memcpy(out_hash, digest, LOTA_HASH_SIZE);
		if (selected_pcr)
			*selected_pcr = candidates[i];
		return 0;
	}

	if (selected_pcr)
		*selected_pcr = -1;
	return -ENOENT;
}
