/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Certificate pin parsing.
 * See pin.h for why it does not live beside the TLS code that enforces the pin.
 */

#include "pin.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>

int lota_pin_sha256_parse(const char *hex, uint8_t *out)
{
	size_t i = 0;
	size_t out_idx = 0;
	uint8_t byte;
	int high;

	if (!hex || !out)
		return -EINVAL;

	while (hex[i] != '\0' && out_idx < LOTA_PIN_SHA256_LEN) {
		/* skip colons and spaces */
		if (hex[i] == ':' || hex[i] == ' ') {
			i++;
			continue;
		}

		/* need two hex nibbles */
		if (hex[i + 1] == '\0')
			return -EINVAL;

		high = 0;
		byte = 0;

		for (int n = 0; n < 2; n++) {
			char c = hex[i + n];
			uint8_t nibble;

			if (c >= '0' && c <= '9')
				nibble = (uint8_t)(c - '0');
			else if (c >= 'a' && c <= 'f')
				nibble = (uint8_t)(c - 'a' + 10);
			else if (c >= 'A' && c <= 'F')
				nibble = (uint8_t)(c - 'A' + 10);
			else
				return -EINVAL;

			if (n == 0)
				high = nibble;
			else
				byte = (uint8_t)((high << 4) | nibble);
		}

		out[out_idx++] = byte;
		i += 2;
	}

	while (hex[i] == ':' || hex[i] == ' ')
		i++;

	if (out_idx != LOTA_PIN_SHA256_LEN || hex[i] != '\0')
		return -EINVAL;

	return 0;
}
