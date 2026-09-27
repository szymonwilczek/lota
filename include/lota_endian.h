/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Little-endian encoding helpers shared across user-space.
 */

#ifndef LOTA_ENDIAN_H
#define LOTA_ENDIAN_H

#include <stdint.h>

/*
 * Each byte is masked before the cast.
 * The cast alone truncates, which is what these want, but it leaves a checker
 * unable to tell a deliberate narrowing from an accidental one -- and callers
 * pass magic constants, so the truncation is visible after constant folding.
 */
static inline void lota__write_le16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v & 0xffu);
	p[1] = (uint8_t)((v >> 8) & 0xffu);
}

static inline void lota__write_le32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v & 0xffu);
	p[1] = (uint8_t)((v >> 8) & 0xffu);
	p[2] = (uint8_t)((v >> 16) & 0xffu);
	p[3] = (uint8_t)((v >> 24) & 0xffu);
}

static inline void lota__write_le64(uint8_t *p, uint64_t v)
{
	lota__write_le32(p, (uint32_t)v);
	lota__write_le32(p + 4, (uint32_t)(v >> 32));
}

#endif /* LOTA_ENDIAN_H */
