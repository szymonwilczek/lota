// SPDX-License-Identifier: MIT
//
// Little-endian encoding helpers shared across user-space.

#ifndef LOTA_ENDIAN_H
#define LOTA_ENDIAN_H

#include <stdint.h>

static inline void lota__write_le32(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v);
  p[1] = (uint8_t)(v >> 8);
  p[2] = (uint8_t)(v >> 16);
  p[3] = (uint8_t)(v >> 24);
}

static inline void lota__write_le64(uint8_t *p, uint64_t v) {
  lota__write_le32(p, (uint32_t)v);
  lota__write_le32(p + 4, (uint32_t)(v >> 32));
}

#endif /* LOTA_ENDIAN_H */
