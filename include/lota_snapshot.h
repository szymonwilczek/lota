/* SPDX-License-Identifier: MIT */
/*
 * LOTA atomic attestation snapshot (writer/reader shared constants)
 */

#ifndef LOTA_SNAPSHOT_H
#define LOTA_SNAPSHOT_H

#include <stdint.h>

/* Snapshot filename inside the token directory */
#define LOTA_SNAPSHOT_FILE_NAME "lota-attestation.bin"

/* "LOTA" little-endian */
#define LOTA_SNAPSHOT_MAGIC 0x41544F4CUL

/* Bump when wire header semantics change */
#define LOTA_SNAPSHOT_VERSION 1

/* Fixed header size on disk */
#define LOTA_SNAPSHOT_HEADER_SIZE 16

struct lota_snapshot_wire_hdr {
  uint32_t magic;      /* offset 0 */
  uint16_t version;    /* offset 4 */
  uint16_t reserved;   /* offset 6 (must be 0 for v1) */
  uint32_t flags;      /* offset 8 */
  uint32_t token_size; /* offset 12 */
} __attribute__((packed));

#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)
_Static_assert(sizeof(struct lota_snapshot_wire_hdr) ==
                   LOTA_SNAPSHOT_HEADER_SIZE,
               "snapshot header size must be 16 bytes");
#endif

#endif /* LOTA_SNAPSHOT_H */
