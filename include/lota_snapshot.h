/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Attestation snapshot file: a header, then the token. Shared by its writer,
 * the Wine hook, and its reader, the anti-cheat SDK.
 */

#ifndef LOTA_SNAPSHOT_H
#define LOTA_SNAPSHOT_H

#include <stdint.h>

/* Snapshot filename inside the token directory */
#define LOTA_SNAPSHOT_FILE_NAME "lota-attestation.bin"

/* "LOTA" little-endian */
#define LOTA_SNAPSHOT_MAGIC 0x41544F4CUL

#define LOTA_SNAPSHOT_VERSION 1

#define LOTA_SNAPSHOT_HEADER_SIZE 16

struct lota_snapshot_wire_hdr {
	uint32_t magic;
	uint16_t version;
	uint16_t reserved; /* must be 0 */
	uint32_t flags;
	uint32_t token_size;
} __attribute__((packed));

#if defined(__STDC_VERSION__) && (__STDC_VERSION__ >= 201112L)
_Static_assert(sizeof(struct lota_snapshot_wire_hdr) ==
		       LOTA_SNAPSHOT_HEADER_SIZE,
	       "snapshot header size must be 16 bytes");
#endif

#endif /* LOTA_SNAPSHOT_H */
