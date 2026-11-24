/* SPDX-License-Identifier: MIT */
/*
 * LOTA - MOK list reader
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_MOKLIST_H
#define LOTA_MOKLIST_H

#include <stddef.h>
#include <stdint.h>

/* longer list goes unsent: it counts against the verifier's report size cap */
#define MOK_LIST_MAX (32 * 1024)

/*
 * mok_list_read - Read MokListRT, without its EFI attributes
 * @buf: Output buffer
 * @buf_size: Size of output buffer
 * @out_size: Bytes of list data; 0 unless this returns 0 with a list present
 *
 * Returns: 0 on success, also when the variable does not exist (a boot
 * without shim), negative errno otherwise
 */
int mok_list_read(uint8_t *buf, size_t buf_size, uint32_t *out_size);

/* same, reading the variable from @path (tests) */
int mok_list_read_path(const char *path, uint8_t *buf, size_t buf_size,
		       uint32_t *out_size);

#endif /* LOTA_MOKLIST_H */
