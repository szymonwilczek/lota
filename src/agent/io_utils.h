/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
#ifndef LOTA_AGENT_IO_UTILS_H
#define LOTA_AGENT_IO_UTILS_H

#include <stddef.h>

int lota_write_full(int fd, const void *buf, size_t len);
int lota_read_full(int fd, void *buf, size_t len);

/*
 * Read an entire file into buf, bounded by max. A missing file returns 0
 * with *out_len == 0 (absent, not an error). A file larger than max
 * returns -EMSGSIZE without reading. Returns negative errno on failure.
 */
int lota_read_file_bounded(const char *path, void *buf, size_t max,
			   size_t *out_len);

#endif
