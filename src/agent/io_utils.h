/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
#ifndef LOTA_AGENT_IO_UTILS_H
#define LOTA_AGENT_IO_UTILS_H

#include <stddef.h>

/* Return: 0, -EIO when write() takes no bytes, or an errno */
int lota_write_full(int fd, const void *buf, size_t len);
/* Return: 0, -ECONNRESET at end of file before @len bytes, or an errno */
int lota_read_full(int fd, void *buf, size_t len);

/**
 * lota_copy_xattr() - Carry one extended attribute from @from to @to.
 * @from: the file replaced by rename.
 * @to: its replacement, which takes the attributes its directory implies.
 * @name: the attribute.
 *
 * Return: 0 when the attribute was carried or @from has none, -EINVAL for
 * a NULL argument, -ERANGE for a value over 512 bytes, or the errno of
 * getxattr() or setxattr().
 */
int lota_copy_xattr(const char *from, const char *to, const char *name);

/**
 * lota_read_file_bounded() - Read a whole file of at most @max bytes.
 * @path: the file.
 * @buf: receives the contents.
 * @max: size of @buf.
 * @out_len: bytes read; 0 for a missing or empty file.
 *
 * Return: 0 (also for a missing or empty file), -EINVAL for a NULL
 * argument, -EMSGSIZE before any read for a file larger than @max,
 * or another negative errno.
 */
int lota_read_file_bounded(const char *path, void *buf, size_t max,
			   size_t *out_len);

#endif
