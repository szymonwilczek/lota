/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
#ifndef LOTA_AGENT_IO_UTILS_H
#define LOTA_AGENT_IO_UTILS_H

#include <stddef.h>

int lota_write_full(int fd, const void *buf, size_t len);
int lota_read_full(int fd, void *buf, size_t len);

/*
 * Carry one extended attribute from @from to @to, if @from has it.
 *
 * A writer that replaces a file by rename gives the replacement whatever
 * the parent directory implies, not what the file it replaced carried,
 * so a rewritten configuration can come back with an SELinux type the confined
 * agent cannot read -- and that denial is dontaudit'ed.
 * @name is the attribute to carry: production passes "security.selinux",
 * a test passes one it is allowed to set.
 *
 * Returns 0 when the attribute was carried or @from had none, and a negative
 * errno otherwise. A destination that refuses the attribute reports its own
 * errno; the data written is unaffected, so the caller decides what that is
 * worth.
 */
int lota_copy_xattr(const char *from, const char *to, const char *name);

/*
 * Read an entire file into buf, bounded by max.
 * A missing or empty file returns 0 with *out_len == 0 (absent, not an error).
 * A file larger than max returns -EMSGSIZE without reading.
 * Returns negative errno on failure.
 */
int lota_read_file_bounded(const char *path, void *buf, size_t max,
			   size_t *out_len);

#endif
