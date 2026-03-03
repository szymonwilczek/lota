/* SPDX-License-Identifier: MIT */
#ifndef LOTA_AGENT_IO_UTILS_H
#define LOTA_AGENT_IO_UTILS_H

#include <stddef.h>

int lota_write_full(int fd, const void *buf, size_t len);
int lota_read_full(int fd, void *buf, size_t len);

#endif
