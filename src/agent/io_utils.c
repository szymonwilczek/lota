/* SPDX-License-Identifier: MIT */

#include "io_utils.h"

#include <errno.h>
#include <stdint.h>
#include <unistd.h>

int lota_write_full(int fd, const void *buf, size_t len) {
  const uint8_t *p = buf;

  while (len > 0) {
    ssize_t n = write(fd, p, len);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      return -errno;
    }
    if (n == 0)
      return -EIO;
    p += (size_t)n;
    len -= (size_t)n;
  }

  return 0;
}

int lota_read_full(int fd, void *buf, size_t len) {
  uint8_t *p = buf;

  while (len > 0) {
    ssize_t n = read(fd, p, len);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      return -errno;
    }
    if (n == 0)
      return -ECONNRESET;
    p += (size_t)n;
    len -= (size_t)n;
  }

  return 0;
}
