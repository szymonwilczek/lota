/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */

#include "io_utils.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <sys/types.h>

int lota_write_full(int fd, const void *buf, size_t len)
{
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

int lota_read_full(int fd, void *buf, size_t len)
{
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

int lota_copy_xattr(const char *from, const char *to, const char *name)
{
	char value[512];
	ssize_t got;

	if (!from || !to || !name)
		return -EINVAL;

	got = getxattr(from, name, value, sizeof(value));
	if (got < 0) {
		if (errno == ENODATA || errno == ENOTSUP)
			return 0;
		return -errno;
	}

	if (setxattr(to, name, value, (size_t)got, 0) < 0)
		return -errno;

	return 0;
}

int lota_read_file_bounded(const char *path, void *buf, size_t max,
			   size_t *out_len)
{
	struct stat st;
	int fd, ret;

	if (!path || !buf || !out_len)
		return -EINVAL;

	*out_len = 0;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		if (errno == ENOENT)
			return 0;
		return -errno;
	}

	if (fstat(fd, &st) < 0) {
		ret = -errno;
		close(fd);
		return ret;
	}
	/* a directory may report size 0, which would read as no file */
	if (S_ISDIR(st.st_mode)) {
		close(fd);
		return -EISDIR;
	}
	if ((uintmax_t)st.st_size > (uintmax_t)max) {
		close(fd);
		return -EMSGSIZE;
	}
	if (st.st_size <= 0) {
		close(fd);
		return 0;
	}

	ret = lota_read_full(fd, buf, (size_t)st.st_size);
	close(fd);
	if (ret < 0)
		return ret;

	*out_len = (size_t)st.st_size;
	return 0;
}
