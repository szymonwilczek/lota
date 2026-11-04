/* SPDX-License-Identifier: MIT */
/*
 * LOTA - MOK list reader
 *
 * shim mirrors the MOK list it measured into PCR 14 to MokListRT. Verifier
 * compares the data with that measurement, so the bytes go out as they are.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>

#include "moklist.h"

#define MOK_LIST_RT_PATH                       \
	"/sys/firmware/efi/efivars/MokListRT-" \
	"605dab50-e046-4300-abb6-3dd810dd8b23"

/* efivarfs prefixes a variable with its attributes */
#define EFI_VAR_ATTR_SIZE 4

/* Returns: bytes read, short only at end of file, or negative errno */
static ssize_t read_full(int fd, uint8_t *buf, size_t size)
{
	size_t got = 0;

	while (got < size) {
		ssize_t n = read(fd, buf + got, size - got);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (n == 0)
			break;
		got += (size_t)n;
	}
	return (ssize_t)got;
}

int mok_list_read_path(const char *path, uint8_t *buf, size_t buf_size,
		       uint32_t *out_size)
{
	uint8_t attrs[EFI_VAR_ATTR_SIZE];
	uint8_t probe;
	ssize_t got;
	int fd;

	if (!path || !buf || !out_size)
		return -EINVAL;

	*out_size = 0;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return errno == ENOENT ? 0 : -errno;

	got = read_full(fd, attrs, sizeof(attrs));
	if (got >= 0 && got != (ssize_t)sizeof(attrs))
		got = -ENODATA;
	if (got >= 0)
		got = read_full(fd, buf, buf_size);
	if (got == (ssize_t)buf_size && read_full(fd, &probe, 1) != 0)
		got = -E2BIG;
	close(fd);

	if (got < 0)
		return (int)got;

	*out_size = (uint32_t)got;
	return 0;
}

int mok_list_read(uint8_t *buf, size_t buf_size, uint32_t *out_size)
{
	return mok_list_read_path(MOK_LIST_RT_PATH, buf, buf_size, out_size);
}
