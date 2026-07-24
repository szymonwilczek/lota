/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * LOTA enrollment state - persist the CA endpoint a host last enrolled
 * against and the AIK generation the issued certificate is bound to.
 *
 * Self-contained file I/O so it stays unit-testable apart from the TPM and
 * network stack the enrollment ceremony pulls in. The record is same-host
 * state written behind a magic/version guard; see struct enroll_state.
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#include "enroll.h"

/* Write a file atomically: write a temp file, fsync, then rename. */
static int state_write_atomic(const char *path, const void *data, size_t len,
			      mode_t mode)
{
	char tmp[PATH_MAX];
	const uint8_t *p = data;
	size_t off = 0;
	int fd, ret;

	if (snprintf(tmp, sizeof(tmp), "%s.tmp", path) >= (int)sizeof(tmp))
		return -ENAMETOOLONG;

	fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
	if (fd < 0)
		return -errno;

	while (off < len) {
		ssize_t w = write(fd, p + off, len - off);
		if (w < 0) {
			ret = -errno;
			close(fd);
			unlink(tmp);
			return ret;
		}
		off += (size_t)w;
	}

	if (fsync(fd) < 0) {
		ret = -errno;
		close(fd);
		unlink(tmp);
		return ret;
	}
	if (close(fd) < 0) {
		ret = -errno;
		unlink(tmp);
		return ret;
	}
	if (rename(tmp, path) < 0) {
		ret = -errno;
		unlink(tmp);
		return ret;
	}
	return 0;
}

int enroll_state_save_path(const char *path, const struct enroll_state *st)
{
	struct enroll_state on_disk;

	if (!path || !st)
		return -EINVAL;
	on_disk = *st;
	on_disk.magic = LOTA_ENROLL_STATE_MAGIC;
	on_disk.version = LOTA_ENROLL_STATE_VERSION;
	/* endpoint, not a secret, but it pins the CA the host re-enrolls to;
	 * keep it root-only */
	return state_write_atomic(path, &on_disk, sizeof(on_disk), 0600);
}

int enroll_state_load_path(const char *path, struct enroll_state *out)
{
	/* version-1 record ends where the token field begins */
	const size_t v1_size = offsetof(struct enroll_state, enroll_token);
	struct enroll_state st;
	ssize_t n;
	int fd;

	if (!path || !out)
		return -EINVAL;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno; /* -ENOENT when the host has never enrolled */

	memset(&st, 0, sizeof(st));
	n = read(fd, &st, sizeof(st));
	close(fd);
	if (n < 0)
		return -errno;
	if (st.magic != LOTA_ENROLL_STATE_MAGIC)
		return -EINVAL;
	if (!((size_t)n == sizeof(st) &&
	      st.version == LOTA_ENROLL_STATE_VERSION) &&
	    !((size_t)n == v1_size && st.version == 1))
		return -EINVAL;

	/* NUL-terminate the string fields defensively before use */
	st.ca_server[sizeof(st.ca_server) - 1] = '\0';
	st.ca_cert[sizeof(st.ca_cert) - 1] = '\0';
	st.enroll_token[sizeof(st.enroll_token) - 1] = '\0';
	*out = st;
	return 0;
}

int enroll_state_save(const struct enroll_state *st)
{
	return enroll_state_save_path(LOTA_ENROLL_STATE_PATH, st);
}

int enroll_state_load(struct enroll_state *out)
{
	return enroll_state_load_path(LOTA_ENROLL_STATE_PATH, out);
}
