/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - File integrity fingerprint helper
 *
 * IMPORTANT SECURITY NOTE:
 * This module intentionally does NOT compute userspace content hashes for
 * security decisions. Userspace read-and-hash is vulnerable to TOCTOU races.
 *
 * Instead, it derives a stable 32-byte fingerprint from kernel-measured
 * fs-verity digest for already-open file descriptors. If fs-verity is not
 * enabled/available for the file, verification fails closed.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include "hash_verify.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/fsverity.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "lota.h"

int hash_verify_init(struct hash_verify_ctx *ctx)
{
	if (!ctx)
		return -EINVAL;

	memset(ctx, 0, sizeof(*ctx));
	return 0;
}

void hash_verify_cleanup(struct hash_verify_ctx *ctx)
{
	if (!ctx)
		return;
	memset(ctx, 0, sizeof(*ctx));
}

/*
 * Compute SHA-256 from an already-open file descriptor.
 * The caller is responsible for opening and closing the fd.
 */
static int hash_fd(int fd, uint8_t sha256_out[LOTA_HASH_SIZE])
{
	/*
	 * fsverity_digest ends in a flexible array; back it with a buffer
	 * sized for the largest digest. The struct is the last union member
	 * so the flexible array sits at the end, which clang requires (gcc
	 * accepts the field-not-at-end GNU extension, clang -Werror rejects
	 * it).
	 */
	union {
		uint8_t buf[sizeof(struct fsverity_digest) +
			    LOTA_VERITY_DIGEST_MAX_SIZE];
		struct fsverity_digest hdr;
	} d;

	if (fd < 0 || !sha256_out)
		return -EINVAL;

	memset(&d, 0, sizeof(d));
	d.hdr.digest_size = (uint16_t)LOTA_VERITY_DIGEST_MAX_SIZE;

	if (ioctl(fd, FS_IOC_MEASURE_VERITY, &d) != 0) {
		int err = errno;

		if (err == ENODATA || err == ENOTTY || err == EOPNOTSUPP)
			return -ENODATA;
		return -err;
	}

	if (d.hdr.digest_size < LOTA_HASH_SIZE ||
	    d.hdr.digest_size > LOTA_VERITY_DIGEST_MAX_SIZE)
		return -EPROTO;

	memcpy(sha256_out, d.hdr.digest, LOTA_HASH_SIZE);
	return 0;
}

int hash_verify_file(const char *path, uint8_t sha256_out[LOTA_HASH_SIZE])
{
	int fd;
	int ret;

	if (!path || !sha256_out)
		return -EINVAL;

	/* reject relative paths and empty strings */
	if (path[0] != '/')
		return -ENOENT;

	fd = open(path, O_RDONLY | O_NOFOLLOW | O_NOCTTY);
	if (fd < 0)
		return -errno;

	/* reject non-regular files */
	{
		struct stat st;
		if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode)) {
			close(fd);
			return -EINVAL;
		}
	}

	ret = hash_fd(fd, sha256_out);
	close(fd);
	return ret;
}

int hash_verify_event(struct hash_verify_ctx *ctx,
		      const struct lota_exec_event *event,
		      uint8_t sha256_out[LOTA_HASH_SIZE])
{
	struct stat st;
	int is_exec;
	int fd;
	int ret;

	if (!ctx || !event || !sha256_out)
		return -EINVAL;

	is_exec = (event->event_type == LOTA_EVENT_EXEC ||
		   event->event_type == LOTA_EVENT_EXEC_BLOCKED);

	/*
	 * For EXEC events, prefer /proc/PID/exe. It references the already-open
	 * executable inode that the kernel used for this process image.
	 *
	 * For non-EXEC file events, use event filename directly (absolute paths
	 * only), but still require fs-verity for a stable fingerprint.
	 */
	if (is_exec) {
		char proc_path[32];

		if (event->event_type == LOTA_EVENT_EXEC_BLOCKED) {
			ctx->errors++;
			return -EPERM;
		}

		snprintf(proc_path, sizeof(proc_path), "/proc/%u/exe",
			 event->pid);
		fd = open(proc_path, O_RDONLY | O_NOCTTY);
	} else {
		if (event->filename[0] != '/')
			return -ENOENT;
		fd = open(event->filename, O_RDONLY | O_NOFOLLOW | O_NOCTTY);
	}

	if (fd < 0) {
		ctx->errors++;
		return -errno;
	}

	if (fstat(fd, &st) < 0) {
		ctx->errors++;
		ret = -errno;
		close(fd);
		return ret;
	}

	if (!S_ISREG(st.st_mode)) {
		ctx->errors++;
		close(fd);
		return -EINVAL;
	}

	ret = hash_fd(fd, sha256_out);

	close(fd);
	if (ret < 0) {
		ctx->errors++;
		return ret;
	}

	ctx->resolved++;
	return 0;
}

void hash_verify_stats(const struct hash_verify_ctx *ctx, uint64_t *resolved,
		       uint64_t *errors)
{
	if (!ctx)
		return;
	if (resolved)
		*resolved = ctx->resolved;
	if (errors)
		*errors = ctx->errors;
}
