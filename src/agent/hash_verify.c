/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - fs-verity fingerprint of the file behind an event.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include "hash_verify.h"

#include <errno.h>
#include <fcntl.h>
#include <linux/fsverity.h>
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

/* first LOTA_HASH_SIZE bytes of the fs-verity digest; the caller owns fd */
static int hash_fd(int fd, uint8_t sha256_out[LOTA_HASH_SIZE])
{
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

int hash_verify_event(struct hash_verify_ctx *ctx,
		      const struct lota_exec_event *event,
		      uint8_t sha256_out[LOTA_HASH_SIZE])
{
	struct stat st;
	int fd;
	int ret;

	if (!ctx || !event || !sha256_out)
		return -EINVAL;

	if (event->filename[0] != '/')
		return -ENOENT;
	fd = open(event->filename, O_RDONLY | O_NOFOLLOW | O_NOCTTY);
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
