/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */

#include "bench.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "io_utils.h"

void bench_writer_init(struct bench_writer *w, gid_t gid)
{
	memset(w, 0, sizeof(*w));
	w->gid = gid;
}

void bench_reset(struct bench_writer *w)
{
	w->len = 0;
	w->overflow = false;
	w->buf[0] = '\0';
}

void bench_append(struct bench_writer *w, const char *fmt, ...)
{
	size_t room = sizeof(w->buf) - w->len;
	va_list ap;
	int n;

	if (w->overflow)
		return;

	va_start(ap, fmt);
	n = vsnprintf(w->buf + w->len, room, fmt, ap);
	va_end(ap);

	if (n < 0 || (size_t)n >= room) {
		w->overflow = true;
		return;
	}
	w->len += (size_t)n;
}

static int write_tmp(int dirfd, const struct bench_writer *w)
{
	int fd, ret;

	/* left by a crash; removed, never opened */
	if (unlinkat(dirfd, LOTA_BENCH_TMP_NAME, 0) < 0 && errno != ENOENT)
		return -errno;

	fd = openat(dirfd, LOTA_BENCH_TMP_NAME,
		    O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
		    LOTA_BENCH_MODE);
	if (fd < 0)
		return -errno;

	ret = lota_write_full(fd, w->buf, w->len);
	if (ret == 0 && fchown(fd, (uid_t)-1, w->gid) < 0)
		ret = -errno;
	if (ret == 0 && fchmod(fd, LOTA_BENCH_MODE) < 0)
		ret = -errno;

	if (close(fd) < 0 && ret == 0)
		ret = -errno;
	return ret;
}

static int commit_in(struct bench_writer *w, const char *dir)
{
	int dirfd, ret;

	if (w->overflow) {
		w->skipped++;
		bench_reset(w);
		return -EMSGSIZE;
	}

	dirfd = open(dir, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (dirfd < 0) {
		ret = -errno;
		goto out;
	}

	ret = write_tmp(dirfd, w);
	if (ret == 0 &&
	    renameat(dirfd, LOTA_BENCH_TMP_NAME, dirfd, LOTA_BENCH_NAME) < 0)
		ret = -errno;
	if (ret < 0)
		(void)unlinkat(dirfd, LOTA_BENCH_TMP_NAME, 0);

	close(dirfd);
out:
	bench_reset(w);
	return ret;
}

int bench_commit(struct bench_writer *w)
{
	return commit_in(w, LOTA_BENCH_DIR);
}

#ifdef LOTA_INTERNAL_TESTS
int bench_commit_in(struct bench_writer *w, const char *dir)
{
	return commit_in(w, dir);
}
#endif
