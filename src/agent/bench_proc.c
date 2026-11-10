/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */

#include "bench_proc.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BENCH_PROC_BUF 4096

static int parse_u64(const char *s, char **end, uint64_t *out)
{
	unsigned long long v;

	while (*s == ' ' || *s == '\t')
		s++;
	if (*s < '0' || *s > '9')
		return -EINVAL;
	errno = 0;
	v = strtoull(s, end, 10);
	if (errno)
		return -EINVAL;
	*out = v;
	return 0;
}

int bench_parse_stat(const char *buf, struct bench_proc *p)
{
	/* comm may hold spaces and parens; fields resume after the last ')' */
	const char *s = strrchr(buf, ')');
	uint64_t v;
	char *end;
	int field;

	if (!s || s[1] != ' ')
		return -EINVAL;
	s += 2;

	/* state is field 3 and not a number */
	s = strchr(s, ' ');
	if (!s)
		return -EINVAL;

	for (field = 4; field <= 22; field++) {
		if (*s != ' ')
			return -EINVAL;
		/* tty_nr, tpgid, priority and nice may be negative */
		if (s[1] == '-') {
			s = strchr(s + 1, ' ');
			if (!s)
				return -EINVAL;
			continue;
		}
		if (parse_u64(s + 1, &end, &v) < 0)
			return -EINVAL;
		s = end;

		switch (field) {
		case 10:
			p->minflt = v;
			break;
		case 12:
			p->majflt = v;
			break;
		case 14:
			p->utime = v;
			break;
		case 15:
			p->stime = v;
			break;
		case 22:
			p->start = v;
			break;
		}
	}
	return 0;
}

static int line_value(const char *buf, const char *key, uint64_t *out)
{
	size_t klen = strlen(key);
	const char *s = buf;

	while (s && *s) {
		if (strncmp(s, key, klen) == 0) {
			char *end;

			return parse_u64(s + klen, &end, out);
		}
		s = strchr(s, '\n');
		if (s)
			s++;
	}
	return -EINVAL;
}

int bench_parse_status(const char *buf, struct bench_proc *p)
{
	if (line_value(buf, "voluntary_ctxt_switches:", &p->ctxt_vol) < 0 ||
	    line_value(buf, "nonvoluntary_ctxt_switches:", &p->ctxt_invol) < 0)
		return -EINVAL;
	if (line_value(buf, "VmRSS:", &p->vm_rss_kb) < 0)
		p->vm_rss_kb = 0;
	return 0;
}

int bench_parse_rollup(const char *buf, struct bench_proc *p)
{
	uint64_t clean, dirty;

	if (line_value(buf, "Rss:", &p->rss_kb) < 0 ||
	    line_value(buf, "Pss:", &p->pss_kb) < 0 ||
	    line_value(buf, "Private_Clean:", &clean) < 0 ||
	    line_value(buf, "Private_Dirty:", &dirty) < 0)
		return -EINVAL;
	p->uss_kb = clean + dirty;
	return 0;
}

static int read_at(int dirfd, const char *name, char *buf, size_t size)
{
	size_t len = 0;
	int fd, ret = 0;

	buf[0] = '\0';
	fd = openat(dirfd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0)
		return -errno;

	for (;;) {
		ssize_t n = read(fd, buf + len, size - 1 - len);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			ret = -errno;
			break;
		}
		if (n == 0)
			break;
		len += (size_t)n;
		if (len == size - 1) {
			char extra;

			do {
				n = read(fd, &extra, 1);
			} while (n < 0 && errno == EINTR);
			if (n < 0)
				ret = -errno;
			else if (n > 0)
				ret = -EMSGSIZE;
			break;
		}
	}
	close(fd);
	buf[len] = '\0';
	return ret;
}

int bench_parse_memlock(const char *buf, uint64_t *out)
{
	return line_value(buf, "memlock:", out);
}

int bench_read_memlock(int fdinfo_dirfd, int fd, uint64_t *out)
{
	char name[16], buf[BENCH_PROC_BUF];
	int ret;

	snprintf(name, sizeof(name), "%d", fd);
	ret = read_at(fdinfo_dirfd, name, buf, sizeof(buf));
	if (ret < 0)
		return ret;
	return bench_parse_memlock(buf, out);
}

int bench_read_proc(int dirfd, struct bench_proc *p, bool rollup)
{
	char buf[BENCH_PROC_BUF];
	int ret;

	memset(p, 0, sizeof(*p));

	ret = read_at(dirfd, "stat", buf, sizeof(buf));
	if (ret == 0)
		ret = bench_parse_stat(buf, p);
	if (ret < 0)
		return ret;

	ret = read_at(dirfd, "status", buf, sizeof(buf));
	if (ret == 0)
		ret = bench_parse_status(buf, p);
	if (ret < 0 || !rollup)
		return ret;

	ret = read_at(dirfd, "smaps_rollup", buf, sizeof(buf));
	if (ret == 0)
		ret = bench_parse_rollup(buf, p);
	return ret;
}
