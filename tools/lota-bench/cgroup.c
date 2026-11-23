/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * lota-bench - cost of one cgroup v2 directory
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cgroup.h"

const char *const bench_metric_names[BM_COUNT] = {
	[BM_CPU_USAGE_USEC] = "cpu_usage_usec",
	[BM_CPU_USER_USEC] = "cpu_user_usec",
	[BM_CPU_SYSTEM_USEC] = "cpu_system_usec",
	[BM_MEMORY_CURRENT_BYTES] = "memory_current_bytes",
	[BM_MEMORY_PEAK_BYTES] = "memory_peak_bytes",
	[BM_MEMORY_ANON_BYTES] = "memory_anon_bytes",
	[BM_MEMORY_FILE_BYTES] = "memory_file_bytes",
	[BM_MEMORY_KERNEL_BYTES] = "memory_kernel_bytes",
	[BM_PGFAULT] = "pgfault",
	[BM_PGMAJFAULT] = "pgmajfault",
	[BM_IO_READ_BYTES] = "io_read_bytes",
	[BM_IO_WRITE_BYTES] = "io_write_bytes",
	[BM_IO_READ_OPS] = "io_read_ops",
	[BM_IO_WRITE_OPS] = "io_write_ops",
};

struct keyed {
	const char *key;
	enum bench_metric m;
};

static const struct keyed cpu_stat_keys[] = {
	{ "usage_usec", BM_CPU_USAGE_USEC },
	{ "user_usec", BM_CPU_USER_USEC },
	{ "system_usec", BM_CPU_SYSTEM_USEC },
};

static const struct keyed memory_stat_keys[] = {
	{ "anon", BM_MEMORY_ANON_BYTES },     { "file", BM_MEMORY_FILE_BYTES },
	{ "kernel", BM_MEMORY_KERNEL_BYTES }, { "pgfault", BM_PGFAULT },
	{ "pgmajfault", BM_PGMAJFAULT },
};

static const struct keyed io_stat_keys[] = {
	{ "rbytes", BM_IO_READ_BYTES },
	{ "wbytes", BM_IO_WRITE_BYTES },
	{ "rios", BM_IO_READ_OPS },
	{ "wios", BM_IO_WRITE_OPS },
};

#define NKEYS(a) (sizeof(a) / sizeof((a)[0]))

/* whole string is a decimal u64 */
static int parse_u64(const char *s, uint64_t *out)
{
	char *end;
	unsigned long long v;

	if (*s < '0' || *s > '9')
		return -EINVAL;
	errno = 0;
	v = strtoull(s, &end, 10);
	if (errno || *end != '\0')
		return -EINVAL;
	*out = v;
	return 0;
}

static void set(struct bench_sample *s, enum bench_metric m, uint64_t v)
{
	s->v[m] = v;
	s->have |= 1u << m;
}

static FILE *open_at(int dirfd, const char *name, int *err)
{
	FILE *f;
	int fd;

	fd = openat(dirfd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0) {
		*err = -errno;
		return NULL;
	}
	f = fdopen(fd, "r");
	if (!f) {
		*err = -errno;
		close(fd);
	}
	return f;
}

static void strip_newline(char *line)
{
	size_t n = strlen(line);

	if (n && line[n - 1] == '\n')
		line[n - 1] = '\0';
}

/* "key value" lines; keys outside @keys are other counters */
static int read_flat_keyed(int dirfd, const char *name,
			   const struct keyed *keys, size_t nkeys,
			   struct bench_sample *s)
{
	char *line = NULL;
	size_t cap = 0;
	int err = 0;
	FILE *f;

	f = open_at(dirfd, name, &err);
	if (!f)
		return err;

	while (getline(&line, &cap, f) > 0) {
		char *val;
		uint64_t v;
		size_t i;

		strip_newline(line);
		val = strchr(line, ' ');
		if (!val)
			continue;
		*val++ = '\0';
		if (parse_u64(val, &v))
			continue;
		for (i = 0; i < nkeys; i++) {
			if (strcmp(line, keys[i].key) == 0) {
				set(s, keys[i].m, v);
				break;
			}
		}
	}
	if (ferror(f))
		err = -EIO;
	free(line);
	fclose(f);
	return err;
}

static void read_single(int dirfd, const char *name, enum bench_metric m,
			struct bench_sample *s)
{
	char *line = NULL;
	size_t cap = 0;
	uint64_t v;
	int err = 0;
	FILE *f;

	f = open_at(dirfd, name, &err);
	if (!f)
		return;
	if (getline(&line, &cap, f) > 0) {
		strip_newline(line);
		if (!parse_u64(line, &v))
			set(s, m, v);
	}
	free(line);
	fclose(f);
}

/*
 * "MAJ:MIN rbytes=N wbytes=N ..." per device, summed;
 * a sum that would wrap leaves the metric unset rather than small
 */
static void read_io_stat(int dirfd, struct bench_sample *s)
{
	uint64_t sum[NKEYS(io_stat_keys)] = { 0 };
	int wrapped[NKEYS(io_stat_keys)] = { 0 };
	char *line = NULL;
	size_t cap = 0;
	int err = 0;
	size_t i;
	FILE *f;

	f = open_at(dirfd, "io.stat", &err);
	if (!f)
		return;

	while (getline(&line, &cap, f) > 0) {
		char *save = NULL;
		char *tok;

		strip_newline(line);
		/* device */
		if (!strtok_r(line, " ", &save))
			continue;
		while ((tok = strtok_r(NULL, " ", &save))) {
			char *val = strchr(tok, '=');
			uint64_t v;

			if (!val)
				continue;
			*val++ = '\0';
			if (parse_u64(val, &v))
				continue;
			for (i = 0; i < NKEYS(io_stat_keys); i++) {
				if (strcmp(tok, io_stat_keys[i].key) != 0)
					continue;
				if (__builtin_add_overflow(sum[i], v, &sum[i]))
					wrapped[i] = 1;
				break;
			}
		}
	}
	/* an empty io.stat is a cgroup that has done no I/O yet */
	if (!ferror(f)) {
		for (i = 0; i < NKEYS(io_stat_keys); i++) {
			if (!wrapped[i])
				set(s, io_stat_keys[i].m, sum[i]);
		}
	}
	free(line);
	fclose(f);
}

int bench_cgroup_read(int dirfd, struct bench_sample *s)
{
	int ret;

	memset(s, 0, sizeof(*s));

	ret = read_flat_keyed(dirfd, "cpu.stat", cpu_stat_keys,
			      NKEYS(cpu_stat_keys), s);
	if (ret)
		return ret;

	read_single(dirfd, "memory.current", BM_MEMORY_CURRENT_BYTES, s);
	read_single(dirfd, "memory.peak", BM_MEMORY_PEAK_BYTES, s);
	(void)read_flat_keyed(dirfd, "memory.stat", memory_stat_keys,
			      NKEYS(memory_stat_keys), s);
	read_io_stat(dirfd, s);
	return 0;
}
