/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * lota-bench - what LOTA costs a game
 *
 * A session measures one title with LOTA stopped, running and protecting
 * it; Documentation/performance/lota-bench.rst describes the method.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "frames.h"
#include "result.h"
#include "validate.h"

#ifndef LOTA_BENCH_VERSION
#define LOTA_BENCH_VERSION "unknown"
#endif

#define EXIT_BENCH_USAGE 2

static void usage(FILE *f)
{
	fputs("Usage: lota-bench validate FILE\n"
	      "       lota-bench frames LOG\n"
	      "       lota-bench --version\n"
	      "\n"
	      "validate  Check a plan, run, result or summary file against\n"
	      "          the schema.\n"
	      "frames    Summarise the frame times of a MangoHud log.\n",
	      f);
}

/*
 * NULL with errno set: EINVAL for anything but a regular file, EFBIG for
 * one over @max bytes
 */
static char *read_file(const char *path, uint64_t max, size_t *len)
{
	struct stat st;
	size_t got = 0;
	char *buf;
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return NULL;
	if (fstat(fd, &st))
		goto fail;
	if (!S_ISREG(st.st_mode)) {
		errno = EINVAL;
		goto fail;
	}
	if ((uint64_t)st.st_size > max) {
		errno = EFBIG;
		goto fail;
	}
	buf = malloc((size_t)st.st_size + 1);
	if (!buf)
		goto fail;
	while (got < (size_t)st.st_size) {
		ssize_t n = read(fd, buf + got, (size_t)st.st_size - got);

		if (n < 0 && errno == EINTR)
			continue;
		if (n <= 0) {
			if (n == 0)
				errno = EIO;
			free(buf);
			goto fail;
		}
		got += (size_t)n;
	}
	close(fd);
	*len = got;
	return buf;
fail:
	close(fd);
	return NULL;
}

static void print_valid(const char *path, const struct bench_doc *d)
{
	const struct bench_plan *p = &d->plan;
	const struct bench_run *r = &d->runs[0];

	switch (d->kind) {
	case BK_PLAN:
		printf("%s: valid plan, %u rounds of %u s every %u ms\n", path,
		       p->rounds, p->duration_s, p->interval_ms);
		break;
	case BK_RUN:
		printf("%s: valid run %u (%s), %u samples (%s)\n", path,
		       r->index, bench_config_names[r->config], r->sample_count,
		       bench_end_names[r->end]);
		break;
	default:
		printf("%s: valid %s, %u runs of %s\n", path,
		       bench_kind_names[d->kind], d->nruns, p->game.title.s);
		break;
	}
}

static int main_validate(int argc, char **argv)
{
	struct bench_doc *d;
	char err[256];
	size_t len;
	char *buf;
	int ret;

	if (argc != 2) {
		usage(stderr);
		return EXIT_BENCH_USAGE;
	}
	buf = read_file(argv[1], BENCH_RESULT_MAX_BYTES, &len);
	if (!buf) {
		fprintf(stderr, "lota-bench: %s: %s\n", argv[1],
			errno == EINVAL ? "not a regular file" :
					  strerror(errno));
		return 1;
	}
	d = malloc(sizeof(*d));
	if (!d) {
		perror("lota-bench");
		free(buf);
		return 1;
	}
	ret = bench_validate(buf, len, d, err, sizeof(err));
	if (ret)
		fprintf(stderr, "%s: invalid: %s\n", argv[1], err);
	else
		print_valid(argv[1], d);
	free(d);
	free(buf);
	return ret ? 1 : 0;
}

static void print_frame_time(const char *label, uint64_t us)
{
	printf("  %-9s %8llu.%03llu ms", label, (unsigned long long)(us / 1000),
	       (unsigned long long)(us % 1000));
	if (us)
		printf("  %7.1f fps", 1e6 / (double)us);
	putchar('\n');
}

static int main_frames(int argc, char **argv)
{
	struct bench_frame_stats s;
	struct bench_frames f;
	char err[256];
	size_t len;
	char *buf;
	int ret;

	if (argc != 2) {
		usage(stderr);
		return EXIT_BENCH_USAGE;
	}
	buf = read_file(argv[1], BENCH_FRAMES_LOG_MAX_BYTES, &len);
	if (!buf) {
		fprintf(stderr, "lota-bench: %s: %s\n", argv[1],
			errno == EINVAL ? "not a regular file" :
					  strerror(errno));
		return 1;
	}
	ret = bench_frames_parse(buf, len, &f, err, sizeof(err));
	free(buf);
	if (ret) {
		bench_frames_free(&f);
		fprintf(stderr, "%s: %s\n", argv[1], err);
		return 1;
	}
	bench_frame_stats(&f, &s);
	bench_frames_free(&f);

	printf("%s: %llu frames in %llu.%03llu s\n", argv[1],
	       (unsigned long long)s.frames,
	       (unsigned long long)(s.total_us / 1000000),
	       (unsigned long long)(s.total_us / 1000 % 1000));
	print_frame_time("mean", s.mean_us);
	print_frame_time("median", s.median_us);
	print_frame_time("p99", s.p99_us);
	print_frame_time("p99.9", s.p999_us);
	print_frame_time("1% low", s.low_1pct_us);
	print_frame_time("0.1% low", s.low_01pct_us);
	print_frame_time("max", s.max_us);
	printf("  stutters  %llu frames over twice the median\n",
	       (unsigned long long)s.stutters);
	return 0;
}

int main(int argc, char **argv)
{
	if (argc < 2) {
		usage(stderr);
		return EXIT_BENCH_USAGE;
	}
	if (strcmp(argv[1], "--version") == 0) {
		printf("lota-bench %s\n", LOTA_BENCH_VERSION);
		return 0;
	}
	if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
		usage(stdout);
		return 0;
	}
	if (strcmp(argv[1], "validate") == 0)
		return main_validate(argc - 1, argv + 1);
	if (strcmp(argv[1], "frames") == 0)
		return main_frames(argc - 1, argv + 1);

	fprintf(stderr, "lota-bench: unknown command '%s'\n", argv[1]);
	usage(stderr);
	return EXIT_BENCH_USAGE;
}
