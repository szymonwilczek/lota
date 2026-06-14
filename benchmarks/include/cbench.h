/* SPDX-License-Identifier: MIT */
/*
 * cbench.h - header-only C microbenchmark harness for LOTA.
 *
 * Auto-calibrates a batch size so each measured run lasts ~BENCH_TARGET_MS,
 * amortizing clock_gettime() overhead, then collects BENCH_REPS ns/op
 * samples and reports min / median / p90 / p99 / mean / stddev and ops/sec.
 * This mirrors how Go's testing.B and kernel userspace microbenchmarks pick
 * an iteration count and report a distribution rather than a single timing.
 *
 * Tunables (environment):
 *   BENCH_REPS       measured samples per benchmark   (default 50)
 *   BENCH_WARMUP     discarded warmup runs            (default 5)
 *   BENCH_TARGET_MS  target wall time per sample/ms   (default 5)
 *   BENCH_JSON       append one JSON object per result to this file
 *
 * A benchmark is a function that runs the measured operation `iters` times:
 *   static void my_op(void *ctx, size_t iters);
 *   cbench_run("suite", "my_op", my_op, ctx);
 *
 * Write into cbench_sink to defeat dead-code elimination.
 */
#ifndef LOTA_CBENCH_H
#define LOTA_CBENCH_H

#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <fcntl.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

/* Sink to prevent the compiler from optimizing the measured work away. */
static volatile uint64_t cbench_sink;

typedef void (*cbench_fn)(void *ctx, size_t iters);

static inline uint64_t cbench_now_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static inline size_t cbench_envu(const char *name, size_t dflt)
{
	const char *v = getenv(name);
	if (!v || !*v)
		return dflt;
	char *end = NULL;
	unsigned long long n = strtoull(v, &end, 10);
	return (end && *end == '\0' && n > 0) ? (size_t)n : dflt;
}

static int cbench_cmp_double(const void *a, const void *b)
{
	double x = *(const double *)a, y = *(const double *)b;
	return (x > y) - (x < y);
}

/* Linear-interpolated percentile over an already-sorted array. */
static inline double cbench_pct(const double *sorted, size_t n, double p)
{
	if (n == 0)
		return 0.0;
	if (n == 1)
		return sorted[0];
	double idx = p * (double)(n - 1);
	size_t lo = (size_t)idx;
	double frac = idx - (double)lo;
	if (lo + 1 >= n)
		return sorted[n - 1];
	return sorted[lo] + frac * (sorted[lo + 1] - sorted[lo]);
}

static inline int cbench_header_done(void)
{
	static int done;
	if (done)
		return 1;
	done = 1;
	return 0;
}

/* Run one benchmark and print a result row. */
static inline void cbench_run(const char *suite, const char *name, cbench_fn fn,
			      void *ctx)
{
	const size_t reps = cbench_envu("BENCH_REPS", 50);
	const size_t warmup = cbench_envu("BENCH_WARMUP", 5);
	const uint64_t target_ns =
	    cbench_envu("BENCH_TARGET_MS", 5) * 1000000ull;

	/* Calibrate: grow the batch until one run reaches the target time. */
	size_t batch = 1;
	while (batch < (1u << 30)) {
		uint64_t t0 = cbench_now_ns();
		fn(ctx, batch);
		uint64_t d = cbench_now_ns() - t0;
		if (d >= target_ns)
			break;
		batch <<= 1;
	}

	for (size_t w = 0; w < warmup; w++)
		fn(ctx, batch);

	double *samples = (double *)malloc(reps * sizeof(double));
	if (!samples) {
		fprintf(stderr, "cbench: OOM\n");
		return;
	}
	for (size_t r = 0; r < reps; r++) {
		uint64_t t0 = cbench_now_ns();
		fn(ctx, batch);
		uint64_t d = cbench_now_ns() - t0;
		samples[r] = (double)d / (double)batch;
	}

	qsort(samples, reps, sizeof(double), cbench_cmp_double);
	double min = samples[0];
	double median = cbench_pct(samples, reps, 0.50);
	double p99 = cbench_pct(samples, reps, 0.99);
	double sum = 0.0;
	for (size_t r = 0; r < reps; r++)
		sum += samples[r];
	double mean = sum / (double)reps;
	double var = 0.0;
	for (size_t r = 0; r < reps; r++) {
		double dx = samples[r] - mean;
		var += dx * dx;
	}
	double stddev = (reps > 1) ? sqrt(var / (double)(reps - 1)) : 0.0;
	double ops = (median > 0.0) ? 1e9 / median : 0.0;

	if (!cbench_header_done())
		printf("%-28s %12s %12s %12s %12s %14s\n", "benchmark",
		       "median_ns", "p99_ns", "min_ns", "stddev", "ops/sec");
	printf("%-28s %12.1f %12.1f %12.1f %12.1f %14.0f\n", name, median, p99,
	       min, stddev, ops);

	const char *jpath = getenv("BENCH_JSON");
	if (jpath && *jpath) {
		/* results file, not group/other writable regardless of umask */
		int jfd = open(jpath, O_WRONLY | O_CREAT | O_APPEND, 0644);
		FILE *jf = NULL;
		if (jfd >= 0) {
			jf = fdopen(jfd, "a");
			if (!jf)
				close(jfd);
		}
		if (jf) {
			fprintf(jf,
				"{\"suite\":\"%s\",\"name\":\"%s\",\"median_"
				"ns\":%.3f,"
				"\"p99_ns\":%.3f,\"min_ns\":%.3f,\"stddev_ns\":"
				"%.3f,"
				"\"ops_per_sec\":%.1f,\"samples\":%zu,"
				"\"batch\":%zu}\n",
				suite, name, median, p99, min, stddev, ops,
				reps, batch);
			fclose(jf);
		}
	}

	free(samples);
}

#endif /* LOTA_CBENCH_H */
