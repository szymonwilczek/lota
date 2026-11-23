/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * lota-bench - one run written as JSON
 *
 * The result holds numbers and a fixed set of names only. No path, unit
 * name of the title, command line or user name is ever written, so a file
 * can be published as it is.
 */

#ifndef LOTA_BENCH_RESULT_H
#define LOTA_BENCH_RESULT_H

#include <stdint.h>
#include <stdio.h>

#include "cgroup.h"

#define BENCH_SCHEMA_VERSION 1

#define BENCH_INTERVAL_MIN_MS 100
#define BENCH_INTERVAL_MAX_MS 60000
/* four hours at one sample a second, or 24 minutes at the fastest rate */
#define BENCH_MAX_SAMPLES 14400

/* what each sample has a cgroup for */
enum bench_source {
	BS_GAME = 0,
	BS_LOTA_AGENT,
	BS_LOTA_ATTEST,
	BS_COUNT,
};

extern const char *const bench_source_names[BS_COUNT];

/* why sampling stopped */
enum bench_end {
	BE_DURATION = 0, /* the requested duration ran out */
	BE_INTERRUPTED, /* SIGINT or SIGTERM */
	BE_GAME_GONE, /* the game's cgroup was removed */
	BE_SAMPLE_CAP, /* BENCH_MAX_SAMPLES reached */
	BE_COUNT,
};

extern const char *const bench_end_names[BE_COUNT];

/* lota-bench's own cost, from getrusage() */
struct bench_self {
	uint64_t cpu_user_usec;
	uint64_t cpu_system_usec;
	uint64_t max_rss_bytes;
};

/* each returns 0, or -EIO once @f has failed */
int bench_write_begin(FILE *f, unsigned int interval_ms);

/* a NULL entry in @src is a source with no cgroup at that moment */
int bench_write_sample(FILE *f, unsigned int index, uint64_t t_ms,
		       const struct bench_sample *const src[BS_COUNT]);

int bench_write_end(FILE *f, enum bench_end end, const struct bench_self *self);

#endif /* LOTA_BENCH_RESULT_H */
