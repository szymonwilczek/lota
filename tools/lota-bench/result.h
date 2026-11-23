/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * lota-bench - the files of a session
 *
 * A session lives in one directory: plan.json says what is measured and on
 * what, run-NN.json holds one run each, and result.json joins them once
 * the last run is in. A summary is a result without its samples, small
 * enough for an issue.
 *
 * Every file holds numbers, names from fixed sets and struct bench_field
 * text only. No path, PID, unit name of the title, command line or user
 * name is ever written, so a file can be published as it is.
 */

#ifndef LOTA_BENCH_RESULT_H
#define LOTA_BENCH_RESULT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "cgroup.h"
#include "field.h"
#include "frames.h"
#include "machine.h"

#define BENCH_SCHEMA_VERSION 1

#define BENCH_INTERVAL_MIN_MS 100
#define BENCH_INTERVAL_MAX_MS 60000
#define BENCH_INTERVAL_DEFAULT_MS 1000
/* four hours at one sample a second, or 24 minutes at the fastest rate */
#define BENCH_MAX_SAMPLES 14400

#define BENCH_ROUNDS_MIN 2
#define BENCH_ROUNDS_MAX 10
#define BENCH_ROUNDS_DEFAULT 3

#define BENCH_DURATION_MIN_S 10
#define BENCH_DURATION_MAX_S 3600
#define BENCH_DURATION_DEFAULT_S 300

/* the file kinds */
enum bench_kind {
	BK_PLAN = 0,
	BK_RUN,
	BK_RESULT,
	BK_SUMMARY,
	BK_COUNT,
};

extern const char *const bench_kind_names[BK_COUNT];

/* what each sample has a cgroup for */
enum bench_source {
	BS_GAME = 0,
	BS_LOTA_AGENT,
	BS_LOTA_ATTEST,
	BS_COUNT,
};

extern const char *const bench_source_names[BS_COUNT];

/*
 * A: LOTA stopped, the reference
 * B: the agent running, the title not protected
 * C: the title protected
 */
enum bench_config {
	BC_A = 0,
	BC_B,
	BC_C,
	BC_COUNT,
};

extern const char *const bench_config_names[BC_COUNT];

/* a warm-up run in A, then rounds of A B C */
#define BENCH_MAX_RUNS (1 + BC_COUNT * BENCH_ROUNDS_MAX)

static inline unsigned int bench_session_runs(unsigned int rounds)
{
	return 1 + BC_COUNT * rounds;
}

static inline enum bench_config bench_run_config(unsigned int index)
{
	return index ? (enum bench_config)((index - 1) % BC_COUNT) : BC_A;
}

/* why sampling stopped */
enum bench_end {
	BE_DURATION = 0, /* the planned duration ran out */
	BE_INTERRUPTED, /* SIGINT or SIGTERM; such a run is not kept */
	BE_GAME_GONE, /* the game's cgroup was removed */
	BE_SAMPLE_CAP, /* BENCH_MAX_SAMPLES reached */
	BE_COUNT,
};

extern const char *const bench_end_names[BE_COUNT];

/* the agent's mode as GET_STATUS reports it; none while it is stopped */
enum bench_mode {
	BMO_NONE = 0,
	BMO_MONITOR,
	BMO_ENFORCE,
	BMO_MAINTENANCE,
	BMO_COUNT,
};

extern const char *const bench_mode_names[BMO_COUNT];

/* a number that may be null */
struct bench_opt {
	uint64_t v;
	bool set;
};

/* one source over a whole run, from its samples */
enum bench_total {
	BT_CPU_USEC = 0, /* cpu.stat usage_usec, summed over the run */
	BT_MEMORY_MAX_BYTES, /* the highest memory.current */
	BT_PGFAULT,
	BT_PGMAJFAULT,
	BT_IO_READ_BYTES,
	BT_IO_WRITE_BYTES,
	BT_COUNT,
};

extern const char *const bench_total_names[BT_COUNT];

/* written as null when the source's cgroup was never there */
struct bench_totals {
	bool present;
	struct bench_opt v[BT_COUNT];
};

/* from the agent's snapshots, first to last of the run */
enum bench_agent_key {
	BA_BPF_RUN_NS = 0,
	BA_BPF_RUN_CNT,
	BA_MAPS_MEMLOCK_BYTES, /* the highest */
	BA_PROTECTED_MAX, /* the most processes protected at once */
	BA_COUNT,
};

extern const char *const bench_agent_names[BA_COUNT];

/* written as null when no snapshot could be read */
struct bench_agent {
	bool present;
	struct bench_opt v[BA_COUNT];
};

/* the keys of struct bench_frame_stats, in its order */
enum bench_frame_stat {
	BF_FRAMES = 0,
	BF_TOTAL_US,
	BF_MEAN_US,
	BF_MEDIAN_US,
	BF_P99_US,
	BF_P999_US,
	BF_LOW_1PCT_US,
	BF_LOW_01PCT_US,
	BF_MAX_US,
	BF_STUTTERS,
	BF_COUNT,
};

extern const char *const bench_frame_stat_names[BF_COUNT];

uint64_t *bench_frame_stat(struct bench_frame_stats *s,
			   enum bench_frame_stat i);

/* written as null without a MangoHud log */
struct bench_run_frames {
	bool present;
	struct bench_frame_stats s;
};

/* lota-bench's own cost, from getrusage() */
struct bench_self {
	uint64_t cpu_user_usec;
	uint64_t cpu_system_usec;
	uint64_t max_rss_bytes;
};

struct bench_run {
	unsigned int index;
	enum bench_config config;
	bool warmup;
	enum bench_mode mode;
	bool agent_bench; /* the agent reported LOTA_STATUS_BENCH */
	struct bench_power power;
	uint64_t wall_ms;
	unsigned int sample_count;
	enum bench_end end;
	struct bench_totals totals[BS_COUNT];
	struct bench_agent agent;
	struct bench_run_frames frames;
	struct bench_self self;
	/* the samples array as it stands in the buffer the run was read from */
	const char *samples;
	size_t samples_len;
};

struct bench_game {
	struct bench_field title;
	struct bench_field proton; /* unset for a native title */
	struct bench_field version;
	struct bench_field settings;
};

struct bench_plan {
	struct bench_field version; /* of lota-bench */
	struct bench_machine machine;
	struct bench_game game;
	unsigned int rounds;
	unsigned int duration_s;
	unsigned int interval_ms;
};

/* any of the four files, as read */
struct bench_doc {
	enum bench_kind kind;
	struct bench_plan plan; /* all kinds but BK_RUN */
	unsigned int nruns;
	struct bench_run runs[BENCH_MAX_RUNS];
};

/* each returns 0, or -EIO once @f has failed */
int bench_write_plan(FILE *f, const struct bench_plan *p);

/* a run file is written in three steps, its samples streamed between */
int bench_write_run_begin(FILE *f, const struct bench_run *r);

/* a NULL entry in @src is a source with no cgroup at that moment */
int bench_write_sample(FILE *f, unsigned int index, uint64_t t_ms,
		       const struct bench_sample *const src[BS_COUNT]);

int bench_write_run_end(FILE *f, const struct bench_run *r);

/*
 * bench_write_session - @d as a result or a summary
 *
 * A result copies each run's samples from where they were read; a summary
 * leaves them out.
 */
int bench_write_session(FILE *f, const struct bench_doc *d,
			enum bench_kind kind);

#endif /* LOTA_BENCH_RESULT_H */
