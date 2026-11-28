/* SPDX-License-Identifier: MIT */
/*
 * The --bench snapshot: what goes into the file, and when.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#ifndef LOTA_AGENT_BENCH_SNAPSHOT_H
#define LOTA_AGENT_BENCH_SNAPSHOT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "bench.h"
#include "bench_proc.h"
#include "bench_protected.h"

#define LOTA_BENCH_VERSION 1
#define LOTA_BENCH_INTERVAL_MS 1000
#define LOTA_BENCH_MAX_PROGS 32
#define LOTA_BENCH_NAME_MAX 32

struct bench_prog {
	char name[LOTA_BENCH_NAME_MAX]; /* [A-Za-z0-9_.] only */
	uint64_t run_ns;
	uint64_t run_cnt;
};

/* The daemon's own BPF objects */
struct bench_bpf {
	bool run_stats; /* the kernel is counting run time */
	size_t map_count;
	bool memlock_ok;
	uint64_t memlock; /* bytes, summed over the maps */
	size_t prog_count;
	size_t prog_dropped; /* past LOTA_BENCH_MAX_PROGS, or info unread */
	struct bench_prog progs[LOTA_BENCH_MAX_PROGS];
};

struct bench_state {
	struct bench_writer w;
	uint64_t seq;
	uint64_t start_ns;
	uint64_t next_ns;
	long clk_tck;
	int stats_fd; /* BPF_ENABLE_STATS; run time is counted while open */
};

uint64_t bench_now_ns(void);
void bench_state_init(struct bench_state *st, gid_t gid, uint64_t now_ns);

/* Milliseconds until the next snapshot is due, 0 when it is */
int bench_timeout_ms(const struct bench_state *st, uint64_t now_ns);

/* True once per interval; moves the schedule past @now_ns */
bool bench_due(struct bench_state *st, uint64_t now_ns);

/**
 * bench_write() - Sample the daemon and replace the file.
 * @st: the state.
 * @now_ns: CLOCK_MONOTONIC now.
 * @bpf: the BPF sample, NULL when nothing is loaded.
 * @prot: the protected sum, NULL when the set could not be read.
 *
 * Return: what bench_commit() returns.
 */
int bench_write(struct bench_state *st, uint64_t now_ns,
		const struct bench_bpf *bpf,
		const struct bench_protected_sum *prot);

void bench_remove(void);

/*
 * The snapshot in parts: header and agent, BPF, protected set, close.
 * @self or @b is NULL when it could not be read; it is written as null.
 */
void bench_format(struct bench_state *st, uint64_t now_ns,
		  const struct bench_proc *self);
void bench_format_bpf(struct bench_writer *w, const struct bench_bpf *b);
void bench_format_protected(struct bench_state *st,
			    const struct bench_protected_sum *p);
void bench_format_end(struct bench_writer *w);

/* Copy @src into @dst, every byte outside [A-Za-z0-9_.] made '_' */
void bench_sanitize_name(char *dst, size_t size, const char *src);

#endif /* LOTA_AGENT_BENCH_SNAPSHOT_H */
