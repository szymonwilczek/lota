/* SPDX-License-Identifier: MIT */
/*
 * The --bench view of the protected set: one sum over every process in
 * it. Nothing names a process, a mapping, a file or an address.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#ifndef LOTA_AGENT_BENCH_PROTECTED_H
#define LOTA_AGENT_BENCH_PROTECTED_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../../include/lota.h"
#include "bench_proc.h"

/* smaps_rollup walks every mapping of the title; read it this seldom */
#define LOTA_BENCH_PSS_EVERY 5

struct bench_pid {
	uint32_t pid;
	uint64_t start; /* the protected entry's start time, clock ticks */
};

struct bench_track {
	uint32_t pid;
	uint64_t start;
	uint64_t cpu; /* clock ticks */
	uint64_t minflt;
	uint64_t majflt;
	uint64_t pss_kb;
	bool pss_ok;
};

struct bench_protected {
	struct bench_track prev[LOTA_MAX_PROTECTED_PIDS];
	struct bench_track next[LOTA_MAX_PROTECTED_PIDS];
	size_t nprev;
	size_t nnext;
};

struct bench_protected_sum {
	size_t count;
	uint64_t cpu; /* clock ticks over the interval */
	uint64_t minflt; /* over the interval */
	uint64_t majflt; /* over the interval */
	uint64_t rss_kb; /* now */
	uint64_t pss_kb; /* as of the last rollup */
	bool pss_ok; /* every process has had a rollup */
};

void bench_protected_begin(struct bench_protected *bp,
			   struct bench_protected_sum *sum);

/**
 * bench_protected_add() - Fold one process into the sum.
 * @bp: the tracked set.
 * @sum: the sum.
 * @pid: the process.
 * @s: its counters.
 * @has_pss: @s carries a rollup.
 *
 * A process first seen adds nothing to the interval counters, so a title
 * protected mid-run is not charged its past.
 */
void bench_protected_add(struct bench_protected *bp,
			 struct bench_protected_sum *sum, uint32_t pid,
			 const struct bench_proc *s, bool has_pss);

void bench_protected_end(struct bench_protected *bp);

/**
 * bench_protected_sample() - Read the protected set from /proc into the sum.
 * @bp: the tracked set.
 * @pids: the protected entries.
 * @n: how many.
 * @rollup: also read smaps_rollup.
 * @sum: the sum.
 *
 * A PID whose start time differs from the entry's is another process and is
 * skipped.
 */
void bench_protected_sample(struct bench_protected *bp,
			    const struct bench_pid *pids, size_t n, bool rollup,
			    struct bench_protected_sum *sum);

#endif /* LOTA_AGENT_BENCH_PROTECTED_H */
