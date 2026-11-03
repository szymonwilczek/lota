/* SPDX-License-Identifier: MIT */
/*
 * The --bench snapshot: what goes into the file, and when.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#ifndef LOTA_AGENT_BENCH_SNAPSHOT_H
#define LOTA_AGENT_BENCH_SNAPSHOT_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

#include "bench.h"
#include "bench_proc.h"

#define LOTA_BENCH_VERSION 1
#define LOTA_BENCH_INTERVAL_MS 1000

struct bench_state {
	struct bench_writer w;
	uint64_t seq;
	uint64_t start_ns;
	uint64_t next_ns;
	long clk_tck;
};

uint64_t bench_now_ns(void);
void bench_state_init(struct bench_state *st, gid_t gid, uint64_t now_ns);

/* Milliseconds until the next snapshot is due, 0 when it is */
int bench_timeout_ms(const struct bench_state *st, uint64_t now_ns);

/* True once per interval; moves the schedule past @now_ns */
bool bench_due(struct bench_state *st, uint64_t now_ns);

/* Write a snapshot when one is due: 1 when none was, else 0 or an error */
int bench_tick(struct bench_state *st, uint64_t now_ns);

/* Remove a snapshot an earlier run left behind */
void bench_remove(void);

/* @self is NULL when the agent's counters could not be read */
void bench_format(struct bench_state *st, uint64_t now_ns,
		  const struct bench_proc *self);

#endif /* LOTA_AGENT_BENCH_SNAPSHOT_H */
