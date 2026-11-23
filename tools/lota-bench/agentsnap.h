/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * lota-bench - the snapshot lota-agent --bench writes
 *
 * The agent writes /run/lota/bench.json once a second, readable by the
 * lota group. Only the sums a session keeps are taken from it: the run
 * time and run count of every LSM program together, the memory charged
 * for the maps, and how many processes are protected. Anything else in
 * it is skipped.
 */

#ifndef LOTA_BENCH_AGENTSNAP_H
#define LOTA_BENCH_AGENTSNAP_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define BENCH_AGENT_SNAP_DIR "/run/lota"
#define BENCH_AGENT_SNAP_NAME "bench.json"

/* the agent caps its snapshot at 8 KiB */
#define BENCH_AGENT_SNAP_MAX 16384

struct bench_agent_snap {
	uint64_t seq;
	bool bpf; /* the agent reported its programs */
	uint64_t run_ns; /* every program's run time, summed */
	uint64_t run_cnt;
	bool memlock_set;
	uint64_t memlock;
	bool protected_set;
	uint64_t protected_count;
};

/* 0, or -EINVAL for anything the agent does not write */
int bench_agent_snap_parse(const char *buf, size_t len,
			   struct bench_agent_snap *s);

/*
 * Read @name in @dirfd without following a link at it. 0, -ENOENT when
 * the agent writes none, or another negative errno.
 */
int bench_agent_snap_read(int dirfd, const char *name,
			  struct bench_agent_snap *s);

#endif /* LOTA_BENCH_AGENTSNAP_H */
