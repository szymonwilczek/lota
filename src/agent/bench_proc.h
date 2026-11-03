/* SPDX-License-Identifier: MIT */
/*
 * What --bench reads from procfs about one process: counters only.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#ifndef LOTA_AGENT_BENCH_PROC_H
#define LOTA_AGENT_BENCH_PROC_H

#include <stdint.h>

struct bench_proc {
	uint64_t utime; /* clock ticks */
	uint64_t stime; /* clock ticks */
	uint64_t minflt;
	uint64_t majflt;
	uint64_t rss_kb;
	uint64_t pss_kb;
	uint64_t uss_kb; /* Private_Clean + Private_Dirty */
	uint64_t ctxt_vol;
	uint64_t ctxt_invol;
};

/* Each takes the whole file as a C string and returns 0 or -EINVAL */
int bench_parse_stat(const char *buf, struct bench_proc *p);
int bench_parse_status(const char *buf, struct bench_proc *p);
int bench_parse_rollup(const char *buf, struct bench_proc *p);

/* "memlock:" of a BPF map's fdinfo, in bytes, under /proc/self/fdinfo */
int bench_parse_memlock(const char *buf, uint64_t *out);
int bench_read_memlock(int fdinfo_dirfd, int fd, uint64_t *out);

/*
 * Fill @p from stat, status and smaps_rollup under the /proc/<pid>
 * directory @dirfd. No descriptor outlives the call.
 */
int bench_read_proc(int dirfd, struct bench_proc *p);

#endif /* LOTA_AGENT_BENCH_PROC_H */
