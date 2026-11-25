/* SPDX-License-Identifier: MIT */
/*
 * What --bench reads from procfs about one process: counters only.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#ifndef LOTA_AGENT_BENCH_PROC_H
#define LOTA_AGENT_BENCH_PROC_H

#include <stdbool.h>
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
	uint64_t start; /* starttime, clock ticks since boot */
	uint64_t vm_rss_kb; /* VmRSS of status, 0 when absent */
};

/* Each takes the whole file as a C string and returns 0 or -EINVAL */
int bench_parse_stat(const char *buf, struct bench_proc *p);
int bench_parse_status(const char *buf, struct bench_proc *p);
int bench_parse_rollup(const char *buf, struct bench_proc *p);

/* "memlock:" of a BPF map's fdinfo, in bytes */
int bench_parse_memlock(const char *buf, uint64_t *out);
int bench_read_memlock(int fdinfo_dirfd, int fd, uint64_t *out);

/**
 * bench_read_proc() - Read the counters of one process.
 * @dirfd: its /proc/<pid> directory.
 * @p: the counters.
 * @rollup: also read smaps_rollup.
 *
 * Return: 0, -EINVAL for a file that does not parse, -EMSGSIZE for one that
 * does not fit the buffer, or the errno of the read.
 */
int bench_read_proc(int dirfd, struct bench_proc *p, bool rollup);

#endif /* LOTA_AGENT_BENCH_PROC_H */
