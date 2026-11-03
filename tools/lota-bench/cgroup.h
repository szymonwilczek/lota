/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * lota-bench - cost of one cgroup v2 directory
 *
 * A protected title refuses every ptrace access from outside, read mode
 * included, and so does the agent; /proc/<pid> of either is closed to us.
 * The cgroup files below are not ptrace-gated and read the same whether
 * LOTA is stopped, running, or protecting the title.
 */

#ifndef LOTA_BENCH_CGROUP_H
#define LOTA_BENCH_CGROUP_H

#include <stdint.h>

enum bench_metric {
	BM_CPU_USAGE_USEC = 0, /* cpu.stat usage_usec */
	BM_CPU_USER_USEC, /* cpu.stat user_usec */
	BM_CPU_SYSTEM_USEC, /* cpu.stat system_usec */
	BM_MEMORY_CURRENT_BYTES, /* memory.current */
	BM_MEMORY_PEAK_BYTES, /* memory.peak */
	BM_MEMORY_ANON_BYTES, /* memory.stat anon */
	BM_MEMORY_FILE_BYTES, /* memory.stat file */
	BM_MEMORY_KERNEL_BYTES, /* memory.stat kernel */
	BM_PGFAULT, /* memory.stat pgfault */
	BM_PGMAJFAULT, /* memory.stat pgmajfault */
	BM_IO_READ_BYTES, /* io.stat rbytes, every device */
	BM_IO_WRITE_BYTES, /* io.stat wbytes */
	BM_IO_READ_OPS, /* io.stat rios */
	BM_IO_WRITE_OPS, /* io.stat wios */
	BM_COUNT,
};

/* bit (1u << metric) in have is set for every value read */
struct bench_sample {
	uint64_t v[BM_COUNT];
	uint32_t have;
};

/* key each metric is recorded under */
extern const char *const bench_metric_names[BM_COUNT];

/*
 * bench_cgroup_read - sample the cgroup @dirfd names
 *
 * A file whose controller is not enabled leaves its metrics unset.
 * Returns 0, or -ENOENT once the cgroup is gone (cpu.stat is in every
 * live cgroup), or another negative errno when cpu.stat cannot be read.
 */
int bench_cgroup_read(int dirfd, struct bench_sample *s);

#endif /* LOTA_BENCH_CGROUP_H */
