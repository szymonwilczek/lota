/* SPDX-License-Identifier: MIT */
/*
 * The snapshot file of --bench.
 *
 * The agent runs as root and the file is read by an unprivileged tool, so the
 * file is an output channel only: one fixed path, replaced whole by rename,
 * never read back, and no descriptor kept between writes.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#ifndef LOTA_AGENT_BENCH_H
#define LOTA_AGENT_BENCH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#define LOTA_BENCH_DIR "/run/lota"
#define LOTA_BENCH_NAME "bench.json"
#define LOTA_BENCH_PATH LOTA_BENCH_DIR "/" LOTA_BENCH_NAME
#define LOTA_BENCH_TMP_NAME ".bench.tmp"
#define LOTA_BENCH_MODE 0640
#define LOTA_BENCH_MAX 8192

struct bench_writer {
	char buf[LOTA_BENCH_MAX];
	size_t len;
	bool overflow;
	uint64_t skipped; /* snapshots dropped for size since start */
	gid_t gid; /* group the file is readable by */
};

void bench_writer_init(struct bench_writer *w, gid_t gid);
void bench_reset(struct bench_writer *w);

__attribute__((format(printf, 2, 3))) void bench_append(struct bench_writer *w,
							const char *fmt, ...);

/*
 * Replace LOTA_BENCH_PATH with the buffer and reset it.
 *
 * A buffer that overflowed is not written: the snapshot is dropped,
 * w->skipped counts it, and -EMSGSIZE is returned.
 */
int bench_commit(struct bench_writer *w);

#ifdef LOTA_INTERNAL_TESTS
int bench_commit_in(struct bench_writer *w, const char *dir);
#endif

#endif /* LOTA_AGENT_BENCH_H */
