/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * lota-bench - frame times from a MangoHud log
 *
 * MangoHud runs inside the game and logs one row per frame, so frame times
 * read the same whether the game is protected or not. Only the frametime
 * and elapsed columns are read; the system description MangoHud writes
 * above the rows is skipped and never copied.
 */

#ifndef LOTA_BENCH_FRAMES_H
#define LOTA_BENCH_FRAMES_H

#include <stddef.h>
#include <stdint.h>

/* 70 minutes at 1000 frames a second */
#define BENCH_FRAMES_MAX (1u << 22)

/* BENCH_FRAMES_MAX rows of 256 bytes */
#define BENCH_FRAMES_LOG_MAX_BYTES (1u << 30)

/* the header row is looked for among this many lines */
#define BENCH_FRAMES_HEADER_LINES 16

/* every frame time in microseconds, in log order */
struct bench_frames {
	uint32_t *us;
	size_t n;
	size_t cap;
};

/* all times in microseconds; a low is the mean of the slowest frames */
struct bench_frame_stats {
	uint64_t frames;
	uint64_t total_us;
	uint64_t mean_us;
	uint64_t median_us;
	uint64_t p99_us;
	uint64_t p999_us;
	uint64_t low_1pct_us;
	uint64_t low_01pct_us;
	uint64_t max_us;
	uint64_t stutters; /* frames over twice the median */
};

/*
 * bench_frames_parse - read the frames of a MangoHud log in @buf
 *
 * Returns 0 with at least one frame in @f, or a negative errno with the
 * line of the first problem in @err. A log written with a log_interval,
 * which holds a row per interval rather than per frame, is refused.
 * The caller frees @f with bench_frames_free() either way.
 */
int bench_frames_parse(const char *buf, size_t len, struct bench_frames *f,
		       char *err, size_t errcap);

void bench_frames_free(struct bench_frames *f);

/* bench_frame_stats - summarise @f; sorts @f->us in place */
void bench_frame_stats(struct bench_frames *f, struct bench_frame_stats *s);

#endif /* LOTA_BENCH_FRAMES_H */
