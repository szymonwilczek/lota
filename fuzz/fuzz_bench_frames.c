// SPDX-License-Identifier: MIT
//
// Fuzz the lota-bench MangoHud log reader.
//
// A log comes from whatever the game's MangoHud wrote, so
// bench_frames_parse() reads untrusted bytes. Besides memory safety, an
// accepted log must hold one to BENCH_FRAMES_MAX frames, its statistics
// must be ordered (median <= p99 <= p99.9 <= max, each low at or above its
// percentile), and every refusal must name a line.
//
// Build:
//   make fuzz-bench-frames
//
// Run:
//   ./build/fuzz-bench-frames -max_len=65536
//
// Copyright (C) 2026 Szymon Wilczek

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../tools/lota-bench/frames.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static void check_stats(struct bench_frames *f)
{
	struct bench_frame_stats s;

	bench_frame_stats(f, &s);
	if (s.frames == 0 || s.frames > BENCH_FRAMES_MAX)
		abort();
	if (s.median_us > s.p99_us || s.p99_us > s.p999_us ||
	    s.p999_us > s.max_us)
		abort();
	if (s.low_1pct_us < s.p99_us || s.low_01pct_us < s.p999_us ||
	    s.low_01pct_us > s.max_us || s.mean_us > s.max_us)
		abort();
	if (s.stutters >= s.frames)
		abort();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct bench_frames f;
	char err[256];

	if (bench_frames_parse((const char *)data, size, &f, err,
			       sizeof(err)) == 0)
		check_stats(&f);
	else if (strncmp(err, "line ", 5) != 0)
		abort();
	bench_frames_free(&f);
	return 0;
}
