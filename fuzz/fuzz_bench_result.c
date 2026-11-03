// SPDX-License-Identifier: MIT
//
// Fuzz the lota-bench result validator.
//
// Result files come from contributors and are validated in CI before they
// are merged, so bench_validate() reads attacker-supplied bytes. Besides
// memory safety, every input it accepts must hold the schema's promise: no
// free text, so no '/' (no path) and no '\' (no escape) anywhere in it.
// Every refusal must name an offset.
//
// Build:
//   make fuzz-bench-result
//
// Run:
//   ./build/fuzz-bench-result -max_len=65536
//
// Copyright (C) 2026 Szymon Wilczek

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../tools/lota-bench/validate.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct bench_validate_info info;
	const char *buf = (const char *)data;
	char err[256];

	if (bench_validate(buf, size, &info, err, sizeof(err)) == 0) {
		if (memchr(buf, '/', size) || memchr(buf, '\\', size))
			abort();
		if (info.samples == 0 || info.samples > BENCH_MAX_SAMPLES)
			abort();
		if (info.interval_ms < BENCH_INTERVAL_MIN_MS ||
		    info.interval_ms > BENCH_INTERVAL_MAX_MS)
			abort();
		return 0;
	}
	if (strncmp(err, "offset ", 7) != 0)
		abort();
	return 0;
}
