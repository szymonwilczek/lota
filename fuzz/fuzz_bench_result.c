// SPDX-License-Identifier: MIT
//
// Fuzz the lota-bench session file reader.
//
// Session files come from contributors and are validated in CI before they
// are merged, so bench_validate() reads attacker-supplied bytes. Besides
// memory safety, every input it accepts must hold the schema's promise: no
// '/' (no path) and no '\' (no escape) anywhere in it, and nothing past the
// bounds the schema sets. Every refusal must name an offset.
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

static struct bench_doc doc;

static void check_run(const struct bench_run *r, int samples)
{
	if (r->sample_count == 0 || r->sample_count > BENCH_MAX_SAMPLES)
		abort();
	if (r->index >= BENCH_MAX_RUNS || r->end == BE_INTERRUPTED ||
	    r->config != bench_run_config(r->index))
		abort();
	if (samples != (r->samples != NULL))
		abort();
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	const char *buf = (const char *)data;
	char err[256];

	if (bench_validate(buf, size, &doc, err, sizeof(err)) == 0) {
		if (memchr(buf, '/', size) || memchr(buf, '\\', size))
			abort();
		if (doc.kind == BK_PLAN && doc.nruns)
			abort();
		if (doc.kind != BK_RUN &&
		    (doc.plan.interval_ms < BENCH_INTERVAL_MIN_MS ||
		     doc.plan.interval_ms > BENCH_INTERVAL_MAX_MS ||
		     doc.plan.machine.ngpus > BENCH_MAX_GPUS))
			abort();
		for (unsigned int i = 0; i < doc.nruns; i++)
			check_run(&doc.runs[i], doc.kind != BK_SUMMARY);
		return 0;
	}
	if (strncmp(err, "offset ", 7) != 0)
		abort();
	return 0;
}
