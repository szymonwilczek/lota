/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * lota-bench - one run written as JSON
 *
 * One sample per line, so a result reads in a diff and greps by time.
 */

#include <errno.h>
#include <inttypes.h>

#include "result.h"

const char *const bench_source_names[BS_COUNT] = {
	[BS_GAME] = "game",
	[BS_LOTA_AGENT] = "lota-agent",
	[BS_LOTA_ATTEST] = "lota-attest",
};

const char *const bench_end_names[BE_COUNT] = {
	[BE_DURATION] = "duration",
	[BE_INTERRUPTED] = "interrupted",
	[BE_GAME_GONE] = "game-gone",
	[BE_SAMPLE_CAP] = "sample-cap",
};

static int status(FILE *f)
{
	return ferror(f) ? -EIO : 0;
}

int bench_write_begin(FILE *f, unsigned int interval_ms)
{
	fprintf(f,
		"{\n"
		"  \"schema_version\": %d,\n"
		"  \"tool\": \"lota-bench\",\n"
		"  \"interval_ms\": %u,\n"
		"  \"samples\": [",
		BENCH_SCHEMA_VERSION, interval_ms);
	return status(f);
}

static void write_metrics(FILE *f, const struct bench_sample *s)
{
	if (!s) {
		fputs("null", f);
		return;
	}
	fputc('{', f);
	for (int m = 0; m < BM_COUNT; m++) {
		fprintf(f, "%s\"%s\": ", m ? ", " : "", bench_metric_names[m]);
		if (s->have & (1u << m))
			fprintf(f, "%" PRIu64, s->v[m]);
		else
			fputs("null", f);
	}
	fputc('}', f);
}

int bench_write_sample(FILE *f, unsigned int index, uint64_t t_ms,
		       const struct bench_sample *const src[BS_COUNT])
{
	fprintf(f, "%s\n    {\"t_ms\": %" PRIu64, index ? "," : "", t_ms);
	for (int i = 0; i < BS_COUNT; i++) {
		fprintf(f, ", \"%s\": ", bench_source_names[i]);
		write_metrics(f, src[i]);
	}
	fputc('}', f);
	return status(f);
}

int bench_write_end(FILE *f, enum bench_end end, const struct bench_self *self)
{
	fprintf(f,
		"\n  ],\n"
		"  \"end\": \"%s\",\n"
		"  \"self\": {\"cpu_user_usec\": %" PRIu64
		", \"cpu_system_usec\": %" PRIu64
		", \"max_rss_bytes\": %" PRIu64 "}\n"
		"}\n",
		bench_end_names[end], self->cpu_user_usec,
		self->cpu_system_usec, self->max_rss_bytes);
	if (fflush(f))
		return -EIO;
	return status(f);
}
