/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * lota-bench - check a result file against the schema
 *
 * The schema is walked as the file is lexed: each object knows its keys,
 * each key its value, so nesting is the schema's and nothing is kept but
 * the previous sample's time.
 */

#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "json.h"
#include "validate.h"

struct vctx {
	struct json_lex lx;
	char *err;
	size_t errcap;
	int failed;
};

static int bad(struct vctx *v, size_t at, const char *fmt, ...)
{
	char msg[160];
	va_list ap;

	if (v->failed)
		return -EINVAL;
	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);
	snprintf(v->err, v->errcap, "offset %zu: %s", at, msg);
	v->failed = 1;
	return -EINVAL;
}

/* the next token, which must be @want */
static int expect(struct vctx *v, enum json_tok want, const char *what)
{
	enum json_tok t = json_next(&v->lx);

	if (t == JT_ERROR)
		return bad(v, json_offset(&v->lx), "%s", v->lx.err);
	if (t != want)
		return bad(v, json_offset(&v->lx), "expected %s", what);
	return 0;
}

/*
 * Read the next key of an object whose '{' is taken and return its index
 * in @keys: -1 at '}', -2 on error. A key seen before or not in @keys is
 * an error.
 */
static int next_key(struct vctx *v, int *first, const char *const *keys,
		    int nkeys, uint32_t *seen)
{
	enum json_tok t = json_next(&v->lx);
	int i;

	if (t == JT_RBRACE)
		return -1;
	if (!*first && t == JT_COMMA)
		t = json_next(&v->lx);
	else if (!*first && t != JT_ERROR) {
		bad(v, json_offset(&v->lx), "expected ',' or '}'");
		return -2;
	}
	*first = 0;
	if (t == JT_ERROR) {
		bad(v, json_offset(&v->lx), "%s", v->lx.err);
		return -2;
	}
	if (t != JT_STRING) {
		bad(v, json_offset(&v->lx), "expected a key");
		return -2;
	}
	for (i = 0; i < nkeys; i++) {
		if (strcmp(v->lx.str, keys[i]) == 0)
			break;
	}
	if (i == nkeys) {
		bad(v, json_offset(&v->lx), "unknown key \"%s\"", v->lx.str);
		return -2;
	}
	if (*seen & (1u << i)) {
		bad(v, json_offset(&v->lx), "key \"%s\" repeated", v->lx.str);
		return -2;
	}
	*seen |= 1u << i;
	if (expect(v, JT_COLON, "':'"))
		return -2;
	return i;
}

/* every key of @keys was seen before the '}' at the current offset */
static int all_keys(struct vctx *v, const char *const *keys, int nkeys,
		    uint32_t seen)
{
	for (int i = 0; i < nkeys; i++) {
		if (!(seen & (1u << i)))
			return bad(v, json_offset(&v->lx), "missing key \"%s\"",
				   keys[i]);
	}
	return 0;
}

static int uint_value(struct vctx *v, uint64_t *out)
{
	if (expect(v, JT_UINT, "an unsigned integer"))
		return -EINVAL;
	*out = v->lx.num;
	return 0;
}

/* @what is one of the @n strings in @set; returns its index */
static int enum_value(struct vctx *v, const char *const *set, int n,
		      const char *what)
{
	if (expect(v, JT_STRING, what))
		return -EINVAL;
	for (int i = 0; i < n; i++) {
		if (strcmp(v->lx.str, set[i]) == 0)
			return i;
	}
	return bad(v, json_offset(&v->lx), "\"%s\" is not %s", v->lx.str, what);
}

/* null, or an object holding every metric as an integer or null */
static int metrics_value(struct vctx *v)
{
	uint32_t seen = 0;
	int first = 1;
	int k;

	if (json_peek(&v->lx) == JT_NULL) {
		json_next(&v->lx);
		return 0;
	}
	if (expect(v, JT_LBRACE, "null or an object of metrics"))
		return -EINVAL;
	while ((k = next_key(v, &first, bench_metric_names, BM_COUNT, &seen)) >=
	       0) {
		enum json_tok t = json_next(&v->lx);

		if (t == JT_ERROR)
			return bad(v, json_offset(&v->lx), "%s", v->lx.err);
		if (t != JT_UINT && t != JT_NULL)
			return bad(v, json_offset(&v->lx),
				   "%s is not an unsigned integer or null",
				   bench_metric_names[k]);
	}
	if (k == -2)
		return -EINVAL;
	return all_keys(v, bench_metric_names, BM_COUNT, seen);
}

/* a sample's keys: t_ms, then one per source */
#define SAMPLE_KEYS (1 + BS_COUNT)

static int sample_value(struct vctx *v, const char *const *keys,
			uint64_t *prev_t, int first_sample)
{
	uint32_t seen = 0;
	int first = 1;
	uint64_t t;
	int k;

	if (expect(v, JT_LBRACE, "a sample object"))
		return -EINVAL;
	while ((k = next_key(v, &first, keys, SAMPLE_KEYS, &seen)) >= 0) {
		if (k > 0) {
			if (metrics_value(v))
				return -EINVAL;
			continue;
		}
		if (uint_value(v, &t))
			return -EINVAL;
		if (!first_sample && t <= *prev_t)
			return bad(v, json_offset(&v->lx),
				   "t_ms %llu does not follow %llu",
				   (unsigned long long)t,
				   (unsigned long long)*prev_t);
		*prev_t = t;
	}
	if (k == -2)
		return -EINVAL;
	return all_keys(v, keys, SAMPLE_KEYS, seen);
}

static int samples_value(struct vctx *v, unsigned int *count)
{
	const char *keys[SAMPLE_KEYS] = { "t_ms" };
	uint64_t prev_t = 0;
	unsigned int n = 0;
	enum json_tok t;

	for (int i = 0; i < BS_COUNT; i++)
		keys[1 + i] = bench_source_names[i];

	if (expect(v, JT_LBRACKET, "an array of samples"))
		return -EINVAL;
	if (json_peek(&v->lx) == JT_RBRACKET)
		return bad(v, v->lx.peek_at, "no samples");
	for (;;) {
		if (n == BENCH_MAX_SAMPLES)
			return bad(v, json_offset(&v->lx),
				   "more than %d samples", BENCH_MAX_SAMPLES);
		if (sample_value(v, keys, &prev_t, n == 0))
			return -EINVAL;
		n++;
		t = json_next(&v->lx);
		if (t == JT_RBRACKET)
			break;
		if (t != JT_COMMA)
			return bad(v, json_offset(&v->lx),
				   "expected ',' or ']'");
	}
	*count = n;
	return 0;
}

static const char *const self_keys[] = {
	"cpu_user_usec",
	"cpu_system_usec",
	"max_rss_bytes",
};

#define NSELF (int)(sizeof(self_keys) / sizeof(self_keys[0]))

static int self_value(struct vctx *v)
{
	uint32_t seen = 0;
	int first = 1;
	uint64_t ignored;
	int k;

	if (expect(v, JT_LBRACE, "an object"))
		return -EINVAL;
	while ((k = next_key(v, &first, self_keys, NSELF, &seen)) >= 0) {
		if (uint_value(v, &ignored))
			return -EINVAL;
	}
	if (k == -2)
		return -EINVAL;
	return all_keys(v, self_keys, NSELF, seen);
}

enum top_key {
	TK_SCHEMA_VERSION = 0,
	TK_TOOL,
	TK_INTERVAL_MS,
	TK_SAMPLES,
	TK_END,
	TK_SELF,
	TK_COUNT,
};

static const char *const top_keys[TK_COUNT] = {
	[TK_SCHEMA_VERSION] = "schema_version",
	[TK_TOOL] = "tool",
	[TK_INTERVAL_MS] = "interval_ms",
	[TK_SAMPLES] = "samples",
	[TK_END] = "end",
	[TK_SELF] = "self",
};

static int top_value(struct vctx *v, int key, struct bench_validate_info *info)
{
	static const char *const tool[] = { "lota-bench" };
	uint64_t n;
	int i;

	switch (key) {
	case TK_SCHEMA_VERSION:
		if (uint_value(v, &n))
			return -EINVAL;
		if (n != BENCH_SCHEMA_VERSION)
			return bad(
				v, json_offset(&v->lx),
				"schema_version %llu; this lota-bench reads %d",
				(unsigned long long)n, BENCH_SCHEMA_VERSION);
		return 0;
	case TK_TOOL:
		return enum_value(v, tool, 1, "lota-bench") < 0 ? -EINVAL : 0;
	case TK_INTERVAL_MS:
		if (uint_value(v, &n))
			return -EINVAL;
		if (n < BENCH_INTERVAL_MIN_MS || n > BENCH_INTERVAL_MAX_MS)
			return bad(v, json_offset(&v->lx),
				   "interval_ms is not %d..%d",
				   BENCH_INTERVAL_MIN_MS,
				   BENCH_INTERVAL_MAX_MS);
		info->interval_ms = (unsigned int)n;
		return 0;
	case TK_SAMPLES:
		return samples_value(v, &info->samples);
	case TK_END:
		i = enum_value(v, bench_end_names, BE_COUNT, "an end reason");
		if (i < 0)
			return -EINVAL;
		info->end = (enum bench_end)i;
		return 0;
	default:
		return self_value(v);
	}
}

int bench_validate(const char *buf, size_t len,
		   struct bench_validate_info *info, char *err, size_t errcap)
{
	struct vctx v = { .err = err, .errcap = errcap };
	uint32_t seen = 0;
	int first = 1;
	int k;

	memset(info, 0, sizeof(*info));
	if (errcap)
		err[0] = '\0';
	if (len > BENCH_RESULT_MAX_BYTES)
		return bad(&v, BENCH_RESULT_MAX_BYTES, "larger than %u bytes",
			   BENCH_RESULT_MAX_BYTES);

	json_init(&v.lx, buf, len);
	if (expect(&v, JT_LBRACE, "a result object"))
		return -EINVAL;
	while ((k = next_key(&v, &first, top_keys, TK_COUNT, &seen)) >= 0) {
		if (top_value(&v, k, info))
			return -EINVAL;
	}
	if (k == -2 || all_keys(&v, top_keys, TK_COUNT, seen))
		return -EINVAL;
	if (json_next(&v.lx) != JT_END)
		return bad(&v, json_offset(&v.lx), "data after the result");
	return 0;
}
