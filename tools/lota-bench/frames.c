/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * lota-bench - frame times from a MangoHud log
 */

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "frames.h"

/* a header wider than this is not MangoHud's */
#define MAX_COLUMNS 256

struct fparse {
	struct bench_frames *f;
	char *err;
	size_t errcap;
	size_t line;
	int ncols;
	int col_ft;
	int col_el;
	uint64_t first_ns;
	uint64_t last_ns;
};

static int bad(struct fparse *p, int ret, const char *fmt, ...)
{
	char msg[160];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(msg, sizeof(msg), fmt, ap);
	va_end(ap);
	if (p->errcap)
		snprintf(p->err, p->errcap, "line %zu: %s", p->line, msg);
	return ret;
}

static int is_digit(char c)
{
	return c >= '0' && c <= '9';
}

/* milliseconds with an optional fraction, truncated to microseconds */
static int parse_ms(const char *s, size_t n, uint32_t *us)
{
	uint64_t v = 0;
	size_t i = 0;
	int frac = 0;

	if (!n || !is_digit(s[0]))
		return -EINVAL;
	for (; i < n && is_digit(s[i]); i++) {
		v = v * 10 + (uint64_t)(s[i] - '0');
		if (v > UINT32_MAX / 1000)
			return -ERANGE;
	}
	v *= 1000;
	if (i < n && s[i] == '.') {
		if (++i == n)
			return -EINVAL;
		for (; i < n && is_digit(s[i]); i++) {
			if (frac < 3)
				v += (uint64_t)(s[i] - '0') * (frac == 0 ? 100 :
							       frac == 1 ? 10 :
									   1);
			frac++;
		}
	}
	if (i != n || v > UINT32_MAX)
		return i != n ? -EINVAL : -ERANGE;
	*us = (uint32_t)v;
	return 0;
}

static int parse_ns(const char *s, size_t n, uint64_t *ns)
{
	uint64_t v = 0;

	if (!n)
		return -EINVAL;
	for (size_t i = 0; i < n; i++) {
		if (!is_digit(s[i]))
			return -EINVAL;
		if (__builtin_mul_overflow(v, 10, &v) ||
		    __builtin_add_overflow(v, (uint64_t)(s[i] - '0'), &v))
			return -ERANGE;
	}
	*ns = v;
	return 0;
}

static int field_is(const char *s, size_t n, const char *name)
{
	return strlen(name) == n && memcmp(s, name, n) == 0;
}

/* whether @s is the row naming the columns; records where they are */
static int take_header(struct fparse *p, const char *s, size_t n)
{
	int ft = -1, el = -1, col = 0;
	size_t start = 0;

	for (size_t i = 0; i <= n; i++) {
		if (i < n && s[i] != ',')
			continue;
		if (col == MAX_COLUMNS)
			return 0;
		if (field_is(s + start, i - start, "frametime"))
			ft = ft < 0 ? col : MAX_COLUMNS;
		else if (field_is(s + start, i - start, "elapsed"))
			el = el < 0 ? col : MAX_COLUMNS;
		col++;
		start = i + 1;
	}
	if (ft < 0 || el < 0 || ft == MAX_COLUMNS || el == MAX_COLUMNS)
		return 0;
	p->ncols = col;
	p->col_ft = ft;
	p->col_el = el;
	return 1;
}

static int push(struct fparse *p, uint32_t us)
{
	struct bench_frames *f = p->f;

	if (f->n == BENCH_FRAMES_MAX)
		return bad(p, -E2BIG, "more than %u frames", BENCH_FRAMES_MAX);
	if (f->n == f->cap) {
		size_t cap = f->cap ? f->cap * 2 : 4096;
		uint32_t *us_new;

		if (cap > BENCH_FRAMES_MAX)
			cap = BENCH_FRAMES_MAX;
		us_new = realloc(f->us, cap * sizeof(*f->us));
		if (!us_new)
			return bad(p, -ENOMEM, "out of memory");
		f->us = us_new;
		f->cap = cap;
	}
	f->us[f->n++] = us;
	return 0;
}

static int take_row(struct fparse *p, const char *s, size_t n)
{
	uint32_t us = 0;
	uint64_t ns = 0;
	size_t start = 0;
	int col = 0;
	int ret;

	for (size_t i = 0; i <= n; i++) {
		if (i < n && s[i] != ',')
			continue;
		if (col == p->ncols)
			return bad(p, -EINVAL, "more than %d columns",
				   p->ncols);
		if (col == p->col_ft) {
			ret = parse_ms(s + start, i - start, &us);
			if (ret)
				return bad(p, ret,
					   "frametime is not a "
					   "time in milliseconds");
		} else if (col == p->col_el) {
			ret = parse_ns(s + start, i - start, &ns);
			if (ret)
				return bad(p, ret,
					   "elapsed is not a "
					   "time in nanoseconds");
		}
		col++;
		start = i + 1;
	}
	if (col != p->ncols)
		return bad(p, -EINVAL, "%d columns, the header has %d", col,
			   p->ncols);
	if (p->f->n && ns < p->last_ns)
		return bad(p, -EINVAL, "elapsed goes back");
	if (!p->f->n)
		p->first_ns = ns;
	p->last_ns = ns;
	return push(p, us);
}

/*
 * Rows logged per frame cover the log's span with their frame times;
 * rows logged every log_interval ms cover a fraction of it.
 * The first row's frame ended at its elapsed, so it is outside the span.
 */
static int check_per_frame(struct fparse *p)
{
	uint64_t span_us = (p->last_ns - p->first_ns) / 1000;
	uint64_t sum_us = 0;

	for (size_t i = 1; i < p->f->n; i++)
		sum_us += p->f->us[i];
	if (sum_us * 2 < span_us)
		return bad(p, -EINVAL,
			   "frames cover %llu of %llu ms: the log has a row "
			   "per interval, not per frame; set log_interval=0",
			   (unsigned long long)(sum_us / 1000),
			   (unsigned long long)(span_us / 1000));
	return 0;
}

int bench_frames_parse(const char *buf, size_t len, struct bench_frames *f,
		       char *err, size_t errcap)
{
	struct fparse p = { .f = f, .err = err, .errcap = errcap };
	size_t pos = 0;
	int ret;

	memset(f, 0, sizeof(*f));
	if (errcap)
		err[0] = '\0';
	while (pos < len) {
		const char *s = buf + pos;
		const char *nl = memchr(s, '\n', len - pos);
		size_t n = nl ? (size_t)(nl - s) : len - pos;

		pos += n + (nl ? 1 : 0);
		p.line++;
		if (!p.ncols) {
			if (take_header(&p, s, n))
				continue;
			if (p.line == BENCH_FRAMES_HEADER_LINES)
				break;
			continue;
		}
		ret = take_row(&p, s, n);
		if (ret)
			return ret;
	}
	if (!p.ncols)
		return bad(&p, -EINVAL,
			   "no row names the frametime and elapsed columns; "
			   "not a MangoHud log");
	if (!f->n)
		return bad(&p, -EINVAL, "no frames");
	return check_per_frame(&p);
}

void bench_frames_free(struct bench_frames *f)
{
	free(f->us);
	memset(f, 0, sizeof(*f));
}

static int cmp_u32(const void *a, const void *b)
{
	uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;

	return (x > y) - (x < y);
}

/* nearest rank: the smallest frame time at or above @per_mille of frames */
static uint64_t rank(const struct bench_frames *f, uint64_t per_mille)
{
	uint64_t r = (per_mille * f->n + 999) / 1000;

	return f->us[r ? r - 1 : 0];
}

/* mean of the slowest @n / @div frames, at least one */
static uint64_t low(const struct bench_frames *f, size_t div)
{
	size_t k = f->n / div ? f->n / div : 1;
	uint64_t sum = 0;

	for (size_t i = f->n - k; i < f->n; i++)
		sum += f->us[i];
	return sum / k;
}

void bench_frame_stats(struct bench_frames *f, struct bench_frame_stats *s)
{
	memset(s, 0, sizeof(*s));
	if (!f->n)
		return;
	for (size_t i = 0; i < f->n; i++)
		s->total_us += f->us[i];
	qsort(f->us, f->n, sizeof(*f->us), cmp_u32);

	s->frames = f->n;
	s->mean_us = s->total_us / f->n;
	s->median_us = rank(f, 500);
	s->p99_us = rank(f, 990);
	s->p999_us = rank(f, 999);
	s->low_1pct_us = low(f, 100);
	s->low_01pct_us = low(f, 1000);
	s->max_us = f->us[f->n - 1];
	for (size_t i = f->n; i-- && f->us[i] > 2 * s->median_us;)
		s->stutters++;
}
