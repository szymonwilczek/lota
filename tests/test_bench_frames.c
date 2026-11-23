/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Unit tests for lota-bench's MangoHud log reader.
 *
 * The logs are made up: a system line of placeholders and rows laid out
 * the way MangoHud lays them out.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test.h"
#include "../tools/lota-bench/frames.h"

#define SYSTEM_INFO                                   \
	"os,cpu,gpu,ram,kernel,driver,cpuscheduler\n" \
	"Some OS,Some CPU,Some GPU,1024,1.0,,none\n"

#define COLUMNS "fps,frametime,cpu_load,gpu_load,elapsed\n"

/* a log of @n frames of @ms each, one row per frame unless @every > 1 */
static char *make_log(const char *head, int n, unsigned int ms, int every)
{
	unsigned long long elapsed = 0;
	char *buf = NULL;
	size_t len = 0;
	FILE *f;

	f = open_memstream(&buf, &len);
	if (!f)
		return NULL;
	fputs(head, f);
	for (int i = 0; i < n; i++) {
		elapsed += (unsigned long long)ms * 1000000 * (unsigned)every;
		fprintf(f, "%.1f,%u.000,1,2,%llu\n", 1000.0 / ms, ms, elapsed);
	}
	fclose(f);
	return buf;
}

static int parse(const char *log, struct bench_frames *f, char *err,
		 size_t errcap)
{
	return bench_frames_parse(log, strlen(log), f, err, errcap);
}

static void test_plain(void)
{
	struct bench_frames f = { .n = 0 };
	char err[256];
	char *log = make_log(SYSTEM_INFO COLUMNS, 50, 16, 1);

	TEST("a per-frame log yields every frame");

	if (!log || parse(log, &f, err, sizeof(err))) {
		FAIL(log ? err : "open_memstream");
	} else if (f.n != 50 || f.us[0] != 16000 || f.us[49] != 16000) {
		FAIL("wrong frames");
	} else {
		PASS();
	}
	bench_frames_free(&f);
	free(log);
}

static void test_versioned(void)
{
	struct bench_frames f = { .n = 0 };
	char err[256];
	char *log = make_log("v1\nv0.0.0\n---SYSTEM INFO---\n" SYSTEM_INFO
			     "---FRAME METRICS---\n" COLUMNS,
			     10, 8, 1);

	TEST("a log with version headers is read past them");

	if (!log || parse(log, &f, err, sizeof(err)))
		FAIL(log ? err : "open_memstream");
	else if (f.n != 10)
		FAIL("wrong frame count");
	else
		PASS();
	bench_frames_free(&f);
	free(log);
}

static void test_column_order(void)
{
	const char *log = "elapsed,frametime\n"
			  "5000000,5.0\n"
			  "10000000,5.0\n";
	struct bench_frames f = { .n = 0 };
	char err[256];

	TEST("columns are found by name, not position");

	if (parse(log, &f, err, sizeof(err)))
		FAIL(err);
	else if (f.n != 2 || f.us[1] != 5000)
		FAIL("wrong frames");
	else
		PASS();
	bench_frames_free(&f);
}

static void test_fraction(void)
{
	const char *log = "frametime,elapsed\n"
			  "5.55663,5556630\n"
			  "0.5,6056630\n"
			  "7,13056630\n";
	struct bench_frames f = { .n = 0 };
	char err[256];

	TEST("frame times keep microseconds and drop the rest");

	if (parse(log, &f, err, sizeof(err)))
		FAIL(err);
	else if (f.us[0] != 5556 || f.us[1] != 500 || f.us[2] != 7000)
		FAIL("wrong frame times");
	else
		PASS();
	bench_frames_free(&f);
}

static void test_interval_log(void)
{
	struct bench_frames f = { .n = 0 };
	char err[256];
	char *log = make_log(SYSTEM_INFO COLUMNS, 20, 5, 20);

	TEST("a log with a row per interval is refused");

	if (!log) {
		FAIL("open_memstream");
	} else if (parse(log, &f, err, sizeof(err)) != -EINVAL ||
		   !strstr(err, "log_interval=0")) {
		FAIL(err[0] ? err : "accepted");
	} else {
		PASS();
	}
	bench_frames_free(&f);
	free(log);
}

struct rejection {
	const char *name;
	const char *log;
	const char *says;
};

static const struct rejection rejections[] = {
	{ "a file with no column row", SYSTEM_INFO "1,2,3\n",
	  "line 3: no row names" },
	{ "a header past the first lines",
	  "\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\nframetime,elapsed\n5,5000000\n",
	  "no row names" },
	{ "a header and no rows", COLUMNS, "no frames" },
	{ "a column named twice", "frametime,elapsed,frametime\n5,1,5\n",
	  "no row names" },
	{ "a negative frame time", "frametime,elapsed\n-5,1\n",
	  "line 2: frametime is not" },
	{ "an exponent", "frametime,elapsed\n1e+06,1\n", "frametime is not" },
	{ "a bare point", "frametime,elapsed\n5.,1\n", "frametime is not" },
	{ "an empty frame time", "frametime,elapsed\n,1\n",
	  "frametime is not" },
	{ "a frame over 71 minutes", "frametime,elapsed\n4294968,1\n",
	  "frametime is not" },
	{ "a fractional elapsed", "frametime,elapsed\n5,1.5\n",
	  "elapsed is not" },
	{ "an elapsed past 64 bits",
	  "frametime,elapsed\n5,18446744073709551616\n", "elapsed is not" },
	{ "a short row", "frametime,elapsed,x\n5,5000000\n",
	  "2 columns, the header has 3" },
	{ "a long row", "frametime,elapsed\n5,5000000,7\n",
	  "more than 2 columns" },
	{ "an empty row", "frametime,elapsed\n5,5000000\n\n5,10000000\n",
	  "line 3: frametime is not" },
	{ "time going back", "frametime,elapsed\n5,10000000\n5,5000000\n",
	  "line 3: elapsed goes back" },
};

static void test_rejections(void)
{
	char err[256];
	char msg[512];

	for (size_t i = 0; i < sizeof(rejections) / sizeof(rejections[0]);
	     i++) {
		const struct rejection *r = &rejections[i];
		struct bench_frames f = { .n = 0 };
		int ret;

		snprintf(msg, sizeof(msg), "refused: %s", r->name);
		TEST(msg);

		ret = parse(r->log, &f, err, sizeof(err));
		bench_frames_free(&f);
		if (ret == 0) {
			FAIL("accepted");
			continue;
		}
		if (!strstr(err, r->says)) {
			snprintf(msg, sizeof(msg), "says \"%s\"", err);
			FAIL(msg);
			continue;
		}
		PASS();
	}
}

static void test_stats(void)
{
	struct bench_frame_stats s;
	struct bench_frames f = { .n = 0 };
	uint32_t us[1000];

	TEST("statistics of a run with a few slow frames");

	/* 990 frames of 10 ms, nine of 30 ms and one of 100 ms, shuffled */
	for (int i = 0; i < 1000; i++)
		us[i] = 10000;
	for (int i = 0; i < 9; i++)
		us[100 * i + 7] = 30000;
	us[500] = 100000;
	f.us = us;
	f.n = 1000;
	f.cap = 1000;
	bench_frame_stats(&f, &s);

	if (s.frames != 1000 || s.total_us != 10270000 || s.mean_us != 10270 ||
	    s.median_us != 10000 || s.p99_us != 10000 || s.p999_us != 30000 ||
	    s.low_1pct_us != 37000 || s.low_01pct_us != 100000 ||
	    s.max_us != 100000 || s.stutters != 10)
		FAIL("wrong statistics");
	else
		PASS();
}

static void test_stats_one_frame(void)
{
	struct bench_frame_stats s;
	struct bench_frames f = { .n = 0 };
	uint32_t us = 4000;

	TEST("statistics of a single frame");

	f.us = &us;
	f.n = 1;
	f.cap = 1;
	bench_frame_stats(&f, &s);
	if (s.median_us != 4000 || s.p999_us != 4000 ||
	    s.low_01pct_us != 4000 || s.stutters != 0)
		FAIL("wrong statistics");
	else
		PASS();
}

int main(void)
{
	printf("lota-bench MangoHud log reader:\n");

	test_plain();
	test_versioned();
	test_column_order();
	test_fraction();
	test_interval_log();
	test_rejections();
	test_stats();
	test_stats_one_frame();

	printf("%d/%d tests passed\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
