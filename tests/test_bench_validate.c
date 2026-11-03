/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Unit tests for lota-bench's result validator.
 *
 * Every case starts from a run the writer produced and changes one thing.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test.h"
#include "../tools/lota-bench/validate.h"

static char *run;

static char *write_run(void)
{
	struct bench_sample game = { .have = 0 }, agent = { .have = 0 };
	const struct bench_sample *src[BS_COUNT] = { NULL };
	struct bench_self self = { 1, 2, 3 };
	char *buf = NULL;
	size_t len = 0;
	FILE *f;

	f = open_memstream(&buf, &len);
	if (!f)
		return NULL;
	game.v[BM_CPU_USAGE_USEC] = 10;
	game.v[BM_MEMORY_CURRENT_BYTES] = 4096;
	game.have = (1u << BM_CPU_USAGE_USEC) | (1u << BM_MEMORY_CURRENT_BYTES);
	agent.have = 1u << BM_CPU_USAGE_USEC;

	bench_write_begin(f, 250);
	src[BS_GAME] = &game;
	bench_write_sample(f, 0, 0, src);
	src[BS_LOTA_AGENT] = &agent;
	bench_write_sample(f, 1, 250, src);
	bench_write_end(f, BE_GAME_GONE, &self);
	fclose(f);
	return buf;
}

/* @run with the first @from replaced by @to */
static char *mutate(const char *from, const char *to)
{
	const char *at = strstr(run, from);
	size_t head, tail;
	char *out;

	if (!at)
		return NULL;
	head = (size_t)(at - run);
	tail = strlen(at + strlen(from));
	out = malloc(head + strlen(to) + tail + 1);
	if (!out)
		return NULL;
	memcpy(out, run, head);
	strcpy(out + head, to);
	strcat(out, at + strlen(from));
	return out;
}

static void test_valid(void)
{
	struct bench_validate_info info;
	char err[256];

	TEST("a run the writer produced validates");

	if (bench_validate(run, strlen(run), &info, err, sizeof(err))) {
		FAIL(err);
		return;
	}
	if (info.samples != 2 || info.interval_ms != 250 ||
	    info.end != BE_GAME_GONE) {
		FAIL("info does not describe the run");
		return;
	}
	PASS();
}

struct rejection {
	const char *name;
	const char *from;
	const char *to;
	const char *says;
};

static const struct rejection rejections[] = {
	{ "an unknown key", "\"end\"", "\"path\"", "unknown key \"path\"" },
	{ "a free-text string", "\"game-gone\"", "\"/home/someone\"",
	  "is not an end reason" },
	{ "an escape in a string", "\"lota-bench\"", "\"lota-\\u0062ench\"",
	  "escape in a string" },
	{ "a non-ASCII byte in a string", "\"game-gone\"", "\"game-\xc3\xa9\"",
	  "byte outside printable ASCII" },
	{ "a string over the length limit", "\"game-gone\"",
	  "\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
	  "string too long" },
	{ "a repeated key", "\"tool\": \"lota-bench\",",
	  "\"tool\": \"lota-bench\", \"tool\": \"lota-bench\",",
	  "key \"tool\" repeated" },
	{ "a missing key", "\"tool\": \"lota-bench\",", "",
	  "missing key \"tool\"" },
	{ "a missing metric", "\"cpu_usage_usec\": 10, ", "",
	  "missing key \"cpu_usage_usec\"" },
	{ "a negative number", "\"t_ms\": 250", "\"t_ms\": -1",
	  "negative number" },
	{ "a fraction", "\"memory_current_bytes\": 4096",
	  "\"memory_current_bytes\": 4096.5", "not an unsigned integer" },
	{ "a number past 64 bits", "\"t_ms\": 250",
	  "\"t_ms\": 18446744073709551616", "does not fit 64 bits" },
	{ "a leading zero", "\"t_ms\": 250", "\"t_ms\": 0250", "leading zero" },
	{ "time that does not move forward", "\"t_ms\": 250", "\"t_ms\": 0",
	  "t_ms 0 does not follow 0" },
	{ "a metric as a string", "\"memory_current_bytes\": 4096",
	  "\"memory_current_bytes\": \"4096\"",
	  "memory_current_bytes is not an unsigned integer or null" },
	{ "a metric as an object", "\"memory_current_bytes\": 4096",
	  "\"memory_current_bytes\": {}",
	  "memory_current_bytes is not an unsigned integer or null" },
	{ "a source as a number", "\"lota-attest\": null", "\"lota-attest\": 0",
	  "null or an object of metrics" },
	{ "another schema version", "\"schema_version\": 1",
	  "\"schema_version\": 2", "this lota-bench reads 1" },
	{ "another tool", "\"tool\": \"lota-bench\"", "\"tool\": \"other\"",
	  "is not lota-bench" },
	{ "an interval out of range", "\"interval_ms\": 250",
	  "\"interval_ms\": 5", "interval_ms is not" },
	{ "a run with no samples", "\"samples\": [",
	  "\"samples\": [], \"x\": [", "no samples" },
	{ "data after the result", "\n}\n", "\n}\n{}",
	  "data after the result" },
	{ "a truncated run", "\"self\"", "", "expected" },
	{ "a missing comma", "\"interval_ms\": 250,", "\"interval_ms\": 250",
	  "expected ',' or '}'" },
	{ "a bare word", "null", "nul", "unexpected character" },
};

static void test_rejections(void)
{
	struct bench_validate_info info;
	char err[256];
	char msg[512];

	for (size_t i = 0; i < sizeof(rejections) / sizeof(rejections[0]);
	     i++) {
		const struct rejection *r = &rejections[i];
		char *bad;
		int ret;

		snprintf(msg, sizeof(msg), "refused: %s", r->name);
		TEST(msg);

		bad = mutate(r->from, r->to);
		if (!bad) {
			FAIL("the case does not apply to the run");
			continue;
		}
		/* a truncated run ends where the self object began */
		if (r->to[0] == '\0' && strcmp(r->from, "\"self\"") == 0)
			bad[strstr(run, r->from) - run] = '\0';

		ret = bench_validate(bad, strlen(bad), &info, err, sizeof(err));
		free(bad);
		if (ret != -EINVAL) {
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

static void test_offset(void)
{
	struct bench_validate_info info;
	char err[256];
	char *bad;

	TEST("an error names the offset of the bad token");

	bad = mutate("\"end\"", "\"path\"");
	if (!bad) {
		FAIL("the case does not apply to the run");
		return;
	}
	bench_validate(bad, strlen(bad), &info, err, sizeof(err));
	{
		char want[64];

		snprintf(want, sizeof(want), "offset %zu:",
			 (size_t)(strstr(bad, "\"path\"") - bad));
		if (strncmp(err, want, strlen(want)) != 0)
			FAIL(err);
		else
			PASS();
	}
	free(bad);
}

static void test_too_large(void)
{
	struct bench_validate_info info;
	char err[256];
	char *big;

	TEST("a file over the size limit is refused unread");

	big = calloc(1, (size_t)BENCH_RESULT_MAX_BYTES + 1);
	if (!big) {
		FAIL("calloc");
		return;
	}
	if (bench_validate(big, (size_t)BENCH_RESULT_MAX_BYTES + 1, &info, err,
			   sizeof(err)) != -EINVAL ||
	    !strstr(err, "larger than"))
		FAIL("accepted");
	else
		PASS();
	free(big);
}

static void test_nesting(void)
{
	struct bench_validate_info info;
	char err[256];
	char *deep;
	size_t n = 100000;

	TEST("deep nesting is refused at the first bracket");

	deep = malloc(n + 1);
	if (!deep) {
		FAIL("malloc");
		return;
	}
	memset(deep, '[', n);
	deep[n] = '\0';
	if (bench_validate(deep, n, &info, err, sizeof(err)) != -EINVAL ||
	    !strstr(err, "offset 0: expected a result object"))
		FAIL(err);
	else
		PASS();
	free(deep);
}

int main(void)
{
	printf("lota-bench result validator:\n");

	run = write_run();
	if (!run) {
		printf("cannot write the reference run\n");
		return 1;
	}

	test_valid();
	test_rejections();
	test_offset();
	test_too_large();
	test_nesting();

	free(run);
	printf("%d/%d tests passed\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
