/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Unit tests for lota-bench's reader of the files of a session.
 *
 * A whole session is written with the writer: a plan, one file per run and
 * the result and summary they join into. Every refusal starts from one of
 * those files and changes one thing.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test.h"
#include "../tools/lota-bench/validate.h"

#define ROUNDS 2
#define NRUNS (1 + BC_COUNT * ROUNDS)
/* a C run */
#define REF_RUN 3

enum text {
	T_PLAN = 0,
	T_RUN,
	T_RESULT,
	T_SUMMARY,
	T_COUNT
};

static char *text[T_COUNT];
static char *runs[NRUNS];
static struct bench_doc *doc;

static void set(struct bench_field *f, const char *s)
{
	bench_field_set(f, s, strlen(s));
}

static void fill_plan(struct bench_plan *p)
{
	memset(p, 0, sizeof(*p));
	set(&p->version, "1.0.0");
	set(&p->machine.cpu_model, "Test CPU 8-Core");
	p->machine.cpu_threads = 16;
	p->machine.memory_bytes = 32ull << 30;
	p->machine.ngpus = 1;
	p->machine.gpu[0].vendor_id = 0x1002;
	p->machine.gpu[0].device_id = 1;
	set(&p->machine.gpu[0].name, "Test GPU");
	set(&p->machine.kernel, "6.0.0-test");
	set(&p->machine.tpm, "none");
	p->machine.selinux = BSE_ENFORCING;
	set(&p->game.title, "Example Title");
	set(&p->game.settings, "high");
	p->rounds = ROUNDS;
	p->settle_s = 30;
	p->duration_s = 600;
	p->interval_ms = 1000;
}

/* run @i as a session in good order records it */
static void fill_run(struct bench_run *r, unsigned int i)
{
	memset(r, 0, sizeof(*r));
	r->index = i;
	r->config = bench_run_config(i);
	r->warmup = i == 0;
	set(&r->power.governor, "performance");
	r->power.supply = BSU_AC;
	r->wall_ms = 1003;
	r->sample_count = 2;
	r->end = BE_DURATION;
	r->totals[BS_GAME].present = true;
	r->totals[BS_GAME].v[BT_CPU_USEC] = (struct bench_opt){ 10, true };
	r->frames.present = true;
	r->frames.s.frames = 100;
	r->frames.s.median_us = 16600;
	r->self = (struct bench_self){ 1, 2, 3 };
	if (r->config == BC_A)
		return;
	r->mode = BMO_ENFORCE;
	r->agent_bench = true;
	r->totals[BS_LOTA_AGENT].present = true;
	r->agent.present = true;
	r->agent.v[BA_BPF_RUN_NS] = (struct bench_opt){ 1500, true };
	r->agent.v[BA_PROTECTED_MAX] =
		(struct bench_opt){ r->config == BC_C ? 2 : 0, true };
}

static char *write_run(unsigned int i)
{
	const struct bench_sample *src[BS_COUNT] = { NULL };
	struct bench_sample game = { .have = 1u << BM_CPU_USAGE_USEC };
	struct bench_run r;
	char *buf = NULL;
	size_t len = 0;
	FILE *f;

	f = open_memstream(&buf, &len);
	if (!f)
		return NULL;
	fill_run(&r, i);
	game.v[BM_CPU_USAGE_USEC] = 10;
	src[BS_GAME] = &game;
	bench_write_run_begin(f, &r);
	bench_write_sample(f, 0, 0, src);
	bench_write_sample(f, 1, 1000, src);
	bench_write_run_end(f, &r);
	fclose(f);
	return buf;
}

static char *write_doc(enum bench_kind kind)
{
	char *buf = NULL;
	size_t len = 0;
	FILE *f;

	f = open_memstream(&buf, &len);
	if (!f)
		return NULL;
	if (kind == BK_PLAN)
		bench_write_plan(f, &doc->plan);
	else
		bench_write_session(f, doc, kind);
	fclose(f);
	return buf;
}

static int check(const char *s, struct bench_doc *d, char *err, size_t cap)
{
	return bench_validate(s, strlen(s), d, err, cap);
}

/* the session's files, each run read back the way lota-bench run does */
static int build(void)
{
	struct bench_doc *one = malloc(sizeof(*one));
	char err[256];

	doc = calloc(1, sizeof(*doc));
	if (!doc || !one) {
		free(one);
		return -1;
	}
	fill_plan(&doc->plan);
	for (unsigned int i = 0; i < NRUNS; i++) {
		runs[i] = write_run(i);
		if (!runs[i] || check(runs[i], one, err, sizeof(err))) {
			printf("run %u: %s\n", i, err);
			free(one);
			return -1;
		}
		doc->runs[i] = one->runs[0];
	}
	free(one);
	doc->nruns = NRUNS;
	text[T_PLAN] = write_doc(BK_PLAN);
	text[T_RUN] = runs[REF_RUN];
	text[T_RESULT] = write_doc(BK_RESULT);
	text[T_SUMMARY] = write_doc(BK_SUMMARY);
	for (int t = 0; t < T_COUNT; t++) {
		if (!text[t])
			return -1;
	}
	return 0;
}

static void test_valid(void)
{
	static const enum bench_kind kinds[T_COUNT] = { BK_PLAN, BK_RUN,
							BK_RESULT, BK_SUMMARY };
	struct bench_doc *d = malloc(sizeof(*d));
	char err[256];

	TEST("every file of a session validates as its kind");

	for (int t = 0; d && t < T_COUNT; t++) {
		if (check(text[t], d, err, sizeof(err))) {
			FAIL(err);
			goto out;
		}
		if (d->kind != kinds[t]) {
			FAIL("wrong kind");
			goto out;
		}
	}
	if (!d || d->nruns != NRUNS || d->runs[NRUNS - 1].samples ||
	    d->plan.rounds != ROUNDS ||
	    strcmp(d->plan.game.title.s, "Example Title") ||
	    d->plan.machine.gpu[0].vendor_id != 0x1002)
		FAIL("the summary is not what was written");
	else
		PASS();
out:
	free(d);
}

/* a result read and written again is the same bytes */
static void test_round_trip(void)
{
	struct bench_doc *saved = doc;
	char err[256];
	char *again;

	TEST("a result reads back into the same bytes");

	doc = malloc(sizeof(*doc));
	if (!doc || check(text[T_RESULT], doc, err, sizeof(err))) {
		FAIL(doc ? err : "malloc");
		free(doc);
		doc = saved;
		return;
	}
	again = write_doc(BK_RESULT);
	if (!again || strcmp(again, text[T_RESULT]))
		FAIL("the bytes differ");
	else if (doc->runs[REF_RUN].sample_count != 2 ||
		 doc->runs[REF_RUN].config != BC_C ||
		 doc->runs[REF_RUN].agent.v[BA_PROTECTED_MAX].v != 2)
		FAIL("a run is not what was written");
	else
		PASS();
	free(again);
	free(doc);
	doc = saved;
}

struct rejection {
	const char *name;
	enum text in;
	const char *from;
	const char *to;
	const char *says;
	/* a second change, when one is not enough */
	const char *from2;
	const char *to2;
};

static const char gpu[] =
	"{\"vendor_id\": 1, \"device_id\": 1, \"name\": null, "
	"\"driver\": null}, ";

#define R(name, in, from, to, says) { name, in, from, to, says, NULL, NULL }
#define R2(name, in, from, to, says, from2, to2) \
	{ name, in, from, to, says, from2, to2 }

static const struct rejection rejections[] = {
	/* text */
	R("a path in a field", T_PLAN, "\"Example Title\"", "\"games/Example\"",
	  "text with a '/'"),
	R("a doubled blank in a field", T_PLAN, "\"Example Title\"",
	  "\"Example  Title\"", "text with a '/'"),
	R("an outer blank in a field", T_PLAN, "\"high\"", "\"high \"",
	  "text with a '/'"),
	R("an empty field", T_PLAN, "\"high\"", "\"\"", "text with a '/'"),
	R("a path for the governor", T_RUN, "\"performance\"", "\"/sys/x\"",
	  "text with a '/'"),
	R("a game with no title", T_PLAN, "\"title\": \"Example Title\"",
	  "\"title\": null", "expected text"),
	R("an escape in a string", T_PLAN, "\"lota-bench\"",
	  "\"lota-\\u0062ench\"", "escape in a string"),
	R("a non-ASCII byte in a string", T_PLAN, "\"high\"", "\"hi\xc3\xa9\"",
	  "byte outside printable ASCII"),
	R("a string over the length limit", T_PLAN, "\"high\"",
	  "\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"",
	  "string too long"),

	/* structure */
	R("an unknown key", T_RUN, "\"end\"", "\"path\"",
	  "unknown key \"path\""),
	R("a repeated key", T_PLAN, "\"tool\": \"lota-bench\",",
	  "\"tool\": \"lota-bench\", \"tool\": \"lota-bench\",",
	  "key \"tool\" repeated"),
	R("a missing key", T_PLAN, ", \"settings\": \"high\"", "",
	  "missing key \"settings\""),
	R("a missing metric", T_RUN, "\"cpu_usage_usec\": 10, ", "",
	  "missing key \"cpu_usage_usec\""),
	R("a key before the kind", T_PLAN,
	  "\"kind\": \"plan\",\n  \"version\": \"1.0.0\",",
	  "\"version\": \"1.0.0\",\n  \"kind\": \"plan\",",
	  "\"kind\" must come before \"version\""),
	R("no kind", T_PLAN, "\"kind\": \"plan\",\n  \"version\": \"1.0.0\",",
	  "", "\"kind\" must come before"),
	R("runs in a plan", T_PLAN, "\"interval_ms\": 1000\n",
	  "\"interval_ms\": 1000, \"runs\": []\n", "a plan holds no \"runs\""),
	R("a run in a result", T_RESULT, "\"runs\": [",
	  "\"run\": {}, \"runs\": [", "a result holds no \"run\""),
	R("samples in a summary", T_SUMMARY, "\"sample_count\"",
	  "\"samples\": [], \"sample_count\"", "a summary holds no samples"),
	R("a negative number", T_RUN, "\"t_ms\": 1000", "\"t_ms\": -1",
	  "negative number"),
	R("a fraction", T_RUN, "\"wall_ms\": 1003", "\"wall_ms\": 1003.5",
	  "not an unsigned integer"),
	R("a number past 64 bits", T_RUN, "\"t_ms\": 1000",
	  "\"t_ms\": 18446744073709551616", "does not fit 64 bits"),
	R("a leading zero", T_RUN, "\"t_ms\": 1000", "\"t_ms\": 01000",
	  "leading zero"),
	R("a metric as a string", T_RUN, "\"cpu_usage_usec\": 10",
	  "\"cpu_usage_usec\": \"10\"",
	  "cpu_usage_usec is not an unsigned integer or null"),
	R("a source as a number", T_RUN, "\"lota-attest\": null",
	  "\"lota-attest\": 0", "null or an object of metrics"),
	R("a null in self", T_RUN, "\"max_rss_bytes\": 3",
	  "\"max_rss_bytes\": null", "max_rss_bytes is null"),
	R("data after the object", T_PLAN, "\n}\n", "\n}\n{}",
	  "data after the object"),
	R("a missing comma", T_PLAN, "\"rounds\": 2,", "\"rounds\": 2",
	  "expected ',' or '}'"),
	R("a bare word", T_RUN, "null", "nul", "unexpected character"),

	/* plan */
	R("another schema version", T_PLAN, "\"schema_version\": 1",
	  "\"schema_version\": 2", "this lota-bench reads 1"),
	R("another tool", T_PLAN, "\"tool\": \"lota-bench\"",
	  "\"tool\": \"other\"", "is not lota-bench"),
	R("another file kind", T_PLAN, "\"kind\": \"plan\"",
	  "\"kind\": \"notes\"", "is not a file kind"),
	R("a SELinux mode of no name", T_PLAN, "\"enforcing\"", "\"relaxed\"",
	  "is not a SELinux mode"),
	R("a PCI id past 16 bits", T_PLAN, "\"vendor_id\": 4098",
	  "\"vendor_id\": 65536", "vendor_id 65536 is not 0..65535"),
	R("more GPUs than a machine is read with", T_PLAN, "\"gpus\": [", NULL,
	  "more than 4 GPUs"),
	R("too few rounds", T_PLAN, "\"rounds\": 2", "\"rounds\": 1",
	  "rounds 1 is not 2..10"),
	R("a run too short to measure", T_PLAN, "\"duration_s\": 600",
	  "\"duration_s\": 9", "duration_s 9 is not 10..3600"),
	R("a settle the frame log cannot start after", T_PLAN,
	  "\"settle_s\": 30", "\"settle_s\": 0", "settle_s 0 is not 1..600"),
	R2("the settle counted in the samples", T_PLAN, "\"settle_s\": 30",
	   "\"settle_s\": 600", "samples a session", "\"interval_ms\": 1000",
	   "\"interval_ms\": 100"),
	R("an interval out of range", T_PLAN, "\"interval_ms\": 1000",
	  "\"interval_ms\": 5", "interval_ms 5 is not"),
	R2("a run over the sample cap", T_PLAN, "\"duration_s\": 600",
	   "\"duration_s\": 3600", "samples a run", "\"interval_ms\": 1000",
	   "\"interval_ms\": 100"),
	R2("a session over the sample cap", T_PLAN, "\"duration_s\": 600",
	   "\"duration_s\": 3600", "samples a session", "\"rounds\": 2",
	   "\"rounds\": 10"),

	/* runs */
	R("an interrupted run", T_RUN, "\"end\": \"duration\"",
	  "\"end\": \"interrupted\"", "an interrupted run is not kept"),
	R("a sample count that disagrees", T_RUN, "\"sample_count\": 2",
	  "\"sample_count\": 3", "sample_count 3, but 2 samples"),
	R("no samples", T_RUN, "\"sample_count\": 2", "\"sample_count\": 0",
	  "sample_count 0 is not"),
	R("time that does not move forward", T_RUN, "\"t_ms\": 1000",
	  "\"t_ms\": 0", "t_ms 0 does not follow 0"),
	R("a run index past the last run", T_RUN, "\"index\": 3",
	  "\"index\": 31", "index 31 is not 0..30"),
	R("a run in the wrong configuration", T_RUN, "\"config\": \"C\"",
	  "\"config\": \"B\"", "run 3 is in C, not B"),
	R("a warm-up past run 0", T_RUN, "\"warmup\": false",
	  "\"warmup\": true", "only run 0 is the warm-up"),
	R("a C run without the agent", T_RUN, "\"mode\": \"enforce\"",
	  "\"mode\": \"none\"", "the agent was not running in C"),
	R("a C run with nothing protected", T_RUN, "\"protected_max\": 2",
	  "\"protected_max\": 0", "nothing was protected in a C run"),
	R("a C run with protection unread", T_RUN, "\"protected_max\": 2",
	  "\"protected_max\": null", "nothing was protected in a C run"),
	R("agent figures without --bench", T_RUN, "\"agent_bench\": true",
	  "\"agent_bench\": false", "agent figures without --bench"),
	/* the warm-up's sources swapped: the agent's totals, the game's null */
	R2("a game without totals", T_SUMMARY, "\"totals\": {\"game\": {",
	   "\"totals\": {\"lota-agent\": {", "the game has no totals",
	   "\"lota-agent\": null,", "\"game\": null,"),
	R("frames without a frame", T_RUN, "{\"frames\": 100", "{\"frames\": 0",
	  "frames without a frame"),
	R("an A run with LOTA", T_RESULT, "\"agent_bench\": false",
	  "\"agent_bench\": true", "LOTA ran during an A run"),
	/* the warm-up's totals, the first in the result */
	R("an A run with lota-attest", T_RESULT,
	  "\"lota-attest\": null},\n   \"agent\"",
	  "\"lota-attest\": {\"cpu_usec\": 10, \"memory_max_bytes\": null, "
	  "\"pgfault\": null, \"pgmajfault\": null, \"io_read_bytes\": null, "
	  "\"io_write_bytes\": null}},\n   \"agent\"",
	  "LOTA ran during an A run"),
	R("a B run that protected the title", T_RESULT, "\"protected_max\": 0",
	  "\"protected_max\": 1", "the title was protected in a B run"),
	R("a run out of place", T_RESULT, "{\"index\": 1,", "{\"index\": 2,",
	  "run 2 where run 1 belongs"),
	R("fewer runs than the rounds make", T_SUMMARY, "\"rounds\": 2",
	  "\"rounds\": 3", "7 runs; 3 rounds make 10"),
};

/* @in with the first @from replaced by @to */
static char *replace(const char *in, const char *from, const char *to)
{
	const char *at = strstr(in, from);
	size_t head;
	char *out;

	if (!at)
		return NULL;
	head = (size_t)(at - in);
	out = malloc(strlen(in) - strlen(from) + strlen(to) + 1);
	if (!out)
		return NULL;
	memcpy(out, in, head);
	strcpy(out + head, to);
	strcat(out, at + strlen(from));
	return out;
}

static char *mutate(const struct rejection *r)
{
	char to[512];
	char *once, *twice;

	if (!r->to) {
		/* four GPUs ahead of the one there is */
		snprintf(to, sizeof(to), "%s%s%s%s%s", r->from, gpu, gpu, gpu,
			 gpu);
		return replace(text[r->in], r->from, to);
	}
	once = replace(text[r->in], r->from, r->to);
	if (!once || !r->from2)
		return once;
	twice = replace(once, r->from2, r->to2);
	free(once);
	return twice;
}

static void test_rejections(void)
{
	struct bench_doc *d = malloc(sizeof(*d));
	char err[256];
	char msg[512];

	for (size_t i = 0; d && i < sizeof(rejections) / sizeof(rejections[0]);
	     i++) {
		const struct rejection *r = &rejections[i];
		char *bad;
		int ret;

		snprintf(msg, sizeof(msg), "refused: %s", r->name);
		TEST(msg);

		bad = mutate(r);
		if (!bad) {
			FAIL("the case does not apply to the file");
			continue;
		}
		ret = check(bad, d, err, sizeof(err));
		free(bad);
		if (ret != -EINVAL) {
			FAIL("accepted");
			continue;
		}
		if (strncmp(err, "offset ", 7) || !strstr(err, r->says)) {
			snprintf(msg, sizeof(msg), "says \"%s\"", err);
			FAIL(msg);
			continue;
		}
		PASS();
	}
	free(d);
}

static void test_truncated(void)
{
	struct bench_doc *d = malloc(sizeof(*d));
	size_t len = strlen(text[T_RESULT]);
	char err[256];

	TEST("a result cut short anywhere is refused");

	for (size_t n = 0; d && n < len; n += 7) {
		if (bench_validate(text[T_RESULT], n, d, err, sizeof(err)) !=
		    -EINVAL) {
			FAIL("a cut result accepted");
			free(d);
			return;
		}
	}
	if (d)
		PASS();
	else
		FAIL("malloc");
	free(d);
}

static void test_offset(void)
{
	struct bench_doc *d = malloc(sizeof(*d));
	char err[256], want[64];
	char *bad;

	TEST("an error names the offset of the bad token");

	bad = replace(text[T_RUN], "\"end\"", "\"path\"");
	if (!bad || !d) {
		FAIL("the case does not apply to the run");
		goto out;
	}
	check(bad, d, err, sizeof(err));
	snprintf(want, sizeof(want),
		 "offset %zu:", (size_t)(strstr(bad, "\"path\"") - bad));
	if (strncmp(err, want, strlen(want)) != 0)
		FAIL(err);
	else
		PASS();
out:
	free(bad);
	free(d);
}

static void test_too_large(void)
{
	struct bench_doc *d = malloc(sizeof(*d));
	char err[256];
	char *big;

	TEST("a file over the size limit is refused unread");

	big = calloc(1, (size_t)BENCH_RESULT_MAX_BYTES + 1);
	if (!big || !d) {
		FAIL("calloc");
	} else if (bench_validate(big, (size_t)BENCH_RESULT_MAX_BYTES + 1, d,
				  err, sizeof(err)) != -EINVAL ||
		   !strstr(err, "larger than")) {
		FAIL("accepted");
	} else {
		PASS();
	}
	free(big);
	free(d);
}

static void test_nesting(void)
{
	struct bench_doc *d = malloc(sizeof(*d));
	size_t n = 100000;
	char err[256];
	char *deep;

	TEST("deep nesting is refused at the first bracket");

	deep = malloc(n + 1);
	if (!deep || !d) {
		FAIL("malloc");
		goto out;
	}
	memset(deep, '[', n);
	deep[n] = '\0';
	if (bench_validate(deep, n, d, err, sizeof(err)) != -EINVAL ||
	    !strstr(err, "offset 0: expected a lota-bench object"))
		FAIL(err);
	else
		PASS();
out:
	free(deep);
	free(d);
}

int main(void)
{
	int ret;

	printf("lota-bench session reader:\n");

	if (build()) {
		printf("cannot write the reference session\n");
		return 1;
	}

	test_valid();
	test_round_trip();
	test_rejections();
	test_truncated();
	test_offset();
	test_too_large();
	test_nesting();

	ret = tests_passed == tests_run ? 0 : 1;
	printf("%d/%d tests passed\n", tests_passed, tests_run);
	free(text[T_PLAN]);
	free(text[T_RESULT]);
	free(text[T_SUMMARY]);
	for (int i = 0; i < NRUNS; i++)
		free(runs[i]);
	free(doc);
	return ret;
}
