/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Unit tests for lota-bench's report of a session.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test.h"
#include "../tools/lota-bench/report.h"
#include "../tools/lota-bench/validate.h"

#define ROUNDS 2
#define NRUNS (1 + BC_COUNT * ROUNDS)

static struct bench_doc *doc;

static void set(struct bench_field *f, const char *s)
{
	bench_field_set(f, s, strlen(s));
}

static void fill(void)
{
	/* frame time medians: A 10.0/10.2, B 10.1/10.3, C 12.0/12.0 */
	static const uint64_t median_us[NRUNS] = { 99000, 10000, 10100, 12000,
						   10200, 10300, 12000 };
	struct bench_plan *p = &doc->plan;

	memset(doc, 0, sizeof(*doc));
	doc->kind = BK_SUMMARY;
	set(&p->version, "1.0.0");
	set(&p->machine.cpu_model, "Test CPU 8-Core");
	set(&p->game.title, "Example Title");
	p->rounds = ROUNDS;
	p->duration_s = 600;
	p->interval_ms = 1000;
	doc->nruns = NRUNS;
	for (unsigned int i = 0; i < NRUNS; i++) {
		struct bench_run *r = &doc->runs[i];

		r->index = i;
		r->config = bench_run_config(i);
		r->warmup = i == 0;
		r->wall_ms = 1000;
		r->sample_count = 2;
		r->end = BE_DURATION;
		r->totals[BS_GAME].present = true;
		/* half a CPU */
		r->totals[BS_GAME].v[BT_CPU_USEC] =
			(struct bench_opt){ 500000, true };
		r->frames.present = true;
		r->frames.s.frames = 100;
		r->frames.s.median_us = median_us[i];
		if (r->config == BC_A)
			continue;
		r->mode = BMO_ENFORCE;
		r->agent_bench = true;
		r->totals[BS_LOTA_AGENT].present = true;
		r->totals[BS_LOTA_AGENT].v[BT_CPU_USEC] =
			(struct bench_opt){ 1000, true };
		r->agent.present = true;
		r->agent.v[BA_BPF_RUN_NS] = (struct bench_opt){ 2000, true };
		r->agent.v[BA_PROTECTED_MAX] =
			(struct bench_opt){ r->config == BC_C ? 1 : 0, true };
	}
}

static char *report(void)
{
	char *buf = NULL;
	size_t len = 0;
	FILE *f;
	int ret;

	f = open_memstream(&buf, &len);
	if (!f)
		return NULL;
	ret = bench_report(f, doc);
	fclose(f);
	if (ret) {
		free(buf);
		return NULL;
	}
	return buf;
}

/* the row named @name, up to its newline */
static const char *row(const char *text, const char *name, char *out,
		       size_t cap)
{
	const char *s = strstr(text, name), *e;

	if (!s)
		return NULL;
	e = strchr(s, '\n');
	if (!e || (size_t)(e - s) >= cap)
		return NULL;
	memcpy(out, s, (size_t)(e - s));
	out[e - s] = '\0';
	return out;
}

static void test_figures(void)
{
	char line[256], *text;

	TEST("a figure is the median of its runs without the warm-up");
	fill();
	text = report();
	if (!text || !row(text, "frame time median ms", line, sizeof(line)))
		FAIL("no frame time row");
	else if (!strstr(line, "10.10 ±0.10") || !strstr(line, "10.20 ±0.10") ||
		 !strstr(line, "12.00 ±0.00"))
		FAIL(line);
	else
		PASS();

	TEST("a difference within the spreads is noise, a larger one not");
	if (!text || !row(text, "frame time median ms", line, sizeof(line)))
		FAIL("no frame time row");
	else if (!strstr(line, "+0.10 ~") || !strstr(line, "+1.90  ") ||
		 strstr(line, "+1.90 ~"))
		FAIL(line);
	else
		PASS();

	TEST("CPU is a share of one CPU, BPF time microseconds a second");
	if (!text || !row(text, "game CPU %", line, sizeof(line)) ||
	    !strstr(line, "50.0 ±0.0"))
		FAIL("game CPU");
	else if (!row(text, "lota-agent CPU %", line, sizeof(line)) ||
		 !strstr(line, "0.00 ±0.00") || !strstr(line, "0.10 ±0.00"))
		FAIL("agent CPU");
	else if (!row(text, "BPF programs us/s", line, sizeof(line)) ||
		 !strstr(line, "2.0 ±0.0"))
		FAIL("BPF time");
	else
		PASS();
	free(text);
}

static void test_missing(void)
{
	char line[256], *text;

	TEST("a run without a figure is marked, none without shows -");
	fill();
	doc->runs[2].frames.present = false;
	for (unsigned int i = 0; i < NRUNS; i++)
		doc->runs[i].totals[BS_GAME].v[BT_MEMORY_MAX_BYTES].set = false;
	text = report();
	if (!text || !row(text, "frame time median ms", line, sizeof(line)))
		FAIL("no frame time row");
	else if (!strstr(line, "10.30 ±0.00*"))
		FAIL(line);
	else if (!row(text, "game memory MiB", line, sizeof(line)) ||
		 strstr(line, "±"))
		FAIL("a figure without runs");
	else if (!strstr(text, "* not every run"))
		FAIL("no note on the mark");
	else
		PASS();
	free(text);

	TEST("runs under other power settings are called out");
	fill();
	set(&doc->runs[4].power.governor, "powersave");
	text = report();
	if (!text || !strstr(text, "Run 4 ran under other power settings"))
		FAIL("not called out");
	else
		PASS();
	free(text);
}

static char *issue(int *ret, char *err, size_t cap)
{
	char *buf = NULL;
	size_t len = 0;
	FILE *f;

	f = open_memstream(&buf, &len);
	if (!f)
		return NULL;
	*ret = bench_issue(f, doc, err, cap);
	fclose(f);
	return buf;
}

static void test_issue(void)
{
	static const char open_block[] = "\n```\n\n```lota-bench\n";
	struct bench_doc *back = malloc(sizeof(*back));
	char err[256], *text, *json, *end;
	int ret = 0;

	TEST("an issue carries the report and a summary that reads back");
	fill();
	text = issue(&ret, err, sizeof(err));
	json = text ? strstr(text, open_block) : NULL;
	end = json ? strstr(json + sizeof(open_block) - 1, "```\n") : NULL;
	if (!back || ret || !json || !end) {
		FAIL(ret ? err : "no lota-bench block");
	} else if (strncmp(text, "```text\nExample Title: ", 23) ||
		   end[4] != '\0') {
		FAIL("not the report, then the block");
	} else {
		json += sizeof(open_block) - 1;
		if (bench_validate(json, (size_t)(end - json), back, err,
				   sizeof(err)))
			FAIL(err);
		else if (back->kind != BK_SUMMARY || back->nruns != NRUNS)
			FAIL("not the session's summary");
		else
			PASS();
	}
	free(text);

	TEST("a session of the most rounds fits an issue");
	fill();
	doc->plan.rounds = BENCH_ROUNDS_MAX;
	doc->nruns = BENCH_MAX_RUNS;
	for (unsigned int i = NRUNS; i < BENCH_MAX_RUNS; i++) {
		doc->runs[i] = doc->runs[i - BC_COUNT];
		doc->runs[i].index = i;
	}
	for (unsigned int i = 0; i < BENCH_MAX_RUNS; i++) {
		struct bench_run *r = &doc->runs[i];

		for (int t = 0; t < BT_COUNT; t++)
			r->totals[BS_GAME].v[t] =
				(struct bench_opt){ UINT64_MAX, true };
		r->frames.present = true;
		for (int k = 0; k < BF_COUNT; k++)
			*bench_frame_stat(&r->frames.s,
					  (enum bench_frame_stat)k) =
				UINT64_MAX;
		r->totals[BS_GAME].v[BT_CPU_USEC].v = 500000;
	}
	for (int c = 0; c < BENCH_MAX_GPUS; c++) {
		doc->plan.machine.gpu[c].vendor_id = 0xffff;
		set(&doc->plan.machine.gpu[c].name,
		    "Test GPU with a name as long as a cleaned field lets it be");
	}
	doc->plan.machine.ngpus = BENCH_MAX_GPUS;
	text = issue(&ret, err, sizeof(err));
	if (ret)
		FAIL(err);
	else
		PASS();
	free(text);

	TEST("a session that does not read back is not put in an issue");
	fill();
	doc->runs[3].agent.v[BA_PROTECTED_MAX].v = 0;
	text = issue(&ret, err, sizeof(err));
	if (ret != -EINVAL || !strstr(err, "does not read back"))
		FAIL("an invalid summary was written");
	else
		PASS();
	free(text);
	free(back);
}

int main(void)
{
	printf("lota-bench report:\n");

	doc = malloc(sizeof(*doc));
	if (!doc)
		return 1;
	test_figures();
	test_missing();
	test_issue();
	free(doc);

	printf("%d/%d tests passed\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
