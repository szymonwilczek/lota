/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Unit tests for lota-bench's writer of the files of a session.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "test.h"
#include "../tools/lota-bench/result.h"

static const char expected_plan[] =
	"{\n"
	"  \"schema_version\": 1,\n"
	"  \"tool\": \"lota-bench\",\n"
	"  \"kind\": \"plan\",\n"
	"  \"version\": \"1.0.0\",\n"
	"  \"machine\": {\"cpu_model\": \"Test CPU 8-Core\", "
	"\"cpu_threads\": 16, \"memory_bytes\": 34359738368, \"gpus\": "
	"[{\"vendor_id\": 4098, \"device_id\": 1, \"name\": \"Test GPU\", "
	"\"driver\": null}], \"kernel\": \"6.0.0-test\", \"distro\": null, "
	"\"tpm\": \"none\", \"selinux\": \"enforcing\"},\n"
	"  \"game\": {\"title\": \"Example Title\", \"proton\": null, "
	"\"version\": null, \"settings\": \"high\"},\n"
	"  \"rounds\": 3,\n"
	"  \"duration_s\": 300,\n"
	"  \"interval_ms\": 1000\n"
	"}\n";

static const char expected_run[] =
	"{\n"
	"  \"schema_version\": 1,\n"
	"  \"tool\": \"lota-bench\",\n"
	"  \"kind\": \"run\",\n"
	"  \"run\": {\"index\": 1, \"config\": \"A\", \"warmup\": false, "
	"\"mode\": \"none\", \"agent_bench\": false, \"power\": "
	"{\"governor\": \"performance\", \"profile\": null, "
	"\"supply\": \"ac\"},\n"
	"   \"samples\": [\n"
	"    {\"t_ms\": 0, \"game\": {\"cpu_usage_usec\": 10, "
	"\"cpu_user_usec\": null, \"cpu_system_usec\": null, "
	"\"memory_current_bytes\": 4096, \"memory_peak_bytes\": null, "
	"\"memory_anon_bytes\": null, \"memory_file_bytes\": null, "
	"\"memory_kernel_bytes\": null, \"pgfault\": null, "
	"\"pgmajfault\": null, \"io_read_bytes\": null, "
	"\"io_write_bytes\": null, \"io_read_ops\": null, "
	"\"io_write_ops\": 18446744073709551615}, \"lota-agent\": null, "
	"\"lota-attest\": null},\n"
	"    {\"t_ms\": 1000, \"game\": null, \"lota-agent\": null, "
	"\"lota-attest\": null}\n"
	"   ],\n"
	"   \"sample_count\": 2, \"wall_ms\": 1003, \"end\": \"game-gone\",\n"
	"   \"totals\": {\"game\": {\"cpu_usec\": 10, "
	"\"memory_max_bytes\": 4096, \"pgfault\": null, \"pgmajfault\": null, "
	"\"io_read_bytes\": null, \"io_write_bytes\": null}, "
	"\"lota-agent\": null, \"lota-attest\": null},\n"
	"   \"agent\": null,\n"
	"   \"frames\": {\"frames\": 2, \"total_us\": 33000, "
	"\"mean_us\": 16500, \"median_us\": 16500, \"p99_us\": 17000, "
	"\"p999_us\": 17000, \"low_1pct_us\": 17000, \"low_01pct_us\": 17000, "
	"\"max_us\": 17000, \"stutters\": 0},\n"
	"   \"self\": {\"cpu_user_usec\": 1, \"cpu_system_usec\": 2, "
	"\"max_rss_bytes\": 3}}\n"
	"}\n";

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
	p->rounds = 3;
	p->duration_s = 300;
	p->interval_ms = 1000;
}

static void fill_run(struct bench_run *r)
{
	memset(r, 0, sizeof(*r));
	r->index = 1;
	r->config = BC_A;
	set(&r->power.governor, "performance");
	r->power.supply = BSU_AC;
	r->wall_ms = 1003;
	r->sample_count = 2;
	r->end = BE_GAME_GONE;
	r->totals[BS_GAME].present = true;
	r->totals[BS_GAME].v[BT_CPU_USEC] = (struct bench_opt){ 10, true };
	r->totals[BS_GAME].v[BT_MEMORY_MAX_BYTES] =
		(struct bench_opt){ 4096, true };
	r->frames.present = true;
	r->frames.s = (struct bench_frame_stats){
		.frames = 2,
		.total_us = 33000,
		.mean_us = 16500,
		.median_us = 16500,
		.p99_us = 17000,
		.p999_us = 17000,
		.low_1pct_us = 17000,
		.low_01pct_us = 17000,
		.max_us = 17000,
	};
	r->self = (struct bench_self){ 1, 2, 3 };
}

static void write_run(FILE *f, int *ret)
{
	const struct bench_sample *src[BS_COUNT] = { NULL };
	struct bench_sample game = { .have = 0 };
	struct bench_run r;

	fill_run(&r);
	game.v[BM_CPU_USAGE_USEC] = 10;
	game.v[BM_MEMORY_CURRENT_BYTES] = 4096;
	game.v[BM_IO_WRITE_OPS] = UINT64_MAX;
	/* a value without its bit is not written */
	game.v[BM_PGFAULT] = 99;
	game.have = (1u << BM_CPU_USAGE_USEC) |
		    (1u << BM_MEMORY_CURRENT_BYTES) | (1u << BM_IO_WRITE_OPS);

	ret[0] = bench_write_run_begin(f, &r);
	src[BS_GAME] = &game;
	ret[1] = bench_write_sample(f, 0, 0, src);
	src[BS_GAME] = NULL;
	ret[2] = bench_write_sample(f, 1, 1000, src);
	ret[3] = bench_write_run_end(f, &r);
}

static void test_plan_layout(void)
{
	struct bench_plan p;
	char *buf = NULL;
	size_t len = 0;
	FILE *f;
	int ret;

	TEST("a plan is written byte for byte as documented");

	fill_plan(&p);
	f = open_memstream(&buf, &len);
	if (!f) {
		FAIL("open_memstream");
		return;
	}
	ret = bench_write_plan(f, &p);
	fclose(f);
	if (ret)
		FAIL("the write reported failure");
	else if (strcmp(buf, expected_plan) != 0)
		FAIL("output differs from the documented layout");
	else
		PASS();
	free(buf);
}

static void test_run_layout(void)
{
	char *buf = NULL;
	size_t len = 0;
	int ret[4];
	FILE *f;

	TEST("a run is written byte for byte as documented");

	f = open_memstream(&buf, &len);
	if (!f) {
		FAIL("open_memstream");
		return;
	}
	write_run(f, ret);
	fclose(f);

	if (ret[0] || ret[1] || ret[2] || ret[3])
		FAIL("a write reported failure");
	else if (strcmp(buf, expected_run) != 0)
		FAIL("output differs from the documented layout");
	else
		PASS();
	free(buf);
}

static void test_session(void)
{
	static const char samples[] = "[\n    {\"t_ms\": 0}\n   ]";
	struct bench_doc *d = calloc(1, sizeof(*d));
	char *res = NULL, *sum = NULL;
	size_t len = 0;
	FILE *f;

	TEST("a result copies the samples, a summary leaves them out");

	if (!d) {
		FAIL("calloc");
		return;
	}
	fill_plan(&d->plan);
	d->nruns = 2;
	fill_run(&d->runs[0]);
	fill_run(&d->runs[1]);
	d->runs[0].index = 0;
	d->runs[0].warmup = true;
	d->runs[0].samples = d->runs[1].samples = samples;
	d->runs[0].samples_len = d->runs[1].samples_len = strlen(samples);

	f = open_memstream(&res, &len);
	if (f) {
		bench_write_session(f, d, BK_RESULT);
		fclose(f);
	}
	f = open_memstream(&sum, &len);
	if (f) {
		bench_write_session(f, d, BK_SUMMARY);
		fclose(f);
	}
	if (!res || !sum)
		FAIL("open_memstream");
	else if (!strstr(res, "\"kind\": \"result\"") ||
		 !strstr(sum, "\"kind\": \"summary\""))
		FAIL("wrong kind");
	else if (!strstr(res, "\"samples\": [\n    {\"t_ms\": 0}\n   ],\n"
			      "   \"sample_count\"") ||
		 strstr(strstr(res, "\"samples\"") + 1, "\"samples\"") == NULL)
		FAIL("a result lost its samples");
	else if (strstr(sum, "samples\""))
		FAIL("a summary holds samples");
	else if (!strstr(sum, "\"warmup\": true") ||
		 !strstr(sum, "\"rounds\": 3"))
		FAIL("a summary lost the plan or a run");
	else
		PASS();
	free(res);
	free(sum);
	free(d);
}

static void test_full_device(void)
{
	int ret[4];
	FILE *f;
	int fd;

	TEST("a full device fails the run instead of truncating it");

	fd = open("/dev/full", O_WRONLY | O_CLOEXEC);
	f = fd < 0 ? NULL : fdopen(fd, "w");
	if (!f) {
		printf("SKIP (no /dev/full)\n");
		tests_run--;
		return;
	}
	write_run(f, ret);
	fclose(f);

	if (ret[3] != -EIO)
		FAIL("the end of a lost run is reported as written");
	else
		PASS();
}

static void test_names(void)
{
	const char *const *tables[] = {
		bench_kind_names,  bench_source_names,	   bench_config_names,
		bench_end_names,   bench_mode_names,	   bench_total_names,
		bench_agent_names, bench_frame_stat_names,
	};
	const int counts[] = { BK_COUNT,  BS_COUNT, BC_COUNT, BE_COUNT,
			       BMO_COUNT, BT_COUNT, BA_COUNT, BF_COUNT };

	TEST("every name table is full");

	for (size_t t = 0; t < sizeof(counts) / sizeof(counts[0]); t++) {
		for (int i = 0; i < counts[t]; i++) {
			if (!tables[t][i]) {
				FAIL("a value has no name");
				return;
			}
		}
	}
	PASS();
}

static void test_schedule(void)
{
	static const enum bench_config want[] = { BC_A, BC_A, BC_B, BC_C,
						  BC_A, BC_B, BC_C };

	TEST("a warm-up in A, then rounds of A B C");

	if (bench_session_runs(2) != 7 ||
	    bench_session_runs(BENCH_ROUNDS_MAX) != BENCH_MAX_RUNS) {
		FAIL("run count");
		return;
	}
	for (unsigned int i = 0; i < 7; i++) {
		if (bench_run_config(i) != want[i]) {
			FAIL("configuration");
			return;
		}
	}
	PASS();
}

int main(void)
{
	printf("lota-bench result writer:\n");

	test_plan_layout();
	test_run_layout();
	test_session();
	test_full_device();
	test_names();
	test_schedule();

	printf("%d/%d tests passed\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
