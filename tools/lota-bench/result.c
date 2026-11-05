/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * lota-bench - the files of a session written as JSON
 *
 * One sample per line, so a result reads in a diff and greps by time.
 */

#include <errno.h>
#include <inttypes.h>

#include "result.h"

const char *const bench_kind_names[BK_COUNT] = {
	[BK_PLAN] = "plan",
	[BK_RUN] = "run",
	[BK_RESULT] = "result",
	[BK_SUMMARY] = "summary",
};

const char *const bench_source_names[BS_COUNT] = {
	[BS_GAME] = "game",
	[BS_LOTA_AGENT] = "lota-agent",
	[BS_LOTA_ATTEST] = "lota-attest",
};

const char *const bench_config_names[BC_COUNT] = {
	[BC_A] = "A",
	[BC_B] = "B",
	[BC_C] = "C",
};

const char *const bench_end_names[BE_COUNT] = {
	[BE_DURATION] = "duration",
	[BE_INTERRUPTED] = "interrupted",
	[BE_GAME_GONE] = "game-gone",
	[BE_SAMPLE_CAP] = "sample-cap",
};

const char *const bench_mode_names[BMO_COUNT] = {
	[BMO_NONE] = "none",
	[BMO_MONITOR] = "monitor",
	[BMO_ENFORCE] = "enforce",
	[BMO_UNKNOWN] = "unknown",
};

const char *const bench_total_names[BT_COUNT] = {
	[BT_CPU_USEC] = "cpu_usec",
	[BT_MEMORY_MAX_BYTES] = "memory_max_bytes",
	[BT_PGFAULT] = "pgfault",
	[BT_PGMAJFAULT] = "pgmajfault",
	[BT_IO_READ_BYTES] = "io_read_bytes",
	[BT_IO_WRITE_BYTES] = "io_write_bytes",
};

const char *const bench_agent_names[BA_COUNT] = {
	[BA_BPF_RUN_NS] = "bpf_run_ns",
	[BA_BPF_RUN_CNT] = "bpf_run_cnt",
	[BA_MAPS_MEMLOCK_BYTES] = "maps_memlock_bytes",
	[BA_PROTECTED_MAX] = "protected_max",
};

const char *const bench_frame_stat_names[BF_COUNT] = {
	[BF_FRAMES] = "frames",		  [BF_TOTAL_US] = "total_us",
	[BF_MEAN_US] = "mean_us",	  [BF_MEDIAN_US] = "median_us",
	[BF_P99_US] = "p99_us",		  [BF_P999_US] = "p999_us",
	[BF_LOW_1PCT_US] = "low_1pct_us", [BF_LOW_01PCT_US] = "low_01pct_us",
	[BF_MAX_US] = "max_us",		  [BF_STUTTERS] = "stutters",
};

uint64_t *bench_frame_stat(struct bench_frame_stats *s, enum bench_frame_stat i)
{
	switch (i) {
	case BF_FRAMES:
		return &s->frames;
	case BF_TOTAL_US:
		return &s->total_us;
	case BF_MEAN_US:
		return &s->mean_us;
	case BF_MEDIAN_US:
		return &s->median_us;
	case BF_P99_US:
		return &s->p99_us;
	case BF_P999_US:
		return &s->p999_us;
	case BF_LOW_1PCT_US:
		return &s->low_1pct_us;
	case BF_LOW_01PCT_US:
		return &s->low_01pct_us;
	case BF_MAX_US:
		return &s->max_us;
	default:
		return &s->stutters;
	}
}

static int status(FILE *f)
{
	return ferror(f) ? -EIO : 0;
}

static void write_field(FILE *f, const struct bench_field *v)
{
	if (v->set)
		fprintf(f, "\"%s\"", v->s);
	else
		fputs("null", f);
}

static void write_opt(FILE *f, const struct bench_opt *v)
{
	if (v->set)
		fprintf(f, "%" PRIu64, v->v);
	else
		fputs("null", f);
}

static void write_header(FILE *f, enum bench_kind kind)
{
	fprintf(f,
		"{\n"
		"  \"schema_version\": %d,\n"
		"  \"tool\": \"lota-bench\",\n"
		"  \"kind\": \"%s\",\n",
		BENCH_SCHEMA_VERSION, bench_kind_names[kind]);
}

static void write_machine(FILE *f, const struct bench_machine *m)
{
	fputs("{\"cpu_model\": ", f);
	write_field(f, &m->cpu_model);
	fprintf(f,
		", \"cpu_threads\": %" PRIu32 ", \"memory_bytes\": %" PRIu64
		", \"gpus\": [",
		m->cpu_threads, m->memory_bytes);
	for (unsigned int i = 0; i < m->ngpus; i++) {
		const struct bench_gpu *g = &m->gpu[i];

		fprintf(f,
			"%s{\"vendor_id\": %" PRIu32 ", \"device_id\": %" PRIu32
			", \"name\": ",
			i ? ", " : "", g->vendor_id, g->device_id);
		write_field(f, &g->name);
		fputs(", \"driver\": ", f);
		write_field(f, &g->driver);
		fputc('}', f);
	}
	fputs("], \"kernel\": ", f);
	write_field(f, &m->kernel);
	fputs(", \"distro\": ", f);
	write_field(f, &m->distro);
	fputs(", \"tpm\": ", f);
	write_field(f, &m->tpm);
	fprintf(f, ", \"selinux\": \"%s\"}", bench_selinux_names[m->selinux]);
}

static void write_game(FILE *f, const struct bench_game *g)
{
	fputs("{\"title\": ", f);
	write_field(f, &g->title);
	fputs(", \"proton\": ", f);
	write_field(f, &g->proton);
	fputs(", \"version\": ", f);
	write_field(f, &g->version);
	fputs(", \"settings\": ", f);
	write_field(f, &g->settings);
	fputc('}', f);
}

/* everything a plan, a result and a summary share */
static void write_plan_body(FILE *f, const struct bench_plan *p)
{
	fputs("  \"version\": ", f);
	write_field(f, &p->version);
	fputs(",\n  \"machine\": ", f);
	write_machine(f, &p->machine);
	fputs(",\n  \"game\": ", f);
	write_game(f, &p->game);
	fprintf(f,
		",\n"
		"  \"rounds\": %u,\n"
		"  \"settle_s\": %u,\n"
		"  \"duration_s\": %u,\n"
		"  \"interval_ms\": %u",
		p->rounds, p->settle_s, p->duration_s, p->interval_ms);
}

int bench_write_plan(FILE *f, const struct bench_plan *p)
{
	write_header(f, BK_PLAN);
	write_plan_body(f, p);
	fputs("\n}\n", f);
	if (fflush(f))
		return -EIO;
	return status(f);
}

/* the keys known when the run starts */
static void write_run_head(FILE *f, const struct bench_run *r)
{
	fprintf(f,
		"{\"index\": %u, \"config\": \"%s\", \"warmup\": %s, "
		"\"mode\": \"%s\", \"agent_bench\": %s, "
		"\"power\": {\"governor\": ",
		r->index, bench_config_names[r->config],
		r->warmup ? "true" : "false", bench_mode_names[r->mode],
		r->agent_bench ? "true" : "false");
	write_field(f, &r->power.governor);
	fputs(", \"profile\": ", f);
	write_field(f, &r->power.profile);
	fprintf(f, ", \"supply\": \"%s\"}",
		bench_supply_names[r->power.supply]);
}

static void write_totals(FILE *f, const struct bench_totals *t)
{
	if (!t->present) {
		fputs("null", f);
		return;
	}
	for (int i = 0; i < BT_COUNT; i++) {
		fprintf(f, "%s\"%s\": ", i ? ", " : "{", bench_total_names[i]);
		write_opt(f, &t->v[i]);
	}
	fputc('}', f);
}

static void write_agent(FILE *f, const struct bench_agent *a)
{
	if (!a->present) {
		fputs("null", f);
		return;
	}
	for (int i = 0; i < BA_COUNT; i++) {
		fprintf(f, "%s\"%s\": ", i ? ", " : "{", bench_agent_names[i]);
		write_opt(f, &a->v[i]);
	}
	fputc('}', f);
}

static void write_frames(FILE *f, const struct bench_run_frames *fr)
{
	struct bench_frame_stats s = fr->s;

	if (!fr->present) {
		fputs("null", f);
		return;
	}
	for (int i = 0; i < BF_COUNT; i++)
		fprintf(f, "%s\"%s\": %" PRIu64, i ? ", " : "{",
			bench_frame_stat_names[i],
			*bench_frame_stat(&s, (enum bench_frame_stat)i));
	fputc('}', f);
}

/* the keys known when the run is over */
static void write_run_tail(FILE *f, const struct bench_run *r)
{
	fprintf(f,
		",\n   \"sample_count\": %u, \"wall_ms\": %" PRIu64
		", \"end\": \"%s\",\n   \"totals\": {",
		r->sample_count, r->wall_ms, bench_end_names[r->end]);
	for (int i = 0; i < BS_COUNT; i++) {
		fprintf(f, "%s\"%s\": ", i ? ", " : "", bench_source_names[i]);
		write_totals(f, &r->totals[i]);
	}
	fputs("},\n   \"agent\": ", f);
	write_agent(f, &r->agent);
	fputs(",\n   \"frames\": ", f);
	write_frames(f, &r->frames);
	fprintf(f,
		",\n   \"self\": {\"cpu_user_usec\": %" PRIu64
		", \"cpu_system_usec\": %" PRIu64
		", \"max_rss_bytes\": %" PRIu64 "}}",
		r->self.cpu_user_usec, r->self.cpu_system_usec,
		r->self.max_rss_bytes);
}

int bench_write_run_begin(FILE *f, const struct bench_run *r)
{
	write_header(f, BK_RUN);
	fputs("  \"run\": ", f);
	write_run_head(f, r);
	fputs(",\n   \"samples\": [", f);
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

int bench_write_run_end(FILE *f, const struct bench_run *r)
{
	fputs("\n   ]", f);
	write_run_tail(f, r);
	fputs("\n}\n", f);
	if (fflush(f))
		return -EIO;
	return status(f);
}

int bench_write_session(FILE *f, const struct bench_doc *d,
			enum bench_kind kind)
{
	write_header(f, kind);
	write_plan_body(f, &d->plan);
	fputs(",\n  \"runs\": [", f);
	for (unsigned int i = 0; i < d->nruns; i++) {
		const struct bench_run *r = &d->runs[i];

		fputs(i ? ",\n  " : "\n  ", f);
		write_run_head(f, r);
		if (kind == BK_RESULT) {
			fputs(",\n   \"samples\": ", f);
			fwrite(r->samples, 1, r->samples_len, f);
		}
		write_run_tail(f, r);
	}
	fputs("\n  ]\n}\n", f);
	if (fflush(f))
		return -EIO;
	return status(f);
}
