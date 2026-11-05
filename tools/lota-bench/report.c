/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * lota-bench report - what a session found, in text
 *
 * A figure per configuration is the median of its runs, so one disturbed
 * run does not move it, and its spread is half their range. A difference
 * from A no larger than the two spreads together is within what the runs
 * of one configuration already disagree by, and is called noise.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "report.h"
#include "validate.h"

struct metric {
	const char *name;
	const char *unit;
	int decimals;
	/* the figure of run @r; false when the run has none */
	bool (*of)(const struct bench_run *r, double *out);
};

static bool frame(const struct bench_run *r, uint64_t us, double *out)
{
	if (!r->frames.present)
		return false;
	*out = (double)us / 1000.0;
	return true;
}

static bool frame_median(const struct bench_run *r, double *out)
{
	return frame(r, r->frames.s.median_us, out);
}

static bool frame_p99(const struct bench_run *r, double *out)
{
	return frame(r, r->frames.s.p99_us, out);
}

static bool frame_low(const struct bench_run *r, double *out)
{
	return frame(r, r->frames.s.low_1pct_us, out);
}

/* the share of one CPU a source took over the run */
static bool cpu(const struct bench_run *r, enum bench_source s, double *out)
{
	const struct bench_opt *o = &r->totals[s].v[BT_CPU_USEC];

	if (!r->totals[s].present || !o->set || !r->wall_ms)
		return false;
	*out = (double)o->v / ((double)r->wall_ms * 10.0);
	return true;
}

static bool memory(const struct bench_run *r, enum bench_source s, double *out)
{
	const struct bench_opt *o = &r->totals[s].v[BT_MEMORY_MAX_BYTES];

	if (!r->totals[s].present || !o->set)
		return false;
	*out = (double)o->v / (1024.0 * 1024.0);
	return true;
}

static bool game_cpu(const struct bench_run *r, double *out)
{
	return cpu(r, BS_GAME, out);
}

static bool game_memory(const struct bench_run *r, double *out)
{
	return memory(r, BS_GAME, out);
}

/* in A the services are stopped, so they cost nothing */
static bool unit_cpu(const struct bench_run *r, enum bench_source s,
		     double *out)
{
	if (r->config == BC_A) {
		*out = 0;
		return true;
	}
	if (!r->totals[s].present) {
		*out = 0;
		return s == BS_LOTA_ATTEST;
	}
	return cpu(r, s, out);
}

static bool agent_cpu(const struct bench_run *r, double *out)
{
	return unit_cpu(r, BS_LOTA_AGENT, out);
}

static bool attest_cpu(const struct bench_run *r, double *out)
{
	return unit_cpu(r, BS_LOTA_ATTEST, out);
}

static bool agent_memory(const struct bench_run *r, double *out)
{
	if (r->config == BC_A) {
		*out = 0;
		return true;
	}
	return memory(r, BS_LOTA_AGENT, out);
}

/* nanoseconds a millisecond is microseconds a second */
static bool bpf_time(const struct bench_run *r, double *out)
{
	const struct bench_opt *o = &r->agent.v[BA_BPF_RUN_NS];

	if (r->config == BC_A) {
		*out = 0;
		return true;
	}
	if (!r->agent.present || !o->set || !r->wall_ms)
		return false;
	*out = (double)o->v / (double)r->wall_ms;
	return true;
}

static const struct metric metrics[] = {
	{ "frame time median", "ms", 2, frame_median },
	{ "frame time p99", "ms", 2, frame_p99 },
	{ "frame time 1% low", "ms", 2, frame_low },
	{ "game CPU", "%", 1, game_cpu },
	{ "game memory", "MiB", 0, game_memory },
	{ "lota-agent CPU", "%", 2, agent_cpu },
	{ "lota-attest CPU", "%", 2, attest_cpu },
	{ "lota-agent memory", "MiB", 1, agent_memory },
	{ "BPF programs", "us/s", 1, bpf_time },
};

#define NMETRICS (sizeof(metrics) / sizeof(metrics[0]))

struct figure {
	unsigned int n; /* runs with the figure */
	unsigned int of; /* runs in the configuration */
	double median;
	double spread;
};

static void sort(double *v, unsigned int n)
{
	for (unsigned int i = 1; i < n; i++) {
		double x = v[i];
		unsigned int j = i;

		for (; j && v[j - 1] > x; j--)
			v[j] = v[j - 1];
		v[j] = x;
	}
}

static void figure_of(const struct bench_doc *d, const struct metric *m,
		      enum bench_config c, struct figure *fig)
{
	double v[BENCH_MAX_RUNS] = { 0 };

	memset(fig, 0, sizeof(*fig));
	for (unsigned int i = 0; i < d->nruns; i++) {
		const struct bench_run *r = &d->runs[i];

		if (r->warmup || r->config != c)
			continue;
		fig->of++;
		if (m->of(r, &v[fig->n]))
			fig->n++;
	}
	if (!fig->n)
		return;
	sort(v, fig->n);
	fig->median = fig->n % 2 ? v[fig->n / 2] :
				   (v[fig->n / 2 - 1] + v[fig->n / 2]) / 2;
	fig->spread = (v[fig->n - 1] - v[0]) / 2;
}

#define COL_NAME 22
#define COL_FIG 16
#define COL_DELTA 12

static void put_figure(FILE *f, const struct metric *m,
		       const struct figure *fig)
{
	char buf[64];

	if (!fig->n)
		snprintf(buf, sizeof(buf), "-");
	else
		snprintf(buf, sizeof(buf), "%.*f ±%.*f%s", m->decimals,
			 fig->median, m->decimals, fig->spread,
			 fig->n < fig->of ? "*" : "");
	/* '±' is two bytes and one column */
	fprintf(f, "%*s", COL_FIG + (fig->n ? 1 : 0), buf);
}

static void put_delta(FILE *f, const struct metric *m, const struct figure *a,
		      const struct figure *x)
{
	char buf[64];
	double delta;

	if (!a->n || !x->n) {
		fprintf(f, "%*s", COL_DELTA, "-");
		return;
	}
	delta = x->median - a->median;
	snprintf(buf, sizeof(buf), "%+.*f%s", m->decimals, delta,
		 (delta < 0 ? -delta : delta) <= a->spread + x->spread ? " ~" :
									 "  ");
	fprintf(f, "%*s", COL_DELTA, buf);
}

static void put_field(FILE *f, const char *label, const struct bench_field *v)
{
	if (v->set)
		fprintf(f, "  %-10s %s\n", label, v->s);
}

static void put_header(FILE *f, const struct bench_doc *d)
{
	const struct bench_plan *p = &d->plan;
	const struct bench_machine *m = &p->machine;
	bool modes[BMO_COUNT] = { false };
	bool no_bench = false;

	fprintf(f,
		"%s: %u rounds of A B C, %u s a run after %u s to settle\n\n",
		p->game.title.s, p->rounds, p->duration_s, p->settle_s);
	put_field(f, "proton", &p->game.proton);
	put_field(f, "version", &p->game.version);
	put_field(f, "settings", &p->game.settings);
	put_field(f, "cpu", &m->cpu_model);
	for (unsigned int i = 0; i < m->ngpus; i++)
		put_field(f, "gpu", &m->gpu[i].name);
	put_field(f, "kernel", &m->kernel);
	put_field(f, "distro", &m->distro);
	put_field(f, "tpm", &m->tpm);
	fprintf(f, "  %-10s %s\n", "selinux", bench_selinux_names[m->selinux]);
	put_field(f, "lota-bench", &p->version);

	for (unsigned int i = 0; i < d->nruns; i++) {
		const struct bench_run *r = &d->runs[i];

		if (r->config == BC_A)
			continue;
		modes[r->mode] = true;
		no_bench = no_bench || !r->agent_bench;
	}
	fprintf(f, "  %-10s", "agent");
	for (int i = BMO_MONITOR; i < BMO_COUNT; i++) {
		if (modes[i])
			fprintf(f, " %s", bench_mode_names[i]);
	}
	fprintf(f, "%s\n", no_bench ? ", some runs without --bench" : "");
}

/* runs that ran under other power settings than run 0 */
static void put_power(FILE *f, const struct bench_doc *d)
{
	const struct bench_power *p0 = &d->runs[0].power;

	for (unsigned int i = 1; i < d->nruns; i++) {
		const struct bench_power *p = &d->runs[i].power;

		if (p->supply != p0->supply ||
		    p->governor.set != p0->governor.set ||
		    strcmp(p->governor.s, p0->governor.s) ||
		    p->profile.set != p0->profile.set ||
		    strcmp(p->profile.s, p0->profile.s)) {
			fprintf(f,
				"\nRun %u ran under other power settings than "
				"run 0; the session is not comparable run to "
				"run.\n",
				i);
			return;
		}
	}
}

int bench_report(FILE *f, const struct bench_doc *d)
{
	bool partial = false;

	put_header(f, d);
	fprintf(f, "\n%-*s%*s%*s%*s%*s%*s\n", COL_NAME, "", COL_FIG, "A",
		COL_FIG, "B", COL_FIG, "C", COL_DELTA, "B-A", COL_DELTA, "C-A");
	for (size_t i = 0; i < NMETRICS; i++) {
		const struct metric *m = &metrics[i];
		struct figure fig[BC_COUNT];
		char name[64];

		for (int c = 0; c < BC_COUNT; c++) {
			figure_of(d, m, (enum bench_config)c, &fig[c]);
			partial = partial || (fig[c].n && fig[c].n < fig[c].of);
		}
		snprintf(name, sizeof(name), "%s %s", m->name, m->unit);
		fprintf(f, "%-*s", COL_NAME, name);
		for (int c = 0; c < BC_COUNT; c++)
			put_figure(f, m, &fig[c]);
		put_delta(f, m, &fig[BC_A], &fig[BC_B]);
		put_delta(f, m, &fig[BC_A], &fig[BC_C]);
		fputc('\n', f);
	}
	fprintf(f,
		"\nEach figure is the median of the configuration's runs, "
		"warm-up left out,\n± half their range. ~ marks a difference "
		"within the two spreads: noise.\n");
	if (partial)
		fprintf(f, "* not every run of the configuration has the "
			   "figure.\n");
	put_power(f, d);
	return ferror(f) ? -EIO : 0;
}

static char *text_of(const struct bench_doc *d, bool summary, size_t *len)
{
	char *buf = NULL;
	FILE *m;
	int ret;

	*len = 0;
	m = open_memstream(&buf, len);
	if (!m)
		return NULL;
	ret = summary ? bench_write_session(m, d, BK_SUMMARY) :
			bench_report(m, d);
	if (fclose(m) || ret) {
		free(buf);
		return NULL;
	}
	return buf;
}

int bench_issue(FILE *f, const struct bench_doc *d, char *err, size_t errcap)
{
	static const char head[] = "```text\n",
			  mid[] = "```\n\n```lota-bench\n", tail[] = "```\n";
	struct bench_doc *back = malloc(sizeof(*back));
	char *report = NULL, *summary = NULL, why[256];
	size_t rlen, slen, total;
	int ret = -EINVAL;

	if (!back) {
		snprintf(err, errcap, "out of memory");
		return -ENOMEM;
	}
	report = text_of(d, false, &rlen);
	summary = text_of(d, true, &slen);
	if (!report || !summary) {
		snprintf(err, errcap, "out of memory");
		ret = -ENOMEM;
		goto out;
	}
	/* what the issue carries is what a reader of it accepts */
	if (bench_validate(summary, slen, back, why, sizeof(why))) {
		snprintf(err, errcap, "the summary does not read back: %s",
			 why);
		goto out;
	}
	if (back->kind != BK_SUMMARY || back->nruns != d->nruns) {
		snprintf(err, errcap, "the summary reads back as another file");
		goto out;
	}
	total = sizeof(head) - 1 + rlen + sizeof(mid) - 1 + slen +
		sizeof(tail) - 1;
	if (total > BENCH_ISSUE_MAX_BYTES) {
		snprintf(err, errcap,
			 "%zu bytes, more than an issue holds (%d)", total,
			 BENCH_ISSUE_MAX_BYTES);
		goto out;
	}
	fputs(head, f);
	fwrite(report, 1, rlen, f);
	fputs(mid, f);
	fwrite(summary, 1, slen, f);
	fputs(tail, f);
	ret = ferror(f) ? -EIO : 0;
	if (ret)
		snprintf(err, errcap, "%s", strerror(EIO));
out:
	free(report);
	free(summary);
	free(back);
	return ret;
}
