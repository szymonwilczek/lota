/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * lota-bench - check a session file against the schema
 *
 * The schema is walked as the file is lexed: each object knows its keys,
 * each key its value, so nesting is the schema's. Samples are checked and
 * passed over; only the span they occupy is kept.
 */

#include <errno.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "json.h"
#include "validate.h"

_Static_assert(BENCH_FIELD_MAX == JSON_STR_MAX,
	       "a field is the longest string the lexer reads");

#define NKEYS(a) (int)(sizeof(a) / sizeof((a)[0]))

struct vctx {
	struct json_lex lx;
	const char *buf;
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

static size_t here(const struct vctx *v)
{
	return json_offset(&v->lx);
}

/* the next token, which must be @want */
static int expect(struct vctx *v, enum json_tok want, const char *what)
{
	enum json_tok t = json_next(&v->lx);

	if (t == JT_ERROR)
		return bad(v, here(v), "%s", v->lx.err);
	if (t != want)
		return bad(v, here(v), "expected %s", what);
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
		bad(v, here(v), "expected ',' or '}'");
		return -2;
	}
	*first = 0;
	if (t == JT_ERROR) {
		bad(v, here(v), "%s", v->lx.err);
		return -2;
	}
	if (t != JT_STRING) {
		bad(v, here(v), "expected a key");
		return -2;
	}
	for (i = 0; i < nkeys; i++) {
		if (strcmp(v->lx.str, keys[i]) == 0)
			break;
	}
	if (i == nkeys) {
		bad(v, here(v), "unknown key \"%s\"", v->lx.str);
		return -2;
	}
	if (*seen & (1u << i)) {
		bad(v, here(v), "key \"%s\" repeated", v->lx.str);
		return -2;
	}
	*seen |= 1u << i;
	if (expect(v, JT_COLON, "':'"))
		return -2;
	return i;
}

/* every key of @keys in @want was seen before the '}' just taken */
static int all_keys(struct vctx *v, const char *const *keys, int nkeys,
		    uint32_t seen, uint32_t want)
{
	for (int i = 0; i < nkeys; i++) {
		if ((want & (1u << i)) && !(seen & (1u << i)))
			return bad(v, here(v), "missing key \"%s\"", keys[i]);
	}
	return 0;
}

#define ALL(n) ((n) >= 32 ? UINT32_MAX : (1u << (n)) - 1)

static int uint_value(struct vctx *v, uint64_t *out)
{
	if (expect(v, JT_UINT, "an unsigned integer"))
		return -EINVAL;
	*out = v->lx.num;
	return 0;
}

static int uint_range(struct vctx *v, const char *what, uint64_t min,
		      uint64_t max, unsigned int *out)
{
	uint64_t n;

	if (uint_value(v, &n))
		return -EINVAL;
	if (n < min || n > max)
		return bad(v, here(v), "%s %llu is not %llu..%llu", what,
			   (unsigned long long)n, (unsigned long long)min,
			   (unsigned long long)max);
	*out = (unsigned int)n;
	return 0;
}

static int opt_value(struct vctx *v, struct bench_opt *o)
{
	if (json_peek(&v->lx) == JT_NULL) {
		json_next(&v->lx);
		o->set = false;
		return 0;
	}
	o->set = true;
	return uint_value(v, &o->v);
}

static int bool_value(struct vctx *v, bool *out)
{
	enum json_tok t = json_next(&v->lx);

	if (t == JT_TRUE || t == JT_FALSE) {
		*out = t == JT_TRUE;
		return 0;
	}
	if (t == JT_ERROR)
		return bad(v, here(v), "%s", v->lx.err);
	return bad(v, here(v), "expected true or false");
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
	return bad(v, here(v), "\"%s\" is not %s", v->lx.str, what);
}

/* a field, or null when @nullable */
static int field_value(struct vctx *v, struct bench_field *f, bool nullable)
{
	enum json_tok t = json_next(&v->lx);

	memset(f, 0, sizeof(*f));
	if (t == JT_NULL && nullable)
		return 0;
	if (t == JT_ERROR)
		return bad(v, here(v), "%s", v->lx.err);
	if (t != JT_STRING)
		return bad(v, here(v),
			   nullable ? "expected text or null" :
				      "expected text");
	if (!bench_field_ok(v->lx.str))
		return bad(
			v, here(v),
			"text with a '/', a doubled or outer blank, or none");
	memcpy(f->s, v->lx.str, sizeof(f->s));
	f->set = true;
	return 0;
}

/* true when the value is null, which is then taken */
static bool take_null(struct vctx *v)
{
	if (json_peek(&v->lx) != JT_NULL)
		return false;
	json_next(&v->lx);
	return true;
}

/* an object of @n keys, each a number or null when @nullable */
static int opts_object(struct vctx *v, const char *const *keys, int n,
		       struct bench_opt *out, bool nullable)
{
	uint32_t seen = 0;
	int first = 1;
	int k;

	if (expect(v, JT_LBRACE, "an object"))
		return -EINVAL;
	while ((k = next_key(v, &first, keys, n, &seen)) >= 0) {
		if (!nullable && json_peek(&v->lx) == JT_NULL)
			return bad(v, v->lx.peek_at, "%s is null", keys[k]);
		if (opt_value(v, &out[k]))
			return -EINVAL;
	}
	if (k == -2)
		return -EINVAL;
	return all_keys(v, keys, n, seen, ALL(n));
}

/* --- machine and game ------------------------------------------------- */

static const char *const gpu_keys[] = { "vendor_id", "device_id", "name",
					"driver" };

static int gpu_value(struct vctx *v, struct bench_gpu *g)
{
	unsigned int id;
	uint32_t seen = 0;
	int first = 1;
	int k, ret;

	if (expect(v, JT_LBRACE, "a GPU object"))
		return -EINVAL;
	while ((k = next_key(v, &first, gpu_keys, NKEYS(gpu_keys), &seen)) >=
	       0) {
		switch (k) {
		case 0:
		case 1:
			ret = uint_range(v, gpu_keys[k], 0, 0xffff, &id);
			if (k == 0)
				g->vendor_id = id;
			else
				g->device_id = id;
			break;
		case 2:
			ret = field_value(v, &g->name, true);
			break;
		default:
			ret = field_value(v, &g->driver, true);
			break;
		}
		if (ret)
			return -EINVAL;
	}
	if (k == -2)
		return -EINVAL;
	return all_keys(v, gpu_keys, NKEYS(gpu_keys), seen,
			ALL(NKEYS(gpu_keys)));
}

static int gpus_value(struct vctx *v, struct bench_machine *m)
{
	enum json_tok t;

	if (expect(v, JT_LBRACKET, "an array of GPUs"))
		return -EINVAL;
	if (json_peek(&v->lx) == JT_RBRACKET) {
		json_next(&v->lx);
		return 0;
	}
	for (;;) {
		if (m->ngpus == BENCH_MAX_GPUS)
			return bad(v, here(v), "more than %d GPUs",
				   BENCH_MAX_GPUS);
		if (gpu_value(v, &m->gpu[m->ngpus]))
			return -EINVAL;
		m->ngpus++;
		t = json_next(&v->lx);
		if (t == JT_RBRACKET)
			return 0;
		if (t != JT_COMMA)
			return bad(v, here(v), "expected ',' or ']'");
	}
}

enum machine_key {
	MK_CPU_MODEL = 0,
	MK_CPU_THREADS,
	MK_MEMORY_BYTES,
	MK_GPUS,
	MK_KERNEL,
	MK_DISTRO,
	MK_TPM,
	MK_SELINUX,
	MK_COUNT,
};

static const char *const machine_keys[MK_COUNT] = {
	[MK_CPU_MODEL] = "cpu_model",
	[MK_CPU_THREADS] = "cpu_threads",
	[MK_MEMORY_BYTES] = "memory_bytes",
	[MK_GPUS] = "gpus",
	[MK_KERNEL] = "kernel",
	[MK_DISTRO] = "distro",
	[MK_TPM] = "tpm",
	[MK_SELINUX] = "selinux",
};

static int machine_value(struct vctx *v, struct bench_machine *m)
{
	unsigned int threads = 0;
	uint32_t seen = 0;
	int first = 1;
	int k, ret, i;

	if (expect(v, JT_LBRACE, "a machine object"))
		return -EINVAL;
	while ((k = next_key(v, &first, machine_keys, MK_COUNT, &seen)) >= 0) {
		switch (k) {
		case MK_CPU_MODEL:
			ret = field_value(v, &m->cpu_model, true);
			break;
		case MK_CPU_THREADS:
			ret = uint_range(v, "cpu_threads", 0, UINT32_MAX,
					 &threads);
			m->cpu_threads = threads;
			break;
		case MK_MEMORY_BYTES:
			ret = uint_value(v, &m->memory_bytes);
			break;
		case MK_GPUS:
			ret = gpus_value(v, m);
			break;
		case MK_KERNEL:
			ret = field_value(v, &m->kernel, true);
			break;
		case MK_DISTRO:
			ret = field_value(v, &m->distro, true);
			break;
		case MK_TPM:
			ret = field_value(v, &m->tpm, true);
			break;
		default:
			i = enum_value(v, bench_selinux_names, BSE_COUNT,
				       "a SELinux mode");
			ret = i < 0 ? -EINVAL : 0;
			if (i >= 0)
				m->selinux = (enum bench_selinux)i;
			break;
		}
		if (ret)
			return -EINVAL;
	}
	if (k == -2)
		return -EINVAL;
	return all_keys(v, machine_keys, MK_COUNT, seen, ALL(MK_COUNT));
}

static const char *const game_keys[] = { "title", "proton", "version",
					 "settings" };

static int game_value(struct vctx *v, struct bench_game *g)
{
	struct bench_field *f[] = { &g->title, &g->proton, &g->version,
				    &g->settings };
	uint32_t seen = 0;
	int first = 1;
	int k;

	if (expect(v, JT_LBRACE, "a game object"))
		return -EINVAL;
	while ((k = next_key(v, &first, game_keys, NKEYS(game_keys), &seen)) >=
	       0) {
		/* a session measures a title it can name */
		if (field_value(v, f[k], k != 0))
			return -EINVAL;
	}
	if (k == -2)
		return -EINVAL;
	return all_keys(v, game_keys, NKEYS(game_keys), seen,
			ALL(NKEYS(game_keys)));
}

/* --- samples ---------------------------------------------------------- */

/* null, or an object holding every metric as an integer or null */
static int metrics_value(struct vctx *v)
{
	uint32_t seen = 0;
	int first = 1;
	int k;

	if (take_null(v))
		return 0;
	if (expect(v, JT_LBRACE, "null or an object of metrics"))
		return -EINVAL;
	while ((k = next_key(v, &first, bench_metric_names, BM_COUNT, &seen)) >=
	       0) {
		enum json_tok t = json_next(&v->lx);

		if (t == JT_ERROR)
			return bad(v, here(v), "%s", v->lx.err);
		if (t != JT_UINT && t != JT_NULL)
			return bad(v, here(v),
				   "%s is not an unsigned integer or null",
				   bench_metric_names[k]);
	}
	if (k == -2)
		return -EINVAL;
	return all_keys(v, bench_metric_names, BM_COUNT, seen, ALL(BM_COUNT));
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
			return bad(v, here(v), "t_ms %llu does not follow %llu",
				   (unsigned long long)t,
				   (unsigned long long)*prev_t);
		*prev_t = t;
	}
	if (k == -2)
		return -EINVAL;
	return all_keys(v, keys, SAMPLE_KEYS, seen, ALL(SAMPLE_KEYS));
}

static int samples_value(struct vctx *v, struct bench_run *r,
			 unsigned int *count)
{
	const char *keys[SAMPLE_KEYS] = { "t_ms" };
	uint64_t prev_t = 0;
	unsigned int n = 0;
	enum json_tok t;
	size_t start;

	for (int i = 0; i < BS_COUNT; i++)
		keys[1 + i] = bench_source_names[i];

	if (expect(v, JT_LBRACKET, "an array of samples"))
		return -EINVAL;
	start = here(v);
	if (json_peek(&v->lx) == JT_RBRACKET)
		return bad(v, v->lx.peek_at, "no samples");
	for (;;) {
		if (n == BENCH_MAX_SAMPLES)
			return bad(v, here(v), "more than %d samples",
				   BENCH_MAX_SAMPLES);
		if (sample_value(v, keys, &prev_t, n == 0))
			return -EINVAL;
		n++;
		t = json_next(&v->lx);
		if (t == JT_RBRACKET)
			break;
		if (t != JT_COMMA)
			return bad(v, here(v), "expected ',' or ']'");
	}
	r->samples = v->buf + start;
	r->samples_len = here(v) + 1 - start;
	*count = n;
	return 0;
}

/* --- a run ------------------------------------------------------------ */

static const char *const power_keys[] = { "governor", "profile", "supply" };

static int power_value(struct vctx *v, struct bench_power *p)
{
	uint32_t seen = 0;
	int first = 1;
	int k, i;

	if (expect(v, JT_LBRACE, "a power object"))
		return -EINVAL;
	while ((k = next_key(v, &first, power_keys, NKEYS(power_keys),
			     &seen)) >= 0) {
		if (k == 2) {
			i = enum_value(v, bench_supply_names, BSU_COUNT,
				       "a power supply");
			if (i < 0)
				return -EINVAL;
			p->supply = (enum bench_supply)i;
		} else if (field_value(v, k ? &p->profile : &p->governor,
				       true)) {
			return -EINVAL;
		}
	}
	if (k == -2)
		return -EINVAL;
	return all_keys(v, power_keys, NKEYS(power_keys), seen,
			ALL(NKEYS(power_keys)));
}

static int totals_value(struct vctx *v, struct bench_totals *t)
{
	uint32_t seen = 0;
	int first = 1;
	int k;

	if (expect(v, JT_LBRACE, "an object of sources"))
		return -EINVAL;
	while ((k = next_key(v, &first, bench_source_names, BS_COUNT, &seen)) >=
	       0) {
		if (take_null(v))
			continue;
		t[k].present = true;
		if (opts_object(v, bench_total_names, BT_COUNT, t[k].v, true))
			return -EINVAL;
	}
	if (k == -2)
		return -EINVAL;
	return all_keys(v, bench_source_names, BS_COUNT, seen, ALL(BS_COUNT));
}

static const char *const self_keys[] = {
	"cpu_user_usec",
	"cpu_system_usec",
	"max_rss_bytes",
};

static int self_value(struct vctx *v, struct bench_self *s)
{
	struct bench_opt o[3];

	if (opts_object(v, self_keys, NKEYS(self_keys), o, false))
		return -EINVAL;
	s->cpu_user_usec = o[0].v;
	s->cpu_system_usec = o[1].v;
	s->max_rss_bytes = o[2].v;
	return 0;
}

static int frames_value(struct vctx *v, struct bench_run_frames *fr)
{
	struct bench_opt o[BF_COUNT];

	if (take_null(v))
		return 0;
	if (opts_object(v, bench_frame_stat_names, BF_COUNT, o, false))
		return -EINVAL;
	fr->present = true;
	for (int i = 0; i < BF_COUNT; i++)
		*bench_frame_stat(&fr->s, (enum bench_frame_stat)i) = o[i].v;
	if (fr->s.frames == 0)
		return bad(v, here(v), "frames without a frame");
	return 0;
}

enum run_key {
	RK_INDEX = 0,
	RK_CONFIG,
	RK_WARMUP,
	RK_MODE,
	RK_AGENT_BENCH,
	RK_POWER,
	RK_SAMPLES,
	RK_SAMPLE_COUNT,
	RK_WALL_MS,
	RK_END,
	RK_TOTALS,
	RK_AGENT,
	RK_FRAMES,
	RK_SELF,
	RK_COUNT,
};

static const char *const run_keys[RK_COUNT] = {
	[RK_INDEX] = "index",
	[RK_CONFIG] = "config",
	[RK_WARMUP] = "warmup",
	[RK_MODE] = "mode",
	[RK_AGENT_BENCH] = "agent_bench",
	[RK_POWER] = "power",
	[RK_SAMPLES] = "samples",
	[RK_SAMPLE_COUNT] = "sample_count",
	[RK_WALL_MS] = "wall_ms",
	[RK_END] = "end",
	[RK_TOTALS] = "totals",
	[RK_AGENT] = "agent",
	[RK_FRAMES] = "frames",
	[RK_SELF] = "self",
};

static int run_key_value(struct vctx *v, int k, struct bench_run *r,
			 unsigned int *counted)
{
	int i;

	switch (k) {
	case RK_INDEX:
		return uint_range(v, "index", 0, BENCH_MAX_RUNS - 1, &r->index);
	case RK_CONFIG:
		i = enum_value(v, bench_config_names, BC_COUNT,
			       "a configuration");
		r->config = (enum bench_config)(i < 0 ? 0 : i);
		return i < 0 ? -EINVAL : 0;
	case RK_WARMUP:
		return bool_value(v, &r->warmup);
	case RK_MODE:
		i = enum_value(v, bench_mode_names, BMO_COUNT, "a mode");
		r->mode = (enum bench_mode)(i < 0 ? 0 : i);
		return i < 0 ? -EINVAL : 0;
	case RK_AGENT_BENCH:
		return bool_value(v, &r->agent_bench);
	case RK_POWER:
		return power_value(v, &r->power);
	case RK_SAMPLES:
		return samples_value(v, r, counted);
	case RK_SAMPLE_COUNT:
		return uint_range(v, "sample_count", 1, BENCH_MAX_SAMPLES,
				  &r->sample_count);
	case RK_WALL_MS:
		return uint_value(v, &r->wall_ms);
	case RK_END:
		i = enum_value(v, bench_end_names, BE_COUNT, "an end reason");
		r->end = (enum bench_end)(i < 0 ? 0 : i);
		return i < 0 ? -EINVAL : 0;
	case RK_TOTALS:
		return totals_value(v, r->totals);
	case RK_AGENT:
		if (take_null(v))
			return 0;
		r->agent.present = true;
		return opts_object(v, bench_agent_names, BA_COUNT, r->agent.v,
				   true);
	case RK_FRAMES:
		return frames_value(v, &r->frames);
	default:
		return self_value(v, &r->self);
	}
}

/* the run is what its configuration says LOTA was doing */
static int run_consistent(struct vctx *v, const struct bench_run *r)
{
	const struct bench_opt *prot = &r->agent.v[BA_PROTECTED_MAX];
	bool agent_ran = r->totals[BS_LOTA_AGENT].present;

	if (r->config != bench_run_config(r->index))
		return bad(v, here(v), "run %u is in %s, not %s", r->index,
			   bench_config_names[bench_run_config(r->index)],
			   bench_config_names[r->config]);
	if (r->warmup != (r->index == 0))
		return bad(v, here(v), "only run 0 is the warm-up");
	if (r->end == BE_INTERRUPTED)
		return bad(v, here(v), "an interrupted run is not kept");
	if (!r->totals[BS_GAME].present)
		return bad(v, here(v), "the game has no totals");
	if (r->agent.present && !r->agent_bench)
		return bad(v, here(v), "agent figures without --bench");
	if (r->config == BC_A) {
		if (r->mode != BMO_NONE || r->agent_bench || agent_ran ||
		    r->agent.present)
			return bad(v, here(v), "LOTA ran during an A run");
		return 0;
	}
	if (r->mode == BMO_NONE || !agent_ran)
		return bad(v, here(v), "the agent was not running in %s",
			   bench_config_names[r->config]);
	if (r->config == BC_C && r->agent.present &&
	    (!prot->set || prot->v == 0))
		return bad(v, here(v), "nothing was protected in a C run");
	if (r->config == BC_B && prot->set && prot->v)
		return bad(v, here(v), "the title was protected in a B run");
	return 0;
}

/* @at is the run's place in a session, or -1 in a run file */
static int run_value(struct vctx *v, struct bench_run *r, bool samples, int at)
{
	uint32_t seen = 0, want = ALL(RK_COUNT);
	unsigned int counted = 0;
	int first = 1;
	int k;

	if (!samples)
		want &= ~(1u << RK_SAMPLES);
	memset(r, 0, sizeof(*r));
	if (expect(v, JT_LBRACE, "a run object"))
		return -EINVAL;
	while ((k = next_key(v, &first, run_keys, RK_COUNT, &seen)) >= 0) {
		if (k == RK_SAMPLES && !samples)
			return bad(v, here(v), "a summary holds no samples");
		if (run_key_value(v, k, r, &counted))
			return -EINVAL;
	}
	if (k == -2 || all_keys(v, run_keys, RK_COUNT, seen, want))
		return -EINVAL;
	if (at >= 0 && r->index != (unsigned int)at)
		return bad(v, here(v), "run %u where run %d belongs", r->index,
			   at);
	if (samples && counted != r->sample_count)
		return bad(v, here(v), "sample_count %u, but %u samples",
			   r->sample_count, counted);
	return run_consistent(v, r);
}

static int runs_value(struct vctx *v, struct bench_doc *d, bool samples)
{
	enum json_tok t;

	if (expect(v, JT_LBRACKET, "an array of runs"))
		return -EINVAL;
	if (json_peek(&v->lx) == JT_RBRACKET)
		return bad(v, v->lx.peek_at, "no runs");
	for (;;) {
		struct bench_run *r = &d->runs[d->nruns];

		if (d->nruns == BENCH_MAX_RUNS)
			return bad(v, here(v), "more than %d runs",
				   BENCH_MAX_RUNS);
		if (run_value(v, r, samples, (int)d->nruns))
			return -EINVAL;
		d->nruns++;
		t = json_next(&v->lx);
		if (t == JT_RBRACKET)
			return 0;
		if (t != JT_COMMA)
			return bad(v, here(v), "expected ',' or ']'");
	}
}

/* --- the file --------------------------------------------------------- */

enum top_key {
	TK_SCHEMA_VERSION = 0,
	TK_TOOL,
	TK_KIND,
	TK_VERSION,
	TK_MACHINE,
	TK_GAME,
	TK_ROUNDS,
	TK_DURATION_S,
	TK_INTERVAL_MS,
	TK_RUN,
	TK_RUNS,
	TK_COUNT,
};

static const char *const top_keys[TK_COUNT] = {
	[TK_SCHEMA_VERSION] = "schema_version",
	[TK_TOOL] = "tool",
	[TK_KIND] = "kind",
	[TK_VERSION] = "version",
	[TK_MACHINE] = "machine",
	[TK_GAME] = "game",
	[TK_ROUNDS] = "rounds",
	[TK_DURATION_S] = "duration_s",
	[TK_INTERVAL_MS] = "interval_ms",
	[TK_RUN] = "run",
	[TK_RUNS] = "runs",
};

#define B(k) (1u << (k))
#define HEAD_KEYS (B(TK_SCHEMA_VERSION) | B(TK_TOOL) | B(TK_KIND))
#define PLAN_KEYS                                                 \
	(HEAD_KEYS | B(TK_VERSION) | B(TK_MACHINE) | B(TK_GAME) | \
	 B(TK_ROUNDS) | B(TK_DURATION_S) | B(TK_INTERVAL_MS))

static const uint32_t kind_keys[BK_COUNT] = {
	[BK_PLAN] = PLAN_KEYS,
	[BK_RUN] = HEAD_KEYS | B(TK_RUN),
	[BK_RESULT] = PLAN_KEYS | B(TK_RUNS),
	[BK_SUMMARY] = PLAN_KEYS | B(TK_RUNS),
};

static int top_value(struct vctx *v, int key, struct bench_doc *d,
		     bool kind_seen)
{
	static const char *const tool[] = { "lota-bench" };
	struct bench_plan *p = &d->plan;
	uint64_t n;
	int i;

	if (key > TK_KIND && !kind_seen)
		return bad(v, here(v), "\"kind\" must come before \"%s\"",
			   top_keys[key]);
	if (key > TK_KIND && !(kind_keys[d->kind] & B(key)))
		return bad(v, here(v), "a %s holds no \"%s\"",
			   bench_kind_names[d->kind], top_keys[key]);
	switch (key) {
	case TK_SCHEMA_VERSION:
		if (uint_value(v, &n))
			return -EINVAL;
		if (n != BENCH_SCHEMA_VERSION)
			return bad(
				v, here(v),
				"schema_version %llu; this lota-bench reads %d",
				(unsigned long long)n, BENCH_SCHEMA_VERSION);
		return 0;
	case TK_TOOL:
		return enum_value(v, tool, 1, "lota-bench") < 0 ? -EINVAL : 0;
	case TK_KIND:
		i = enum_value(v, bench_kind_names, BK_COUNT, "a file kind");
		if (i < 0)
			return -EINVAL;
		d->kind = (enum bench_kind)i;
		return 0;
	case TK_VERSION:
		return field_value(v, &p->version, true);
	case TK_MACHINE:
		return machine_value(v, &p->machine);
	case TK_GAME:
		return game_value(v, &p->game);
	case TK_ROUNDS:
		return uint_range(v, "rounds", BENCH_ROUNDS_MIN,
				  BENCH_ROUNDS_MAX, &p->rounds);
	case TK_DURATION_S:
		return uint_range(v, "duration_s", BENCH_DURATION_MIN_S,
				  BENCH_DURATION_MAX_S, &p->duration_s);
	case TK_INTERVAL_MS:
		return uint_range(v, "interval_ms", BENCH_INTERVAL_MIN_MS,
				  BENCH_INTERVAL_MAX_MS, &p->interval_ms);
	case TK_RUN:
		d->nruns = 1;
		return run_value(v, &d->runs[0], true, -1);
	default:
		return runs_value(v, d, d->kind == BK_RESULT);
	}
}

/* what holds across the keys of a plan */
static int plan_consistent(struct vctx *v, const struct bench_doc *d)
{
	const struct bench_plan *p = &d->plan;
	uint64_t per_run = (uint64_t)p->duration_s * 1000 / p->interval_ms + 1;

	if (per_run > BENCH_MAX_SAMPLES)
		return bad(v, here(v),
			   "%llu samples a run; a run holds at most %d",
			   (unsigned long long)per_run, BENCH_MAX_SAMPLES);
	if (per_run * bench_session_runs(p->rounds) > BENCH_SESSION_MAX_SAMPLES)
		return bad(v, here(v),
			   "%llu samples a session; a session holds at most %d",
			   (unsigned long long)(per_run *
						bench_session_runs(p->rounds)),
			   BENCH_SESSION_MAX_SAMPLES);
	if (d->kind != BK_PLAN && d->nruns != bench_session_runs(p->rounds))
		return bad(v, here(v), "%u runs; %u rounds make %u", d->nruns,
			   p->rounds, bench_session_runs(p->rounds));
	return 0;
}

int bench_validate(const char *buf, size_t len, struct bench_doc *d, char *err,
		   size_t errcap)
{
	struct vctx v = { .buf = buf, .err = err, .errcap = errcap };
	uint32_t seen = 0;
	int first = 1;
	int k;

	memset(d, 0, sizeof(*d));
	if (errcap)
		err[0] = '\0';
	if (len > BENCH_RESULT_MAX_BYTES)
		return bad(&v, BENCH_RESULT_MAX_BYTES, "larger than %u bytes",
			   BENCH_RESULT_MAX_BYTES);

	json_init(&v.lx, buf, len);
	if (expect(&v, JT_LBRACE, "a lota-bench object"))
		return -EINVAL;
	while ((k = next_key(&v, &first, top_keys, TK_COUNT, &seen)) >= 0) {
		if (top_value(&v, k, d, seen & B(TK_KIND)))
			return -EINVAL;
	}
	if (k == -2)
		return -EINVAL;
	if (!(seen & B(TK_KIND)))
		return bad(&v, here(&v), "missing key \"kind\"");
	if (all_keys(&v, top_keys, TK_COUNT, seen, kind_keys[d->kind]))
		return -EINVAL;
	if (d->kind != BK_RUN && plan_consistent(&v, d))
		return -EINVAL;
	if (json_next(&v.lx) != JT_END)
		return bad(&v, here(&v), "data after the object");
	return 0;
}
