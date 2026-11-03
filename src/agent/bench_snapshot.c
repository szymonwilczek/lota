/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */

#include "bench_snapshot.h"

#include <fcntl.h>
#include <inttypes.h>
#include <time.h>
#include <unistd.h>

#define NS_PER_MS UINT64_C(1000000)
#define INTERVAL_NS ((uint64_t)LOTA_BENCH_INTERVAL_MS * NS_PER_MS)

uint64_t bench_now_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
		return 0;
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

void bench_state_init(struct bench_state *st, gid_t gid, uint64_t now_ns)
{
	bench_writer_init(&st->w, gid);
	st->seq = 0;
	st->start_ns = now_ns;
	st->next_ns = now_ns;
	st->stats_fd = -1;
	st->clk_tck = sysconf(_SC_CLK_TCK);
	if (st->clk_tck <= 0)
		st->clk_tck = 100;
}

int bench_timeout_ms(const struct bench_state *st, uint64_t now_ns)
{
	uint64_t left;

	if (now_ns >= st->next_ns)
		return 0;
	left = st->next_ns - now_ns;
	return (int)((left + NS_PER_MS - 1) / NS_PER_MS);
}

static uint64_t ticks_ns(uint64_t ticks, long clk_tck)
{
	return ticks * (1000000000ULL / (uint64_t)clk_tck);
}

void bench_format(struct bench_state *st, uint64_t now_ns,
		  const struct bench_proc *self)
{
	struct bench_writer *w = &st->w;

	bench_append(w,
		     "{\"version\":%d,\"seq\":%" PRIu64
		     ",\"uptime_ms\":%" PRIu64
		     ",\"interval_ms\":%d,\"skipped\":%" PRIu64 ",\"agent\":",
		     LOTA_BENCH_VERSION, st->seq,
		     (now_ns - st->start_ns) / NS_PER_MS,
		     LOTA_BENCH_INTERVAL_MS, w->skipped);

	if (!self) {
		bench_append(w, "null");
		return;
	}

	bench_append(w,
		     "{\"cpu_user_ns\":%" PRIu64 ",\"cpu_sys_ns\":%" PRIu64
		     ",\"minflt\":%" PRIu64 ",\"majflt\":%" PRIu64
		     ",\"rss_kb\":%" PRIu64 ",\"pss_kb\":%" PRIu64
		     ",\"uss_kb\":%" PRIu64 ",\"ctxt_vol\":%" PRIu64
		     ",\"ctxt_invol\":%" PRIu64 "}",
		     ticks_ns(self->utime, st->clk_tck),
		     ticks_ns(self->stime, st->clk_tck), self->minflt,
		     self->majflt, self->rss_kb, self->pss_kb, self->uss_kb,
		     self->ctxt_vol, self->ctxt_invol);
}

void bench_sanitize_name(char *dst, size_t size, const char *src)
{
	size_t i;

	if (size == 0)
		return;
	for (i = 0; i + 1 < size && src[i]; i++) {
		char c = src[i];

		dst[i] = ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			  (c >= '0' && c <= '9') || c == '_' || c == '.') ?
				 c :
				 '_';
	}
	dst[i] = '\0';
}

void bench_format_bpf(struct bench_writer *w, const struct bench_bpf *b)
{
	size_t i;

	if (!b) {
		bench_append(w, ",\"bpf\":null");
		return;
	}

	bench_append(w, ",\"bpf\":{\"run_stats\":%s,\"maps\":%zu",
		     b->run_stats ? "true" : "false", b->map_count);
	if (b->memlock_ok)
		bench_append(w, ",\"maps_memlock\":%" PRIu64, b->memlock);
	else
		bench_append(w, ",\"maps_memlock\":null");
	bench_append(w, ",\"progs_dropped\":%zu,\"progs\":[", b->prog_dropped);
	for (i = 0; i < b->prog_count; i++) {
		const struct bench_prog *p = &b->progs[i];

		bench_append(w,
			     "%s{\"name\":\"%s\",\"run_ns\":%" PRIu64
			     ",\"run_cnt\":%" PRIu64 "}",
			     i ? "," : "", p->name, p->run_ns, p->run_cnt);
	}
	bench_append(w, "]}");
}

void bench_format_end(struct bench_writer *w)
{
	bench_append(w, "}\n");
}

bool bench_due(struct bench_state *st, uint64_t now_ns)
{
	if (now_ns < st->next_ns)
		return false;

	/* a late loop skips the ticks it missed */
	st->next_ns += INTERVAL_NS;
	if (st->next_ns <= now_ns)
		st->next_ns = now_ns + INTERVAL_NS;
	return true;
}

int bench_write(struct bench_state *st, uint64_t now_ns,
		const struct bench_bpf *bpf)
{
	struct bench_proc self;
	int dirfd, ok = 0;

	dirfd = open("/proc/self", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (dirfd >= 0) {
		ok = bench_read_proc(dirfd, &self) == 0;
		close(dirfd);
	}

	st->seq++;
	bench_format(st, now_ns, ok ? &self : NULL);
	bench_format_bpf(&st->w, bpf);
	bench_format_end(&st->w);
	return bench_commit(&st->w);
}

void bench_remove(void)
{
	(void)unlink(LOTA_BENCH_PATH);
}
