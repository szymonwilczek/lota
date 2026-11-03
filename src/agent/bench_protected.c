/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */

#include "bench_protected.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void bench_protected_begin(struct bench_protected *bp,
			   struct bench_protected_sum *sum)
{
	bp->nnext = 0;
	memset(sum, 0, sizeof(*sum));
	sum->pss_ok = true;
}

static const struct bench_track *find_prev(const struct bench_protected *bp,
					   uint32_t pid, uint64_t start)
{
	size_t i;

	for (i = 0; i < bp->nprev; i++) {
		if (bp->prev[i].pid == pid && bp->prev[i].start == start)
			return &bp->prev[i];
	}
	return NULL;
}

static uint64_t delta(uint64_t now, uint64_t then)
{
	return now >= then ? now - then : 0;
}

void bench_protected_add(struct bench_protected *bp,
			 struct bench_protected_sum *sum, uint32_t pid,
			 const struct bench_proc *s, bool has_pss)
{
	const struct bench_track *old;
	struct bench_track *t;

	if (bp->nnext == LOTA_MAX_PROTECTED_PIDS)
		return;

	old = find_prev(bp, pid, s->start);
	t = &bp->next[bp->nnext++];
	t->pid = pid;
	t->start = s->start;
	t->cpu = s->utime + s->stime;
	t->minflt = s->minflt;
	t->majflt = s->majflt;
	t->pss_kb = has_pss ? s->pss_kb : 0;
	t->pss_ok = has_pss;
	if (old) {
		if (!has_pss) {
			t->pss_kb = old->pss_kb;
			t->pss_ok = old->pss_ok;
		}
		sum->cpu += delta(t->cpu, old->cpu);
		sum->minflt += delta(t->minflt, old->minflt);
		sum->majflt += delta(t->majflt, old->majflt);
	}

	sum->count++;
	sum->rss_kb += s->vm_rss_kb;
	sum->pss_kb += t->pss_kb;
	sum->pss_ok = sum->pss_ok && t->pss_ok;
}

void bench_protected_end(struct bench_protected *bp)
{
	memcpy(bp->prev, bp->next, bp->nnext * sizeof(bp->next[0]));
	bp->nprev = bp->nnext;
}

void bench_protected_sample(struct bench_protected *bp,
			    const struct bench_pid *pids, size_t n, bool rollup,
			    struct bench_protected_sum *sum)
{
	size_t i;

	bench_protected_begin(bp, sum);
	for (i = 0; i < n; i++) {
		struct bench_proc s;
		char path[32];
		bool has_pss;
		int dirfd, ret;

		snprintf(path, sizeof(path), "/proc/%u", pids[i].pid);
		dirfd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
		if (dirfd < 0)
			continue;
		ret = bench_read_proc(dirfd, &s, rollup);
		has_pss = rollup && ret == 0;
		/* a refused rollup still leaves the counters */
		if (ret < 0 && rollup)
			ret = bench_read_proc(dirfd, &s, false);
		close(dirfd);
		if (ret < 0 || s.start != pids[i].start)
			continue;
		bench_protected_add(bp, sum, pids[i].pid, &s, has_pss);
	}
	bench_protected_end(bp);
}
