/* SPDX-License-Identifier: MIT */
/*
 * Keeps the agent's protected-PID set in step with the processes in it:
 * the ones gone from /proc leave, the ones that run in a protected instance
 * join. The token carries this set and the runtime image measurement walks it.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#ifndef LOTA_AGENT_PROTECT_PIDS_H
#define LOTA_AGENT_PROTECT_PIDS_H

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "../../include/lota_ipc.h"

/* Whether @pid stays in the set; @ctx is the caller's */
typedef bool (*protect_pid_alive_fn)(uint32_t pid, void *ctx);

/**
 * protect_pids_reap() - Copy the set without the PIDs @alive drops.
 * @pids: The set.
 * @count: Its size.
 * @alive: Says whether a PID stays.
 * @ctx: Passed to @alive.
 * @out: Holds @count entries, in the order of @pids.
 * @out_count: Receives the number kept.
 *
 * Return: 1 when something was dropped, and the caller then bumps the
 * mutation epoch; 0 when nothing was; or -EINVAL.
 */
static inline int protect_pids_reap(const uint32_t *pids, int count,
				    protect_pid_alive_fn alive, void *ctx,
				    uint32_t *out, int *out_count)
{
	int kept = 0;

	if (!alive || !out || !out_count || count < 0)
		return -EINVAL;

	*out_count = 0;

	if (count == 0)
		return 0;

	if (!pids)
		return -EINVAL;

	for (int i = 0; i < count; i++) {
		if (alive(pids[i], ctx))
			out[kept++] = pids[i];
	}

	*out_count = kept;
	return kept == count ? 0 : 1;
}

/*
 * 1 when @pid runs in a protected instance and went into the kernel's map,
 * 0 when it is not a member, or a negative errno.
 */
typedef int (*protect_pid_adopt_fn)(uint32_t pid, void *ctx);

/**
 * protect_pids_adopt() - Copy the set and add what runs in its instances.
 * @pids: The set.
 * @count: Its size.
 * @cands: Candidate PIDs.
 * @cand_count: How many.
 * @adopt: Takes a candidate, or refuses it.
 * @ctx: Passed to @adopt.
 * @cap: Capacity of @out; adoption stops there.
 * @out: Receives the result.
 * @out_count: Receives its size.
 *
 * A candidate already in @pids is skipped, and so is one @adopt does not
 * take.
 *
 * Return: the number adopted, or -EINVAL. Above zero, the caller bumps the
 * mutation epoch.
 */
static inline int protect_pids_adopt(const uint32_t *pids, int count,
				     const uint32_t *cands, int cand_count,
				     protect_pid_adopt_fn adopt, void *ctx,
				     int cap, uint32_t *out, int *out_count)
{
	int added = 0;
	int n;

	if (!adopt || !out || !out_count || count < 0 || cand_count < 0 ||
	    count > cap)
		return -EINVAL;
	if ((count && !pids) || (cand_count && !cands))
		return -EINVAL;

	for (n = 0; n < count; n++)
		out[n] = pids[n];

	for (int i = 0; i < cand_count && n < cap; i++) {
		bool known = false;

		for (int j = 0; j < n; j++) {
			if (out[j] == cands[i]) {
				known = true;
				break;
			}
		}
		if (known || adopt(cands[i], ctx) <= 0)
			continue;

		out[n++] = cands[i];
		added++;
	}

	*out_count = n;
	return added;
}

/* The last executable mapping the gate refused one protected process. */
struct protect_refusal_slot {
	uint32_t tgid;
	uint64_t start_ticks; /* tells the process from a later one of @tgid */
	bool used;
	struct lota_ipc_refusal refusal;
};

/**
 * protect_refusal_record() - Keep a refusal as its process's last.
 * @table: The refusals kept.
 * @n: Slots in @table.
 * @tgid: The refused process.
 * @start_ticks: Its start time, from /proc/<tgid>/stat.
 * @at_ns: When, CLOCK_MONOTONIC.
 * @object: What the gate refused; cut to the slot.
 *
 * A full @table gives the slot of the oldest refusal to a new process.
 */
static inline void protect_refusal_record(struct protect_refusal_slot *table,
					  size_t n, uint32_t tgid,
					  uint64_t start_ticks, uint64_t at_ns,
					  const char *object)
{
	struct protect_refusal_slot *victim = &table[0];

	for (size_t i = 0; i < n; i++) {
		struct protect_refusal_slot *s = &table[i];

		if (s->used && s->tgid == tgid) {
			victim = s;
			break;
		}
		if (!victim->used)
			continue;
		if (!s->used || s->refusal.at_ns < victim->refusal.at_ns)
			victim = s;
	}

	victim->used = true;
	victim->tgid = tgid;
	victim->start_ticks = start_ticks;
	victim->refusal.at_ns = at_ns;
	snprintf(victim->refusal.object, sizeof(victim->refusal.object), "%s",
		 object);
}

/*
 * Whether a process started at @start_ticks, of @tick_ns each, began after
 * a refusal at @at_boot_ns, CLOCK_BOOTTIME: one that took the refused PID.
 * A process started in the refusal's own tick is not told apart.
 */
static inline bool protect_started_after(uint64_t start_ticks, uint64_t tick_ns,
					 uint64_t at_boot_ns)
{
	return tick_ns && start_ticks > at_boot_ns / tick_ns;
}

/* Return: the last refusal kept for @tgid started at @start_ticks, or NULL. */
static inline const struct lota_ipc_refusal *
protect_refusal_find(const struct protect_refusal_slot *table, size_t n,
		     uint32_t tgid, uint64_t start_ticks)
{
	for (size_t i = 0; i < n; i++) {
		if (table[i].used && table[i].tgid == tgid &&
		    table[i].start_ticks == start_ticks)
			return &table[i].refusal;
	}
	return NULL;
}

#endif /* LOTA_AGENT_PROTECT_PIDS_H */
