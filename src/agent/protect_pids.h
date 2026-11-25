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
#include <stdint.h>

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

#endif /* LOTA_AGENT_PROTECT_PIDS_H */
