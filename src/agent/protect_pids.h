/* SPDX-License-Identifier: MIT */
/*
 * Keeping the agent's protected-PID set in step with the processes in it:
 * the ones that exited leave, the ones a protected process created join.
 *
 * BPF map is maintained by the kernel: lota_task_free drops protected task
 * the moment it exits. Agent keeps its own copy of that set, because token
 * carries it and the runtime image measurement walks it, and nothing dropped
 * anything from that copy -- so title that protected itself and exited left
 * behind PID that resolves to nothing, and every later token failed closed
 * on measurement that could not be taken.
 *
 * Split out of ipc.c so the filter can be tested against stand-in for /proc
 * rather than against processes a test would have to spawn and kill.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#ifndef LOTA_AGENT_PROTECT_PIDS_H
#define LOTA_AGENT_PROTECT_PIDS_H

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>

/*
 * Whether @pid is still a running process.
 * @ctx is the caller's, untouched here; production predicate reads /proc
 * and the tests answer from a list.
 */
typedef bool (*protect_pid_alive_fn)(uint32_t pid, void *ctx);

/*
 * Copy @pids into @out, dropping every entry @alive says has gone.
 *
 * @out must hold @count entries.
 * Order is preserved, so the canonical form the token is built from
 * is unaffected beyond the removals.
 *
 * Returns 1 when something was dropped, 0 when nothing was, or a negative
 * errno.
 *
 * Distinction between 1 and 0 is what tells the caller to bump the mutation
 * epoch: relying party comparing epochs must never see the same epoch with
 * different protected set.
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
 * Whether @pid runs in a protected instance, and if so put it in the
 * kernel's map. Returns 1 when it was added, 0 when it is not a member,
 * or a negative errno. The production predicate asks lota_instance.
 */
typedef int (*protect_pid_adopt_fn)(uint32_t pid, void *ctx);

/*
 * Copy @pids into @out, then append every candidate @adopt takes.
 *
 * A process created by a protected one is protected in the kernel from
 * its first instruction, but only the root of its tree is named in the
 * set. This brings the rest in, so the token and the measurement cover
 * every process of the instance.
 *
 * @out must hold @cap entries; a candidate already in @pids is skipped,
 * and adoption stops at @cap. Returns the number adopted, or a negative
 * errno. Above zero, the caller bumps the mutation epoch.
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
