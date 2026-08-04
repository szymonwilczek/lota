/* SPDX-License-Identifier: MIT */
/*
 * Keeping the agent's protected-PID set in step with the processes in it.
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

#endif /* LOTA_AGENT_PROTECT_PIDS_H */
