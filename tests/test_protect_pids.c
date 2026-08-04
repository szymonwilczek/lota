/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for reaping exited processes out of the protected-PID set.
 *
 * Kernel side already drops a protected task on exit -- lota_task_free deletes
 * the map entry. Agent's own copy of that set is what a token carries and what
 * the runtime image measurement walks, and nothing dropped anything from it,
 * so one title protecting itself and exiting left a PID behind that no longer
 * resolves.
 * Every later GET_TOKEN then failed closed on measurement it could not take,
 * for every title on the host.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#include <stdio.h>
#include <string.h>

#include "../src/agent/protect_pids.h"

static int g_failures;

#define CHECK(cond, msg)                                    \
	do {                                                \
		if (!(cond)) {                              \
			fprintf(stderr, "FAIL: %s\n", msg); \
			g_failures++;                       \
		} else {                                    \
			printf("PASS: %s\n", msg);          \
		}                                           \
	} while (0)

/* stand-in for /proc: any pid in the list below is running */
struct fake_procfs {
	const uint32_t *live;
	int live_count;
};

static bool fake_alive(uint32_t pid, void *ctx)
{
	const struct fake_procfs *fs = ctx;

	for (int i = 0; i < fs->live_count; i++) {
		if (fs->live[i] == pid)
			return true;
	}
	return false;
}

int main(void)
{
	uint32_t out[8];
	int out_count = 0;
	int ret;

	printf("=== protected-PID reap tests ===\n\n");

	{
		const uint32_t set[] = { 10, 20, 30 };
		const uint32_t live[] = { 10, 20, 30 };
		struct fake_procfs fs = { live, 3 };

		ret = protect_pids_reap(set, 3, fake_alive, &fs, out,
					&out_count);
		CHECK(ret == 0 && out_count == 3,
		      "a set where every process is running is left alone");
	}

	{
		const uint32_t set[] = { 10, 20, 30 };
		const uint32_t live[] = { 10, 30 };
		struct fake_procfs fs = { live, 2 };

		ret = protect_pids_reap(set, 3, fake_alive, &fs, out,
					&out_count);
		CHECK(ret == 1 && out_count == 2 && out[0] == 10 &&
			      out[1] == 30,
		      "an exited process is dropped and the survivors keep their order");
	}

	{
		const uint32_t set[] = { 10, 20 };
		const uint32_t live[] = { 0 };
		struct fake_procfs fs = { live, 0 };

		ret = protect_pids_reap(set, 2, fake_alive, &fs, out,
					&out_count);
		CHECK(ret == 1 && out_count == 0,
		      "a set whose every process has exited reaps to empty");
	}

	{
		struct fake_procfs fs = { NULL, 0 };

		ret = protect_pids_reap(NULL, 0, fake_alive, &fs, out,
					&out_count);
		CHECK(ret == 0 && out_count == 0,
		      "an empty set reaps to empty");
	}

	/*
	 * return value is what tells the caller to bump the mutation epoch,
	 * so "nothing changed" and "something was dropped" must not be confusable:
	 * relying party comparing epochs would otherwise see the same epoch with
	 * different protected set
	 */
	{
		const uint32_t set[] = { 42 };
		const uint32_t live[] = { 42 };
		struct fake_procfs fs = { live, 1 };

		ret = protect_pids_reap(set, 1, fake_alive, &fs, out,
					&out_count);
		CHECK(ret == 0, "no reap reports no change");

		fs.live_count = 0;
		ret = protect_pids_reap(set, 1, fake_alive, &fs, out,
					&out_count);
		CHECK(ret == 1, "a reap reports a change");
	}

	{
		const uint32_t set[] = { 1, 2 };
		struct fake_procfs fs = { NULL, 0 };

		CHECK(protect_pids_reap(set, 2, NULL, &fs, out, &out_count) < 0,
		      "a missing liveness predicate is refused rather than assumed");
		CHECK(protect_pids_reap(set, -1, fake_alive, &fs, out,
					&out_count) < 0,
		      "a negative count is refused");
	}

	printf("\n%s\n", g_failures ? "FAILURES" : "All tests passed");
	return g_failures ? 1 : 0;
}
