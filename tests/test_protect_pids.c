/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for keeping the protected-PID set in step with its processes:
 * reaping the ones that exited, adopting the ones a protected process created.
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
#include <errno.h>
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

/* stand-in for lota_instance: members join, one errs, the rest are not */
struct fake_instance {
	const uint32_t *members;
	int member_count;
	uint32_t failing;
	int calls;
};

static int fake_adopt(uint32_t pid, void *ctx)
{
	struct fake_instance *in = ctx;

	in->calls++;
	if (pid == in->failing)
		return -ESRCH;
	for (int i = 0; i < in->member_count; i++) {
		if (in->members[i] == pid)
			return 1;
	}
	return 0;
}

static void test_adopt(void)
{
	uint32_t out[8];
	int out_count = 0;
	int ret;

	{
		const uint32_t set[] = { 10 };
		const uint32_t cands[] = { 1, 10, 11, 12, 13 };
		const uint32_t members[] = { 11, 13 };
		struct fake_instance in = { members, 2, 0, 0 };

		ret = protect_pids_adopt(set, 1, cands, 5, fake_adopt, &in, 8,
					 out, &out_count);
		CHECK(ret == 2 && out_count == 3 && out[0] == 10 &&
			      out[1] == 11 && out[2] == 13,
		      "the members of an instance join after the root");
		CHECK(in.calls == 4,
		      "a process already in the set is not asked about again");
	}

	{
		const uint32_t set[] = { 10 };
		const uint32_t cands[] = { 20, 21 };
		const uint32_t members[] = { 0 };
		struct fake_instance in = { members, 0, 0, 0 };

		ret = protect_pids_adopt(set, 1, cands, 2, fake_adopt, &in, 8,
					 out, &out_count);
		CHECK(ret == 0 && out_count == 1,
		      "no member adopts nothing, so the epoch stays");
	}

	{
		const uint32_t cands[] = { 20, 21 };
		const uint32_t members[] = { 20, 21 };
		struct fake_instance in = { members, 2, 20, 0 };

		ret = protect_pids_adopt(NULL, 0, cands, 2, fake_adopt, &in, 8,
					 out, &out_count);
		CHECK(ret == 1 && out_count == 1 && out[0] == 21,
		      "a process that exits mid-sweep is skipped, not fatal");
	}

	{
		const uint32_t set[] = { 10, 11 };
		const uint32_t cands[] = { 20, 21 };
		const uint32_t members[] = { 20, 21 };
		struct fake_instance in = { members, 2, 0, 0 };

		ret = protect_pids_adopt(set, 2, cands, 2, fake_adopt, &in, 3,
					 out, &out_count);
		CHECK(ret == 1 && out_count == 3 && in.calls == 1,
		      "adoption stops at the capacity of the set");
	}

	{
		struct fake_instance in = { NULL, 0, 0, 0 };

		CHECK(protect_pids_adopt(NULL, 0, NULL, 0, NULL, &in, 8, out,
					 &out_count) < 0,
		      "a missing membership predicate is refused");
		CHECK(protect_pids_adopt(NULL, 3, NULL, 0, fake_adopt, &in, 2,
					 out, &out_count) < 0,
		      "a set larger than the capacity is refused");
	}
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

	test_adopt();

	printf("\n%s\n", g_failures ? "FAILURES" : "All tests passed");
	return g_failures ? 1 : 0;
}
