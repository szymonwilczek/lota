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
#include <string.h>

#include "../src/agent/protect_pids.h"

#include "test.h"

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
		TEST("the members of an instance join after the root");
		if (!(ret == 2 && out_count == 3 && out[0] == 10 &&
		      out[1] == 11 && out[2] == 13))
			FAIL("expected: ret == 2 && out_count == 3 && out[0] == 10 && "
			     "out[1] == 11 && out[2] == 13");
		TEST("a process already in the set is not asked about again");
		if (in.calls != 4)
			FAIL("expected: in.calls == 4");
	}

	{
		const uint32_t set[] = { 10 };
		const uint32_t cands[] = { 20, 21 };
		const uint32_t members[] = { 0 };
		struct fake_instance in = { members, 0, 0, 0 };

		ret = protect_pids_adopt(set, 1, cands, 2, fake_adopt, &in, 8,
					 out, &out_count);
		TEST("no member adopts nothing, so the epoch stays");
		if (!(ret == 0 && out_count == 1))
			FAIL("expected: ret == 0 && out_count == 1");
	}

	{
		const uint32_t cands[] = { 20, 21 };
		const uint32_t members[] = { 20, 21 };
		struct fake_instance in = { members, 2, 20, 0 };

		ret = protect_pids_adopt(NULL, 0, cands, 2, fake_adopt, &in, 8,
					 out, &out_count);
		TEST("a process that exits mid-sweep is skipped, not fatal");
		if (!(ret == 1 && out_count == 1 && out[0] == 21))
			FAIL("expected: ret == 1 && out_count == 1 && out[0] == 21");
	}

	{
		const uint32_t set[] = { 10, 11 };
		const uint32_t cands[] = { 20, 21 };
		const uint32_t members[] = { 20, 21 };
		struct fake_instance in = { members, 2, 0, 0 };

		ret = protect_pids_adopt(set, 2, cands, 2, fake_adopt, &in, 3,
					 out, &out_count);
		TEST("adoption stops at the capacity of the set");
		if (!(ret == 1 && out_count == 3 && in.calls == 1))
			FAIL("expected: ret == 1 && out_count == 3 && in.calls == 1");
	}

	{
		struct fake_instance in = { NULL, 0, 0, 0 };

		TEST("a missing membership predicate is refused");
		if (protect_pids_adopt(NULL, 0, NULL, 0, NULL, &in, 8, out,
				       &out_count) >= 0)
			FAIL("expected: protect_pids_adopt(NULL, 0, NULL, 0, NULL, "
			     "&in, 8, out, &out_count) < 0");
		TEST("a set larger than the capacity is refused");
		if (protect_pids_adopt(NULL, 3, NULL, 0, fake_adopt, &in, 2,
				       out, &out_count) >= 0)
			FAIL("expected: protect_pids_adopt(NULL, 3, NULL, 0, "
			     "fake_adopt, &in, 2, out, &out_count) < 0");
	}
}

#define PUB_A "aaaa"
#define PUB_B "bbbb"

/* Two titles of two publishers, each with a child the kernel adopted */
static void test_owners(void)
{
	struct protect_owner v[6];
	struct protect_owners t = { v, 0, 6 };
	const uint32_t set[] = { 100, 101, 200, 201, 300 };

	protect_owner_note(&t, 100, 1000, 100, 1000, PUB_A);
	protect_owner_note(&t, 101, 1010, 100, 1000, NULL);
	protect_owner_note(&t, 200, 2000, 200, 2000, PUB_B);
	protect_owner_note(&t, 201, 2010, 200, 2000, NULL);
	protect_owner_note(&t, 300, 3000, 300, 3000, NULL);

	TEST("a process named on a publisher's connection is theirs");
	if (!(strcmp(protect_owner_publisher(&t, 100, 1000), PUB_A) == 0 &&
	      strcmp(protect_owner_publisher(&t, 200, 2000), PUB_B) == 0))
		FAIL("expected: strcmp(protect_owner_publisher(&t, 100, "
		     "1000), PUB_A) == 0 && "
		     "strcmp(protect_owner_publisher(&t, 200, 2000), PUB_B) "
		     "== 0");
	TEST("an adopted member is its instance root's publisher's");
	if (!(strcmp(protect_owner_publisher(&t, 101, 1010), PUB_A) == 0 &&
	      strcmp(protect_owner_publisher(&t, 201, 2010), PUB_B) == 0))
		FAIL("expected: strcmp(protect_owner_publisher(&t, 101, "
		     "1010), PUB_A) == 0 && "
		     "strcmp(protect_owner_publisher(&t, 201, 2010), PUB_B) "
		     "== 0");
	TEST("a process named for no publisher, or never named, is no one's");
	if (!(protect_owner_publisher(&t, 300, 3000)[0] == '\0' &&
	      protect_owner_publisher(&t, 400, 4000)[0] == '\0'))
		FAIL("expected: protect_owner_publisher(&t, 300, 3000)[0] == "
		     "'\\0' && protect_owner_publisher(&t, 400, 4000)[0] == "
		     "'\\0'");
	TEST("a later process on the PID is not the earlier one's");
	if (protect_owner_publisher(&t, 100, 1001)[0] != '\0')
		FAIL("expected: protect_owner_publisher(&t, 100, 1001)[0] == "
		     "'\\0'");

	protect_owner_note(&t, 101, 1010, 101, 1010, PUB_B);
	TEST("a member that names itself for a publisher is that publisher's");
	if (strcmp(protect_owner_publisher(&t, 101, 1010), PUB_B) != 0)
		FAIL("expected: strcmp(protect_owner_publisher(&t, 101, "
		     "1010), PUB_B) == 0");
	protect_owner_note(&t, 100, 1000, 100, 1000, PUB_B);
	TEST("a second name does not move a process to another publisher");
	if (strcmp(protect_owner_publisher(&t, 100, 1000), PUB_A) != 0)
		FAIL("expected: strcmp(protect_owner_publisher(&t, 100, "
		     "1000), PUB_A) == 0");

	protect_owner_note(&t, 300, 3001, 300, 3001, PUB_A);
	TEST("a reused PID replaces the entry of the process it outlived");
	if (!(t.n == 5 &&
	      strcmp(protect_owner_publisher(&t, 300, 3001), PUB_A) == 0))
		FAIL("expected: t.n == 5 && "
		     "strcmp(protect_owner_publisher(&t, 300, 3001), PUB_A) "
		     "== 0");

	protect_owners_retain(&t, set + 1, 4);
	TEST("an exited root stays while a member of it is protected");
	if (!(t.n == 5 &&
	      strcmp(protect_owner_publisher(&t, 201, 2010), PUB_B) == 0))
		FAIL("expected: t.n == 5 && "
		     "strcmp(protect_owner_publisher(&t, 201, 2010), PUB_B) "
		     "== 0");

	protect_owners_retain(&t, set + 2, 2);
	TEST("an entry no protected process needs is dropped");
	if (!(t.n == 2 && !protect_owner_find(&t, 100, 1000) &&
	      !protect_owner_find(&t, 101, 1010)))
		FAIL("expected: t.n == 2 && !protect_owner_find(&t, 100, "
		     "1000) && !protect_owner_find(&t, 101, 1010)");

	t.n = t.cap;
	TEST("a full table refuses an entry");
	if (protect_owner_note(&t, 999, 1, 999, 1, PUB_A) != -ENOSPC)
		FAIL("expected: protect_owner_note(&t, 999, 1, 999, 1, PUB_A) "
		     "== -ENOSPC");
}

int main(void)
{
	uint32_t out[8];
	int out_count = 0;
	int ret;

	test_begin("protect pids");

	{
		const uint32_t set[] = { 10, 20, 30 };
		const uint32_t live[] = { 10, 20, 30 };
		struct fake_procfs fs = { live, 3 };

		ret = protect_pids_reap(set, 3, fake_alive, &fs, out,
					&out_count);
		TEST("a set where every process is running is left alone");
		if (!(ret == 0 && out_count == 3))
			FAIL("expected: ret == 0 && out_count == 3");
	}

	{
		const uint32_t set[] = { 10, 20, 30 };
		const uint32_t live[] = { 10, 30 };
		struct fake_procfs fs = { live, 2 };

		ret = protect_pids_reap(set, 3, fake_alive, &fs, out,
					&out_count);
		TEST("an exited process is dropped and the survivors keep their order");
		if (!(ret == 1 && out_count == 2 && out[0] == 10 &&
		      out[1] == 30))
			FAIL("expected: ret == 1 && out_count == 2 && out[0] == 10 && "
			     "out[1] == 30");
	}

	{
		const uint32_t set[] = { 10, 20 };
		const uint32_t live[] = { 0 };
		struct fake_procfs fs = { live, 0 };

		ret = protect_pids_reap(set, 2, fake_alive, &fs, out,
					&out_count);
		TEST("a set whose every process has exited reaps to empty");
		if (!(ret == 1 && out_count == 0))
			FAIL("expected: ret == 1 && out_count == 0");
	}

	{
		struct fake_procfs fs = { NULL, 0 };

		ret = protect_pids_reap(NULL, 0, fake_alive, &fs, out,
					&out_count);
		TEST("an empty set reaps to empty");
		if (!(ret == 0 && out_count == 0))
			FAIL("expected: ret == 0 && out_count == 0");
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
		TEST("no reap reports no change");
		if (ret != 0)
			FAIL("expected: ret == 0");

		fs.live_count = 0;
		ret = protect_pids_reap(set, 1, fake_alive, &fs, out,
					&out_count);
		TEST("a reap reports a change");
		if (ret != 1)
			FAIL("expected: ret == 1");
	}

	{
		const uint32_t set[] = { 1, 2 };
		struct fake_procfs fs = { NULL, 0 };

		TEST("a missing liveness predicate is refused rather than assumed");
		if (protect_pids_reap(set, 2, NULL, &fs, out, &out_count) >= 0)
			FAIL("expected: protect_pids_reap(set, 2, NULL, &fs, out, "
			     "&out_count) < 0");
		TEST("a negative count is refused");
		if (protect_pids_reap(set, -1, fake_alive, &fs, out,
				      &out_count) >= 0)
			FAIL("expected: protect_pids_reap(set, -1, fake_alive, &fs, "
			     "out, &out_count) < 0");
	}

	test_adopt();
	test_owners();

	return test_end();
}
