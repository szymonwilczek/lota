/* SPDX-License-Identifier: MIT */
/*
 * LOTA kernel-anchored per-process measurement - Unit Tests
 *
 * Full fs-verity measurement path is validated on a verity-enabled filesystem
 * in the VM scenarios; here is the pinned fail-closed contract that matters
 * even without fs-verity: the function never reports success with an absent
 * measurement, and it rejects unmeasurable inputs.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

#include "../src/agent/runtime_image_measure.h"
#include "lota.h"

static int tests_run;
static int tests_passed;

#define TEST(name)                                                             \
	do {                                                                   \
		tests_run++;                                                   \
		printf("  [%2d] %-55s", tests_run, name);                      \
	} while (0)

#define PASS()                                                                 \
	do {                                                                   \
		tests_passed++;                                                \
		printf("PASS\n");                                              \
	} while (0)

#define FAIL(reason)                                                           \
	do {                                                                   \
		printf("FAIL (%s)\n", reason);                                 \
	} while (0)

static int digest_is_zero(const uint8_t d[32])
{
	for (int i = 0; i < 32; i++)
		if (d[i] != 0)
			return 0;
	return 1;
}

int main(void)
{
	uint8_t digest[32];
	int ret;

	printf("Kernel-anchored per-process measurement tests:\n");

	TEST("measure_pid never reports success with an absent digest");
	memset(digest, 0, sizeof(digest));
	ret = lota_runtime_measure_pid(getpid(), digest);
	/*
	 * Without fs-verity on the freshly built test binary the call fails
	 * closed; with fs-verity it must yield a non-zero digest.
	 * Either way it must never return success while leaving the digest
	 * unset.
	 */
	if (ret < 0 || !digest_is_zero(digest))
		PASS();
	else
		FAIL("success with zero digest");

	TEST("measure_pid rejects a nonexistent process");
	if (lota_runtime_measure_pid(-1, digest) < 0)
		PASS();
	else
		FAIL("accepted bad pid");

	TEST("measure_pid rejects NULL output");
	if (lota_runtime_measure_pid(getpid(), NULL) < 0)
		PASS();
	else
		FAIL("accepted NULL output");

	TEST("measure_entry_verity rejects an unbacked range");
	{
		struct lota_rt_map_entry e;
		struct lota_verity_digest_key v;
		memset(&e, 0, sizeof(e));
		strcpy(e.soname, "none");
		if (lota_rt_measure_entry_verity(getpid(), &e, &v) < 0)
			PASS();
		else
			FAIL("accepted unbacked range");
	}

	printf("\n%d/%d kernel-anchored measurement tests passed\n",
	       tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
