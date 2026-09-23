/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for the attestation round's failure stages (attest.c).
 *
 * A round that fails has to say where it failed. The continuous loop reports
 * only "Attestation FAILED" and a backoff, so the stage name is the whole of
 * what an operator gets: it is pinned here that every stage has one, that no
 * two stages share it, and that an unknown value still yields a printable
 * string.
 *
 * No TPM and no network.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <stdio.h>
#include <string.h>

#include "../src/agent/attest.h"

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

/*
 * Every stage a round can fail at is named. A stage with no name would reach
 * the operator as an empty string in the one line they are given.
 */
static void test_every_stage_is_named(void)
{
	int named = 1;

	for (int s = 0; s < ATTEST_STAGE_COUNT; s++) {
		const char *name = attest_stage_str((enum attest_stage)s);

		if (!name || name[0] == '\0') {
			fprintf(stderr, "  stage %d has no name\n", s);
			named = 0;
		}
	}
	CHECK(named, "every attestation stage has a name");
}

/*
 * Two stages sharing a name would send an operator to the wrong half of the
 * round -- a TLS setup failure reads nothing like a rejected verdict.
 */
static void test_stage_names_are_distinct(void)
{
	int distinct = 1;

	for (int a = 0; a < ATTEST_STAGE_COUNT; a++) {
		for (int b = a + 1; b < ATTEST_STAGE_COUNT; b++) {
			const char *na = attest_stage_str((enum attest_stage)a);
			const char *nb = attest_stage_str((enum attest_stage)b);

			if (na && nb && strcmp(na, nb) == 0) {
				fprintf(stderr,
					"  stages %d and %d share '%s'\n", a, b,
					na);
				distinct = 0;
			}
		}
	}
	CHECK(distinct, "no two attestation stages share a name");
}

/*
 * The value reaching this function comes from a code path that may grow a
 * stage before the table does, and it is passed straight to a log call.
 */
static void test_unknown_stage_is_printable(void)
{
	const char *below = attest_stage_str((enum attest_stage) - 1);
	const char *above =
		attest_stage_str((enum attest_stage)ATTEST_STAGE_COUNT);

	CHECK(below && below[0] != '\0',
	      "a stage below the table is still printable");
	CHECK(above && above[0] != '\0',
	      "a stage past the table is still printable");
}

int main(void)
{
	printf("=== attestation stage tests ===\n");
	test_every_stage_is_named();
	test_stage_names_are_distinct();
	test_unknown_stage_is_printable();

	if (g_failures) {
		fprintf(stderr, "\n%d test(s) failed\n", g_failures);
		return 1;
	}
	printf("\nAll attestation stage tests passed\n");
	return 0;
}
