// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
/*
 * The two decisions token issuance turns on.
 *
 * Both were found on hardware with more than one publisher and more than one
 * title running, which is the only arrangement that shows them: a token-only
 * publisher asking for the token that is its entire evidence, and one title's
 * packaging deciding whether another title's publisher gets an answer.
 */

#include <stdio.h>

#include "../include/lota_ipc.h"
#include "../src/agent/token_gate.h"

static int g_failures;
static const char *g_current;

#define TEST(name)                                 \
	do {                                       \
		g_current = name;                  \
		printf("[ RUN      ] %s\n", name); \
	} while (0)

#define PASS() printf("[       OK ] %s\n", g_current)

#define FAIL(msg)                                                         \
	do {                                                              \
		fprintf(stderr, "[  FAILED  ] %s: %s\n", g_current, msg); \
		g_failures++;                                             \
		return;                                                   \
	} while (0)

/*
 * A publisher who runs a verifier is answered with that verifier's verdict,
 * so a token before there is one would claim one.
 */
static void test_verifier_publisher_still_needs_a_verdict(void)
{
	TEST("a publisher with a verifier still needs a verdict");

	if (!token_gate_needs_attested(0))
		FAIL("a publisher who reports was answered without a verdict");
	if (!token_gate_needs_attested(LOTA_STATUS_TPM_OK))
		FAIL("a publisher who reports was answered without a verdict");
	PASS();
}

/*
 * A publisher who runs no verifier is never reported to, so no verdict of theirs
 * can exist. The token is their evidence, and requiring a verdict first makes
 * the light path unreachable.
 */
static void test_token_only_publisher_is_answered(void)
{
	TEST("a token-only publisher does not need a verdict it cannot have");

	if (token_gate_needs_attested(LOTA_STATUS_TOKEN_ONLY))
		FAIL("a token-only publisher was asked for a verdict that "
		     "cannot exist");
	if (token_gate_needs_attested(LOTA_STATUS_TOKEN_ONLY |
				      LOTA_STATUS_TPM_OK))
		FAIL("a token-only publisher was asked for a verdict that "
		     "cannot exist");
	PASS();
}

/*
 * A publisher controls its own executable, so an unmeasurable one is its own
 * answer to give.
 */
static void test_own_measurement_failure_refuses(void)
{
	TEST("a caller whose own executable cannot be measured is refused");

	if (!token_gate_failure_is_fatal(4242, 4242))
		FAIL("a caller was issued a token over its own unmeasurable "
		     "executable");
	PASS();
}

/*
 * Any local program may protect itself, so folding another process's measurement
 * failure into this request hands out a way to stop every title on the machine.
 */
static void test_another_process_does_not_decide_this_token(void)
{
	TEST("another process's measurement failure does not decide this token");

	if (token_gate_failure_is_fatal(8255, 4242))
		FAIL("one title's packaging refused another title's token");
	PASS();
}

int main(void)
{
	test_verifier_publisher_still_needs_a_verdict();
	test_token_only_publisher_is_answered();
	test_own_measurement_failure_refuses();
	test_another_process_does_not_decide_this_token();

	if (g_failures == 0) {
		printf("\nAll tests passed.\n");
		return 0;
	}
	fprintf(stderr, "\n%d test(s) failed.\n", g_failures);
	return 1;
}
