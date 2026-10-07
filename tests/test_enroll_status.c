/* SPDX-License-Identifier: MIT */
/*
 * What an operator is told when a CA refuses to enroll their machine.
 *
 * Enrollment is the first thing a machine does, so a refusal arrives with no
 * other context: a bare number leaves the operator with no cause and no remedy
 * on the one step where nothing else has happened yet. Every status the wire
 * defines therefore has to have a sentence, and a status this build does not
 * know has to be distinguishable from one it does.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#include <stdio.h>
#include <string.h>

#include "../src/agent/enroll.h"

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

/* every refusal the wire can carry, and the name it is known by */
static const struct {
	unsigned int status;
	const char *name;
} refusals[] = {
	{ LOTA_ENROLL_STATUS_BAD_REQUEST, "BAD_REQUEST" },
	{ LOTA_ENROLL_STATUS_EK_REJECTED, "EK_REJECTED" },
	{ LOTA_ENROLL_STATUS_AIK_REJECTED, "AIK_REJECTED" },
	{ LOTA_ENROLL_STATUS_ACTIVATION_FAIL, "ACTIVATION_FAIL" },
	{ LOTA_ENROLL_STATUS_UNKNOWN_SESSION, "UNKNOWN_SESSION" },
	{ LOTA_ENROLL_STATUS_INTERNAL_ERROR, "INTERNAL_ERROR" },
	{ LOTA_ENROLL_STATUS_RATE_LIMITED, "RATE_LIMITED" },
	{ LOTA_ENROLL_STATUS_TOKEN_REJECTED, "TOKEN_REJECTED" },
};

int main(void)
{
	size_t i, j;
	char msg[128];

	printf("=== enrollment refusal messages ===\n\n");

	for (i = 0; i < sizeof(refusals) / sizeof(refusals[0]); i++) {
		const char *text = lota_enroll_status_text(refusals[i].status);

		snprintf(msg, sizeof(msg),
			 "%s is explained rather than numbered",
			 refusals[i].name);
		CHECK(text != NULL && text[0] != '\0', msg);

		if (!text)
			continue;

		/* the number is printed by the caller;
		 * a sentence that only repeats it tells the operator nothing */
		snprintf(msg, sizeof(msg), "%s says more than its own number",
			 refusals[i].name);
		CHECK(strlen(text) > 16 && strstr(text, "status") == NULL, msg);
	}

	/* two refusals sharing a sentence means one of them is unexplained */
	for (i = 0; i < sizeof(refusals) / sizeof(refusals[0]); i++) {
		const char *a = lota_enroll_status_text(refusals[i].status);

		if (!a)
			continue;
		for (j = i + 1; j < sizeof(refusals) / sizeof(refusals[0]);
		     j++) {
			const char *b =
				lota_enroll_status_text(refusals[j].status);

			if (!b || strcmp(a, b) != 0)
				continue;
			snprintf(msg, sizeof(msg),
				 "%s and %s do not share one sentence",
				 refusals[i].name, refusals[j].name);
			CHECK(0, msg);
		}
	}

	/* a CA newer than this agent: the caller prints the number and says so,
	 * which it can only do if it can tell the two apart */
	CHECK(lota_enroll_status_text(9) == NULL,
	      "a status this build does not know has no sentence");
	CHECK(lota_enroll_status_text(65535) == NULL,
	      "a status far outside the range has no sentence either");

	/* success is not a refusal and is never rendered as one */
	CHECK(lota_enroll_status_text(LOTA_ENROLL_STATUS_OK) == NULL,
	      "the OK status is not an explanation of a refusal");

	printf("\n%s\n", g_failures ? "FAILURES" : "All tests passed");
	return g_failures ? 1 : 0;
}
