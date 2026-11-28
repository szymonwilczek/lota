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

#include <errno.h>
#include <string.h>

#include "../src/agent/attest.h"
#include "../src/agent/tpm.h"

#include "test.h"

/*
 * Every stage a round can fail at is named. A stage with no name would reach
 * the operator as an empty string in the one line they are given.
 */
static void test_every_stage_is_named(void)
{
	TEST("every attestation stage has a name");
	for (int s = 0; s < ATTEST_STAGE_COUNT; s++) {
		const char *name = attest_stage_str((enum attest_stage)s);

		if (!name || name[0] == '\0')
			FAIL("stage %d has no name", s);
	}
}

/*
 * Two stages sharing a name would send an operator to the wrong half of the
 * round -- a TLS setup failure reads nothing like a rejected verdict.
 */
static void test_stage_names_are_distinct(void)
{
	TEST("no two attestation stages share a name");
	for (int a = 0; a < ATTEST_STAGE_COUNT; a++) {
		for (int b = a + 1; b < ATTEST_STAGE_COUNT; b++) {
			const char *na = attest_stage_str((enum attest_stage)a);
			const char *nb = attest_stage_str((enum attest_stage)b);

			if (na && nb && strcmp(na, nb) == 0)
				FAIL("stages %d and %d share '%s'", a, b, na);
		}
	}
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

	TEST("a stage below the table is still printable");
	if (!(below && below[0] != '\0'))
		FAIL("expected: below && below[0] != '\\0'");
	TEST("a stage past the table is still printable");
	if (!(above && above[0] != '\0'))
		FAIL("expected: above && above[0] != '\\0'");
}

/*
 * A round that failed on the TPM has to say so.
 *
 * tpm.h defines LOTA-private codes above the POSIX range precisely so a lockout
 * is not reported as a number, and says in its own comment that callers should
 * render them through tpm_strerror() instead of "Unknown error 4097".
 * The continuous loop logs one line per failed round, so that line is the whole
 * of what an unattended host reports.
 */
static void test_tpm_codes_are_named(void)
{
	const char *locked = attest_failure_reason(-LOTA_ERR_TPM_LOCKED);
	const char *authfail = attest_failure_reason(-LOTA_ERR_TPM_AUTH_FAIL);

	TEST("a dictionary-attack lockout is named, not numbered");
	if (!(locked && strstr(locked, "lockout")))
		FAIL("expected: locked && strstr(locked, \"lockout\")");
	/*
	 * Stated against the C library:
	 * strerror() is localised, so "Unknown error 4097" is only what
	 * an operator sees in one locale.
	 * What must hold everywhere is that a LOTA-private code is not left
	 * to strerror() at all.
	 */
	TEST("the lockout reason is not whatever strerror makes of 4097");
	if (!(locked && strcmp(locked, strerror(LOTA_ERR_TPM_LOCKED)) != 0))
		FAIL("expected: locked && strcmp(locked, "
		     "strerror(LOTA_ERR_TPM_LOCKED)) != 0");

	/* BAD_AUTH and NV_AUTHORIZATION share the code and leave the counter */
	TEST("an authorization failure promises no DA count");
	if (!(authfail && strstr(authfail, "authorization") &&
	      !strstr(authfail, "DA")))
		FAIL("expected: authfail && strstr(authfail, "
		     "\"authorization\") && !strstr(authfail, \"DA\")");
}

/*
 * Ordinary errno values still render as themselves:
 * the round fails on sockets and files far more often than on the TPM.
 */
static void test_posix_errors_still_render(void)
{
	const char *eio = attest_failure_reason(-EIO);

	TEST("a POSIX errno renders as the C library renders it");
	if (!(eio && strcmp(eio, strerror(EIO)) == 0))
		FAIL("expected: eio && strcmp(eio, strerror(EIO)) == 0");
}

int main(void)
{
	test_begin("attest stage");
	test_every_stage_is_named();
	test_stage_names_are_distinct();
	test_unknown_stage_is_printable();
	test_tpm_codes_are_named();
	test_posix_errors_still_render();

	return test_end();
}
