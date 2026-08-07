/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Names for the stages an attestation round can fail at.
 *
 * The continuous loop has no operator watching its stdout, so the stage name
 * is what a failure is reported as.
 *
 * Kept apart from attest.c so it links into a test without a TPM or a network
 * stack behind it.
 */

#include "attest.h"

static const char *const stage_names[ATTEST_STAGE_COUNT] = {
	[ATTEST_STAGE_TLS_SETUP] = "TLS setup",
	[ATTEST_STAGE_CONNECT] = "connecting to the verifier",
	[ATTEST_STAGE_CHALLENGE] = "receiving the challenge",
	[ATTEST_STAGE_BUILD_REPORT] = "building the report",
	[ATTEST_STAGE_SERIALIZE] = "serializing the report",
	[ATTEST_STAGE_SEND] = "sending the report",
	[ATTEST_STAGE_RESULT] = "receiving the verdict",
	[ATTEST_STAGE_VERDICT] = "the verifier's verdict",
};

const char *attest_stage_str(enum attest_stage stage)
{
	if (stage < 0 || stage >= ATTEST_STAGE_COUNT)
		return "an unnamed stage";
	return stage_names[stage] ? stage_names[stage] : "an unnamed stage";
}
