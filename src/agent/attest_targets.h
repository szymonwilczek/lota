/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Attestation targets: who this host reports to, and on what cadence.
 *
 * Player's machine has one state and several publishers judging it,
 * so the attestation loop is not one verifier on one timer.
 * Each target carries the publisher profile whose AIK answers to it and its own
 * schedule and failure state, because one unreachable verifier must not back off
 * another publisher's reporting.
 *
 * Built apart from the loop so the list can be tested without a TPM.
 */

#ifndef LOTA_AGENT_ATTEST_TARGETS_H
#define LOTA_AGENT_ATTEST_TARGETS_H

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "config.h"
#include "profile.h"

struct attest_target {
	char server[256];
	int port;
	char ca_cert[PATH_MAX];
	int interval;

	struct profile_paths paths;
	bool has_profile;
	/* why the anchor produced no profile, 0 when it did or none was set */
	int profile_error;

	/* schedule, on the monotonic clock */
	uint64_t next_due_ms;

	/* per-target attestation state */
	int consecutive_failures;
	int backoff_sec;
	time_t last_success;
	bool attested;
	uint64_t valid_until;

	/* per-target certificate renewal */
	bool auto_renew;
	int renew_backoff;
	uint64_t next_renew_ms;
};

/*
 * Build the target list.
 *
 * Configured profile list is the target list:
 * each publisher names its own verifier, its own trust anchor and optionally
 * its own cadence, inheriting @interval_sec when it states none.
 * With no profiles configured the single @server / @port / @ca_cert is the only
 * target, which is the enterprise fleet the agent has always served.
 *
 * Returns 0, -EINVAL on a missing single-target server or bad argument,
 * or E2BIG when @max cannot hold every configured profile.
 */
int attest_targets_build(const struct lota_config *cfg, const char *server,
			 int port, const char *ca_cert, int interval_sec,
			 struct attest_target *out, size_t max, size_t *count);

#endif /* LOTA_AGENT_ATTEST_TARGETS_H */
