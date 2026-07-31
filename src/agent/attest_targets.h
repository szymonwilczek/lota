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

	/*
	 * How this target is named in log line, built once by attest_targets_build()
	 * Every message about a target says which one it means, and deriving
	 * that at each site made the identity of target formatting decision
	 * repeated fifteen times.
	 */
	char label[288];
	char ca_cert[PATH_MAX];
	int interval;

	/* the attestation CA this publisher enrolls against,
	 * empty when the target came from the single-verifier path */
	char ca[256];
	int ca_port;

	/*
	 * This publisher runs no verifier:
	 * their backend checks the tokens a title fetches, so nothing is reported here.
	 * The target still exists because everything else about it does
	 * -- it enrolls, it holds an AIK, that key rotates and its certificate
	 * is renewed, and dropping it from the list would let the certificate
	 * the publisher's backend chains against lapse while the player is playing.
	 */
	bool token_only;

	/*
	 * Report only while a title of this publisher's is running.
	 *
	 * sessions counts the connections currently bound to this publisher,
	 * maintained by the IPC layer.
	 * Reporting is exfiltration and closed game has no reason to produce any;
	 * enforcement and the boot commitment are local and never stop,
	 * which is what lets session's first quote still prove the whole
	 * boot-to-now window.
	 */
	bool session_gated;
	int sessions;

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

	/*
	 * First enrollment, which happens while the host runs rather than while
	 * it is installed: player has no CA endpoint to type in at install time,
	 * and the publisher they buy from is not known until title of theirs runs.
	 * enroll_pending is raised by title selecting this publisher,
	 * so the loop stops sleeping and enrolls now.
	 */
	bool enroll_pending;
	int enroll_backoff;
	uint64_t next_enroll_ms;

	/* session has just opened or closed;
	 * the loop reacts on its next pass instead of sleeping through the change */
	bool session_changed;
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
