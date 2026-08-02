/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
#ifndef LOTA_ATTEST_H
#define LOTA_ATTEST_H

#include <stdint.h>

#include "config.h"
#include "profile.h"

/*
 * Operator-facing floor on the continuous-attestation interval,
 * enforced where the interval is read and reported by --help
 *
 * Retry backoff below is separate quantity:
 * it is the first delay after failed attestation,
 * doubled per consecutive failure.
 */
#define MIN_ATTEST_INTERVAL 30 /* seconds */
#define ATTEST_BACKOFF_BASE_SEC 10 /* first retry delay */
#define MAX_BACKOFF_SECONDS 300 /* Max retry delay */

/*
 * Slack added to the interval when the attestation loop sets token's valid_until,
 * so token outlives the round that minted it.
 */
#define ATTEST_TOKEN_VALIDITY_SLACK_SEC 60

/*
 * How far into the future a relying party will accept a valid_until:
 * DefaultMaxTokenAge plus MaxClockSkew in src/sdk/server/verify.go, which is
 * the tighter of the two verifier implementations and therefore the bound
 * the agent has to mint within.
 * Token past it is refused by every relying party, not merely by strict one.
 */
#define RELYING_PARTY_TOKEN_WINDOW_SEC (300 + 60)

/*
 * Cadence a host attests at when it names publishers but not an interval.
 * It matches the value configs/lota.conf.example ships, so host that took
 * the default and a host that copied the example behave the same, and it sits
 * at the ceiling below -- the widest spacing whose tokens every relying party
 * still accepts.
 */
#define DEFAULT_ATTEST_INTERVAL 300

/*
 * Ceiling on the continuous-attestation interval.
 * Above it the loop mints tokens no relying party accepts, which is running agent
 * whose every token is refused.
 */
#define MAX_ATTEST_INTERVAL \
	(RELYING_PARTY_TOKEN_WINDOW_SEC - ATTEST_TOKEN_VALIDITY_SLACK_SEC)

/* Interval the operator can set has to exist between the two bounds */
_Static_assert(MIN_ATTEST_INTERVAL < MAX_ATTEST_INTERVAL,
	       "attestation interval floor must stay below the ceiling");

/* The default a host falls back to has to be one an operator could have set */
_Static_assert(DEFAULT_ATTEST_INTERVAL >= MIN_ATTEST_INTERVAL &&
		       DEFAULT_ATTEST_INTERVAL <= MAX_ATTEST_INTERVAL,
	       "the default attestation interval must lie between the bounds");

/*
 * Slack is charged against the same window the ceiling is derived from,
 * so token minted at the ceiling still lands inside it.
 */
_Static_assert(MAX_ATTEST_INTERVAL + ATTEST_TOKEN_VALIDITY_SLACK_SEC <=
		       RELYING_PARTY_TOKEN_WINDOW_SEC,
	       "a token minted at the interval ceiling must stay verifiable");

/*
 * The cadence --attest runs at:
 * what the host configured, the default when it named publishers but no interval,
 * and 0 when it named neither -- the only case that still belongs to the
 * single-verifier one-shot.
 *
 * Pure function so the choice is testable without a TPM or a verifier:
 * it decides whether a configured publisher list is attested to at all.
 */
static inline int attest_effective_interval(int configured, int profile_count)
{
	if (configured > 0)
		return configured;
	if (profile_count > 0)
		return DEFAULT_ATTEST_INTERVAL;
	return 0;
}

int export_policy(int mode);
int do_attest(const char *server, int port, const char *ca_cert,
	      int skip_verify, const uint8_t *pin_sha256);
/*
 * Continuous attestation.
 *
 * @cfg names the publisher profiles to report to; with profile list configured
 * it is the target list, each profile reporting to its own verifier on its own
 * cadence and signing with its own AIK.
 * With no profiles (or no config) the single server/port/ca_cert the caller
 * resolved is the only target.
 * @interval_sec is the cadence a profile that states none inherits.
 */
int do_continuous_attest(const struct lota_config *cfg, const char *server,
			 int port, const char *ca_cert, int skip_verify,
			 const uint8_t *pin_sha256, int interval_sec,
			 uint32_t aik_ttl);

/*
 * Publish the current AIK rotation state (generation, provisioned time,
 * next-rotation deadline, grace window, reenroll-required) over IPC / D-Bus
 * from the loaded AIK metadata. Safe to call once the IPC context exists and
 * the AIK metadata is loaded; a no-op until then.
 * aik_ttl mirrors the -aik-ttl / config value (0 selects the default).
 * paths names the publisher profile whose enrollment is compared against the
 * live AIK;
 * NULL when no CA trust anchor is configured and there is therefore no enrollment
 * to compare.
 */
void publish_rotation_state(uint32_t aik_ttl,
			    const struct profile_paths *paths);

#endif /* LOTA_ATTEST_H */
