/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
#ifndef LOTA_ATTEST_H
#define LOTA_ATTEST_H

#include <stdbool.h>
#include <stdint.h>

#include "config.h"
#include "profile.h"

/* Floor on the continuous-attestation interval */
#define MIN_ATTEST_INTERVAL 30 /* seconds */
#define ATTEST_BACKOFF_BASE_SEC 10 /* first retry delay, doubled per failure */
#define MAX_BACKOFF_SECONDS 300 /* Max retry delay */

/*
 * Added to the interval in a publisher's valid_until: the window outlasts the
 * wait for the next round.
 */
#define ATTEST_TOKEN_VALIDITY_SLACK_SEC 60

/*
 * How far ahead the SDK verifiers accept a valid_until is DefaultMaxTokenAge
 * plus MaxClockSkew in sdk/server/verify.go, LOTA_SERVER_MAX_TOKEN_AGE_SEC plus
 * LOTA_SERVER_MAX_CLOCK_SKEW_SEC in include/lota_server.h. The agent stays
 * within the age and leaves the skew to a verifier's clock.
 */
#define RELYING_PARTY_MAX_TOKEN_AGE_SEC 300

/*
 * Cadence of a host that names publishers or nothing, but no interval.
 * It matches configs/lota.conf.example and sits at the ceiling below.
 */
#define DEFAULT_ATTEST_INTERVAL 240

/*
 * How long a token issued to a publisher who runs no verifier is good for.
 * Nothing is reported to that publisher, so the agent sets the bound itself.
 */
#define TOKEN_ONLY_VALIDITY_SEC DEFAULT_ATTEST_INTERVAL

/* Ceiling on the interval: past it a token outlives the age above */
#define MAX_ATTEST_INTERVAL \
	(RELYING_PARTY_MAX_TOKEN_AGE_SEC - ATTEST_TOKEN_VALIDITY_SLACK_SEC)

_Static_assert(TOKEN_ONLY_VALIDITY_SEC + ATTEST_TOKEN_VALIDITY_SLACK_SEC <=
		       RELYING_PARTY_MAX_TOKEN_AGE_SEC,
	       "a token-only token must stay verifiable by every relying party");

_Static_assert(MIN_ATTEST_INTERVAL < MAX_ATTEST_INTERVAL,
	       "attestation interval floor must stay below the ceiling");

_Static_assert(DEFAULT_ATTEST_INTERVAL >= MIN_ATTEST_INTERVAL &&
		       DEFAULT_ATTEST_INTERVAL <= MAX_ATTEST_INTERVAL,
	       "the default attestation interval must lie between the bounds");

_Static_assert(MAX_ATTEST_INTERVAL + ATTEST_TOKEN_VALIDITY_SLACK_SEC <=
		       RELYING_PARTY_MAX_TOKEN_AGE_SEC,
	       "a token minted at the interval ceiling must stay verifiable");

/**
 * attest_effective_interval() - The cadence --attest runs at.
 * @configured: Configured interval, 0 when none.
 * @profile_count: How many publishers the host names.
 * @has_server: The options name a single verifier.
 *
 * A host that names nothing still gets the loop, which waits for a reload to
 * name a target.
 *
 * Return: @configured when set, DEFAULT_ATTEST_INTERVAL for publishers or for
 * nothing named, 0 for a single verifier alone: the one-shot.
 */
static inline int attest_effective_interval(int configured, int profile_count,
					    bool has_server)
{
	if (configured > 0)
		return configured;
	if (profile_count > 0 || !has_server)
		return DEFAULT_ATTEST_INTERVAL;
	return 0;
}

/**
 * attest_env_overrides_allowed() - May the environment redirect the TPM?
 * @attest_flag: --attest was given.
 * @configured: As for attest_effective_interval().
 * @profile_count: As for attest_effective_interval().
 * @has_server: As for attest_effective_interval().
 *
 * LOTA_TCTI and LOTA_AIK_META_PATH serve one-shots, the swtpm demo and tests:
 * a continuous round would quote the host against another TPM.
 *
 * Return: false for --attest at a cadence, true otherwise.
 */
static inline bool attest_env_overrides_allowed(int attest_flag, int configured,
						int profile_count,
						bool has_server)
{
	if (!attest_flag)
		return true;
	return attest_effective_interval(configured, profile_count,
					 has_server) <= 0;
}

/* Stages an attestation round can fail at; the loop logs the failing one */
enum attest_stage {
	ATTEST_STAGE_TLS_SETUP,
	ATTEST_STAGE_CONNECT,
	ATTEST_STAGE_CHALLENGE,
	ATTEST_STAGE_BUILD_REPORT,
	ATTEST_STAGE_SERIALIZE,
	ATTEST_STAGE_SEND,
	ATTEST_STAGE_RESULT,
	ATTEST_STAGE_VERDICT,
	ATTEST_STAGE_COUNT,
};

/**
 * attest_stage_str() - Name of a stage, for a log line.
 * @stage: The stage.
 *
 * Return: the name, never NULL, also for a value the table does not cover.
 */
const char *attest_stage_str(enum attest_stage stage);

/**
 * attest_failure_reason() - Why a round failed, for the line the loop logs.
 * @ret: The round's return value: a negative errno or LOTA-private TPM code.
 *
 * Return: a printable reason.
 */
const char *attest_failure_reason(int ret);

/**
 * attest_warn_cert_orphaned() - Log a stored certificate naming a lost key.
 * @paths: The profile just bound, or NULL when the caller has none.
 * @label: How this publisher is named in log lines.
 * @key_present: What tpm_aik_key_present() answered before provisioning.
 *
 * Call right after provisioning: an absent key may come back derived to the
 * value the certificate still names. Only logs.
 */
void attest_warn_cert_orphaned(const struct profile_paths *paths,
			       const char *label, int key_present);

/**
 * export_policy() - Write a verifier-ready YAML policy of this host to stdout.
 * @mode: The agent's LOTA_MODE_*, recorded as the policy's enforce mode.
 *
 * Return: 0 on success, negative on a TPM or write failure.
 */
int export_policy(int mode);
int do_attest(const char *server, int port, const char *ca_cert,
	      int skip_verify, const uint8_t *pin_sha256);
/**
 * do_continuous_attest() - Run the continuous attestation loop.
 * @cfg: Publisher profiles to report to, each to its own verifier on its own
 *       cadence with its own AIK.
 * @config_path: The file a SIGHUP re-reads that list from; NULL is the default.
 * @server: With no profiles, the only target.
 * @port: Its port.
 * @ca_cert: Its CA certificate.
 * @skip_verify: Nonzero disables TLS certificate verification.
 * @pin_sha256: The pin of a target that states none; NULL for none.
 * @interval_sec: The cadence a profile that states none inherits.
 *
 * Return: 0 after a shutdown, 1 when the loop cannot start,
 * LOTA_EXIT_OPERATOR_ACTION when a restart cannot clear a refused
 * self-measurement.
 */
int do_continuous_attest(const struct lota_config *cfg, const char *config_path,
			 const char *server, int port, const char *ca_cert,
			 int skip_verify, const uint8_t *pin_sha256,
			 int interval_sec);

#endif /* LOTA_ATTEST_H */
