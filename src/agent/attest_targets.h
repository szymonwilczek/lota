/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Attestation targets: who this host reports to, and on what cadence.
 *
 * Each target carries the publisher profile whose AIK answers to it and its own
 * schedule and failure state, so an unreachable verifier does not back off
 * another publisher's reporting.
 */

#ifndef LOTA_AGENT_ATTEST_TARGETS_H
#define LOTA_AGENT_ATTEST_TARGETS_H

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "config.h"
#include "pin.h"
#include "profile.h"

struct attest_target {
	char server[256];
	int port;

	/* How log lines name this target, built by attest_targets_build() */
	char label[288];
	char ca_cert[PATH_MAX];
	int interval;

	/* this publisher's enrollment CA, empty on the single-verifier path */
	char ca[256];
	int ca_port;

	/*
	 * This publisher runs no verifier: nothing is reported here. The target
	 * still enrolls, holds an AIK and renews its certificate.
	 */
	bool token_only;

	/*
	 * Report only while a title of this publisher's runs. sessions counts
	 * the connections bound to this publisher, as last synced from the
	 * socket owner.
	 */
	bool session_gated;
	int sessions;

	/* Said it is waiting for a title of this publisher's to start */
	bool wait_announced;

	/*
	 * Said the key at its handle is not the one its certificate names;
	 * cleared when they agree.
	 */
	bool key_mismatch_announced;

	/* Said its stored certificate cannot be read; reading it clears it */
	bool cert_unreadable_announced;

	/* Said the TPM refused its quote's auth; a good round clears it */
	bool auth_fail_announced;

	/* Said its record names the shared key; naming its own clears it */
	bool shared_key_announced;

	/* SHA-256 of the certificate this target's verifier must present */
	uint8_t pin_sha256[LOTA_PIN_SHA256_LEN];
	bool has_pin;

	struct profile_paths paths;
	bool has_profile;
	/* why the anchor produced no profile, 0 when it did or none was set */
	int profile_error;

	/* schedule, on the monotonic clock */
	uint64_t next_due_ms;

	int consecutive_failures;
	int backoff_sec;
	time_t last_success;
	bool attested;
	uint64_t valid_until;

	bool auto_renew;
	int renew_backoff;
	uint64_t next_renew_ms;

	/* renewal endpoint, from the enrollment record */
	char renew_ca[256];
	int renew_ca_port;

	bool renew_announced; /* current renewal decision logged */
	bool renew_move_announced; /* configured vs recorded CA mismatch logged */

	/*
	 * First enrollment. enroll_pending is raised by a title selecting this
	 * publisher, so the loop stops sleeping and enrolls.
	 */
	bool enroll_pending;
	int enroll_backoff;
	uint64_t next_enroll_ms;

	/*
	 * Its certificate does not name the key at its handle and the loop
	 * enrolls it again, so its titles read LOTA_STATUS_REENROLLING.
	 */
	bool reenrolling;
	/* Said it is not enrolled again unattended; an agreement clears it */
	bool reenroll_refused_announced;
	int reenroll_backoff;
	uint64_t next_reenroll_ms;

	/* a session opened or closed: the loop reacts on its next pass */
	bool session_changed;

	/* The agent ended a process protected for this publisher */
	bool protected_terminated;
};

/* what to log about a target's certificate renewal */
enum attest_renew_say {
	ATTEST_RENEW_SILENT = 0, /* unchanged and already logged */
	ATTEST_RENEW_ENABLED,
	ATTEST_RENEW_OFF,
};

/**
 * attest_target_resolve_renew() - Set @t's renewal from its enrollment record.
 * @t: The target; stores the endpoint on it.
 * @rec_server: Recorded endpoint, NULL if never enrolled.
 * @rec_port: Recorded port.
 *
 * Call on every pass.
 *
 * Return: what to log.
 */
enum attest_renew_say attest_target_resolve_renew(struct attest_target *t,
						  const char *rec_server,
						  int rec_port);

/* ", renewing at " plus the recorded endpoint */
#define LOTA_RENEW_AT_LEN 288

/**
 * attest_target_renew_at() - Write ", renewing at <host>:<port>" for @t.
 * @t: The target.
 * @buf: Destination; empty when @t cannot renew or a token-only label already
 *       names that endpoint.
 * @len: Size of @buf.
 *
 * Return: @buf.
 */
const char *attest_target_renew_at(const struct attest_target *t, char *buf,
				   size_t len);

/**
 * attest_target_should_announce_renew_move() - Time to say the CA moved?
 * @t: The target; records the answer.
 *
 * Return: true once while @t's configured CA differs from the recorded renewal
 * endpoint; re-armed when they agree or that endpoint changes.
 */
bool attest_target_should_announce_renew_move(struct attest_target *t);

/* what to log about the key at a target's handle against its certificate */
enum attest_cert_say {
	ATTEST_CERT_SILENT = 0, /* nothing new to log */
	ATTEST_CERT_MISMATCH,
	ATTEST_CERT_MATCHES_AGAIN,
	ATTEST_CERT_UNREADABLE,
};

/**
 * attest_target_note_cert_match() - Record what the certificate check said.
 * @t: The target; records the answer.
 * @match_rc: aik_cert_matches_key() for the key at @t's handle.
 *
 * A certificate that cannot be read confirms nothing and clears no mismatch.
 *
 * Return: what to log.
 */
enum attest_cert_say attest_target_note_cert_match(struct attest_target *t,
						   int match_rc);

/* what the loop does about a certificate that does not name the key */
enum attest_reenroll {
	ATTEST_REENROLL_NOW = 0,
	ATTEST_REENROLL_WAIT, /* the last attempt failed and backs off */
	ATTEST_REENROLL_REFUSED, /* no agreement recorded: log it */
	ATTEST_REENROLL_REFUSED_SILENT, /* the same, already logged */
};

/**
 * attest_target_reenroll_decide() - Enroll @t again for the key now present?
 * @t: The target, whose certificate does not name the key at its handle.
 * @consent_rc: profile_consent_time() for @t.
 * @now_ms: Now, on the monotonic clock.
 *
 * Sets @t->reenrolling unless the answer is a refusal.
 *
 * Return: what to do.
 */
enum attest_reenroll attest_target_reenroll_decide(struct attest_target *t,
						   int consent_rc,
						   uint64_t now_ms);

/**
 * attest_target_reenroll_failed() - Back off @t after a failed attempt.
 * @t: The target.
 * @now_ms: Now, on the monotonic clock.
 *
 * Return: seconds until the next attempt.
 */
int attest_target_reenroll_failed(struct attest_target *t, uint64_t now_ms);

/**
 * attest_target_reenroll_wait() - Seconds until @t's next round.
 * @t: The target, whose certificate does not name the key at its handle.
 * @now_ms: Now, on the monotonic clock.
 *
 * Return: seconds until the next re-enrollment attempt while one is backed
 * off, else @t->interval.
 */
int attest_target_reenroll_wait(const struct attest_target *t, uint64_t now_ms);

/**
 * attest_target_reenroll_clear() - Forget @t's re-enrollment state.
 * @t: The target, whose certificate names the key at its handle again.
 */
void attest_target_reenroll_clear(struct attest_target *t);

/**
 * attest_targets_take_wakeups() - Make due now every target a title asked for.
 * @targets: The targets.
 * @count: Number of @targets.
 * @now_ms: Now, on the monotonic clock.
 *
 * Clears each request it serves, so a request wakes the loop once.
 *
 * Return: true when a target was made due.
 */
bool attest_targets_take_wakeups(struct attest_target *targets, size_t count,
				 uint64_t now_ms);

/**
 * attest_target_reports() - Whether this round sends a report for @t.
 * @t: The target.
 *
 * A token-only publisher holds no verdict here, and a session-gated one is
 * reported to only with a title of theirs running. Enrollment and
 * certificate renewal do not depend on this answer.
 *
 * Return: true when a report goes out.
 */
static inline bool attest_target_reports(const struct attest_target *t)
{
	if (!t || t->token_only)
		return false;

	return !t->session_gated || t->sessions > 0;
}

/**
 * attest_targets_rebuild() - Rebuild the list from a configuration.
 * @cfg: The configuration.
 * @server: As attest_targets_build().
 * @port: As attest_targets_build().
 * @ca_cert: As attest_targets_build().
 * @interval_sec: As attest_targets_build().
 * @targets: The list; a target still configured keeps its verdict, schedule,
 *           failure state and session count.
 * @max: Capacity of @targets.
 * @count: Length of @targets.
 *
 * Return: 0, the list empty when neither @cfg nor @server names a target,
 * or a negative errno with @targets untouched.
 */
int attest_targets_rebuild(const struct lota_config *cfg, const char *server,
			   int port, const char *ca_cert, int interval_sec,
			   struct attest_target *targets, size_t max,
			   size_t *count);

/**
 * attest_targets_reload() - Re-read the configuration and rebuild the list.
 * @config_path: The configuration file.
 * @server: As attest_targets_build().
 * @port: As attest_targets_build().
 * @ca_cert: As attest_targets_build().
 * @interval_sec: As attest_targets_build().
 * @pinned: The loop pins @server's certificate.
 * @targets: As attest_targets_rebuild().
 * @max: Capacity of @targets.
 * @count: Length of @targets.
 *
 * Return: as attest_targets_rebuild(), -ENOTUNIQ when @pinned and the file
 * configures profiles, or a negative errno with @targets untouched when the
 * file does not load.
 */
int attest_targets_reload(const char *config_path, const char *server, int port,
			  const char *ca_cert, int interval_sec, bool pinned,
			  struct attest_target *targets, size_t max,
			  size_t *count);

/**
 * attest_target_should_announce_wait() - Time to say @t waits for a title?
 * @t: The target; records the answer.
 *
 * Return: true once for a session-gated target that is not token-only and has
 * no session; a reload re-arms it.
 */
bool attest_target_should_announce_wait(struct attest_target *t);

/**
 * attest_targets_build() - Build the target list.
 * @cfg: Each configured profile is one target.
 * @server: The only target when @cfg configures no profile.
 * @port: Port of @server.
 * @ca_cert: Trust anchor of @server.
 * @interval_sec: Cadence of a target that states none.
 * @out: The list.
 * @max: Capacity of @out.
 * @count: Length of @out.
 *
 * Return: 0, -EINVAL on a missing or empty single-target server or a bad
 * argument, or -E2BIG when @max cannot hold every configured profile.
 */
int attest_targets_build(const struct lota_config *cfg, const char *server,
			 int port, const char *ca_cert, int interval_sec,
			 struct attest_target *out, size_t max, size_t *count);

#endif /* LOTA_AGENT_ATTEST_TARGETS_H */
