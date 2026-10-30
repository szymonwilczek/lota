/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Attestation target list.
 * See attest_targets.h for what a target is.
 *
 * No logging and no TPM here: the loop reports what this produced, including
 * the reason anchor yielded no profile, so the list itself stays testable.
 */

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "attest_targets.h"

bool attest_target_should_announce_wait(struct attest_target *t)
{
	if (!t || !t->session_gated || t->token_only)
		return false;
	if (t->sessions > 0 || t->wait_announced)
		return false;

	t->wait_announced = true;
	return true;
}

enum attest_renew_say attest_target_resolve_renew(struct attest_target *t,
						  const char *rec_server,
						  int rec_port)
{
	bool was;

	if (!t)
		return ATTEST_RENEW_SILENT;

	was = t->auto_renew;
	t->auto_renew = t->has_profile && rec_server && rec_server[0];

	/*
	 * No stale endpoint on a target that cannot renew;
	 * a changed endpoint is logged again.
	 */
	if (t->auto_renew) {
		if (strcmp(t->renew_ca, rec_server) != 0 ||
		    t->renew_ca_port != rec_port)
			t->renew_move_announced = false;
		snprintf(t->renew_ca, sizeof(t->renew_ca), "%s", rec_server);
		t->renew_ca_port = rec_port;
	} else {
		t->renew_ca[0] = '\0';
		t->renew_ca_port = 0;
		t->renew_move_announced = false;
	}

	if (t->auto_renew == was && t->renew_announced)
		return ATTEST_RENEW_SILENT;

	t->renew_announced = true;
	return t->auto_renew ? ATTEST_RENEW_ENABLED : ATTEST_RENEW_OFF;
}

const char *attest_target_renew_at(const struct attest_target *t, char *buf,
				   size_t len)
{
	if (!buf || len == 0)
		return "";

	buf[0] = '\0';
	if (!t || !t->auto_renew)
		return buf;

	/* the label already names it */
	if (t->token_only && strcmp(t->ca, t->renew_ca) == 0 &&
	    t->ca_port == t->renew_ca_port)
		return buf;

	snprintf(buf, len, ", renewing at %s:%d", t->renew_ca,
		 t->renew_ca_port);
	return buf;
}

bool attest_target_should_announce_renew_move(struct attest_target *t)
{
	bool differs;

	/* nothing to compare: no renewal, or no CA configured for one */
	if (!t || !t->auto_renew || t->ca[0] == '\0')
		return false;

	differs = strcmp(t->ca, t->renew_ca) != 0 ||
		  t->ca_port != t->renew_ca_port;
	if (!differs) {
		t->renew_move_announced = false;
		return false;
	}
	if (t->renew_move_announced)
		return false;

	t->renew_move_announced = true;
	return true;
}

/*
 * Same publisher as before the reload.
 *
 * The identity is the trust anchor's key, so a publisher that moved its CA
 * or its verifier is still the one this list was holding state for.
 * A target without a profile has no identity to compare and falls back to
 * where it reports.
 */
static bool same_target(const struct attest_target *a,
			const struct attest_target *b)
{
	if (a->has_profile && b->has_profile)
		return strcmp(a->paths.id, b->paths.id) == 0;
	if (a->has_profile != b->has_profile)
		return false;
	return strcmp(a->server, b->server) == 0 && a->port == b->port;
}

/* What the loop knows and the file does not: the schedule,
 * the failure state and the session count the IPC layer maintains here */
static void carry_live_state(struct attest_target *to,
			     const struct attest_target *from)
{
	to->sessions = from->sessions;
	to->session_changed = from->session_changed;
	to->next_due_ms = from->next_due_ms;
	to->consecutive_failures = from->consecutive_failures;
	to->backoff_sec = from->backoff_sec;
	to->last_success = from->last_success;
	to->key_mismatch_announced = from->key_mismatch_announced;
	to->auth_fail_announced = from->auth_fail_announced;
	to->shared_key_announced = from->shared_key_announced;
	to->attested = from->attested;
	to->valid_until = from->valid_until;
	to->auto_renew = from->auto_renew;
	to->renew_announced = from->renew_announced;
	/* not renew_move_announced: a reload may change the configured CA */
	to->renew_backoff = from->renew_backoff;
	to->next_renew_ms = from->next_renew_ms;
	to->enroll_pending = from->enroll_pending;
	to->enroll_backoff = from->enroll_backoff;
	to->next_enroll_ms = from->next_enroll_ms;
}

int attest_targets_reload(const char *config_path, const char *server, int port,
			  const char *ca_cert, int interval_sec,
			  struct attest_target *targets, size_t max,
			  size_t *count)
{
	struct lota_config *fresh;
	struct attest_target *rebuilt;
	size_t n = 0;
	int ret;

	if (!config_path || !targets || !count || max == 0)
		return -EINVAL;

	/* Both are far too large for this frame, and neither may touch what
	 * the loop is using until the whole rebuild has succeeded */
	fresh = config_new();
	rebuilt = calloc(max, sizeof(*rebuilt));
	if (!fresh || !rebuilt) {
		ret = -ENOMEM;
		goto out;
	}

	ret = config_load(fresh, config_path);
	if (ret < 0)
		goto out;

	ret = attest_targets_build(fresh, server, port, ca_cert, interval_sec,
				   rebuilt, max, &n);
	if (ret < 0) {
		/*
		 * A file that names no publisher and no single verifier is
		 * an operator with nothing configured, which is a state
		 * and not a failure.
		 * Every other error leaves the list alone.
		 */
		if (ret != -EINVAL)
			goto out;
		n = 0;
	}

	for (size_t i = 0; i < n; i++) {
		for (size_t j = 0; j < *count; j++) {
			if (!same_target(&rebuilt[i], &targets[j]))
				continue;
			carry_live_state(&rebuilt[i], &targets[j]);
			break;
		}
	}

	memcpy(targets, rebuilt, max * sizeof(*rebuilt));
	*count = n;
	ret = 0;

out:
	config_free(fresh);
	free(rebuilt);
	return ret;
}

int attest_targets_build(const struct lota_config *cfg, const char *server,
			 int port, const char *ca_cert, int interval_sec,
			 struct attest_target *out, size_t max, size_t *count)
{
	size_t n = 0;

	if (!out || !count || max == 0)
		return -EINVAL;

	memset(out, 0, max * sizeof(*out));
	*count = 0;

	if (cfg && cfg->profile_count > 0) {
		if ((size_t)cfg->profile_count > max)
			return -E2BIG;

		for (int i = 0; i < cfg->profile_count; i++) {
			const struct lota_profile *p = &cfg->profiles[i];

			snprintf(out[n].server, sizeof(out[n].server), "%s",
				 p->verifier);
			out[n].port = p->verifier_port;
			snprintf(out[n].ca_cert, sizeof(out[n].ca_cert), "%s",
				 p->ca_cert);
			snprintf(out[n].ca, sizeof(out[n].ca), "%s", p->ca);
			out[n].ca_port = p->ca_port;
			out[n].token_only = p->token_only;
			out[n].session_gated = p->session_gated;
			out[n].has_pin =
				p->pin_sha256[0] &&
				lota_pin_sha256_parse(p->pin_sha256,
						      out[n].pin_sha256) == 0;
			/* profile without its own cadence keeps the host's */
			out[n].interval = p->attest_interval ?
						  p->attest_interval :
						  interval_sec;
			n++;
		}
	} else {
		if (!server)
			return -EINVAL;

		snprintf(out[n].server, sizeof(out[n].server), "%s", server);
		out[n].port = port;
		if (ca_cert)
			snprintf(out[n].ca_cert, sizeof(out[n].ca_cert), "%s",
				 ca_cert);
		out[n].interval = interval_sec;
		out[n].session_gated = false;
		n++;
	}

	for (size_t i = 0; i < n; i++) {
		int ret;

		/*
		 * Label from the configuration only; the enrolled endpoint
		 * lives in the --enroll record, which this list never reads.
		 */
		if (out[i].token_only)
			snprintf(out[i].label, sizeof(out[i].label),
				 "token-only publisher at CA %s:%d", out[i].ca,
				 out[i].ca_port);
		else
			snprintf(out[i].label, sizeof(out[i].label), "%s:%d",
				 out[i].server, out[i].port);

		if (out[i].ca_cert[0] == '\0')
			continue; /* no anchor, so no publisher profile */

		ret = profile_paths_from_anchor(out[i].ca_cert, &out[i].paths);
		if (ret == 0)
			out[i].has_profile = true;
		else
			out[i].profile_error = ret;
	}

	*count = n;
	return 0;
}
