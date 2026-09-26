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
	to->attested = from->attested;
	to->valid_until = from->valid_until;
	to->auto_renew = from->auto_renew;
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

		if (out[i].token_only)
			snprintf(out[i].label, sizeof(out[i].label),
				 "token-only publisher enrolled at %s:%d",
				 out[i].ca, out[i].ca_port);
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
