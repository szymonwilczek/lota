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
#include <string.h>

#include "attest_targets.h"

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
