/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * IMA appraisal scope check.
 *
 * ima_appraise= on the cmdline is not enough: appraisal applies only to
 * the func= rules in the loaded policy, so a measure-only policy under
 * ima_appraise=enforce blocks nothing.
 *
 * Without fs-verity on the agent binary, the agent refuses to start if no
 * rule appraises executables. The installer uses the same rules from here,
 * so it cannot pass a host the agent refuses.
 */
#ifndef LOTA_IMA_POLICY_SCOPE_H
#define LOTA_IMA_POLICY_SCOPE_H

#include <string.h>

/* Longest policy rule line the predicate reads; a longer one is no match */
#define LOTA_IMA_POLICY_RULE_MAX 512

/*
 * Return 1 if @rule appraises executables.
 *
 * Appraise rule without func= covers every hook, exec included.
 * With func=, only BPRM_CHECK covers exec.
 * dont_appraise is an exclusion, not appraisal.
 */
static inline int lota_ima_policy_rule_appraises_exec(const char *rule)
{
	char buf[LOTA_IMA_POLICY_RULE_MAX];
	char *save = NULL;
	char *tok;
	size_t len;

	if (!rule)
		return 0;
	len = strlen(rule);
	if (len >= sizeof(buf))
		return 0;
	memcpy(buf, rule, len + 1);

	tok = strtok_r(buf, " \t\n", &save);
	if (!tok || strcmp(tok, "appraise") != 0)
		return 0;

	while ((tok = strtok_r(NULL, " \t\n", &save))) {
		if (strncmp(tok, "func=", 5) != 0)
			continue;
		return strcmp(tok + 5, "BPRM_CHECK") == 0;
	}
	return 1;
}

/*
 * Return 1 if a kernel that appraises no executable is advisory.
 *
 * With fs-verity and PCR 14 binding the agent binary, appraisal only adds
 * coverage of the rest of the host. Without verity, a signed security.ima
 * xattr is the only binding and means nothing unless appraised.
 */
static inline int lota_ima_scope_is_advisory(int agent_verity_bound)
{
	return agent_verity_bound ? 1 : 0;
}

#endif /* LOTA_IMA_POLICY_SCOPE_H */
