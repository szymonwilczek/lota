/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * IMA appraisal scope check.
 *
 * Appraisal applies only to the rules of the loaded policy, so a measure-only
 * policy under ima_appraise=enforce blocks nothing.
 */
#ifndef LOTA_IMA_POLICY_SCOPE_H
#define LOTA_IMA_POLICY_SCOPE_H

#include <string.h>

/* Longest policy rule line the predicate reads; a longer one is no match */
#define LOTA_IMA_POLICY_RULE_MAX 512

/**
 * lota_ima_policy_rule_appraises_exec() - Test a policy rule for exec coverage.
 * @rule: one policy line.
 *
 * Reads only the action and the first func=. Other hooks that run during exec
 * (FILE_CHECK, MMAP_CHECK, CREDS_CHECK) do not count, and conditions such as
 * fowner= and earlier dont_appraise rules are not read, so the answer proves
 * nothing about one given executable.
 *
 * Return: 1 for an appraise rule on BPRM_CHECK or with no func=, 0 otherwise.
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

/**
 * lota_ima_scope_is_advisory() - Test whether exec appraisal may be missing.
 * @agent_verity_bound: the agent binary has fs-verity enabled.
 *
 * fs-verity on the binary passes the immutability gate alone. Without it, the
 * gate rests on a signed security.ima xattr, which means nothing unless
 * appraised.
 *
 * Return: 1 if a kernel that appraises no executable is advisory, 0 otherwise.
 */
static inline int lota_ima_scope_is_advisory(int agent_verity_bound)
{
	return agent_verity_bound ? 1 : 0;
}

#endif /* LOTA_IMA_POLICY_SCOPE_H */
