/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for the attestation target list (attest_targets.c).
 *
 * The list decides who a host reports to and how often, so what is pinned here
 * is that a configured publisher list replaces the single verifier rather than
 * being added to it, that a profile keeps its own cadence, and that a target
 * whose anchor cannot be read still reports -- without claiming profile it does
 * not have.
 *
 * No TPM and no network: only the config struct and the profile layout.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/types.h>
#include <openssl/x509.h>

#include "../include/lota_server.h"
#include "../src/agent/attest.h"
#include "../src/agent/attest_targets.h"

#include "test.h"

/* self-signed anchor, so target can resolve real profile identity */
static int write_anchor(const char *path)
{
	EVP_PKEY *pkey = EVP_EC_gen("P-256");
	uint8_t *der = NULL;
	X509_NAME *name;
	X509 *x = NULL;
	int len, fd, ret = -1;

	if (!pkey)
		goto out;
	x = X509_new();
	if (!x)
		goto out;

	X509_set_version(x, 2);
	ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
	X509_gmtime_adj(X509_getm_notBefore(x), 0);
	X509_gmtime_adj(X509_getm_notAfter(x), 3600);
	X509_set_pubkey(x, pkey);
	name = X509_get_subject_name(x);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
				   (const unsigned char *)"lota-test", -1, -1,
				   0);
	X509_set_issuer_name(x, name);
	if (!X509_sign(x, pkey, EVP_sha256()))
		goto out;

	len = i2d_X509(x, &der);
	if (len <= 0)
		goto out;

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0)
		goto out;
	if (write(fd, der, (size_t)len) == (ssize_t)len)
		ret = 0;
	close(fd);

out:
	OPENSSL_free(der);
	X509_free(x);
	EVP_PKEY_free(pkey);
	return ret;
}

static void test_single_verifier(void)
{
	struct attest_target targets[LOTA_CONFIG_MAX_PROFILES];
	struct lota_config cfg;
	size_t count = 0;

	memset(&cfg, 0, sizeof(cfg));

	TEST("no profiles leaves the single verifier as the only target");
	if (!(attest_targets_build(&cfg, "verifier.example", 8443, NULL, 300,
				   targets, LOTA_CONFIG_MAX_PROFILES,
				   &count) == 0 &&
	      count == 1))
		FAIL("expected: attest_targets_build(&cfg, "
		     "\"verifier.example\", 8443, NULL, 300, targets, "
		     "LOTA_CONFIG_MAX_PROFILES, &count) == 0 && count == 1");
	TEST("the single target carries the caller's endpoint and cadence");
	if (!(strcmp(targets[0].server, "verifier.example") == 0 &&
	      targets[0].port == 8443 && targets[0].interval == 300))
		FAIL("expected: strcmp(targets[0].server, "
		     "\"verifier.example\") == 0 && targets[0].port == 8443 "
		     "&& targets[0].interval == 300");
	TEST("no anchor is not an error, it is a host without a publisher");
	if (!(!targets[0].has_profile && targets[0].profile_error == 0))
		FAIL("expected: !targets[0].has_profile && "
		     "targets[0].profile_error == 0");
	TEST("the single verifier keeps the continuous stream it always had");
	if (targets[0].session_gated)
		FAIL("expected: !targets[0].session_gated");
	TEST("the target names itself the way its log lines will");
	if (strcmp(targets[0].label, "verifier.example:8443") != 0)
		FAIL("expected: strcmp(targets[0].label, "
		     "\"verifier.example:8443\") == 0");

	TEST("a single target with no verifier is refused");
	if (attest_targets_build(&cfg, NULL, 8443, NULL, 300, targets,
				 LOTA_CONFIG_MAX_PROFILES, &count) != -EINVAL)
		FAIL("expected: attest_targets_build(&cfg, NULL, 8443, NULL, "
		     "300, targets, LOTA_CONFIG_MAX_PROFILES, &count) == "
		     "-EINVAL");
	/* what the CLI hands over when neither a file nor --server named one */
	TEST("an empty verifier name is no verifier either");
	if (attest_targets_build(&cfg, "", 8443, NULL, 300, targets,
				 LOTA_CONFIG_MAX_PROFILES, &count) != -EINVAL)
		FAIL("expected: attest_targets_build(&cfg, \"\", 8443, NULL, "
		     "300, targets, LOTA_CONFIG_MAX_PROFILES, &count) == "
		     "-EINVAL");

	/* NULL config is the same case as config with no profiles */
	TEST("no config at all still yields the single target");
	if (!(attest_targets_build(NULL, "verifier.example", 8443, NULL, 300,
				   targets, LOTA_CONFIG_MAX_PROFILES,
				   &count) == 0 &&
	      count == 1))
		FAIL("expected: attest_targets_build(NULL, "
		     "\"verifier.example\", 8443, NULL, 300, targets, "
		     "LOTA_CONFIG_MAX_PROFILES, &count) == 0 && count == 1");
}

static void test_profiles_replace_the_single_verifier(void)
{
	struct attest_target targets[LOTA_CONFIG_MAX_PROFILES];
	char anchor[256];
	struct lota_config cfg;
	size_t count = 0;

	snprintf(anchor, sizeof(anchor), "/tmp/lota-targets-anchor.%d.der",
		 getpid());
	if (write_anchor(anchor) != 0) {
		TEST("write an anchor");
		if (!0)
			FAIL("expected: 0");
		return;
	}

	memset(&cfg, 0, sizeof(cfg));
	cfg.profile_count = 2;
	snprintf(cfg.profiles[0].name, sizeof(cfg.profiles[0].name), "%s",
		 "publisher-a");
	snprintf(cfg.profiles[0].verifier, sizeof(cfg.profiles[0].verifier),
		 "%s", "a.example");
	cfg.profiles[0].verifier_port = 8443;
	snprintf(cfg.profiles[0].ca_cert, sizeof(cfg.profiles[0].ca_cert), "%s",
		 anchor);
	snprintf(cfg.profiles[0].ca, sizeof(cfg.profiles[0].ca), "%s",
		 "ca.a.example");
	cfg.profiles[0].ca_port = 8444;
	cfg.profiles[0].attest_interval = 60;
	cfg.profiles[0].session_gated = true;

	snprintf(cfg.profiles[1].name, sizeof(cfg.profiles[1].name), "%s",
		 "publisher-b");
	snprintf(cfg.profiles[1].verifier, sizeof(cfg.profiles[1].verifier),
		 "%s", "b.example");
	cfg.profiles[1].verifier_port = 9443;
	snprintf(cfg.profiles[1].ca_cert, sizeof(cfg.profiles[1].ca_cert), "%s",
		 "/tmp/lota-targets-absent.XXXXXX");
	/* profile B states no cadence and inherits the host's */
	cfg.profiles[1].attest_interval = 0;

	TEST("the profile list is the target list");
	if (!(attest_targets_build(&cfg, "host-level.example", 1234, NULL, 300,
				   targets, LOTA_CONFIG_MAX_PROFILES,
				   &count) == 0 &&
	      count == 2))
		FAIL("expected: attest_targets_build(&cfg, "
		     "\"host-level.example\", 1234, NULL, 300, targets, "
		     "LOTA_CONFIG_MAX_PROFILES, &count) == 0 && count == 2");
	TEST("the host-level verifier is replaced, not added to");
	if (!(strcmp(targets[0].server, "a.example") == 0 &&
	      targets[0].port == 8443 &&
	      strcmp(targets[1].server, "b.example") == 0 &&
	      targets[1].port == 9443))
		FAIL("expected: strcmp(targets[0].server, \"a.example\") == 0 "
		     "&& targets[0].port == 8443 && strcmp(targets[1].server, "
		     "\"b.example\") == 0 && targets[1].port == 9443");
	TEST("a profile keeps the cadence it states");
	if (targets[0].interval != 60)
		FAIL("expected: targets[0].interval == 60");
	TEST("a profile that states none inherits the host's");
	if (targets[1].interval != 300)
		FAIL("expected: targets[1].interval == 300");

	TEST("a readable anchor resolves the publisher profile");
	if (!(targets[0].has_profile && targets[0].profile_error == 0 &&
	      strlen(targets[0].paths.id) == LOTA_PROFILE_ID_LEN - 1))
		FAIL("expected: targets[0].has_profile && "
		     "targets[0].profile_error == 0 && "
		     "strlen(targets[0].paths.id) == LOTA_PROFILE_ID_LEN - 1");
	TEST("an unreadable anchor reports and says why it has no profile");
	if (!(!targets[1].has_profile && targets[1].profile_error == -ENOENT))
		FAIL("expected: !targets[1].has_profile && "
		     "targets[1].profile_error == -ENOENT");

	/*
	 * CA travels with the target because enrollment is runtime action:
	 * host that meets publisher for the first time while title is running
	 * has to know where to enroll without being told again.
	 */
	TEST("a target carries the CA its publisher enrolls against");
	if (!(strcmp(targets[0].ca, "ca.a.example") == 0 &&
	      targets[0].ca_port == 8444))
		FAIL("expected: strcmp(targets[0].ca, \"ca.a.example\") == 0 "
		     "&& targets[0].ca_port == 8444");
	TEST("a profile that names no CA carries none");
	if (targets[1].ca[0] != '\0')
		FAIL("expected: targets[1].ca[0] == '\\0'");

	/*
	 * Reporting is exfiltration, so publisher gets it only while title of
	 * theirs runs.
	 * Fleet that wants the continuous stream says so per profile;
	 * the single-verifier path keeps it, because that is the deployment
	 * the stream was the feature for
	 */
	TEST("each profile carries its own reporting mode");
	if (!(targets[0].session_gated && !targets[1].session_gated))
		FAIL("expected: targets[0].session_gated && "
		     "!targets[1].session_gated");

	unlink(anchor);
}

/*
 * Publisher who verifies tokens in their own backend runs no verifier here.
 * The target still exists: it enrolls, it holds the AIK a token is signed with,
 * and that key's certificate has to keep being renewed.
 * What it never does is report.
 */
static void test_token_only_publisher(void)
{
	struct attest_target targets[LOTA_CONFIG_MAX_PROFILES];
	struct lota_config cfg;
	size_t count = 0;

	memset(&cfg, 0, sizeof(cfg));
	cfg.profile_count = 1;
	snprintf(cfg.profiles[0].name, sizeof(cfg.profiles[0].name), "%s",
		 "publisher-light");
	snprintf(cfg.profiles[0].ca, sizeof(cfg.profiles[0].ca), "%s",
		 "ca.light.example");
	cfg.profiles[0].ca_port = 8444;
	snprintf(cfg.profiles[0].ca_cert, sizeof(cfg.profiles[0].ca_cert), "%s",
		 "/tmp/lota-targets-absent.XXXXXX");
	cfg.profiles[0].token_only = true;

	TEST("a publisher with no verifier is still a target");
	if (!(attest_targets_build(&cfg, "host-level.example", 1234, NULL, 300,
				   targets, LOTA_CONFIG_MAX_PROFILES,
				   &count) == 0 &&
	      count == 1))
		FAIL("expected: attest_targets_build(&cfg, "
		     "\"host-level.example\", 1234, NULL, 300, targets, "
		     "LOTA_CONFIG_MAX_PROFILES, &count) == 0 && count == 1");
	TEST("the target says it reports to nobody and names no verifier");
	if (!(targets[0].token_only && targets[0].server[0] == '\0'))
		FAIL("expected: targets[0].token_only && targets[0].server[0] "
		     "== '\\0'");
	TEST("the CA it enrolls against travels with it, as renewal goes on");
	if (!(strcmp(targets[0].ca, "ca.light.example") == 0 &&
	      targets[0].ca_port == 8444))
		FAIL("expected: strcmp(targets[0].ca, \"ca.light.example\") "
		     "== 0 && targets[0].ca_port == 8444");
	TEST("its log lines name the CA, there being no verifier to name");
	if (strstr(targets[0].label, "ca.light.example:8444") == NULL)
		FAIL("expected: strstr(targets[0].label, "
		     "\"ca.light.example:8444\") != NULL");
	TEST("the label names the CA without claiming the host enrolled there");
	if (strstr(targets[0].label, "enrolled") != NULL)
		FAIL("expected: strstr(targets[0].label, \"enrolled\") == NULL");
}

static void test_more_profiles_than_room(void)
{
	struct attest_target targets[2];
	struct lota_config cfg;
	size_t count = 0;

	memset(&cfg, 0, sizeof(cfg));
	cfg.profile_count = 3;
	for (int i = 0; i < 3; i++) {
		snprintf(cfg.profiles[i].verifier,
			 sizeof(cfg.profiles[i].verifier), "v%d.example", i);
		cfg.profiles[i].verifier_port = 8443;
	}

	TEST("a list that does not fit is refused rather than truncated");
	if (!(attest_targets_build(&cfg, NULL, 0, NULL, 300, targets, 2,
				   &count) == -E2BIG &&
	      count == 0))
		FAIL("expected: attest_targets_build(&cfg, NULL, 0, NULL, "
		     "300, targets, 2, &count) == -E2BIG && count == 0");
}

/*
 * Configured publisher list has to be attested to.
 * The cadence is what decides whether the loop runs at all, so host that named
 * publishers and no interval must not fall through to the single-verifier
 * one-shot -- that path has no target list and reports to a verifier a consumer
 * install never set.
 */
static void test_effective_interval(void)
{
	TEST("a single verifier and no interval stays a one-shot");
	if (attest_effective_interval(0, 0, true) != 0)
		FAIL("expected: attest_effective_interval(0, 0, true) == 0");
	TEST("naming nothing runs the loop, which waits for a publisher");
	if (attest_effective_interval(0, 0, false) != DEFAULT_ATTEST_INTERVAL)
		FAIL("expected: attest_effective_interval(0, 0, false) == "
		     "DEFAULT_ATTEST_INTERVAL");
	TEST("one publisher and no interval attests at the default cadence");
	if (attest_effective_interval(0, 1, false) != DEFAULT_ATTEST_INTERVAL)
		FAIL("expected: attest_effective_interval(0, 1, false) == "
		     "DEFAULT_ATTEST_INTERVAL");
	TEST("several publishers and no interval do the same");
	if (attest_effective_interval(0, 8, true) != DEFAULT_ATTEST_INTERVAL)
		FAIL("expected: attest_effective_interval(0, 8, true) == "
		     "DEFAULT_ATTEST_INTERVAL");
	TEST("a configured cadence wins over the default");
	if (attest_effective_interval(45, 3, false) != 45)
		FAIL("expected: attest_effective_interval(45, 3, false) == 45");
	TEST("a configured cadence runs the loop without profiles too");
	if (attest_effective_interval(45, 0, true) != 45)
		FAIL("expected: attest_effective_interval(45, 0, true) == 45");
}

/* A verifier whose clock runs behind still accepts the latest token. */
_Static_assert(MAX_ATTEST_INTERVAL + ATTEST_TOKEN_VALIDITY_SLACK_SEC +
			       LOTA_SERVER_MAX_CLOCK_SKEW_SEC <=
		       LOTA_SERVER_MAX_TOKEN_AGE_SEC +
			       LOTA_SERVER_MAX_CLOCK_SKEW_SEC,
	       "a token at the ceiling passes a verifier a full skew behind");

/*
 * A deployment (continuous attestation, lota-attest.service) must not take
 * the overrides: every round would quote against whatever the environment
 * named.
 */
static void test_env_overrides_stop_at_the_deployment(void)
{
	TEST("a verb that is not --attest is interactive");
	if (!attest_env_overrides_allowed(0, 0, 0, false))
		FAIL("expected: attest_env_overrides_allowed(0, 0, 0, false)");
	TEST("--attest to a verifier with no cadence or publisher is one-shot");
	if (!attest_env_overrides_allowed(1, 0, 0, true))
		FAIL("expected: attest_env_overrides_allowed(1, 0, 0, true)");
	TEST("--attest that names nothing is the loop, so overrides stop");
	if (attest_env_overrides_allowed(1, 0, 0, false))
		FAIL("expected: !attest_env_overrides_allowed(1, 0, 0, false)");
	TEST("one publisher and no interval is the loop, so overrides stop");
	if (attest_env_overrides_allowed(1, 0, 1, true))
		FAIL("expected: !attest_env_overrides_allowed(1, 0, 1, true)");
	TEST("a configured cadence is the loop without publishers too");
	if (attest_env_overrides_allowed(1, 45, 0, true))
		FAIL("expected: !attest_env_overrides_allowed(1, 45, 0, true)");
	TEST("the deployed shape takes neither variable");
	if (attest_env_overrides_allowed(1, 45, 3, false))
		FAIL("expected: !attest_env_overrides_allowed(1, 45, 3, false)");
}

/*
 * The two gates that decide whether a round reports.
 * Neither may gate the round's enrollment: session-gated publisher that has
 * never enrolled cannot be selected by a title (SET_PROFILE refuses one),
 * so waiting for session before enrolling would leave that profile unreachable
 * for good.
 */
static void test_target_reports(void)
{
	struct attest_target t;

	memset(&t, 0, sizeof(t));
	TEST("a plain publisher is reported to every round");
	if (!attest_target_reports(&t))
		FAIL("expected: attest_target_reports(&t)");

	memset(&t, 0, sizeof(t));
	t.token_only = true;
	TEST("a publisher who runs no verifier is never reported to");
	if (attest_target_reports(&t))
		FAIL("expected: !attest_target_reports(&t)");

	memset(&t, 0, sizeof(t));
	t.session_gated = true;
	t.sessions = 0;
	TEST("a session-gated publisher with no title running gets no report");
	if (attest_target_reports(&t))
		FAIL("expected: !attest_target_reports(&t)");

	t.sessions = 1;
	TEST("the same publisher is reported to while a title of theirs runs");
	if (!attest_target_reports(&t))
		FAIL("expected: attest_target_reports(&t)");

	memset(&t, 0, sizeof(t));
	t.token_only = true;
	t.session_gated = true;
	t.sessions = 3;
	TEST("running no verifier outranks a live session");
	if (attest_target_reports(&t))
		FAIL("expected: !attest_target_reports(&t)");

	TEST("no target is reported to");
	if (attest_target_reports(NULL))
		FAIL("expected: !attest_target_reports(NULL)");
}

/*
 * A publisher that gates on a session and has never had one is the case that
 * reads as a hang.
 *
 * "--attest" says it performs an attestation and exits. With publisher
 * profiles configured it runs the loop instead -- deliberately, because
 * a one-shot against the single top-level verifier would leave every
 * configured publisher unattested -- and on the shipped consumer default,
 * which is session-gated, the loop then reports to nobody until a title
 * starts.
 * The target already announces the end of a session. The start of waiting
 * for the first one is what it never said, and the two are told apart by
 * whether this target has ever been attested to.
 */
static void test_wait_for_a_first_session_is_announced(void)
{
	struct attest_target t;

	memset(&t, 0, sizeof(t));
	t.session_gated = true;
	t.sessions = 0;

	TEST("a session-gated target with no session yet says so");
	if (!attest_target_should_announce_wait(&t))
		FAIL("expected: attest_target_should_announce_wait(&t)");
	TEST("and says it once, not every round");
	if (attest_target_should_announce_wait(&t))
		FAIL("expected: !attest_target_should_announce_wait(&t)");

	memset(&t, 0, sizeof(t));
	t.session_gated = true;
	t.sessions = 1;
	TEST("a target with a live session is not waiting for one");
	if (attest_target_should_announce_wait(&t))
		FAIL("expected: !attest_target_should_announce_wait(&t)");

	memset(&t, 0, sizeof(t));
	t.sessions = 0;
	TEST("a publisher that does not gate on sessions is not waiting");
	if (attest_target_should_announce_wait(&t))
		FAIL("expected: !attest_target_should_announce_wait(&t)");

	memset(&t, 0, sizeof(t));
	t.session_gated = true;
	t.token_only = true;
	TEST("a publisher who runs no verifier is not waiting to report");
	if (attest_target_should_announce_wait(&t))
		FAIL("expected: !attest_target_should_announce_wait(&t)");

	TEST("no target is waiting");
	if (attest_target_should_announce_wait(NULL))
		FAIL("expected: !attest_target_should_announce_wait(NULL)");
}

/* an enrollment record that appears at runtime enables renewal */
static void test_renewal_follows_the_record(void)
{
	struct attest_target t;

	memset(&t, 0, sizeof(t));
	t.has_profile = true;

	TEST("a publisher with no enrollment record cannot renew unattended");
	if (!(attest_target_resolve_renew(&t, NULL, 0) == ATTEST_RENEW_OFF &&
	      !t.auto_renew))
		FAIL("expected: attest_target_resolve_renew(&t, NULL, 0) == "
		     "ATTEST_RENEW_OFF && !t.auto_renew");
	TEST("and is told so once, not on every pass");
	if (attest_target_resolve_renew(&t, NULL, 0) != ATTEST_RENEW_SILENT)
		FAIL("expected: attest_target_resolve_renew(&t, NULL, 0) == "
		     "ATTEST_RENEW_SILENT");

	TEST("a record that appears mid-loop enables renewal with no reload");
	if (!(attest_target_resolve_renew(&t, "ca.example", 8444) ==
		      ATTEST_RENEW_ENABLED &&
	      t.auto_renew))
		FAIL("expected: attest_target_resolve_renew(&t, "
		     "\"ca.example\", 8444) == ATTEST_RENEW_ENABLED && "
		     "t.auto_renew");
	TEST("the target carries the endpoint that renewal will dial");
	if (!(strcmp(t.renew_ca, "ca.example") == 0 && t.renew_ca_port == 8444))
		FAIL("expected: strcmp(t.renew_ca, \"ca.example\") == 0 && "
		     "t.renew_ca_port == 8444");
	TEST("a decision that has not changed says nothing");
	if (attest_target_resolve_renew(&t, "ca.example", 8444) !=
	    ATTEST_RENEW_SILENT)
		FAIL("expected: attest_target_resolve_renew(&t, "
		     "\"ca.example\", 8444) == ATTEST_RENEW_SILENT");

	TEST("a record that goes away disables renewal and leaves no address");
	if (!(attest_target_resolve_renew(&t, NULL, 0) == ATTEST_RENEW_OFF &&
	      !t.auto_renew && t.renew_ca[0] == '\0'))
		FAIL("expected: attest_target_resolve_renew(&t, NULL, 0) == "
		     "ATTEST_RENEW_OFF && !t.auto_renew && t.renew_ca[0] == "
		     "'\\0'");

	memset(&t, 0, sizeof(t));
	TEST("a target with no publisher profile has no certificate to renew");
	if (!(attest_target_resolve_renew(&t, "ca.example", 8444) ==
		      ATTEST_RENEW_OFF &&
	      !t.auto_renew))
		FAIL("expected: attest_target_resolve_renew(&t, "
		     "\"ca.example\", 8444) == ATTEST_RENEW_OFF && "
		     "!t.auto_renew");

	TEST("no target, nothing to decide");
	if (attest_target_resolve_renew(NULL, "ca.example", 8444) !=
	    ATTEST_RENEW_SILENT)
		FAIL("expected: attest_target_resolve_renew(NULL, "
		     "\"ca.example\", 8444) == ATTEST_RENEW_SILENT");
}

/* a configured CA that differs from the recorded endpoint is reported once */
static void test_a_moved_ca_is_reported(void)
{
	struct attest_target t;

	memset(&t, 0, sizeof(t));
	t.has_profile = true;
	snprintf(t.ca, sizeof(t.ca), "%s", "ca.example");
	t.ca_port = 8444;

	attest_target_resolve_renew(&t, "ca.example", 8444);
	TEST("a profile enrolled where it is configured has nothing to say");
	if (attest_target_should_announce_renew_move(&t))
		FAIL("expected: !attest_target_should_announce_renew_move(&t)");

	attest_target_resolve_renew(&t, "old-ca.example", 8444);
	TEST("a record naming another host is reported");
	if (!attest_target_should_announce_renew_move(&t))
		FAIL("expected: attest_target_should_announce_renew_move(&t)");
	TEST("and reported once, not on every pass");
	if (attest_target_should_announce_renew_move(&t))
		FAIL("expected: !attest_target_should_announce_renew_move(&t)");

	attest_target_resolve_renew(&t, "ca.example", 8599);
	TEST("the port is half the endpoint, so a moved port is reported too");
	if (!attest_target_should_announce_renew_move(&t))
		FAIL("expected: attest_target_should_announce_renew_move(&t)");

	attest_target_resolve_renew(&t, "ca.example", 8444);
	TEST("an endpoint that agrees again is silent");
	if (attest_target_should_announce_renew_move(&t))
		FAIL("expected: !attest_target_should_announce_renew_move(&t)");
	attest_target_resolve_renew(&t, "old-ca.example", 8444);
	TEST("and a later divergence is reported afresh");
	if (!attest_target_should_announce_renew_move(&t))
		FAIL("expected: attest_target_should_announce_renew_move(&t)");

	attest_target_resolve_renew(&t, NULL, 0);
	TEST("a publisher that cannot renew has no endpoint to disagree with");
	if (attest_target_should_announce_renew_move(&t))
		FAIL("expected: !attest_target_should_announce_renew_move(&t)");

	TEST("no target, nothing to compare");
	if (attest_target_should_announce_renew_move(NULL))
		FAIL("expected: !attest_target_should_announce_renew_move(NULL)");
}

/* no renewal clause when a token-only label already names the endpoint */
static void test_the_renewal_endpoint_is_said_once(void)
{
	struct attest_target t;
	char at[LOTA_RENEW_AT_LEN];

	memset(&t, 0, sizeof(t));
	t.has_profile = true;
	t.token_only = true;
	snprintf(t.ca, sizeof(t.ca), "%s", "ca.example");
	t.ca_port = 8444;

	attest_target_resolve_renew(&t, "ca.example", 8444);
	TEST("a token-only label naming the endpoint gets no second copy");
	if (attest_target_renew_at(&t, at, sizeof(at))[0] != '\0')
		FAIL("expected: attest_target_renew_at(&t, at, sizeof(at))[0] "
		     "== '\\0'");

	attest_target_resolve_renew(&t, "old-ca.example", 8444);
	TEST("an endpoint the label does not name is written out");
	if (strcmp(attest_target_renew_at(&t, at, sizeof(at)),
		   ", renewing at old-ca.example:8444") != 0)
		FAIL("expected: strcmp(attest_target_renew_at(&t, at, "
		     "sizeof(at)), \", renewing at old-ca.example:8444\") == 0");

	t.token_only = false;
	attest_target_resolve_renew(&t, "ca.example", 8444);
	TEST("a verifier labels its publisher, so the CA is always written");
	if (strcmp(attest_target_renew_at(&t, at, sizeof(at)),
		   ", renewing at ca.example:8444") != 0)
		FAIL("expected: strcmp(attest_target_renew_at(&t, at, "
		     "sizeof(at)), \", renewing at ca.example:8444\") == 0");

	attest_target_resolve_renew(&t, NULL, 0);
	TEST("a target that cannot renew names no endpoint");
	if (attest_target_renew_at(&t, at, sizeof(at))[0] != '\0')
		FAIL("expected: attest_target_renew_at(&t, at, sizeof(at))[0] "
		     "== '\\0'");

	TEST("no target, no endpoint");
	if (attest_target_renew_at(NULL, at, sizeof(at))[0] != '\0')
		FAIL("expected: attest_target_renew_at(NULL, at, "
		     "sizeof(at))[0] == '\\0'");
	TEST("no room, no endpoint");
	if (attest_target_renew_at(&t, NULL, 0)[0] != '\0')
		FAIL("expected: attest_target_renew_at(&t, NULL, 0)[0] == "
		     "'\\0'");
}

/*
 * Pinning is per publisher because the certificate is: each publisher runs its
 * own verifier, so a fingerprint measured against one is refused by every other.
 * What is pinned here is that each target carries the pin of the profile that
 * named it, and that a profile which names none is unpinned whatever the
 * host-level key says.
 */
static void test_each_profile_pins_its_own_verifier(void)
{
	static const char pin_a[] = "4fd24ead1c6c1c0d2e5f0a9b8c7d6e5f"
				    "4a3b2c1d0e9f8a7b6c5d4e3f2a1b0c9d";
	static const char pin_b[] = "0123456789abcdef0123456789abcdef"
				    "fedcba9876543210fedcba9876543210";
	struct attest_target targets[LOTA_CONFIG_MAX_PROFILES];
	uint8_t want_a[LOTA_PIN_SHA256_LEN];
	uint8_t want_b[LOTA_PIN_SHA256_LEN];
	char anchor[256];
	struct lota_config cfg;
	size_t count = 0;

	snprintf(anchor, sizeof(anchor), "/tmp/lota-targets-pin.%d.der",
		 getpid());
	if (write_anchor(anchor) != 0) {
		TEST("write an anchor");
		if (!0)
			FAIL("expected: 0");
		return;
	}
	if (lota_pin_sha256_parse(pin_a, want_a) != 0 ||
	    lota_pin_sha256_parse(pin_b, want_b) != 0) {
		TEST("parse the expected pins");
		if (!0)
			FAIL("expected: 0");
		return;
	}

	memset(&cfg, 0, sizeof(cfg));
	/* the host-level pin belongs to the single-verifier deployment;
	 * configuration carrying both is refused before it reaches here */
	snprintf(cfg.pin_sha256, sizeof(cfg.pin_sha256), "%s", pin_a);
	cfg.profile_count = 3;

	snprintf(cfg.profiles[0].name, sizeof(cfg.profiles[0].name), "pinned");
	snprintf(cfg.profiles[0].verifier, sizeof(cfg.profiles[0].verifier),
		 "a.example");
	cfg.profiles[0].verifier_port = 8443;
	snprintf(cfg.profiles[0].ca_cert, sizeof(cfg.profiles[0].ca_cert), "%s",
		 anchor);
	snprintf(cfg.profiles[0].ca, sizeof(cfg.profiles[0].ca),
		 "ca.a.example");
	snprintf(cfg.profiles[0].pin_sha256, sizeof(cfg.profiles[0].pin_sha256),
		 "%s", pin_a);

	snprintf(cfg.profiles[1].name, sizeof(cfg.profiles[1].name), "other");
	snprintf(cfg.profiles[1].verifier, sizeof(cfg.profiles[1].verifier),
		 "b.example");
	cfg.profiles[1].verifier_port = 9443;
	snprintf(cfg.profiles[1].ca_cert, sizeof(cfg.profiles[1].ca_cert), "%s",
		 anchor);
	snprintf(cfg.profiles[1].ca, sizeof(cfg.profiles[1].ca),
		 "ca.b.example");
	snprintf(cfg.profiles[1].pin_sha256, sizeof(cfg.profiles[1].pin_sha256),
		 "%s", pin_b);

	snprintf(cfg.profiles[2].name, sizeof(cfg.profiles[2].name),
		 "unpinned");
	snprintf(cfg.profiles[2].verifier, sizeof(cfg.profiles[2].verifier),
		 "c.example");
	cfg.profiles[2].verifier_port = 7443;
	snprintf(cfg.profiles[2].ca_cert, sizeof(cfg.profiles[2].ca_cert), "%s",
		 anchor);
	snprintf(cfg.profiles[2].ca, sizeof(cfg.profiles[2].ca),
		 "ca.c.example");

	TEST("a pinned profile list builds");
	if (!(attest_targets_build(&cfg, NULL, 0, NULL, 300, targets,
				   LOTA_CONFIG_MAX_PROFILES, &count) == 0 &&
	      count == 3))
		FAIL("expected: attest_targets_build(&cfg, NULL, 0, NULL, "
		     "300, targets, LOTA_CONFIG_MAX_PROFILES, &count) == 0 && "
		     "count == 3");

	TEST("a profile's pin reaches its own target");
	if (!(targets[0].has_pin &&
	      memcmp(targets[0].pin_sha256, want_a, LOTA_PIN_SHA256_LEN) == 0))
		FAIL("expected: targets[0].has_pin && "
		     "memcmp(targets[0].pin_sha256, want_a, "
		     "LOTA_PIN_SHA256_LEN) == 0");
	TEST("the second publisher carries its own pin, not the first's");
	if (!(targets[1].has_pin &&
	      memcmp(targets[1].pin_sha256, want_b, LOTA_PIN_SHA256_LEN) == 0))
		FAIL("expected: targets[1].has_pin && "
		     "memcmp(targets[1].pin_sha256, want_b, "
		     "LOTA_PIN_SHA256_LEN) == 0");
	TEST("two publishers do not share one certificate");
	if (memcmp(targets[0].pin_sha256, targets[1].pin_sha256,
		   LOTA_PIN_SHA256_LEN) == 0)
		FAIL("expected: memcmp(targets[0].pin_sha256, "
		     "targets[1].pin_sha256, LOTA_PIN_SHA256_LEN) != 0");
	TEST("a profile naming no pin is unpinned, whatever the host key says");
	if (targets[2].has_pin)
		FAIL("expected: !targets[2].has_pin");

	unlink(anchor);
}

/* A certificate that cannot be read confirms nothing about the key. */
static void test_an_unreadable_cert_confirms_nothing(void)
{
	struct attest_target t;

	memset(&t, 0, sizeof(t));
	TEST("a foreign key is reported");
	if (attest_target_note_cert_match(&t, -EKEYREJECTED) !=
	    ATTEST_CERT_MISMATCH)
		FAIL("expected: attest_target_note_cert_match(&t, "
		     "-EKEYREJECTED) == ATTEST_CERT_MISMATCH");
	TEST("an unreadable certificate keeps the mismatch");
	if (!(attest_target_note_cert_match(&t, -EINVAL) ==
		      ATTEST_CERT_UNREADABLE &&
	      t.key_mismatch_announced))
		FAIL("expected: attest_target_note_cert_match(&t, -EINVAL) == "
		     "ATTEST_CERT_UNREADABLE && t.key_mismatch_announced");
	TEST("an unreadable certificate is reported once");
	if (attest_target_note_cert_match(&t, -EINVAL) != ATTEST_CERT_SILENT)
		FAIL("expected: attest_target_note_cert_match(&t, -EINVAL) == "
		     "ATTEST_CERT_SILENT");
	TEST("only a certificate naming the key clears the mismatch");
	if (!(attest_target_note_cert_match(&t, 0) ==
		      ATTEST_CERT_MATCHES_AGAIN &&
	      !t.key_mismatch_announced))
		FAIL("expected: attest_target_note_cert_match(&t, 0) == "
		     "ATTEST_CERT_MATCHES_AGAIN && !t.key_mismatch_announced");
	TEST("a certificate that broke again is reported again");
	if (attest_target_note_cert_match(&t, -EINVAL) !=
	    ATTEST_CERT_UNREADABLE)
		FAIL("expected: attest_target_note_cert_match(&t, -EINVAL) == "
		     "ATTEST_CERT_UNREADABLE");
	attest_target_note_cert_match(&t, -EKEYREJECTED);
	TEST("a certificate read as a foreign key's counts as read");
	if (attest_target_note_cert_match(&t, -EINVAL) !=
	    ATTEST_CERT_UNREADABLE)
		FAIL("expected: attest_target_note_cert_match(&t, -EINVAL) == "
		     "ATTEST_CERT_UNREADABLE");
}

/* A title asking for an enrolled publisher wakes the loop once, not forever. */
static void test_a_request_wakes_the_loop_once(void)
{
	struct attest_target t[2];

	memset(t, 0, sizeof(t));
	t[0].next_due_ms = 9000;
	t[1].next_due_ms = 9000;
	t[1].enroll_pending = true;

	TEST("a pending enrollment makes its target due now");
	if (!(attest_targets_take_wakeups(t, 2, 100) &&
	      t[1].next_due_ms == 100))
		FAIL("expected: attest_targets_take_wakeups(t, 2, 100) && "
		     "t[1].next_due_ms == 100");
	TEST("a target nobody asked for keeps its slot");
	if (t[0].next_due_ms != 9000)
		FAIL("expected: t[0].next_due_ms == 9000");

	t[1].next_due_ms = 5000;
	TEST("the request is spent once served");
	if (!(!attest_targets_take_wakeups(t, 2, 200) &&
	      t[1].next_due_ms == 5000))
		FAIL("expected: !attest_targets_take_wakeups(t, 2, 200) && "
		     "t[1].next_due_ms == 5000");

	t[0].session_changed = true;
	TEST("a session change wakes the loop once too");
	if (!(attest_targets_take_wakeups(t, 2, 300) &&
	      !attest_targets_take_wakeups(t, 2, 400) &&
	      t[0].next_due_ms == 300))
		FAIL("expected: attest_targets_take_wakeups(t, 2, 300) && "
		     "!attest_targets_take_wakeups(t, 2, 400) && "
		     "t[0].next_due_ms == 300");
}

/* A lost key is enrolled again only for a publisher somebody agreed to. */
static void test_a_lost_key_is_enrolled_again_with_consent(void)
{
	struct attest_target t;
	int delay;

	memset(&t, 0, sizeof(t));
	TEST("recorded consent enrolls again at once and says so");
	if (!(attest_target_reenroll_decide(&t, 0, 1000) ==
		      ATTEST_REENROLL_NOW &&
	      t.reenrolling))
		FAIL("expected: attest_target_reenroll_decide(&t, 0, 1000) == "
		     "ATTEST_REENROLL_NOW && t.reenrolling");

	delay = attest_target_reenroll_failed(&t, 1000);
	TEST("a failed attempt waits out its backoff");
	if (!(delay > 0 && attest_target_reenroll_decide(&t, 0, 1001) ==
				   ATTEST_REENROLL_WAIT))
		FAIL("expected: delay > 0 && "
		     "attest_target_reenroll_decide(&t, 0, 1001) == "
		     "ATTEST_REENROLL_WAIT");
	TEST("the attempt is made again once the backoff lapses");
	if (attest_target_reenroll_decide(&t, 0,
					  1000 + (uint64_t)delay * 1000) !=
	    ATTEST_REENROLL_NOW)
		FAIL("expected: attest_target_reenroll_decide(&t, 0, 1000 + "
		     "(uint64_t)delay * 1000) == ATTEST_REENROLL_NOW");
	t.interval = 240;
	TEST("the next round comes when the backoff lapses");
	if (attest_target_reenroll_wait(&t, 1500) != delay)
		FAIL("expected: attest_target_reenroll_wait(&t, 1500) == delay");
	TEST("each failure waits longer");
	if (attest_target_reenroll_failed(&t, 2000) <= delay)
		FAIL("expected: attest_target_reenroll_failed(&t, 2000) > "
		     "delay");

	attest_target_reenroll_clear(&t);
	TEST("a certificate that names the key ends the re-enrollment");
	if (!(!t.reenrolling && t.next_reenroll_ms == 0 &&
	      t.reenroll_backoff == 0))
		FAIL("expected: !t.reenrolling && t.next_reenroll_ms == 0 && "
		     "t.reenroll_backoff == 0");
	TEST("without a backoff the round keeps its interval");
	if (attest_target_reenroll_wait(&t, 3000) != 240)
		FAIL("expected: attest_target_reenroll_wait(&t, 3000) == 240");
}

/* A failed enrollment comes back when it said it would. */
static void test_a_failed_enrollment_returns_on_its_backoff(void)
{
	struct attest_target t;
	int delay;

	memset(&t, 0, sizeof(t));
	t.interval = 240;
	TEST("with nothing backed off the round keeps its interval");
	if (attest_target_enroll_wait(&t, 1000) != 240)
		FAIL("expected: attest_target_enroll_wait(&t, 1000) == 240");

	delay = attest_target_enroll_failed(&t, 1000);
	TEST("the next round comes when the enrollment backoff lapses");
	if (!(delay > 0 && delay < 240 &&
	      attest_target_enroll_wait(&t, 1000) == delay))
		FAIL("expected: delay > 0 && delay < 240 && "
		     "attest_target_enroll_wait(&t, 1000) == delay");
	TEST("each failed enrollment waits longer");
	if (attest_target_enroll_failed(&t, 2000) <= delay)
		FAIL("expected: attest_target_enroll_failed(&t, 2000) > delay");
	TEST("a lapsed backoff leaves the interval");
	if (attest_target_enroll_wait(&t, 1000000) != 240)
		FAIL("expected: attest_target_enroll_wait(&t, 1000000) == 240");
}

/* A failed renewal is retried in a round, never sooner than it comes. */
static void test_a_failed_renewal_waits_a_round(void)
{
	struct attest_target t;

	memset(&t, 0, sizeof(t));
	t.interval = 240;
	TEST("a backoff below the interval waits the interval");
	if (!(attest_target_renew_failed(&t, 1000) == 240 &&
	      t.next_renew_ms == 1000 + 240 * 1000))
		FAIL("expected: attest_target_renew_failed(&t, 1000) == 240 "
		     "&& t.next_renew_ms == 1000 + 240 * 1000");

	t.interval = 5;
	TEST("a backoff above the interval is kept");
	if (attest_target_renew_failed(&t, 1000) <= 5)
		FAIL("expected: attest_target_renew_failed(&t, 1000) > 5");
}

/* Without consent the loop says why once and leaves the host alone. */
static void test_no_consent_is_said_once(void)
{
	struct attest_target t;

	memset(&t, 0, sizeof(t));
	t.reenrolling = true;
	TEST("no consent refuses and does not report re-enrolling");
	if (!(attest_target_reenroll_decide(&t, -ENOENT, 1000) ==
		      ATTEST_REENROLL_REFUSED &&
	      !t.reenrolling))
		FAIL("expected: attest_target_reenroll_decide(&t, -ENOENT, "
		     "1000) == ATTEST_REENROLL_REFUSED && !t.reenrolling");
	TEST("the refusal is said once");
	if (attest_target_reenroll_decide(&t, -ENOENT, 2000) !=
	    ATTEST_REENROLL_REFUSED_SILENT)
		FAIL("expected: attest_target_reenroll_decide(&t, -ENOENT, "
		     "2000) == ATTEST_REENROLL_REFUSED_SILENT");
	TEST("an unreadable consent record is no consent");
	if (attest_target_reenroll_decide(&t, -EIO, 3000) !=
	    ATTEST_REENROLL_REFUSED_SILENT)
		FAIL("expected: attest_target_reenroll_decide(&t, -EIO, 3000) "
		     "== ATTEST_REENROLL_REFUSED_SILENT");

	TEST("an agreement in between makes a later refusal said again");
	if (!(attest_target_reenroll_decide(&t, 0, 4000) ==
		      ATTEST_REENROLL_NOW &&
	      attest_target_reenroll_decide(&t, -ENOENT, 5000) ==
		      ATTEST_REENROLL_REFUSED))
		FAIL("expected: attest_target_reenroll_decide(&t, 0, 4000) == "
		     "ATTEST_REENROLL_NOW && "
		     "attest_target_reenroll_decide(&t, -ENOENT, 5000) == "
		     "ATTEST_REENROLL_REFUSED");
}

/* A reload keeps what the agent recorded about a publisher's processes. */
static void test_a_reload_keeps_the_termination_record(void)
{
	struct attest_target t[1];
	size_t n = 0;

	TEST("one verifier builds one target");
	if (!(attest_targets_build(NULL, "verifier.example", 8443, NULL, 300, t,
				   1, &n) == 0 &&
	      n == 1))
		FAIL("expected: attest_targets_build(NULL, "
		     "\"verifier.example\", 8443, NULL, 300, t, 1, &n) == 0 "
		     "&& n == 1");
	t[0].protected_terminated = true;
	TEST("the rebuilt target still says a process was ended");
	if (!(attest_targets_rebuild(NULL, "verifier.example", 8443, NULL, 300,
				     t, 1, &n) == 0 &&
	      n == 1 && t[0].protected_terminated))
		FAIL("expected: attest_targets_rebuild(NULL, "
		     "\"verifier.example\", 8443, NULL, 300, t, 1, &n) == 0 "
		     "&& n == 1 && t[0].protected_terminated");
}

int main(void)
{
	test_begin("attest targets");

	test_single_verifier();
	test_profiles_replace_the_single_verifier();
	test_token_only_publisher();
	test_more_profiles_than_room();
	test_effective_interval();
	test_env_overrides_stop_at_the_deployment();
	test_target_reports();
	test_wait_for_a_first_session_is_announced();
	test_renewal_follows_the_record();
	test_a_moved_ca_is_reported();
	test_the_renewal_endpoint_is_said_once();
	test_each_profile_pins_its_own_verifier();
	test_a_request_wakes_the_loop_once();
	test_an_unreadable_cert_confirms_nothing();
	test_a_lost_key_is_enrolled_again_with_consent();
	test_a_failed_enrollment_returns_on_its_backoff();
	test_a_failed_renewal_waits_a_round();
	test_no_consent_is_said_once();
	test_a_reload_keeps_the_termination_record();

	return test_end();
}
