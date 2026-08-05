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

#include "../src/agent/attest.h"
#include "../src/agent/attest_targets.h"

static int g_failures;

#define CHECK(cond, msg)                                    \
	do {                                                \
		if (!(cond)) {                              \
			fprintf(stderr, "FAIL: %s\n", msg); \
			g_failures++;                       \
		} else {                                    \
			printf("PASS: %s\n", msg);          \
		}                                           \
	} while (0)

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

	CHECK(attest_targets_build(&cfg, "verifier.example", 8443, NULL, 300,
				   targets, LOTA_CONFIG_MAX_PROFILES,
				   &count) == 0 &&
		      count == 1,
	      "no profiles leaves the single verifier as the only target");
	CHECK(strcmp(targets[0].server, "verifier.example") == 0 &&
		      targets[0].port == 8443 && targets[0].interval == 300,
	      "the single target carries the caller's endpoint and cadence");
	CHECK(!targets[0].has_profile && targets[0].profile_error == 0,
	      "no anchor is not an error, it is a host without a publisher");
	CHECK(!targets[0].session_gated,
	      "the single verifier keeps the continuous stream it always had");
	CHECK(strcmp(targets[0].label, "verifier.example:8443") == 0,
	      "the target names itself the way its log lines will");

	CHECK(attest_targets_build(&cfg, NULL, 8443, NULL, 300, targets,
				   LOTA_CONFIG_MAX_PROFILES, &count) == -EINVAL,
	      "a single target with no verifier is refused");

	/* NULL config is the same case as config with no profiles */
	CHECK(attest_targets_build(NULL, "verifier.example", 8443, NULL, 300,
				   targets, LOTA_CONFIG_MAX_PROFILES,
				   &count) == 0 &&
		      count == 1,
	      "no config at all still yields the single target");
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
		CHECK(0, "write an anchor");
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

	CHECK(attest_targets_build(&cfg, "host-level.example", 1234, NULL, 300,
				   targets, LOTA_CONFIG_MAX_PROFILES,
				   &count) == 0 &&
		      count == 2,
	      "the profile list is the target list");
	CHECK(strcmp(targets[0].server, "a.example") == 0 &&
		      targets[0].port == 8443 &&
		      strcmp(targets[1].server, "b.example") == 0 &&
		      targets[1].port == 9443,
	      "the host-level verifier is replaced, not added to");
	CHECK(targets[0].interval == 60,
	      "a profile keeps the cadence it states");
	CHECK(targets[1].interval == 300,
	      "a profile that states none inherits the host's");

	CHECK(targets[0].has_profile && targets[0].profile_error == 0 &&
		      strlen(targets[0].paths.id) == LOTA_PROFILE_ID_LEN - 1,
	      "a readable anchor resolves the publisher profile");
	CHECK(!targets[1].has_profile && targets[1].profile_error == -ENOENT,
	      "an unreadable anchor still reports, and says why it has no "
	      "profile");

	/*
	 * CA travels with the target because enrollment is runtime action:
	 * host that meets publisher for the first time while title is running
	 * has to know where to enroll without being told again.
	 */
	CHECK(strcmp(targets[0].ca, "ca.a.example") == 0 &&
		      targets[0].ca_port == 8444,
	      "a target carries the CA its publisher enrolls against");
	CHECK(targets[1].ca[0] == '\0',
	      "a profile that names no CA carries none");

	/*
	 * Reporting is exfiltration, so publisher gets it only while title of
	 * theirs runs.
	 * Fleet that wants the continuous stream says so per profile;
	 * the single-verifier path keeps it, because that is the deployment
	 * the stream was the feature for
	 */
	CHECK(targets[0].session_gated && !targets[1].session_gated,
	      "each profile carries its own reporting mode");

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

	CHECK(attest_targets_build(&cfg, "host-level.example", 1234, NULL, 300,
				   targets, LOTA_CONFIG_MAX_PROFILES,
				   &count) == 0 &&
		      count == 1,
	      "a publisher with no verifier is still a target");
	CHECK(targets[0].token_only && targets[0].server[0] == '\0',
	      "the target says it reports to nobody and names no verifier");
	CHECK(strcmp(targets[0].ca, "ca.light.example") == 0 &&
		      targets[0].ca_port == 8444,
	      "the CA it enrolls against travels with it, since renewal does "
	      "not stop");
	CHECK(strstr(targets[0].label, "ca.light.example:8444") != NULL,
	      "its log lines name the CA, there being no verifier to name");
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

	CHECK(attest_targets_build(&cfg, NULL, 0, NULL, 300, targets, 2,
				   &count) == -E2BIG &&
		      count == 0,
	      "a list that does not fit is refused rather than truncated");
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
	CHECK(attest_effective_interval(0, 0) == 0,
	      "no publishers and no interval stays a one-shot");
	CHECK(attest_effective_interval(0, 1) == DEFAULT_ATTEST_INTERVAL,
	      "one publisher and no interval attests at the default cadence");
	CHECK(attest_effective_interval(0, 8) == DEFAULT_ATTEST_INTERVAL,
	      "several publishers and no interval do the same");
	CHECK(attest_effective_interval(45, 3) == 45,
	      "a configured cadence wins over the default");
	CHECK(attest_effective_interval(45, 0) == 45,
	      "a configured cadence runs the loop without profiles too");
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
	CHECK(attest_target_reports(&t),
	      "a plain publisher is reported to every round");

	memset(&t, 0, sizeof(t));
	t.token_only = true;
	CHECK(!attest_target_reports(&t),
	      "a publisher who runs no verifier is never reported to");

	memset(&t, 0, sizeof(t));
	t.session_gated = true;
	t.sessions = 0;
	CHECK(!attest_target_reports(&t),
	      "a session-gated publisher with no title running is not reported to");

	t.sessions = 1;
	CHECK(attest_target_reports(&t),
	      "the same publisher is reported to while a title of theirs runs");

	memset(&t, 0, sizeof(t));
	t.token_only = true;
	t.session_gated = true;
	t.sessions = 3;
	CHECK(!attest_target_reports(&t),
	      "running no verifier outranks a live session");

	CHECK(!attest_target_reports(NULL), "no target is reported to");
}

int main(void)
{
	printf("=== Attestation target list tests ===\n\n");

	test_single_verifier();
	test_profiles_replace_the_single_verifier();
	test_token_only_publisher();
	test_more_profiles_than_room();
	test_effective_interval();
	test_target_reports();

	printf("\n%s\n", g_failures ? "FAILURES" : "All tests passed");
	return g_failures ? 1 : 0;
}
