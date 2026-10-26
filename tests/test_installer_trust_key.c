/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Which key the installer names when the enforcement signature does not
 * verify.
 * Order, as the agent resolves it: --policy-pubkey, policy_pubkey in the
 * configuration, the operator's override key, the packaged key.
 * Keys are real files in a temporary directory.
 * The refusal names the key the agent would fall back to, or none when the
 * failing key is the packaged one.
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../installer/install.h"

static int tests_run;
static int tests_passed;

#define TEST(name)                                         \
	do {                                               \
		tests_run++;                               \
		printf("  [%2d] %-55s ", tests_run, name); \
	} while (0)

#define PASS()                    \
	do {                      \
		tests_passed++;   \
		printf("PASS\n"); \
	} while (0)

#define FAIL(msg)                          \
	do {                               \
		printf("FAIL: %s\n", msg); \
	} while (0)

static char dir[] = "/tmp/lota-trust-key-XXXXXX";
static char conf_key[256];
static char override_key[256];
static char packaged_key[256];

static int write_file(const char *path)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	FILE *f = fd < 0 ? NULL : fdopen(fd, "w");

	if (!f) {
		if (fd >= 0)
			close(fd);
		return -1;
	}
	fputs("key\n", f);
	fclose(f);
	return 0;
}

/* policy_pubkey beats the override and the packaged key */
static void test_configured_key_wins(void)
{
	enum trust_key_source src = TRUST_KEY_NONE;
	const char *got;

	TEST("policy_pubkey from the configuration is the key named");
	got = installer_trust_key(NULL, conf_key, override_key, packaged_key,
				  &src);
	if (!got || strcmp(got, conf_key) != 0) {
		FAIL(got ? got : "(none)");
		return;
	}
	if (src != TRUST_KEY_CONFIGURED) {
		FAIL("named the right file for the wrong reason");
		return;
	}
	PASS();
}

/* a configured path that no longer exists is skipped */
static void test_a_configured_key_that_is_gone_falls_through(void)
{
	enum trust_key_source src = TRUST_KEY_NONE;
	const char *got;

	TEST("a configured key that is not there falls through");
	got = installer_trust_key(NULL, "/nonexistent/configured.pub",
				  override_key, packaged_key, &src);
	if (!got || strcmp(got, override_key) != 0) {
		FAIL(got ? got : "(none)");
		return;
	}
	if (src != TRUST_KEY_OVERRIDE) {
		FAIL("wrong source");
		return;
	}
	PASS();
}

/* the override beats the packaged key */
static void test_the_override_beats_the_package(void)
{
	enum trust_key_source src = TRUST_KEY_NONE;
	const char *got;

	TEST("the operator's own key beats the packaged one");
	got = installer_trust_key(NULL, NULL, override_key, packaged_key, &src);
	if (!got || strcmp(got, override_key) != 0) {
		FAIL(got ? got : "(none)");
		return;
	}
	if (src != TRUST_KEY_OVERRIDE) {
		FAIL("wrong source");
		return;
	}
	PASS();
}

/* --policy-pubkey beats every other source */
static void test_a_named_key_wins_over_everything(void)
{
	enum trust_key_source src = TRUST_KEY_NONE;
	const char *got;

	TEST("--policy-pubkey wins over the configuration");
	got = installer_trust_key(packaged_key, conf_key, override_key,
				  packaged_key, &src);
	if (!got || strcmp(got, packaged_key) != 0) {
		FAIL(got ? got : "(none)");
		return;
	}
	if (src != TRUST_KEY_NAMED) {
		FAIL("wrong source");
		return;
	}
	PASS();
}

/* no readable key yields TRUST_KEY_NONE and a message for it */
static void test_no_key_anywhere_is_said(void)
{
	enum trust_key_source src = TRUST_KEY_NAMED;
	const char *got;

	TEST("no readable key anywhere is reported as none");
	got = installer_trust_key(NULL, "/nonexistent/a.pub",
				  "/nonexistent/b.pub", "/nonexistent/c.pub",
				  &src);
	if (got) {
		FAIL(got);
		return;
	}
	if (src != TRUST_KEY_NONE) {
		FAIL("wrong source");
		return;
	}
	PASS();
}

/* every source has a distinct message */
static void test_every_source_says_where_it_came_from(void)
{
	static const enum trust_key_source all[] = {
		TRUST_KEY_NONE, TRUST_KEY_NAMED, TRUST_KEY_CONFIGURED,
		TRUST_KEY_OVERRIDE, TRUST_KEY_PACKAGED
	};
	size_t i, j;

	TEST("each source is named, and named distinctly");
	for (i = 0; i < sizeof(all) / sizeof(all[0]); i++) {
		const char *a = installer_trust_key_source_says(all[i]);

		if (!a || !a[0]) {
			FAIL("a source says nothing");
			return;
		}
		for (j = 0; j < i; j++) {
			if (strcmp(a, installer_trust_key_source_says(
					      all[j])) == 0) {
				FAIL("two sources say the same thing");
				return;
			}
		}
	}
	PASS();
}

static char note[4096];

static int says(const char *what)
{
	return strstr(note, what) != NULL;
}

/* The fallback advice names the file removing the key actually leads to,
 * and only where there is one. */
static void refusal_for(const char *key, enum trust_key_source src,
			const char *conf, const char *override)
{
	installer_trust_refusal(note, sizeof(note), key, src,
				installer_trust_fallback(
					key, src, conf, override, packaged_key),
				"/usr/lib/lota/lota_lsm.bpf.o");
}

static int offers_no_fallback(void)
{
	if (says("falls through") || says("out of the way") ||
	    says("leave out")) {
		FAIL(note);
		return 0;
	}
	if (!says("reinstall the agent package") ||
	    !says("--sign-policy /usr/lib/lota/lota_lsm.bpf.o")) {
		FAIL("no route that exists is offered");
		return 0;
	}
	return 1;
}

/* The packaged key has nothing behind it: moving it leaves no key at all. */
static void test_the_packaged_key_has_no_fallback(void)
{
	TEST("a failing packaged key is not moved aside");
	if (installer_trust_fallback(packaged_key, TRUST_KEY_PACKAGED, NULL,
				     "/nonexistent/policy.pub", packaged_key)) {
		FAIL("a fallback behind the packaged key");
		return;
	}
	refusal_for(packaged_key, TRUST_KEY_PACKAGED, NULL,
		    "/nonexistent/policy.pub");
	if (offers_no_fallback())
		PASS();
}

/* policy_pubkey naming the packaged file is the packaged key:
 * removing the setting resolves to the same file. */
static void test_a_configured_packaged_key_has_no_fallback(void)
{
	TEST("policy_pubkey naming the packaged key: no fallback");
	refusal_for(packaged_key, TRUST_KEY_CONFIGURED, packaged_key,
		    "/nonexistent/policy.pub");
	if (offers_no_fallback())
		PASS();
}

/* The same file under another name is still the same file. */
static void test_a_link_to_the_packaged_key_has_no_fallback(void)
{
	char link_path[300];

	TEST("a link to the packaged key: no fallback");
	snprintf(link_path, sizeof(link_path), "%s/link.pub", dir);
	unlink(link_path);
	if (symlink(packaged_key, link_path) != 0) {
		FAIL("symlink");
		return;
	}
	refusal_for(link_path, TRUST_KEY_CONFIGURED, link_path,
		    "/nonexistent/policy.pub");
	unlink(link_path);
	if (offers_no_fallback())
		PASS();
}

/* A configured key falls through to the operator's key when there is one,
 * not straight to the package. */
static void test_a_configured_key_falls_through_to_the_override(void)
{
	TEST("a configured key falls through to the override");
	refusal_for(conf_key, TRUST_KEY_CONFIGURED, conf_key, override_key);
	if (!says("remove policy_pubkey from") || !says(override_key)) {
		FAIL(note);
		return;
	}
	if (says(packaged_key)) {
		FAIL("names the packaged key, which the agent would not reach");
		return;
	}
	PASS();
}

/* The operator's key falls through to the packaged one. */
static void test_the_override_falls_through_to_the_package(void)
{
	TEST("the operator's key falls through to the packaged one");
	refusal_for(override_key, TRUST_KEY_OVERRIDE, NULL, override_key);
	if (!says("move it out of the way") || !says(packaged_key)) {
		FAIL(note);
		return;
	}
	PASS();
}

/* A named key is dropped from the command line, not moved. */
static void test_a_named_key_falls_back_to_what_the_agent_resolves(void)
{
	TEST("a named key: leave out --policy-pubkey");
	refusal_for("/nonexistent/named.pub", TRUST_KEY_NAMED, conf_key,
		    override_key);
	if (!says("leave out --policy-pubkey") || !says(conf_key)) {
		FAIL(note);
		return;
	}
	PASS();
}

int main(void)
{
	static void (*const tests[])(void) = {
		test_configured_key_wins,
		test_a_configured_key_that_is_gone_falls_through,
		test_the_override_beats_the_package,
		test_a_named_key_wins_over_everything,
		test_no_key_anywhere_is_said,
		test_every_source_says_where_it_came_from,
		test_the_packaged_key_has_no_fallback,
		test_a_configured_packaged_key_has_no_fallback,
		test_a_link_to_the_packaged_key_has_no_fallback,
		test_a_configured_key_falls_through_to_the_override,
		test_the_override_falls_through_to_the_package,
		test_a_named_key_falls_back_to_what_the_agent_resolves,
	};
	size_t i;

	printf("\n=== lota-install: the key the enforcement check names ===\n");

	if (!mkdtemp(dir)) {
		perror("mkdtemp");
		return 1;
	}
	snprintf(conf_key, sizeof(conf_key), "%s/configured.pub", dir);
	snprintf(override_key, sizeof(override_key), "%s/policy.pub", dir);
	snprintf(packaged_key, sizeof(packaged_key), "%s/enforcement.pub", dir);
	if (write_file(conf_key) || write_file(override_key) ||
	    write_file(packaged_key)) {
		perror("write");
		return 1;
	}

	for (i = 0; i < sizeof(tests) / sizeof(tests[0]); i++)
		tests[i]();

	unlink(conf_key);
	unlink(override_key);
	unlink(packaged_key);
	rmdir(dir);

	printf("\nPassed: %d / %d\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
