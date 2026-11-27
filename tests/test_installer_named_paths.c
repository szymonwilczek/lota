/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * What lota-install says when a file the operator named is not there.
 *
 * Four options take a path: --ca-cert, --policy-pubkey, --selinux-module
 * and --verity-manifest. A path reaches them only by being typed, so one
 * that does not resolve is the operator's own mistake, and the installer
 * hands it back before any stage runs: the path named, the run refused
 * with EXIT_INSTALL_USAGE.
 *
 * Both halves are asserted because each can hold without the other.
 * A stage that wants the file can name it in its own report and still let
 * the run go on; a check that comes first can refuse for its own reason,
 * or answer with the remedy for a different problem, and never say which file
 * was missing.
 * --selinux-module is the sharpest case: its stage never opens the file,
 * so without the check up front it reports whatever the loaded policy says,
 * whatever path was given.
 *
 * A readable file must not draw the same refusal, or the four cases would pass
 * against an installer that refuses every path.
 *
 * The installer runs the way an operator would run it.
 * --status is used where it can be, because it changes nothing at any privilege
 * level;
 * --verity-manifest refuses to be combined with it, so that one runs alone,
 * which reaches no further than the missing file either.
 *
 * --help names the same default key order the trust stage resolves,
 * the lota.conf key first, and closes every parenthesis it opens.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "test.h"
#include "../installer/install.h"

#ifndef LOTA_INSTALL_BIN
#define LOTA_INSTALL_BIN "build/lota-install"
#endif

/*
 * Everything the installer wrote, on both streams.
 *
 * The refusal is on stderr and the report is on stdout, and which one an operator
 * reads it from is not the subject: what matters is that the path they typed
 * comes back.
 */
static int run_installer(const char *args, char *out, size_t cap)
{
	char cmd[512];
	size_t len = 0;
	FILE *p;
	int rc;

	snprintf(cmd, sizeof(cmd), "%s --plain %s 2>&1", LOTA_INSTALL_BIN,
		 args);

	p = popen(cmd, "r");
	if (!p)
		return -1;

	while (len + 1 < cap) {
		size_t n = fread(out + len, 1, cap - len - 1, p);

		if (n == 0)
			break;
		len += n;
	}
	out[len] = '\0';

	rc = pclose(p);
	if (rc < 0 || !WIFEXITED(rc))
		return -1;

	return WEXITSTATUS(rc);
}

/*
 * @args must place the missing path in a position the installer parses;
 * the path itself is what the assertion is about.
 */
static void expect_path_named(const char *what, const char *args,
			      const char *path)
{
	char out[65536];
	int rc;

	TEST(what);

	rc = run_installer(args, out, sizeof(out));
	if (rc < 0) {
		FAIL("cannot run lota-install");
		return;
	}

	if (!strstr(out, path)) {
		FAIL("the installer never names the path it was given");
		return;
	}

	if (rc != EXIT_INSTALL_USAGE) {
		FAIL("the run was not refused for the path it was given");
		return;
	}

	PASS();
}

/* A file that is there must not be turned into a refusal */
static void expect_not_refused(const char *what, const char *args)
{
	char out[65536];
	int rc;

	TEST(what);

	rc = run_installer(args, out, sizeof(out));
	if (rc < 0) {
		FAIL("cannot run lota-install");
		return;
	}

	if (rc == EXIT_INSTALL_USAGE) {
		FAIL("a readable file was refused as a usage error");
		return;
	}

	PASS();
}

static void expect_help_text(void)
{
	char out[65536];
	int depth = 0;
	const char *p;

	TEST("--help names lota.conf and closes its parentheses");
	if (run_installer("--help", out, sizeof(out)) != 0) {
		FAIL("--help did not exit 0");
		return;
	}
	for (p = out; *p && depth >= 0; p++)
		depth += (*p == '(') - (*p == ')');
	if (depth != 0) {
		FAIL("a parenthesis is left open or closed twice");
		return;
	}
	if (!strstr(out, "policy_pubkey in " PATH_LOTA_CONF)) {
		FAIL("the default key order leaves out lota.conf");
		return;
	}
	PASS();
}

int main(void)
{
	if (access(LOTA_INSTALL_BIN, X_OK) != 0) {
		printf("SKIP: %s is not built\n", LOTA_INSTALL_BIN);
		return 0;
	}

	printf("=== lota-install: a named file that is not there ===\n\n");

	expect_path_named("--ca-cert names the file it cannot read",
			  "--status --ca-cert /nonexistent/lota-ca.crt",
			  "/nonexistent/lota-ca.crt");

	expect_path_named("--policy-pubkey names the file it cannot read",
			  "--status --policy-pubkey /nonexistent/lota-key.pub",
			  "/nonexistent/lota-key.pub");

	expect_path_named("--selinux-module names the file it cannot read",
			  "--status --selinux-module /nonexistent/lota.pp",
			  "/nonexistent/lota.pp");

	expect_path_named("--verity-manifest names the file it cannot read",
			  "--verity-manifest /nonexistent/lota-manifest.txt",
			  "/nonexistent/lota-manifest.txt");

	expect_not_refused("a readable file is not a usage error",
			   "--status --ca-cert /etc/hostname");

	expect_help_text();

	printf("\n=== %d/%d passed ===\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
