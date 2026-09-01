/* SPDX-License-Identifier: MIT */
/*
 * LOTA packaging invariants.
 *
 * These tests validate files shipped by the repository rather than a
 * runtime integration layer. Keep package, unit, udev, D-Bus, and SELinux
 * layout checks here so module-specific test runners stay focused.
 *
 * Copyright (C) 2026 Szymon Wilczek
 *
 */

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static int tests_run;
static int tests_passed;

#define TEST(name)                                        \
	do {                                              \
		tests_run++;                              \
		printf("  [%d] %-55s ", tests_run, name); \
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

/*
 * The packaged unit must not pass a --mode flag on ExecStart. The agent
 * picks cfg.mode (default enforce) and refuses to weaken that without
 * --insecure-allow-mode-downgrade. A unit that re-introduces e.g.
 * --mode monitor silently demotes the daemon below the configured
 * policy, so guard the regression here.
 */
static void test_packaged_unit_does_not_set_mode(void)
{
	TEST("packaged unit: ExecStart has no --mode override");

	FILE *fp = fopen("systemd/lota-agent.service", "re");
	if (!fp) {
		fp = fopen("../systemd/lota-agent.service", "re");
	}
	if (!fp) {
		FAIL("could not open lota-agent.service");
		return;
	}

	char line[1024];
	bool saw_exec_start = false;
	bool saw_mode_flag = false;
	while (fgets(line, sizeof(line), fp)) {
		if (strncmp(line, "ExecStart=", 10) != 0)
			continue;
		saw_exec_start = true;
		if (strstr(line, " --mode") || strstr(line, "\t--mode") ||
		    strstr(line, " -m ") || strstr(line, "\t-m ")) {
			saw_mode_flag = true;
			break;
		}
	}
	fclose(fp);

	if (!saw_exec_start) {
		FAIL("ExecStart= not found");
		return;
	}
	if (saw_mode_flag) {
		FAIL("ExecStart must not pass --mode (would override cfg.mode)");
		return;
	}
	PASS();
}

static FILE *open_shipped(const char *rel)
{
	FILE *fp = fopen(rel, "re");

	if (!fp) {
		char up[256];

		snprintf(up, sizeof(up), "../%s", rel);
		fp = fopen(up, "re");
	}
	return fp;
}

/*
 * Continuous-attestation unit must drive the verifier and cadence from
 * /etc/lota/lota.conf, so ExecStart carries --attest but pins neither the
 * interval nor --mode.
 * Hardcoded --attest-interval would override the operator's lota.conf;
 * --mode flag would fight the enforce-by-config rule
 */
static void test_attest_unit_config_driven(void)
{
	TEST("attest unit: ExecStart is --attest, no interval/mode pin");

	FILE *fp = open_shipped("systemd/lota-attest.service");
	if (!fp) {
		FAIL("could not open lota-attest.service");
		return;
	}

	char line[1024];
	bool saw_attest = false;
	bool bad_flag = false;
	while (fgets(line, sizeof(line), fp)) {
		if (strncmp(line, "ExecStart=", 10) != 0)
			continue;
		if (strstr(line, "--attest"))
			saw_attest = true;
		if (strstr(line, "--attest-interval") || strstr(line, "--mode"))
			bad_flag = true;
	}
	fclose(fp);

	if (!saw_attest) {
		FAIL("ExecStart must invoke --attest");
		return;
	}
	if (bad_flag) {
		FAIL("ExecStart must not pin --attest-interval or --mode");
		return;
	}
	PASS();
}

/*
 * attest loop is network-facing and runs as a separate process from the
 * enforcement daemon precisely so it carries a smaller blast radius.
 * Guard that it never grants itself the enforcement daemon's powerful caps,
 * and that it gates on a completed first enrollment.
 */
static void test_attest_unit_isolated(void)
{
	TEST("attest unit: no BPF/admin caps, gated on first enroll");

	FILE *fp = open_shipped("systemd/lota-attest.service");
	if (!fp) {
		FAIL("could not open lota-attest.service");
		return;
	}

	char line[1024];
	bool powerful_cap = false;
	bool enroll_gate = false;
	while (fgets(line, sizeof(line), fp)) {
		if (strstr(line, "CapabilityBoundingSet=") &&
		    (strstr(line, "CAP_BPF") || strstr(line, "CAP_SYS_ADMIN") ||
		     strstr(line, "CAP_PERFMON") ||
		     strstr(line, "CAP_SYS_RAWIO")))
			powerful_cap = true;
		if (strstr(line, "ConditionDirectoryNotEmpty=") &&
		    strstr(line, "/var/lib/lota/profiles"))
			enroll_gate = true;
	}
	fclose(fp);

	if (powerful_cap) {
		FAIL("attest unit must not hold BPF/admin/rawio caps");
		return;
	}
	if (!enroll_gate) {
		FAIL("attest unit must gate on a non-empty profiles directory");
		return;
	}
	PASS();
}

/*
 * Installing a package must enable nothing.
 *
 * Preset used to enable the daemon and the attestation loop on any host that installed
 * the package -- but only where rpm applied it, since the nfpm post-install runs
 * no `systemctl preset`, so the same package armed a machine or did not depending on
 * who built it.
 *
 * File is gone, so this asserts its absence:
 * Preset re-appearing in either manifest is the regression, and the test that used to
 * demand one is what made it invisible when the ruling landed.
 */
static void test_no_preset_is_shipped(void)
{
	TEST("packaging: no systemd preset is shipped");

	FILE *fp = open_shipped("systemd/85-lota.preset");

	if (fp) {
		fclose(fp);
		FAIL("a systemd preset is shipped again; installing a package must enable nothing");
		return;
	}
	PASS();
}

/*
 * Installer is what arms a host, so it has to enable all three units.
 * Host driven through bring-up that enforced but never reported is exactly
 * what missing line here produced.
 */
static void test_installer_enables_the_units(void)
{
	TEST("installer: enables socket, daemon and attest loop");

	FILE *fp = open_shipped("installer/stages.c");
	if (!fp) {
		FAIL("could not open installer/stages.c");
		return;
	}

	char line[1024];
	bool socket_unit = false, daemon_unit = false, attest_unit = false;

	while (fgets(line, sizeof(line), fp)) {
		if (strstr(line, "\"lota-agent.socket\""))
			socket_unit = true;
		if (strstr(line, "\"lota-agent.service\""))
			daemon_unit = true;
		if (strstr(line, "\"lota-attest.service\""))
			attest_unit = true;
	}
	fclose(fp);

	if (!socket_unit || !daemon_unit || !attest_unit) {
		FAIL("installer does not enable all three units");
		return;
	}
	PASS();
}

/*
 * Callers resolve these interfaces from the devel include directory: one
 * missing from lota.if, or lota.if not installed, fails the caller's
 * checkmodule with the name as an unknown token.
 */
static void test_documented_selinux_interfaces_exist(void)
{
	static const char *const documented[] = {
		"lota_query_status", "lota_query_status_container",
		"lota_gaming_client", "lota_anticheat_client", "lota_admin"
	};
	enum {
		DOCUMENTED_COUNT = 5
	};
	bool found[DOCUMENTED_COUNT] = { false, false, false, false, false };
	char line[1024];
	FILE *fp;

	TEST("selinux: the documented interfaces are defined in lota.if");

	fp = open_shipped("selinux/lota.if");
	if (!fp) {
		FAIL("could not open selinux/lota.if");
		return;
	}

	while (fgets(line, sizeof(line), fp)) {
		for (size_t i = 0; i < DOCUMENTED_COUNT; i++) {
			char want[64];

			snprintf(want, sizeof(want), "interface(`%s'",
				 documented[i]);
			if (strstr(line, want))
				found[i] = true;
		}
	}
	fclose(fp);

	for (size_t i = 0; i < DOCUMENTED_COUNT; i++) {
		if (!found[i]) {
			char msg[128];

			snprintf(msg, sizeof(msg),
				 "%s is documented and not defined",
				 documented[i]);
			FAIL(msg);
			return;
		}
	}
	PASS();
}

static void test_selinux_interfaces_are_installed(void)
{
	char line[1024];
	bool devel_include = false;
	bool packaged = false;
	FILE *fp;

	TEST("selinux: lota.if reaches an interface path both ways");

	fp = open_shipped("selinux/Makefile");
	if (!fp) {
		FAIL("could not open selinux/Makefile");
		return;
	}
	while (fgets(line, sizeof(line), fp)) {
		if (strstr(line, "$(IF_FILES)") &&
		    strstr(line, "$(SELINUX_INTERFACE_DIR)"))
			devel_include = true;
	}
	fclose(fp);

	fp = open_shipped("packaging/nfpm/lota-agent.yaml");
	if (!fp) {
		FAIL("could not open packaging/nfpm/lota-agent.yaml");
		return;
	}
	while (fgets(line, sizeof(line), fp)) {
		if (strstr(line, "/usr/share/lota/selinux/lota.if"))
			packaged = true;
	}
	fclose(fp);

	if (!devel_include) {
		FAIL("make install no longer installs lota.if for callers");
		return;
	}
	if (!packaged) {
		FAIL("the package ships no lota.if, so a packaged host cannot call the interfaces");
		return;
	}
	PASS();
}

/*
 * make verify and the install banner must walk TUNABLES, read out of the
 * policy sources; a hand-kept second list drifts from what is declared.
 */
static void test_selinux_reports_every_tunable(void)
{
	char tunables[16][64];
	int count = 0;
	char line[1024];
	bool derived = false;
	int iterating_targets = 0;
	static const char *const sources[] = { "selinux/lota.te",
					       "selinux/lota_gaming.te" };
	FILE *fp;

	TEST("selinux: the reported tunables are read from the policy");

	for (size_t i = 0; i < sizeof(sources) / sizeof(sources[0]); i++) {
		fp = open_shipped(sources[i]);
		if (!fp) {
			FAIL("could not open a policy source");
			return;
		}
		while (fgets(line, sizeof(line), fp)) {
			const char *p = strstr(line, "gen_tunable(");
			const char *end;
			size_t len;

			if (!p || line[0] == '#')
				continue;
			p += strlen("gen_tunable(");
			end = strchr(p, ',');
			if (!end || count == 16)
				continue;
			len = (size_t)(end - p);
			if (len >= sizeof(tunables[0]))
				continue;
			memcpy(tunables[count], p, len);
			tunables[count][len] = '\0';
			count++;
		}
		fclose(fp);
	}

	if (count == 0) {
		FAIL("no gen_tunable found; the parser or the policy moved");
		return;
	}

	fp = open_shipped("selinux/Makefile");
	if (!fp) {
		FAIL("could not open selinux/Makefile");
		return;
	}
	while (fgets(line, sizeof(line), fp)) {
		if (strstr(line, "TUNABLES") && strstr(line, "gen_tunable") &&
		    strstr(line, "$(TE_FILES)"))
			derived = true;
		if (strstr(line, "for bool in $(TUNABLES)"))
			iterating_targets++;

		/* a hand-kept second list is what drifted */
		for (int i = 0; i < count; i++) {
			if (strstr(line, tunables[i]) &&
			    !strstr(line, "TUNABLES")) {
				char msg[160];

				fclose(fp);
				snprintf(
					msg, sizeof(msg),
					"%.40s is named in the Makefile, so a hand-kept list is back",
					tunables[i]);
				FAIL(msg);
				return;
			}
		}
	}
	fclose(fp);

	if (!derived) {
		FAIL("TUNABLES is not read out of the policy sources");
		return;
	}
	/* make verify, and the banner make install prints */
	if (iterating_targets < 2) {
		char msg[128];

		snprintf(
			msg, sizeof(msg),
			"only %d target walks TUNABLES; verify and the install banner both must",
			iterating_targets);
		FAIL(msg);
		return;
	}
	PASS();
}

/*
 * A loadable module cannot carry port contexts, so a portcon in this tree
 * would be a rule that silently does nothing.
 */
static void test_selinux_policy_carries_no_portcon(void)
{
	static const char *const sources[] = { "selinux/lota.te",
					       "selinux/lota.fc",
					       "selinux/lota_gaming.te",
					       "selinux/lota_gaming.fc" };
	char line[1024];

	TEST("selinux: no source declares a port context");

	for (size_t i = 0; i < sizeof(sources) / sizeof(sources[0]); i++) {
		FILE *fp = open_shipped(sources[i]);

		if (!fp)
			continue;
		while (fgets(line, sizeof(line), fp)) {
			const char *p = line;

			/* the comments explain why there is none */
			while (*p == ' ' || *p == '\t')
				p++;
			if (*p == '#')
				continue;
			if (strstr(line, "portcon")) {
				fclose(fp);
				FAIL("a portcon was added; a loadable module cannot carry one");
				return;
			}
		}
		fclose(fp);
	}
	PASS();
}

/*
 * A title in a Proton container reaches the agent through the socket under
 * /run/user/<uid>/lota, user_tmp_t throughout. Every client interface must
 * pull in access to it, not only to the system socket under /var/lib/lota.
 */
static bool iface_body(const char *policy, const char *name, const char **body,
		       size_t *len)
{
	char want[64];
	const char *start, *end;

	snprintf(want, sizeof(want), "interface(`%.40s'", name);
	start = strstr(policy, want);
	if (!start)
		return false;
	start += strlen(want);
	end = strstr(start, "\n')");
	if (!end)
		return false;

	*body = start;
	*len = (size_t)(end - start);
	return true;
}

static bool body_grants_user_tmp(const char *body, size_t len)
{
	for (size_t i = 0; i + 8 <= len; i++) {
		if (strncmp(body + i, "user_tmp", 8) == 0)
			return true;
	}
	return false;
}

/* append the lota_* interfaces this body calls to the walk list */
static size_t iface_calls(const char *body, size_t len, char out[][64],
			  size_t max, size_t count)
{
	for (size_t i = 0; i + 5 < len; i++) {
		const char *p = body + i;
		size_t n = 0;

		if (i &&
		    (isalnum((unsigned char)body[i - 1]) || body[i - 1] == '_'))
			continue;
		if (strncmp(p, "lota_", 5) != 0)
			continue;
		while (n + 1 < 64 && i + n < len &&
		       (isalnum((unsigned char)p[n]) || p[n] == '_'))
			n++;
		if (i + n >= len || p[n] != '(')
			continue;
		if (count == max)
			break;
		memcpy(out[count], p, n);
		out[count][n] = '\0';
		count++;
	}
	return count;
}

static void test_selinux_gaming_client_reaches_container_socket(void)
{
	static const char *const road[] = { "lota_gaming_client",
					    "lota_anticheat_client" };
	enum {
		WALK_MAX = 16
	};
	static char policy[65536];
	static char walk[WALK_MAX][64];
	FILE *fp;
	size_t got;

	TEST("selinux: the client interfaces reach the container socket");

	fp = open_shipped("selinux/lota.if");
	if (!fp) {
		FAIL("could not open selinux/lota.if");
		return;
	}
	got = fread(policy, 1, sizeof(policy) - 1, fp);
	fclose(fp);
	policy[got] = '\0';

	for (size_t i = 0; i < sizeof(road) / sizeof(road[0]); i++) {
		size_t seen = 1;
		bool reaches = false;

		snprintf(walk[0], sizeof(walk[0]), "%s", road[i]);

		for (size_t j = 0; j < seen && !reaches; j++) {
			const char *body;
			size_t len;

			if (!iface_body(policy, walk[j], &body, &len)) {
				FAIL("an interface the reference names is not defined");
				return;
			}
			if (body_grants_user_tmp(body, len)) {
				reaches = true;
				break;
			}
			seen = iface_calls(body, len, walk, WALK_MAX, seen);
		}

		if (!reaches) {
			char msg[128];

			snprintf(msg, sizeof(msg),
				 "%s grants no access to the per-user socket",
				 road[i]);
			FAIL(msg);
			return;
		}
	}
	PASS();
}

int main(void)
{
	printf("=== LOTA Packaging Tests ===\n\n");

	test_packaged_unit_does_not_set_mode();
	test_attest_unit_config_driven();
	test_attest_unit_isolated();
	test_no_preset_is_shipped();
	test_installer_enables_the_units();
	test_documented_selinux_interfaces_exist();
	test_selinux_interfaces_are_installed();
	test_selinux_reports_every_tunable();
	test_selinux_policy_carries_no_portcon();
	test_selinux_gaming_client_reaches_container_socket();

	printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
	return (tests_passed == tests_run) ? 0 : 1;
}
