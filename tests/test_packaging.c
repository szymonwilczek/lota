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
		if (strstr(line, "ConditionPathExists=") &&
		    strstr(line, "/var/lib/lota/enroll_state.dat"))
			enroll_gate = true;
	}
	fclose(fp);

	if (powerful_cap) {
		FAIL("attest unit must not hold BPF/admin/rawio caps");
		return;
	}
	if (!enroll_gate) {
		FAIL("attest unit must gate on enroll_state.dat");
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

int main(void)
{
	printf("=== LOTA Packaging Tests ===\n\n");

	test_packaged_unit_does_not_set_mode();
	test_attest_unit_config_driven();
	test_attest_unit_isolated();
	test_no_preset_is_shipped();
	test_installer_enables_the_units();

	printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
	return (tests_passed == tests_run) ? 0 : 1;
}
