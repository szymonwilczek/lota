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

/* whole file into caller's buffer, NUL-terminated; 0 when it cannot be read */
static size_t slurp_shipped(const char *rel, char *buf, size_t cap)
{
	FILE *fp = open_shipped(rel);
	size_t got;

	if (!fp)
		return 0;
	got = fread(buf, 1, cap - 1, fp);
	fclose(fp);
	buf[got] = '\0';
	return got;
}

/*
 * One argv literal, from the command name to the closing brace.
 * Every run_cmd() call in the installer builds one, so a claim about what
 * a step runs is a claim about the tokens between those two points.
 */
static bool argv_window(const char *src, const char *cmd, size_t skip,
			const char **win, size_t *len)
{
	char want[32];
	const char *start, *end;

	snprintf(want, sizeof(want), "\"%.24s\"", cmd);
	for (start = src; skip > 0; skip--) {
		start = strstr(start, want);
		if (!start)
			return false;
		start += strlen(want);
	}
	start = strstr(start, want);
	if (!start)
		return false;
	end = strstr(start, "};");
	if (!end)
		return false;
	*win = start;
	*len = (size_t)(end - start);
	return true;
}

static bool win_has(const char *win, size_t len, const char *tok)
{
	const char *hit = strstr(win, tok);

	return hit && (size_t)(hit - win) < len;
}

/*
 * lota.fc gives /etc/lota lota_etc_t; unless the installer restorecons it,
 * lota.conf, policy.key, the CA anchors and every later file keep etc_t.
 */
static void test_installer_labels_the_config_directory(void)
{
	static char src[262144];
	bool labelled = false;

	TEST("installer: restorecons the config directory");

	if (!slurp_shipped("installer/stages.c", src, sizeof(src))) {
		FAIL("could not open installer/stages.c");
		return;
	}

	for (size_t i = 0; i < 8 && !labelled; i++) {
		const char *win;
		size_t len;

		if (!argv_window(src, "restorecon", i, &win, &len))
			break;
		labelled = win_has(win, len, "PATH_LOTA_CONF_DIR");
	}

	if (!labelled) {
		FAIL("no restorecon reaches the config directory");
		return;
	}
	PASS();
}

/*
 * SECLABEL{selinux} is applied when udev adds the device, so a trigger that
 * sends the default change event re-runs the rules and moves no label.
 * The step reports success and leaves both nodes where they were.
 */
static void test_installer_relabel_reapplies_the_device_labels(void)
{
	static char src[262144];
	const char *win;
	size_t len;

	TEST("installer: the TPM relabel re-applies SECLABEL");

	if (!slurp_shipped("installer/stages.c", src, sizeof(src))) {
		FAIL("could not open installer/stages.c");
		return;
	}
	if (!argv_window(src, "trigger", 0, &win, &len)) {
		FAIL("the installer triggers no udev relabel");
		return;
	}
	if (!win_has(win, len, "--action=add")) {
		FAIL("the udev trigger sends a change event, which re-applies no label");
		return;
	}
	if (!win_has(win, len, "/dev/tpmrm0") ||
	    !win_has(win, len, "/dev/tpm0")) {
		FAIL("the udev trigger does not name both TPM nodes");
		return;
	}
	PASS();
}

/*
 * The resource manager is in subsystem tpmrm, not tpm, and it is the node the
 * agent's gate reads first. A documented remedy matching on tpm alone brings
 * /dev/tpm0 back, exits 0, and leaves the agent refusing for the same reason
 * the operator was told to fix.
 */
static void test_documented_tpm_relabel_reaches_both_nodes(void)
{
	static const char *const pages[] = { "configs/udev/99-lota-tpm.rules",
					     "selinux/README.rst" };

	TEST("docs: the TPM relabel command reaches both nodes");

	for (size_t i = 0; i < sizeof(pages) / sizeof(pages[0]); i++) {
		FILE *fp = open_shipped(pages[i]);
		char cmd[2048];
		char line[1024];
		bool saw = false;

		if (!fp) {
			FAIL("could not open a page that documents the relabel");
			return;
		}
		while (fgets(cmd, sizeof(cmd), fp)) {
			char *cont = strchr(cmd, '\\');

			/* a wrapped command is still one command */
			while (cont && cont[1] == '\n' &&
			       fgets(line, sizeof(line), fp)) {
				snprintf(cont,
					 sizeof(cmd) - (size_t)(cont - cmd),
					 " %s", line);
				cont = strchr(cmd, '\\');
			}
			if (!strstr(cmd, "udevadm trigger"))
				continue;
			saw = true;
			if (!strstr(cmd, "--action=add") ||
			    !strstr(cmd, "tpmrm")) {
				fclose(fp);
				FAIL("a documented trigger leaves /dev/tpmrm0 where it was");
				return;
			}
		}
		fclose(fp);
		if (!saw) {
			FAIL("a page that documents the relabel names no trigger");
			return;
		}
	}
	PASS();
}

/*
 * The monitoring API reads one credential header, Authorization: Bearer
 * (src/verifier/server/api.go::extractBearerToken), so a page that hands
 * a reader an API key in any other header hands them a request that authenticates
 * nothing. On an instance with no key configured the reader endpoints are public,
 * so the wrong header still answers 200 and hides that it was never read;
 * the moment a key is configured every copy of it is a 401.
 */
static void lowercase(const char *src, char *dst, size_t dst_size)
{
	size_t i;

	for (i = 0; i < dst_size - 1 && src[i]; i++)
		dst[i] = (char)tolower((unsigned char)src[i]);
	dst[i] = '\0';
}

static void test_documented_api_calls_use_the_bearer_header(void)
{
	static const char *const pages[] = {
		"examples/ha-postgres/README.rst",
		"Documentation/operator/production-bringup/ca-enrollment.rst",
		"Documentation/operator/observability.rst",
	};

	TEST("docs: every documented API call sends Authorization: Bearer");

	for (size_t i = 0; i < sizeof(pages) / sizeof(pages[0]); i++) {
		FILE *fp = open_shipped(pages[i]);
		char line[1024];
		char lower[1024];
		bool saw = false;

		if (!fp) {
			FAIL("could not open a page that calls the API");
			return;
		}
		while (fgets(line, sizeof(line), fp)) {
			/* a header carrying a credential, whichever name it was given */
			if (!strstr(line, "-H \""))
				continue;
			lowercase(line, lower, sizeof(lower));
			if (!strstr(lower, "key") && !strstr(lower, "token") &&
			    !strstr(lower, "bearer"))
				continue;
			saw = true;
			if (!strstr(line, "Authorization: Bearer")) {
				fclose(fp);
				FAIL("a documented call authenticates with a header the API never reads");
				return;
			}
		}
		fclose(fp);
		if (!saw) {
			FAIL("a page that calls the API sends no credential at all");
			return;
		}
	}
	PASS();
}

/*
 * Reads one shipped command per call, joining the backslash continuations a script
 * or a code block wraps a long invocation over.
 * Returns false at end of file.
 */
static bool next_command(FILE *fp, char *cmd, size_t cmd_size)
{
	char line[1024];
	char *cont;

	if (!fgets(cmd, (int)cmd_size, fp))
		return false;

	cont = strrchr(cmd, '\\');
	while (cont && cont[1] == '\n' && fgets(line, sizeof(line), fp)) {
		snprintf(cont, cmd_size - (size_t)(cont - cmd), " %s", line);
		cont = strrchr(cmd, '\\');
	}
	return true;
}

/*
 * The enrollment example runs on a host with a real TPM. A firmware TPM's EK
 * chains through intermediates to the vendor root, so its trust material is a
 * bundle directory; passed as a single anchor, the CA refuses the host's EK.
 * The agent refuses --server while publisher profiles are configured, so the
 * attest step brings its own config.
 */
static void test_enrollment_example_runs_on_a_provisioned_host(void)
{
	FILE *fp = open_shipped("examples/enrollment/run.sh");
	char cmd[4096];
	bool classes_ek_material = false;
	bool bundle_flag = false;
	bool saw_attest = false;

	TEST("examples: the enrollment demo runs on a host with a TPM chain");

	if (!fp) {
		FAIL("could not open the enrollment example");
		return;
	}
	while (next_command(fp, cmd, sizeof(cmd))) {
		if (strstr(cmd, "-ek-root-bundle"))
			bundle_flag = true;
		/* whichever flag the material gets, the script picks it by asking */
		if (strstr(cmd, "-d \"$EK_ROOT\""))
			classes_ek_material = true;
		if (!strstr(cmd, "--attest"))
			continue;
		saw_attest = true;
		if (!strstr(cmd, "--config")) {
			fclose(fp);
			FAIL("the attest step is refused on any host that configured a publisher");
			return;
		}
	}
	fclose(fp);

	if (!bundle_flag || !classes_ek_material) {
		FAIL("a vendor EK chain has no way to reach the CA");
		return;
	}
	if (!saw_attest) {
		FAIL("the example no longer attests");
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
	test_documented_selinux_interfaces_exist();
	test_selinux_interfaces_are_installed();
	test_selinux_reports_every_tunable();
	test_selinux_policy_carries_no_portcon();
	test_selinux_gaming_client_reaches_container_socket();
	test_installer_labels_the_config_directory();
	test_installer_relabel_reapplies_the_device_labels();
	test_documented_tpm_relabel_reaches_both_nodes();
	test_documented_api_calls_use_the_bearer_header();
	test_enrollment_example_runs_on_a_provisioned_host();

	printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
	return (tests_passed == tests_run) ? 0 : 1;
}
