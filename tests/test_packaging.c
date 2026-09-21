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
#include <dirent.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

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

enum {
	TYPE_LEN = 64,
	TYPES_MAX = 32
};

/* the argument a flag takes on a command line, e.g. -s lota_agent_t */
static bool cmd_flag_arg(const char *cmd, const char *flag, char *out,
			 size_t cap)
{
	const char *p = strstr(cmd, flag);
	size_t n = 0;

	if (!p)
		return false;
	p += strlen(flag);
	while (*p == ' ')
		p++;
	while (n + 1 < cap && *p && !isspace((unsigned char)*p))
		out[n++] = *p++;
	out[n] = '\0';
	return n > 0;
}

/*
 * Types the LOTA policy declares itself. gen_require() names are indented,
 * so only a line opening with "type " is a declaration.
 */
static size_t lota_declared_types(char types[][TYPE_LEN], size_t cap)
{
	static const char *const sources[] = { "selinux/lota.te",
					       "selinux/lota_gaming.te" };
	size_t n = 0;

	for (size_t i = 0; i < sizeof(sources) / sizeof(sources[0]); i++) {
		FILE *fp = open_shipped(sources[i]);
		char line[512];

		if (!fp)
			return 0;
		while (n < cap && fgets(line, sizeof(line), fp)) {
			char *semi;

			if (strncmp(line, "type ", 5) != 0)
				continue;
			semi = strchr(line + 5, ';');
			if (!semi)
				continue;
			*semi = '\0';
			if (strlen(line + 5) >= TYPE_LEN)
				continue;
			memcpy(types[n++], line + 5, strlen(line + 5) + 1);
		}
		fclose(fp);
	}
	return n;
}

static const char *shell_command(const char *line)
{
	while (isspace((unsigned char)*line))
		line++;
	if (strncmp(line, "sudo ", 5) == 0)
		line += 5;
	return line;
}

/*
 * A documented sesearch must answer with the module's own rules: from a type
 * the policy declares, matched literally (-ds -dt). A domain a gaming block
 * only requires may be undeclared, and sesearch refuses the search ("steam_t
 * is not a valid type attribute"); an unconfined one has its module rules
 * dropped as redundant, and attribute expansion answers with base-policy
 * rules instead.
 */
static void test_selinux_reference_searches_the_modules_own_rules(void)
{
	char types[TYPES_MAX][TYPE_LEN];
	size_t ntypes;
	FILE *fp;
	char line[1024];
	bool saw = false;

	TEST("selinux: documented searches match the module's rules");

	ntypes = lota_declared_types(types, TYPES_MAX);
	if (!ntypes) {
		FAIL("the policy sources declare no types to search for");
		return;
	}
	fp = open_shipped("selinux/README.rst");
	if (!fp) {
		FAIL("could not open selinux/README.rst");
		return;
	}
	while (fgets(line, sizeof(line), fp)) {
		const char *cmd = shell_command(line);
		char src[TYPE_LEN];
		bool ours = false;

		if (strncmp(cmd, "sesearch", 8) != 0)
			continue;
		saw = true;
		if (!cmd_flag_arg(cmd, "-s ", src, sizeof(src))) {
			fclose(fp);
			FAIL("a documented search names no source domain");
			return;
		}
		for (size_t i = 0; i < ntypes; i++) {
			if (strcmp(types[i], src) == 0)
				ours = true;
		}
		if (!ours) {
			fclose(fp);
			FAIL("a documented search starts from a domain the policy need not declare");
			return;
		}
		if (!strstr(cmd, "-ds") || !strstr(cmd, "-dt")) {
			fclose(fp);
			FAIL("a documented search lets attribute rules answer for the module");
			return;
		}
	}
	fclose(fp);
	if (!saw) {
		FAIL("the reference documents no search at all");
		return;
	}
	PASS();
}

static void rstrip(char *line)
{
	size_t n = strlen(line);

	while (n && isspace((unsigned char)line[n - 1]))
		line[--n] = '\0';
}

/* one command, backslash continuations folded in */
static bool read_command(FILE *fp, char *cmd, size_t cap)
{
	char *cont;

	if (!fgets(cmd, (int)cap, fp))
		return false;
	rstrip(cmd);
	cont = cmd + strlen(cmd);
	while (cont > cmd && cont[-1] == '\\') {
		char more[512];

		cont[-1] = '\0';
		if (!fgets(more, sizeof(more), fp))
			break;
		rstrip(more);
		snprintf(cmd + strlen(cmd), cap - strlen(cmd), "%s", more);
		cont = cmd + strlen(cmd);
	}
	return true;
}

static bool rst_underline(const char *line)
{
	size_t n = strlen(line);

	if (n < 3 || isalnum((unsigned char)line[0]) ||
	    isspace((unsigned char)line[0]))
		return false;
	for (size_t i = 1; i < n; i++) {
		if (line[i] != line[0])
			return false;
	}
	return true;
}

/*
 * A lockout grep spelled differently from tpm2_getcap's output matches
 * nothing, which reads as a healthy TPM.
 * Every alternative must match a line of the page's own sample output.
 */
static void test_lockout_runbook_matches_what_the_chip_prints(void)
{
	enum {
		SAMPLE_MAX = 16
	};
	char sample[SAMPLE_MAX][256];
	size_t nsample = 0;
	char line[256];
	char cmd[1024];
	char pattern[512];
	char *open_quote;
	char *close_quote;
	char *alt;
	FILE *fp;
	bool found = false;

	TEST("selinux: the lockout search matches what the chip prints");

	fp = open_shipped("selinux/README.rst");
	if (!fp) {
		FAIL("could not open selinux/README.rst");
		return;
	}
	while (read_command(fp, cmd, sizeof(cmd))) {
		if (strstr(cmd, "tpm2_getcap properties-variable")) {
			found = true;
			break;
		}
	}
	if (!found) {
		fclose(fp);
		FAIL("the runbook reads no variable properties off the chip");
		return;
	}
	open_quote = strstr(cmd, "grep -E \"");
	if (!open_quote) {
		fclose(fp);
		FAIL("the lockout confirmation matches the dump against nothing");
		return;
	}
	open_quote += strlen("grep -E \"");
	close_quote = strchr(open_quote, '"');
	if (!close_quote) {
		fclose(fp);
		FAIL("the lockout confirmation has an unterminated pattern");
		return;
	}
	*close_quote = '\0';
	snprintf(pattern, sizeof(pattern), "%s", open_quote);

	/* the sample's literal block, within this section only */
	while (fgets(line, sizeof(line), fp)) {
		rstrip(line);
		if (!nsample) {
			size_t n = strlen(line);

			if (rst_underline(line))
				break;
			if (n >= 2 && line[n - 1] == ':' && line[n - 2] == ':')
				nsample = 1;
			continue;
		}
		if (!line[0])
			continue;
		if (!isspace((unsigned char)line[0]))
			break;
		if (nsample - 1 < SAMPLE_MAX)
			snprintf(sample[nsample - 1], sizeof(sample[0]), "%s",
				 line);
		nsample++;
	}
	fclose(fp);
	if (nsample < 2) {
		FAIL("the page quotes no output for the pattern to match");
		return;
	}
	for (alt = strtok(pattern, "|"); alt; alt = strtok(NULL, "|")) {
		bool hit = false;

		for (size_t i = 0; i + 1 < nsample && i < SAMPLE_MAX; i++) {
			if (strstr(sample[i], alt))
				hit = true;
		}
		if (!hit) {
			FAIL("the lockout confirmation matches on a field the chip does not print");
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
 * the operator was told to fix. A trigger without --action sends a change
 * event, which re-runs the rules and re-applies no SECLABEL, so a device that
 * lost its label keeps the stock one.
 */
static void test_documented_tpm_relabel_reaches_both_nodes(void)
{
	static const char *const pages[] = {
		"configs/udev/99-lota-tpm.rules",
		"selinux/README.rst",
		"Documentation/operator/production-bringup/manual-reference.rst",
		"Documentation/operator/production-bringup/gate-matrix.rst",
	};

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
			if (!strstr(cmd, "--action=add")) {
				fclose(fp);
				FAIL("a documented trigger sends a change event, which re-applies no label");
				return;
			}
			if (!strstr(cmd, "tpmrm")) {
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

/* true when line carries the boot parameter ima=, not ima_appraise= */
static bool line_sets_ima(const char *line)
{
	for (const char *p = strstr(line, "ima="); p;
	     p = strstr(p + 1, "ima=")) {
		if (p == line || isspace((unsigned char)p[-1]) ||
		    p[-1] == '"' || p[-1] == '\'')
			return true;
	}
	return false;
}

/*
 * Outside a kdump kernel ima= is refused with "ima setup option only
 * permitted in kdump", so a documented cmdline must not carry it.
 * The reference quotes this refusal beside the ima_appraise= one.
 */
static void test_documented_cmdline_carries_no_kdump_option(void)
{
	static const char *const pages[] = {
		"Documentation/operator/production-bringup/manual-reference.rst",
		"scripts/lota-dev-bringup.sh",
	};
	bool quoted = false;

	TEST("docs: a documented cmdline carries no kdump-only ima=");

	for (size_t i = 0; i < sizeof(pages) / sizeof(pages[0]); i++) {
		FILE *fp = open_shipped(pages[i]);
		char line[1024];
		bool saw = false;

		if (!fp) {
			FAIL("could not open a page that documents the cmdline");
			return;
		}
		while (fgets(line, sizeof(line), fp)) {
			if (strstr(line, "only permitted in kdump"))
				quoted = true;
			if (!strstr(line, "grubby") || !strstr(line, "--args"))
				continue;
			saw = true;
			if (line_sets_ima(line)) {
				fclose(fp);
				FAIL("a documented cmdline sets ima=, which the kernel refuses");
				return;
			}
		}
		fclose(fp);
		if (!saw) {
			FAIL("a page that documents the cmdline names no grubby --args");
			return;
		}
	}
	if (!quoted) {
		FAIL("the reference does not quote the kernel's ima= refusal");
		return;
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
static bool has_suffix(const char *name, const char *suffix)
{
	size_t n = strlen(name);
	size_t s = strlen(suffix);

	return n >= s && strcmp(name + n - s, suffix) == 0;
}

static void lowercase(const char *src, char *dst, size_t dst_size)
{
	size_t i;

	for (i = 0; i < dst_size - 1 && src[i]; i++)
		dst[i] = (char)tolower((unsigned char)src[i]);
	dst[i] = '\0';
}

/* False at the first credential header that is not Bearer; names the page */
static bool page_credentials_are_readable(const char *path, bool *saw_any,
					  char *offender, size_t offender_size)
{
	FILE *fp = fopen(path, "re");
	char line[1024];
	char lower[1024];

	if (!fp)
		return true;

	while (fgets(line, sizeof(line), fp)) {
		/* any header carrying a credential */
		if (!strstr(line, "-H \""))
			continue;
		lowercase(line, lower, sizeof(lower));
		if (!strstr(lower, "key") && !strstr(lower, "token") &&
		    !strstr(lower, "bearer"))
			continue;
		*saw_any = true;
		if (!strstr(line, "Authorization: Bearer")) {
			snprintf(
				offender, offender_size,
				"%.400s authenticates with a header the API never reads",
				path);
			fclose(fp);
			return false;
		}
	}
	fclose(fp);
	return true;
}

/* Every shipped page, not a list that misses the next one */
static bool pages_under(const char *dir, bool *saw_any, char *offender,
			size_t offender_size)
{
	DIR *d = opendir(dir);
	struct dirent *ent;
	bool ok = true;

	if (!d)
		return true;

	while (ok && (ent = readdir(d)) != NULL) {
		char path[512];

		/* _build is rendered copies, not pages */
		if (ent->d_name[0] == '.' || strcmp(ent->d_name, "_build") == 0)
			continue;

		snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);
		if (ent->d_type == DT_DIR) {
			ok = pages_under(path, saw_any, offender,
					 offender_size);
			continue;
		}
		if (has_suffix(ent->d_name, ".rst") ||
		    has_suffix(ent->d_name, ".md"))
			ok = page_credentials_are_readable(
				path, saw_any, offender, offender_size);
	}
	closedir(d);
	return ok;
}

static void test_documented_api_calls_use_the_bearer_header(void)
{
	static const char *const roots[] = { "Documentation", "examples" };
	char offender[512];
	bool saw = false;
	size_t i;

	TEST("docs: every documented API call sends Authorization: Bearer");

	for (i = 0; i < sizeof(roots) / sizeof(roots[0]); i++) {
		char root[512];
		struct stat st;

		snprintf(root, sizeof(root), "%s", roots[i]);
		if (stat(root, &st) != 0)
			snprintf(root, sizeof(root), "../%s", roots[i]);

		if (!pages_under(root, &saw, offender, sizeof(offender))) {
			FAIL(offender);
			return;
		}
	}

	if (!saw) {
		FAIL("no shipped page calls the API with a credential");
		return;
	}
	PASS();
}

/* check-patch runs the unit tests, as CI does; a gap shows only after a push */
static void test_the_gate_runs_the_unit_tests(void)
{
	FILE *fp = open_shipped("scripts/check-patch");
	char line[1024];
	bool defines = false;
	bool runs = false;
	bool invokes_make = false;

	TEST("check-patch: the gate runs the unit tests");

	if (!fp) {
		FAIL("could not open the gate");
		return;
	}
	while (fgets(line, sizeof(line), fp)) {
		if (strstr(line, "check_unit_tests()"))
			defines = true;
		else if (strstr(line, "check_unit_tests"))
			runs = true;
		if (strstr(line, "test-unit"))
			invokes_make = true;
	}
	fclose(fp);

	if (!defines || !invokes_make) {
		FAIL("the gate has no check that runs the unit tests");
		return;
	}
	if (!runs) {
		FAIL("the gate defines a unit-test check it never calls");
		return;
	}
	PASS();
}

#define SYMBOL_MAX 80
#define SYMBOLS_MAX 4096

/* LOTA_ tokens in code (string literals included, for getenv()) and comments */
static char code_symbols[SYMBOLS_MAX][SYMBOL_MAX];
static size_t code_symbol_count;
static char comment_symbols[SYMBOLS_MAX][SYMBOL_MAX];
static char comment_sources[SYMBOLS_MAX][160];
static size_t comment_symbol_count;

static bool symbol_seen(const char table[][SYMBOL_MAX], size_t count,
			const char *name)
{
	size_t i;

	for (i = 0; i < count; i++)
		if (strcmp(table[i], name) == 0)
			return true;
	return false;
}

/* A trailing underscore names a family (LOTA_ERR_), not a symbol */
static bool symbol_is_a_name(const char *tok)
{
	size_t len = strlen(tok);

	return len > 5 && tok[len - 1] != '_';
}

static void remember_symbol(char table[][SYMBOL_MAX], size_t *count,
			    const char *tok)
{
	if (*count >= SYMBOLS_MAX || symbol_seen(table, *count, tok))
		return;
	snprintf(table[*count], SYMBOL_MAX, "%s", tok);
	(*count)++;
}

static void remember_mention(const char *tok, const char *path)
{
	if (symbol_seen(comment_symbols, comment_symbol_count, tok))
		return;
	if (comment_symbol_count >= SYMBOLS_MAX)
		return;
	snprintf(comment_sources[comment_symbol_count],
		 sizeof(comment_sources[0]), "%s", path);
	remember_symbol(comment_symbols, &comment_symbol_count, tok);
}

static void keep_symbol(const char *tok, bool in_comment, const char *path)
{
	if (strncmp(tok, "LOTA_", 5) != 0 || !symbol_is_a_name(tok))
		return;
	if (in_comment)
		remember_mention(tok, path);
	else
		remember_symbol(code_symbols, &code_symbol_count, tok);
}

/* Collect LOTA_ tokens from code and from comments; literals count as code */
static void scan_source(const char *path)
{
	enum {
		CODE,
		BLOCK,
		LINE,
		STRING,
		CHARLIT
	} state = CODE;
	FILE *fp = fopen(path, "re");
	char tok[SYMBOL_MAX];
	size_t tok_len = 0;
	bool tok_in_comment = false;
	int c;

	if (!fp)
		return;

	while ((c = fgetc(fp)) != EOF) {
		bool in_comment = (state == BLOCK || state == LINE);

		if (isalnum(c) || c == '_') {
			if (tok_len == 0)
				tok_in_comment = in_comment;
			if (tok_len < sizeof(tok) - 1)
				tok[tok_len++] = (char)c;
			continue;
		}
		if (tok_len) {
			tok[tok_len] = '\0';
			keep_symbol(tok, tok_in_comment, path);
			tok_len = 0;
		}

		switch (state) {
		case CODE:
			if (c == '/') {
				int next = fgetc(fp);

				if (next == '*')
					state = BLOCK;
				else if (next == '/')
					state = LINE;
				else if (next != EOF)
					ungetc(next, fp);
			} else if (c == '"') {
				state = STRING;
			} else if (c == '\'') {
				state = CHARLIT;
			}
			break;
		case BLOCK:
			if (c == '*') {
				int next = fgetc(fp);

				if (next == '/')
					state = CODE;
				else if (next != EOF)
					ungetc(next, fp);
			}
			break;
		case LINE:
			if (c == '\n')
				state = CODE;
			break;
		case STRING:
		case CHARLIT:
			if (c == '\\')
				(void)fgetc(fp);
			else if ((state == STRING && c == '"') ||
				 (state == CHARLIT && c == '\''))
				state = CODE;
			break;
		}
	}
	if (tok_len) {
		tok[tok_len] = '\0';
		keep_symbol(tok, tok_in_comment, path);
	}
	fclose(fp);
}

static void sources_under(const char *dir)
{
	DIR *d = opendir(dir);
	struct dirent *ent;

	if (!d)
		return;

	while ((ent = readdir(d)) != NULL) {
		char path[512];

		if (ent->d_name[0] == '.')
			continue;

		snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);
		if (ent->d_type == DT_DIR) {
			sources_under(path);
			continue;
		}
		if (has_suffix(ent->d_name, ".c") ||
		    has_suffix(ent->d_name, ".h"))
			scan_source(path);
	}
	closedir(d);
}

/*
 * A comment naming a symbol the tree lacks fails silently: the reader sets
 * it and nothing changes. Renames cause it, so every comment is checked.
 */
static void test_comments_name_symbols_that_exist(void)
{
	static const char *const roots[] = { "src", "include", "tests",
					     "examples" };
	size_t i;

	TEST("sources: every comment names a symbol the tree defines");

	for (i = 0; i < sizeof(roots) / sizeof(roots[0]); i++) {
		char root[512];
		struct stat st;

		snprintf(root, sizeof(root), "%s", roots[i]);
		if (stat(root, &st) != 0)
			snprintf(root, sizeof(root), "../%s", roots[i]);
		sources_under(root);
	}

	if (!code_symbol_count || !comment_symbol_count) {
		FAIL("no sources were read");
		return;
	}

	for (i = 0; i < comment_symbol_count; i++) {
		char msg[512];

		if (symbol_seen(code_symbols, code_symbol_count,
				comment_symbols[i]))
			continue;

		snprintf(msg, sizeof(msg),
			 "%.160s names %.80s, which the tree does not define",
			 comment_sources[i], comment_symbols[i]);
		FAIL(msg);
		return;
	}
	PASS();
}

#define PAGE_SYMBOLS_MAX 1024

/* LOTA_ tokens the pages name, and those the tree spells outside its prose */
static char tree_symbols[SYMBOLS_MAX][SYMBOL_MAX];
static size_t tree_symbol_count;
static char page_symbols[PAGE_SYMBOLS_MAX][SYMBOL_MAX];
static char page_sources[PAGE_SYMBOLS_MAX][160];
static size_t page_symbol_count;

static void remember_page_mention(const char *tok, const char *path)
{
	if (symbol_seen(page_symbols, page_symbol_count, tok))
		return;
	if (page_symbol_count >= PAGE_SYMBOLS_MAX)
		return;
	snprintf(page_sources[page_symbol_count], sizeof(page_sources[0]), "%s",
		 path);
	snprintf(page_symbols[page_symbol_count], SYMBOL_MAX, "%s", tok);
	page_symbol_count++;
}

static void keep_tree_symbol(const char *tok, bool on_a_page, const char *path)
{
	if (strncmp(tok, "LOTA_", 5) != 0 || !symbol_is_a_name(tok))
		return;
	if (on_a_page)
		remember_page_mention(tok, path);
	else
		remember_symbol(tree_symbols, &tree_symbol_count, tok);
}

/* Pages and build files are flat text: every LOTA_ token counts */
static void scan_flat(const char *path, bool on_a_page)
{
	FILE *fp = fopen(path, "re");
	char tok[SYMBOL_MAX];
	size_t tok_len = 0;
	int c;

	if (!fp)
		return;

	while ((c = fgetc(fp)) != EOF) {
		if (isalnum(c) || c == '_') {
			if (tok_len < sizeof(tok) - 1)
				tok[tok_len++] = (char)c;
			continue;
		}
		if (tok_len) {
			tok[tok_len] = '\0';
			keep_tree_symbol(tok, on_a_page, path);
			tok_len = 0;
		}
	}
	if (tok_len) {
		tok[tok_len] = '\0';
		keep_tree_symbol(tok, on_a_page, path);
	}
	fclose(fp);
}

/* generated output and unshipped notes */
static bool walk_skips(const char *name)
{
	return strcmp(name, "build") == 0 || strcmp(name, "docs") == 0;
}

static void texts_under(const char *dir)
{
	DIR *d = opendir(dir);
	struct dirent *ent;

	if (!d)
		return;

	while ((ent = readdir(d)) != NULL) {
		char path[512];
		bool on_a_page;

		if (ent->d_name[0] == '.' || walk_skips(ent->d_name))
			continue;

		if (dir[0] == '.' && dir[1] == '\0')
			snprintf(path, sizeof(path), "%s", ent->d_name);
		else
			snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);

		if (ent->d_type == DT_DIR) {
			texts_under(path);
			continue;
		}
		on_a_page = has_suffix(ent->d_name, ".rst") ||
			    has_suffix(ent->d_name, ".md");
		scan_flat(path, on_a_page);
	}
	closedir(d);
}

/* A page naming a symbol the tree lacks sends its reader after nothing */
static void test_pages_name_symbols_that_exist(void)
{
	struct stat st;
	size_t i;

	TEST("docs: every shipped page names a symbol the tree defines");

	texts_under(stat("src", &st) == 0 ? "." : "..");

	if (!tree_symbol_count || !page_symbol_count) {
		FAIL("no pages were read");
		return;
	}

	for (i = 0; i < page_symbol_count; i++) {
		char msg[512];

		if (symbol_seen(tree_symbols, tree_symbol_count,
				page_symbols[i]))
			continue;

		snprintf(msg, sizeof(msg),
			 "%.160s names %.80s, which the tree does not define",
			 page_sources[i], page_symbols[i]);
		FAIL(msg);
		return;
	}
	PASS();
}

#define PACKAGES_MAX 16
#define PACKAGE_NAME_MAX 64
#define PACKAGE_BINS_MAX 8
#define PACKAGE_DEPS_MAX 8

struct package {
	char name[PACKAGE_NAME_MAX];
	char bins[PACKAGE_BINS_MAX][PACKAGE_NAME_MAX];
	size_t bin_count;
	char deps[PACKAGE_DEPS_MAX][PACKAGE_NAME_MAX];
	size_t dep_count;
};

static struct package packages[PACKAGES_MAX];
static size_t package_count;
static char install_offender[512];

/* yaml scalar or list item up to the first space */
static void first_word(const char *src, char *dst, size_t dst_size)
{
	size_t i;

	for (i = 0; i < dst_size - 1 && src[i] && src[i] != ' '; i++)
		dst[i] = src[i];
	dst[i] = '\0';
}

/* One nfpm manifest: name, /usr/bin commands, lota- dependencies */
static void read_manifest(const char *dir, const char *file)
{
	char path[512];
	char line[1024];
	struct package *pkg;
	FILE *fp;
	bool in_depends = false;

	if (package_count == PACKAGES_MAX)
		return;
	snprintf(path, sizeof(path), "%s/packaging/nfpm/%s", dir, file);
	fp = fopen(path, "re");
	if (!fp)
		return;

	pkg = &packages[package_count++];
	memset(pkg, 0, sizeof(*pkg));

	while (fgets(line, sizeof(line), fp)) {
		const char *p = line;
		const char *dst;

		rstrip(line);
		if (strncmp(line, "name: ", 6) == 0) {
			first_word(line + 6, pkg->name, sizeof(pkg->name));
			continue;
		}

		while (*p == ' ' || *p == '\t')
			p++;
		if (strcmp(p, "depends:") == 0) {
			in_depends = true;
			continue;
		}
		if (in_depends) {
			if (*p != '-') {
				in_depends = false;
			} else {
				p++;
				while (*p == ' ')
					p++;
				if (strncmp(p, "lota-", 5) == 0 &&
				    pkg->dep_count < PACKAGE_DEPS_MAX)
					first_word(p,
						   pkg->deps[pkg->dep_count++],
						   PACKAGE_NAME_MAX);
				continue;
			}
		}

		dst = strstr(line, "dst: /usr/bin/");
		if (dst && pkg->bin_count < PACKAGE_BINS_MAX)
			first_word(dst + strlen("dst: /usr/bin/"),
				   pkg->bins[pkg->bin_count++],
				   PACKAGE_NAME_MAX);
	}
	fclose(fp);
}

static struct package *package_named(const char *name)
{
	size_t i;

	for (i = 0; i < package_count; i++)
		if (strcmp(packages[i].name, name) == 0)
			return &packages[i];
	return NULL;
}

static bool package_ships(const struct package *pkg, const char *cmd)
{
	size_t i;

	for (i = 0; i < pkg->bin_count; i++)
		if (strcmp(pkg->bins[i], cmd) == 0)
			return true;
	return false;
}

/* Does any package this tree builds ship `cmd`? */
static bool tree_ships_command(const char *cmd)
{
	size_t i;

	for (i = 0; i < package_count; i++)
		if (package_ships(&packages[i], cmd))
			return true;
	return false;
}

/* An install brings the dependency closure; depth bounded by package count */
static bool install_reaches(const char *name, const char *cmd, size_t depth)
{
	const struct package *pkg = package_named(name);
	size_t i;

	if (!pkg || depth > package_count)
		return false;
	if (package_ships(pkg, cmd))
		return true;
	for (i = 0; i < pkg->dep_count; i++)
		if (install_reaches(pkg->deps[i], cmd, depth + 1))
			return true;
	return false;
}

/* Program an indented line runs, past sudo and VAR=value; else prose */
static bool command_word(const char *line, char *out, size_t out_size)
{
	const char *p = line;
	size_t n = 0;

	if (*p != ' ' && *p != '\t')
		return false;
	while (*p == ' ' || *p == '\t')
		p++;

	while (*p) {
		const char *sp = strchr(p, ' ');

		if (strncmp(p, "sudo ", 5) == 0)
			p += 5;
		else if (sp && memchr(p, '=', (size_t)(sp - p)))
			p = sp + 1;
		else
			break;
		while (*p == ' ')
			p++;
	}

	while ((islower((unsigned char)*p) || isdigit((unsigned char)*p) ||
		*p == '-') &&
	       n < out_size - 1)
		out[n++] = *p++;
	out[n] = '\0';
	return n > 0;
}

/* False at the first command the page runs that its installs do not ship */
static bool page_commands_are_installed(const char *path)
{
	char installs[4][PACKAGE_NAME_MAX];
	size_t install_count = 0;
	char line[1024];
	FILE *fp = fopen(path, "re");

	if (!fp)
		return true;

	while (fgets(line, sizeof(line), fp)) {
		char cmd[PACKAGE_NAME_MAX];
		size_t i;

		rstrip(line);

		if (strstr(line, "dnf install")) {
			const char *p = strstr(line, "lota-");

			if (p && install_count < 4)
				first_word(p, installs[install_count++],
					   PACKAGE_NAME_MAX);
			continue;
		}

		/* nothing to hold the page to until it has named a package */
		if (!install_count)
			continue;
		if (!command_word(line, cmd, sizeof(cmd)))
			continue;
		if (strncmp(cmd, "lota-", 5) != 0 || !tree_ships_command(cmd))
			continue;

		for (i = 0; i < install_count; i++)
			if (install_reaches(installs[i], cmd, 0))
				break;
		if (i == install_count) {
			snprintf(
				install_offender, sizeof(install_offender),
				"%.200s runs %.60s, which %.60s does not install",
				path, cmd, installs[0]);
			fclose(fp);
			return false;
		}
	}
	fclose(fp);
	return true;
}

static bool commands_under(const char *dir)
{
	DIR *d = opendir(dir);
	struct dirent *ent;
	bool ok = true;

	if (!d)
		return true;

	while (ok && (ent = readdir(d)) != NULL) {
		char path[512];

		if (ent->d_name[0] == '.' || strcmp(ent->d_name, "_build") == 0)
			continue;

		snprintf(path, sizeof(path), "%s/%s", dir, ent->d_name);
		if (ent->d_type == DT_DIR) {
			ok = commands_under(path);
			continue;
		}
		if (has_suffix(ent->d_name, ".rst") ||
		    has_suffix(ent->d_name, ".md"))
			ok = page_commands_are_installed(path);
	}
	closedir(d);
	return ok;
}

/* Fixture manifest at <dir>/packaging/nfpm/<file> */
static bool write_manifest(const char *dir, const char *file, const char *body)
{
	char path[512];
	int fd;
	FILE *fp;

	snprintf(path, sizeof(path), "%s/packaging/nfpm/%s", dir, file);
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	fp = fd >= 0 ? fdopen(fd, "w") : NULL;
	if (!fp) {
		if (fd >= 0)
			close(fd);
		return false;
	}
	fputs(body, fp);
	return fclose(fp) == 0;
}

static void unlink_manifest(const char *dir, const char *file)
{
	char path[512];

	snprintf(path, sizeof(path), "%s/packaging/nfpm/%s", dir, file);
	unlink(path);
}

/* A comment or blank line inside a list must not drop the entries below */
static void test_manifest_lists_survive_a_comment(void)
{
	static const char plain[] = "name: lota-probe\n"
				    "overrides:\n"
				    "  rpm:\n"
				    "    depends:\n"
				    "      - lota-sdk = 1.0\n"
				    "      - lota-verifier\n"
				    "\n"
				    "contents:\n"
				    "  - src: ./stage/probe\n"
				    "    dst: /usr/bin/probe\n";
	static const char commented[] =
		"name: lota-probe\n"
		"overrides:\n"
		"  rpm:\n"
		"    depends:\n"
		"      # the headers were written against this soname\n"
		"      - lota-sdk = 1.0\n"
		"\n"
		"      # the fleet half, which the probe reports to\n"
		"      - lota-verifier\n"
		"\n"
		"contents:\n"
		"  - src: ./stage/probe\n"
		"    dst: /usr/bin/probe\n";
	char dir[] = "/tmp/lota_test_manifest_XXXXXX";
	char nfpm[320];
	struct package *pkg;
	char msg[256];
	size_t i, plain_deps;
	char plain_names[PACKAGE_DEPS_MAX][PACKAGE_NAME_MAX];

	TEST("packaging: a comment inside a manifest list ends nothing");

	if (!mkdtemp(dir)) {
		FAIL("could not make a scratch directory");
		return;
	}
	snprintf(nfpm, sizeof(nfpm), "%s/packaging", dir);
	if (mkdir(nfpm, 0700) != 0) {
		FAIL("could not make the fixture tree");
		goto out;
	}
	snprintf(nfpm, sizeof(nfpm), "%s/packaging/nfpm", dir);
	if (mkdir(nfpm, 0700) != 0) {
		FAIL("could not make the fixture tree");
		goto out;
	}

	if (!write_manifest(dir, "plain.yaml", plain) ||
	    !write_manifest(dir, "commented.yaml", commented)) {
		FAIL("could not write the fixture manifests");
		goto out;
	}

	package_count = 0;
	read_manifest(dir, "plain.yaml");
	read_manifest(dir, "commented.yaml");
	if (package_count != 2) {
		FAIL("the fixture manifests were not read");
		goto out;
	}

	/* both are lota-probe; packages[0] is plain.yaml */
	plain_deps = packages[0].dep_count;
	for (i = 0; i < plain_deps; i++)
		snprintf(plain_names[i], PACKAGE_NAME_MAX, "%s",
			 packages[0].deps[i]);

	if (plain_deps != 2) {
		snprintf(
			msg, sizeof(msg),
			"the uncommented manifest read %zu dependencies, not 2",
			plain_deps);
		FAIL(msg);
		goto out;
	}

	pkg = &packages[1];
	if (pkg->dep_count != plain_deps) {
		snprintf(
			msg, sizeof(msg),
			"a comment inside depends hid %zu of %zu entries under it",
			plain_deps - pkg->dep_count, plain_deps);
		FAIL(msg);
		goto out;
	}
	for (i = 0; i < plain_deps; i++)
		if (strcmp(pkg->deps[i], plain_names[i]) != 0) {
			snprintf(
				msg, sizeof(msg),
				"the commented manifest read '%.*s' where the plain one read '%.*s'",
				(int)PACKAGE_NAME_MAX, pkg->deps[i],
				(int)PACKAGE_NAME_MAX, plain_names[i]);
			FAIL(msg);
			goto out;
		}

	/* the next key still ends the list */
	if (pkg->bin_count != 1 || strcmp(pkg->bins[0], "probe") != 0) {
		FAIL("the commented manifest lost the command it ships");
		goto out;
	}

	PASS();
out:
	unlink_manifest(dir, "plain.yaml");
	unlink_manifest(dir, "commented.yaml");
	snprintf(nfpm, sizeof(nfpm), "%s/packaging/nfpm", dir);
	rmdir(nfpm);
	snprintf(nfpm, sizeof(nfpm), "%s/packaging", dir);
	rmdir(nfpm);
	rmdir(dir);
}

/* Every command a page runs comes with the packages the same page installs */
static void test_installed_packages_carry_the_documented_commands(void)
{
	static const char *const manifests[] = {
		"lota-agent.yaml",     "lota-sdk.yaml",
		"lota-sdk-devel.yaml", "lota-verifier.yaml",
		"lota-attest-ca.yaml",
	};
	static const char *const roots[] = { "Documentation", "examples" };
	struct stat st;
	const char *dir;
	size_t i;

	TEST("docs: every command a page installs for is on the machine");

	dir = stat("src", &st) == 0 ? "." : "..";
	package_count = 0;
	for (i = 0; i < sizeof(manifests) / sizeof(manifests[0]); i++)
		read_manifest(dir, manifests[i]);

	if (package_count != sizeof(manifests) / sizeof(manifests[0])) {
		FAIL("no package manifests were read");
		return;
	}

	for (i = 0; i < sizeof(roots) / sizeof(roots[0]); i++) {
		char path[512];

		snprintf(path, sizeof(path), "%s/%s", dir, roots[i]);
		if (!commands_under(path)) {
			FAIL(install_offender);
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

/* Whether a shipped file names @needle anywhere */
static bool shipped_file_names(const char *rel, const char *needle)
{
	FILE *fp = open_shipped(rel);
	char line[2048];
	bool found = false;

	if (!fp)
		return false;
	while (!found && fgets(line, sizeof(line), fp))
		found = strstr(line, needle) != NULL;
	fclose(fp);
	return found;
}

/*
 * Both packages ship the enforcement object with its signature and key.
 * A page saying the object ships unsigned has the operator mint a key on
 * the host and leave it at /etc/lota/policy.pub, which the agent prefers
 * over the packaged key; local malware with that key can re-sign a tampered
 * object. The installer refuses to create that state.
 */
static void test_bringup_reference_matches_the_packaged_object(void)
{
	static const char *const manifests[] = {
		"packaging/nfpm/lota-agent.yaml",
		"packaging/rpm/lota.spec",
	};
	static const char *const page =
		"Documentation/operator/production-bringup/manual-reference.rst";
	FILE *fp;
	char line[2048];
	char lower[2048];

	TEST("docs: the bring-up reference matches what the packages ship");

	for (size_t i = 0; i < sizeof(manifests) / sizeof(manifests[0]); i++) {
		if (!shipped_file_names(manifests[i], "lota_lsm.bpf.o.sig") ||
		    !shipped_file_names(manifests[i], "enforcement.pub")) {
			FAIL("a package no longer ships the signature or the key");
			return;
		}
	}

	fp = open_shipped(page);
	if (!fp) {
		FAIL("could not open the bring-up reference");
		return;
	}
	while (fgets(line, sizeof(line), fp)) {
		lowercase(line, lower, sizeof(lower));
		if (strstr(lower, "ship") && strstr(lower, "unsigned")) {
			fclose(fp);
			FAIL("the reference says the package ships the object unsigned");
			return;
		}
	}
	fclose(fp);

	if (!shipped_file_names(page, "/usr/lib/lota/enforcement.pub")) {
		FAIL("the reference never names the key the package brought");
		return;
	}
	PASS();
}

/*
 * Reads the reStructuredText section @title into @buf as one line with
 * whitespace collapsed, so a claim matches across line wraps. The buffer ends
 * with the next section's title: fit to show a claim is absent, not present.
 */
static bool read_rst_section(const char *rel, const char *title, char *buf,
			     size_t buf_size)
{
	FILE *fp = open_shipped(rel);
	char line[1024];
	size_t used = 0;
	bool in_section = false;

	if (!fp)
		return false;
	buf[0] = '\0';
	while (fgets(line, sizeof(line), fp)) {
		size_t i;
		bool underline;

		line[strcspn(line, "\n")] = '\0';
		underline = line[0] == '-' || line[0] == '=';
		for (i = 0; underline && line[i]; i++)
			underline = line[i] == line[0];
		underline = underline && i >= 3;

		if (!in_section) {
			in_section = strcmp(line, title) == 0;
			continue;
		}
		if (underline && used > 0)
			break;
		for (i = 0; line[i]; i++) {
			char c = line[i] == '\t' ? ' ' : line[i];

			if (c == ' ' && (used == 0 || buf[used - 1] == ' '))
				continue;
			if (used + 2 >= buf_size)
				break;
			buf[used++] = c;
		}
		if (used > 0 && buf[used - 1] != ' ')
			buf[used++] = ' ';
		buf[used] = '\0';
	}
	fclose(fp);
	return in_section && used > 0;
}

/*
 * TPM2_Clear deletes every owner-hierarchy NV index and keeps the platform-created
 * ones, so the EK certificates survive but indexes other consumers on the host
 * created do not. It also restarts the TPM clock and resetCount, which the agent's
 * PCR 14 rollback verdict reads as going back.
 */
static void test_tpm_clear_section_says_what_nv_costs(void)
{
	static const char *const page =
		"Documentation/operator/platform-support.rst";
	char section[8192];

	TEST("docs: what a TPM clear costs names NV and the counters");

	if (!read_rst_section(page, "What clearing a TPM costs", section,
			      sizeof(section))) {
		FAIL("could not read the section a clear is planned from");
		return;
	}
	if (strstr(section, "NV storage** alone") ||
	    strstr(section, "NV storage alone")) {
		FAIL("the section says a clear leaves NV storage alone");
		return;
	}
	if (!strstr(section, "owner") || !strstr(section, "platform-created")) {
		FAIL("the section does not separate the two NV populations");
		return;
	}
	if (!strstr(section, "resetCount") || !strstr(section, "clock")) {
		FAIL("the section is silent on the counters a clear rebases");
		return;
	}
	PASS();
}

/* Whether @sentence-shaped span appears in a normalised section */
static bool section_claims(const char *section, const char *claim)
{
	return strstr(section, claim) != NULL;
}

/*
 * After a clear the key at each publisher's handle no longer matches its
 * certificate, so the agent refuses before quoting; a quote would fail in
 * the TPM and spend a dictionary-attack attempt.
 * No round opens, so the verifier sees nothing to alert on.
 */
static void test_tpm_clear_section_names_what_refuses(void)
{
	static const char *const page =
		"Documentation/operator/platform-support.rst";
	char section[8192];

	TEST("docs: what a TPM clear costs names the side that refuses");

	if (!read_rst_section(page, "What clearing a TPM costs", section,
			      sizeof(section))) {
		FAIL("could not read the section a clear is planned from");
		return;
	}
	if (section_claims(section, "a verifier holding the old certificate")) {
		FAIL("the section promises a verifier refusal that never happens");
		return;
	}
	if (!section_claims(section, "--reenroll")) {
		FAIL("the section does not name the remedy");
		return;
	}
	if (!section_claims(section, "no round") &&
	    !section_claims(section, "No round")) {
		FAIL("the section does not say the round never opens");
		return;
	}
	if (!section_claims(section, "verifier") ||
	    !section_claims(section, "agent refuses")) {
		FAIL("the section does not say which side refuses");
		return;
	}
	PASS();
}

/*
 * The fleet CLI page calls the binary static. With a C toolchain present,
 * go build picks the cgo resolvers for net and os/user and links libc,
 * so the binary fails on an older glibc.
 * A static claim needs CGO_ENABLED=0 in the recipe.
 */
static void test_static_cli_is_built_without_cgo(void)
{
	static const char *const page = "Documentation/operator/fleet-cli.rst";
	FILE *fp;
	char cmd[4096];
	bool claims_static = false;
	bool recipe_disables_cgo = false;
	bool in_recipe = false;

	TEST("build: a CLI documented as static is built with cgo off");

	fp = open_shipped(page);
	if (!fp) {
		FAIL("could not open the fleet CLI reference");
		return;
	}
	while (next_command(fp, cmd, sizeof(cmd)))
		if (strstr(cmd, "static"))
			claims_static = true;
	fclose(fp);

	if (!claims_static) {
		/* the page no longer promises it; nothing to hold the recipe to */
		PASS();
		return;
	}

	fp = open_shipped("Makefile");
	if (!fp) {
		FAIL("could not open the Makefile");
		return;
	}
	while (next_command(fp, cmd, sizeof(cmd))) {
		if (strstr(cmd, "$(FLEETCTL_BIN):"))
			in_recipe = true;
		else if (in_recipe && cmd[0] != '\t' && cmd[0] != '\n')
			in_recipe = false;
		if (in_recipe && strstr(cmd, "CGO_ENABLED=0"))
			recipe_disables_cgo = true;
	}
	fclose(fp);

	if (!recipe_disables_cgo) {
		FAIL("the recipe builds a dynamically linked binary");
		return;
	}
	PASS();
}

/*
 * Reads the integer a header #defines, so a page's claim about a record on disk
 * can be held against the record the build writes.
 */
static bool header_define(const char *rel, const char *name, long *out)
{
	FILE *fp = open_shipped(rel);
	char line[1024];
	bool found = false;

	if (!fp)
		return false;
	while (!found && fgets(line, sizeof(line), fp)) {
		const char *p = strstr(line, "#define ");
		char *end;
		long value;

		if (!p)
			continue;
		p += strlen("#define ");
		if (strncmp(p, name, strlen(name)) != 0)
			continue;
		p += strlen(name);
		if (*p != ' ' && *p != '\t')
			continue;
		value = strtol(p, &end, 0);
		if (end == p)
			continue;
		*out = value;
		found = true;
	}
	fclose(fp);
	return found;
}

/*
 * The threat model must name key_derivation as the AIK metadata byte that
 * separates per-publisher keys from the shared key; the agent reads it to
 * decide. The record version never changed, so any version the page names
 * must be TPM_AIK_META_VERSION.
 */
static void test_threat_model_names_what_separates_the_keys(void)
{
	static const char *const page =
		"Documentation/security/threat-model.rst";
	char section[16384];
	long record_version = 0;
	unsigned n;

	TEST("docs: the threat model names what separates the AIK keys");

	if (!read_rst_section(page, "Attestation CA", section,
			      sizeof(section))) {
		FAIL("could not read the attestation CA section");
		return;
	}
	if (!section_claims(section, "metadata record")) {
		FAIL("the section no longer describes the AIK metadata record");
		return;
	}
	if (!section_claims(section, "key_derivation")) {
		FAIL("the field that carries the distinction is not named");
		return;
	}
	if (!header_define("src/agent/tpm.h", "TPM_AIK_META_VERSION",
			   &record_version)) {
		FAIL("could not read TPM_AIK_META_VERSION from the header");
		return;
	}

	/* a version the page attributes to the record is the one it carries */
	for (n = 0; n < 10; n++) {
		char spaced[32];
		char hyphened[32];

		snprintf(spaced, sizeof(spaced), "version %u", n);
		snprintf(hyphened, sizeof(hyphened), "version-%u", n);
		if (!section_claims(section, spaced) &&
		    !section_claims(section, hyphened))
			continue;
		if ((long)n != record_version) {
			FAIL("the section names a record version the agent never writes");
			return;
		}
	}
	PASS();
}

/*
 * The static archives export nothing but API: every other function in those
 * sources is static. What a static link gives up is the soname and version
 * node, and each archive is a single object, so one call pulls in the whole
 * API. The page must say that, not claim non-API symbols.
 */
static void test_static_archive_paragraph_matches_the_archives(void)
{
	static const char *const page =
		"Documentation/contributor/development/api-stability.rst";
	char section[16384];

	TEST("docs: the static archives are described as they are built");

	if (!read_rst_section(page, "Shared-library symbols", section,
			      sizeof(section))) {
		FAIL("could not read the shared-library symbols section");
		return;
	}
	if (!section_claims(section, "liblotagaming.a") ||
	    !section_claims(section, "liblotaserver.a")) {
		FAIL("the section no longer describes the static archives");
		return;
	}
	if (section_claims(section, "symbols that are not API")) {
		FAIL("the section claims the archives carry symbols that are not API");
		return;
	}
	if (!section_claims(section, "soname") ||
	    !section_claims(section, "version node")) {
		FAIL("the section does not say what a static link gives up");
		return;
	}
	if (!section_claims(section, "single object")) {
		FAIL("the section does not say a static link absorbs the whole archive");
		return;
	}
	PASS();
}

/*
 * Enrollment refuses a full TPM at handle bind and at key provisioning.
 * The operator page promises both name the count and the verbs that free a slot,
 * so every -ENOSPC branch must call report_no_room_for_a_key().
 */
static void test_a_full_tpm_is_refused_the_same_way_twice(void)
{
	static const char *const page =
		"Documentation/operator/platform-support.rst";
	static const char *const src_file = "src/agent/enroll_client.c";
	char section[16384];
	FILE *fp;
	char line[1024];
	unsigned no_space_branches = 0;
	unsigned reported = 0;

	TEST("agent: a full TPM is refused with the count and the verbs");

	if (!read_rst_section(page, "How many publishers a TPM has room for",
			      section, sizeof(section))) {
		FAIL("could not read the publisher capacity section");
		return;
	}
	if (!section_claims(section, "--forget-publisher")) {
		/* the page no longer promises it; nothing to hold the code to */
		PASS();
		return;
	}

	fp = open_shipped(src_file);
	if (!fp) {
		FAIL("could not open the enrollment client");
		return;
	}
	while (fgets(line, sizeof(line), fp)) {
		/* the branch, not a mention of the errno in a comment */
		if (strstr(line, "== -ENOSPC"))
			no_space_branches++;
		if (strstr(line, "report_no_room_for_a_key("))
			reported++;
	}
	fclose(fp);

	if (no_space_branches == 0) {
		FAIL("no refusal for a full TPM is left to check");
		return;
	}
	/* one definition plus one call per branch */
	if (reported < no_space_branches + 1) {
		FAIL("a refusal for a full TPM does not name the count and the verbs");
		return;
	}
	PASS();
}

/*
 * The page promises the shared-key refusal names the publisher: the daemon
 * and the attest loop both print TPM_AIK_SHARED_KEY_ADVICE, the loop with
 * t->label.
 */
static void test_shared_key_refusal_names_the_publisher(void)
{
	static const char *const page =
		"Documentation/operator/production-bringup/ca-enrollment.rst";
	static const char *const advice = "TPM_AIK_SHARED_KEY_ADVICE";
	char buf[65536];
	FILE *fp;
	char line[1024];
	unsigned defined = 0, in_daemon = 0, in_loop = 0, named = 0;

	TEST("agent: the shared-key refusal names the publisher in both paths");

	if (!slurp_shipped(page, buf, sizeof(buf))) {
		FAIL("could not read the CA enrollment page");
		return;
	}
	if (!strstr(buf, "says which publisher it belongs to")) {
		/* the page no longer promises it; nothing to hold to */
		PASS();
		return;
	}

	if (!slurp_shipped("src/agent/tpm.h", buf, sizeof(buf))) {
		FAIL("could not read the TPM header");
		return;
	}
	if (strstr(buf, advice))
		defined++;

	fp = open_shipped("src/agent/main.c");
	if (!fp) {
		FAIL("could not open the daemon");
		return;
	}
	while (fgets(line, sizeof(line), fp))
		if (strstr(line, advice))
			in_daemon++;
	fclose(fp);

	fp = open_shipped("src/agent/attest.c");
	if (!fp) {
		FAIL("could not open the attestation loop");
		return;
	}
	while (fgets(line, sizeof(line), fp)) {
		if (!strstr(line, advice))
			continue;
		in_loop++;
	}
	fclose(fp);

	/* the loop's own line has to carry the publisher's label */
	if (!slurp_shipped("src/agent/attest.c", buf, sizeof(buf))) {
		FAIL("could not read the attestation loop");
		return;
	}
	{
		const char *at = strstr(buf, advice);
		const char *end;

		if (at) {
			end = strstr(at, ");");
			if (end && memmem(at, (size_t)(end - at), "t->label",
					  strlen("t->label")))
				named++;
		}
	}

	if (defined == 0) {
		FAIL("the sentence has no single home the two paths share");
		return;
	}
	if (in_daemon == 0 || in_loop == 0) {
		FAIL("one of the two refusals spells its own sentence");
		return;
	}
	if (named == 0) {
		FAIL("the loop's refusal does not name the publisher");
		return;
	}
	PASS();
}

/*
 * A shared key shows only in the AIK record, which binding a profile drops:
 * attest.c asks for the key once, after tpm_aik_load_metadata() in the same
 * function.
 */
static void test_shared_key_refusal_survives_several_publishers(void)
{
	static char buf[131072];
	const char *at, *body, *reads, *asks;

	TEST("agent: the shared-key refusal holds with several publishers");

	if (!slurp_shipped("src/agent/attest.c", buf, sizeof(buf))) {
		FAIL("could not read the attestation loop");
		return;
	}

	asks = strstr(buf, "tpm_provision_aik(");
	if (!asks) {
		FAIL("the loop no longer asks for the publisher's key");
		return;
	}
	if (strstr(asks + 1, "tpm_provision_aik(")) {
		FAIL("the key is asked for in more than one place");
		return;
	}

	/* from the previous function's closing brace */
	for (body = buf, at = buf; at && at < asks;
	     at = strstr(at + 1, "\n}\n"))
		body = at;
	reads = memmem(body, (size_t)(asks - body), "tpm_aik_load_metadata(",
		       strlen("tpm_aik_load_metadata("));
	if (!reads) {
		FAIL("the key is asked for before the publisher's record is read");
		return;
	}
	PASS();
}

/*
 * The pre-profile record names the base handle, now the first publisher's:
 * quoting with it fails and spends a DA attempt. --test-tpm quotes each
 * publisher through its profile.
 */
static void test_probe_quotes_the_keys_the_host_attests_with(void)
{
	static char buf[131072];
	const char *verb, *end, *helpers;
	size_t span;

	TEST("agent: --test-tpm quotes the keys the host attests with");

	if (!slurp_shipped("src/agent/selftest.c", buf, sizeof(buf))) {
		FAIL("could not read the probe");
		return;
	}
	/* quote helpers precede the verb */
	verb = strstr(buf, "int test_tpm(void)");
	end = verb ? strstr(verb, "\nint test_iommu(void)") : NULL;
	if (!verb || !end) {
		FAIL("the probe no longer has a TPM verb to read");
		return;
	}
	span = (size_t)(end - verb);

	if (!memmem(verb, span, "publishers_", strlen("publishers_"))) {
		FAIL("the probe never asks which publishers hold a key");
		return;
	}
	if (!memmem(verb, span, "selftest_quote_key(",
		    strlen("selftest_quote_key("))) {
		FAIL("the probe does not decide whose key it quotes with");
		return;
	}

	helpers = strstr(buf, "static void selftest_quote");
	if (!helpers || helpers > verb) {
		FAIL("the probe has nothing that quotes a publisher's key");
		return;
	}
	if (!memmem(helpers, (size_t)(verb - helpers), "tpm_bind_profile(",
		    strlen("tpm_bind_profile("))) {
		FAIL("the probe quotes without binding a publisher's profile");
		return;
	}
	PASS();
}

/*
 * A key replaced before the CA answers is named by no certificate:
 * run_enrollment() calls net_connect() before tpm_provision_aik().
 */
static void test_enrollment_reaches_the_ca_before_it_spends_a_key(void)
{
	static char buf[262144];
	const char *enrolls, *end, *opens, *asks, *helper;
	size_t span;

	TEST("agent: enrollment reaches the CA before replacing a key");

	if (!slurp_shipped("src/agent/enroll_client.c", buf, sizeof(buf))) {
		FAIL("could not read the enrollment client");
		return;
	}

	enrolls = strstr(buf, "static int run_enrollment(");
	end = enrolls ? strstr(enrolls, "\n}\n") : NULL;
	if (!enrolls || !end) {
		FAIL("could not find the enrollment this all runs through");
		return;
	}
	span = (size_t)(end - enrolls);

	asks = memmem(enrolls, span, "tpm_provision_aik(",
		      strlen("tpm_provision_aik("));
	if (!asks) {
		FAIL("the enrollment no longer asks for a key");
		return;
	}
	opens = memmem(enrolls, span, "ca_session_opens(",
		       strlen("ca_session_opens("));
	if (!opens || opens > asks) {
		FAIL("the key is replaced before the CA is reached");
		return;
	}

	/* and what it opens is a session, not a name that reads like one */
	helper = strstr(buf, "static int ca_session_opens(");
	if (!helper || helper > enrolls) {
		FAIL("nothing opens a session to the CA");
		return;
	}
	if (!memmem(helper, (size_t)(enrolls - helper), "net_connect(",
		    strlen("net_connect("))) {
		FAIL("the session is declared open without connecting");
		return;
	}
	PASS();
}

/* A command-line endpoint beats the recorded one; a stale one spends the key. */
static void test_reenroll_dials_what_the_command_line_named(void)
{
	static char buf[262144];
	const char *verb, *end;
	size_t span;

	TEST("agent: --reenroll dials the endpoint it was given");

	if (!slurp_shipped("src/agent/enroll_client.c", buf, sizeof(buf))) {
		FAIL("could not read the enrollment client");
		return;
	}

	verb = strstr(buf, "int do_reenroll(");
	end = verb ? strstr(verb, "\n}\n") : NULL;
	if (!verb || !end) {
		FAIL("could not find the re-enrollment verb");
		return;
	}
	span = (size_t)(end - verb);

	if (!memmem(verb, span, "enroll_endpoint_server(",
		    strlen("enroll_endpoint_server(")) ||
	    !memmem(verb, span, "enroll_endpoint_port(",
		    strlen("enroll_endpoint_port("))) {
		FAIL("the verb dials the record whatever it was given");
		return;
	}
	if (!memmem(verb, span, "enroll_endpoint_source(",
		    strlen("enroll_endpoint_source("))) {
		FAIL("the run never says which endpoint it dialled");
		return;
	}
	PASS();
}

/*
 * A key --seal-aik-auth cannot seal usually has no plaintext left,
 * so the failure line must read each key's auth state, not assert plaintext.
 */
static void test_seal_report_reads_the_state_it_reports(void)
{
	FILE *fp;
	char line[1024];
	bool in_verb = false;
	bool reads_state = false;
	bool asserts_plaintext = false;

	TEST("agent: the sealing report reads each key's state");

	fp = open_shipped("src/agent/selftest.c");
	if (!fp) {
		FAIL("could not open the selftest sources");
		return;
	}
	while (fgets(line, sizeof(line), fp)) {
		if (strstr(line, "int do_seal_aik_auth("))
			in_verb = true;
		else if (in_verb && line[0] == '}')
			break;
		if (!in_verb)
			continue;
		if (strstr(line, "profile_aik_auth_state") ||
		    strstr(line, "profile_aik_auth_needs_sealing"))
			reads_state = true;
		if (strstr(line, "still hold their"))
			asserts_plaintext = true;
	}
	fclose(fp);

	if (!in_verb) {
		FAIL("could not find do_seal_aik_auth");
		return;
	}
	if (asserts_plaintext) {
		FAIL("the failure line asserts a plaintext copy it never read");
		return;
	}
	if (!reads_state) {
		FAIL("the report never reads the state of a key it could not seal");
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
	test_selinux_reference_searches_the_modules_own_rules();
	test_lockout_runbook_matches_what_the_chip_prints();
	test_installer_labels_the_config_directory();
	test_installer_relabel_reapplies_the_device_labels();
	test_documented_tpm_relabel_reaches_both_nodes();
	test_documented_cmdline_carries_no_kdump_option();
	test_documented_api_calls_use_the_bearer_header();
	test_the_gate_runs_the_unit_tests();
	test_comments_name_symbols_that_exist();
	test_pages_name_symbols_that_exist();
	test_manifest_lists_survive_a_comment();
	test_installed_packages_carry_the_documented_commands();
	test_enrollment_example_runs_on_a_provisioned_host();
	test_bringup_reference_matches_the_packaged_object();
	test_tpm_clear_section_says_what_nv_costs();
	test_tpm_clear_section_names_what_refuses();
	test_static_cli_is_built_without_cgo();
	test_threat_model_names_what_separates_the_keys();
	test_static_archive_paragraph_matches_the_archives();
	test_a_full_tpm_is_refused_the_same_way_twice();
	test_seal_report_reads_the_state_it_reports();
	test_shared_key_refusal_names_the_publisher();
	test_shared_key_refusal_survives_several_publishers();
	test_probe_quotes_the_keys_the_host_attests_with();
	test_enrollment_reaches_the_ca_before_it_spends_a_key();
	test_reenroll_dials_what_the_command_line_named();

	printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
	return (tests_passed == tests_run) ? 0 : 1;
}
