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

#include "test.h"

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
 * Guard that it never grants itself the enforcement daemon's powerful caps.
 *
 * It must not gate on a completed first enrollment either: the condition is
 * read once, at start, and the profile appears after the installer has
 * started the unit -- the loop itself enrolls for the first title -- so a
 * gated unit stays stopped until the next boot.
 */
static void test_attest_unit_isolated(void)
{
	TEST("attest unit: no BPF/admin caps, not gated on first enroll");

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
		if (strncmp(line, "Condition", 9) == 0)
			enroll_gate = true;
	}
	fclose(fp);

	if (powerful_cap) {
		FAIL("attest unit must not hold BPF/admin/rawio caps");
		return;
	}
	if (enroll_gate) {
		FAIL("a condition keeps the unit stopped after enrollment");
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
	static const char *const sources[] = { "selinux/lota.te" };
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
					       "selinux/lota.fc" };
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

static void test_selinux_container_listener_is_shipped(void)
{
	static const char *const rules[] = {
		"userdom_manage_tmp_dirs(lota_agent_t)",
		"userdom_manage_tmp_sockets(lota_agent_t)",
		"userdom_watch_tmp_dirs(lota_agent_t)", " chown "
	};
	static char policy[65536];
	FILE *fp;
	size_t got;

	TEST("selinux: the shipped module carries the container listener");

	fp = open_shipped("selinux/lota.te");
	if (!fp) {
		FAIL("could not open selinux/lota.te");
		return;
	}
	got = fread(policy, 1, sizeof(policy) - 1, fp);
	fclose(fp);
	policy[got] = '\0';

	for (size_t i = 0; i < sizeof(rules) / sizeof(rules[0]); i++) {
		if (!strstr(policy, rules[i])) {
			FAIL("the packages ship lota.pp alone: the rule belongs there");
			return;
		}
	}
	PASS();
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
 * A title in a user namespace is checked against that namespace, which is the
 * cap_userns class. The capability class does not cover it.
 */
static void test_selinux_agent_reaches_user_namespaces(void)
{
	static char policy[65536];

	TEST("selinux: the agent reaches titles in user namespaces");

	if (!slurp_shipped("selinux/lota.te", policy, sizeof(policy))) {
		FAIL("could not read selinux/lota.te");
		return;
	}
	if (!strstr(policy, "self:cap_userns { kill sys_ptrace };")) {
		FAIL("no cap_userns rule: Proton titles stay out of reach");
		return;
	}
	PASS();
}

/*
 * The road for a store install turns on the type of the filesystem a title
 * lives on, and fstatfs() on it needs filesystem getattr.
 */
static void test_selinux_agent_reads_filesystem_types(void)
{
	static char policy[65536];

	TEST("selinux: the agent reads the filesystem type of a title");

	if (!slurp_shipped("selinux/lota.te", policy, sizeof(policy))) {
		FAIL("could not read selinux/lota.te");
		return;
	}
	if (!strstr(policy, "fs_getattr_all_fs(lota_agent_t)")) {
		FAIL("no filesystem getattr: a title without verity loses its token");
		return;
	}
	PASS();
}

/*
 * A binary linked with its own relro flags misses the noexecstack and
 * separate-code the shared set carries.
 */
static void test_every_binary_links_hardened(void)
{
	static char mk[262144];
	const char *first;

	TEST("make: every binary links with the shared hardening flags");

	if (!slurp_shipped("Makefile", mk, sizeof(mk))) {
		FAIL("could not read the Makefile");
		return;
	}
	first = strstr(mk, "-z,relro");
	if (!first || strstr(first + 1, "-z,relro")) {
		FAIL("a binary links outside HARDENING_LDFLAGS");
		return;
	}
	PASS();
}

/* the read the runtime image measurement holds on mapped files */
#define MEASURE_READ_RULE "{ file_type -security_file_type -system_map_t }:file"

/*
 * The agent reads no kernel symbol table: every ksym of the BPF object
 * resolves through BTF.
 */
static void test_selinux_agent_skips_the_symbol_table(void)
{
	static char policy[65536];

	TEST("selinux: the agent gets no read on the kernel symbol table");

	if (!slurp_shipped("selinux/lota.te", policy, sizeof(policy))) {
		FAIL("could not read selinux/lota.te");
		return;
	}
	if (strstr(policy, "files_read_all_files(lota_agent_t)") ||
	    strstr(policy, "file_type:file") ||
	    strstr(policy, "system_map_t:file") ||
	    !strstr(policy, MEASURE_READ_RULE)) {
		FAIL("lota_agent_t may read /proc/kallsyms and System.map");
		return;
	}
	PASS();
}

/*
 * The agent reads no security file: shadow, keytabs, home records,
 * the audit log. One a title maps stays unmeasured.
 */
static void test_selinux_agent_skips_security_files(void)
{
	static char policy[65536];

	TEST("selinux: the agent gets no read on security files");

	if (!slurp_shipped("selinux/lota.te", policy, sizeof(policy))) {
		FAIL("could not read selinux/lota.te");
		return;
	}
	if (strstr(policy, "auth_read_shadow") ||
	    strstr(policy, "shadow_t:file") ||
	    strstr(policy, "security_file_type:file") ||
	    !strstr(policy, MEASURE_READ_RULE)) {
		FAIL("lota_agent_t may read /etc/shadow or a keytab");
		return;
	}
	PASS();
}

/*
 * A client stats the socket before it connects, so write alone leaves it with
 * EACCES on the system socket.
 */
static void test_selinux_status_client_stats_socket(void)
{
	static char policy[65536];
	const char *want = "lota_var_t:sock_file write_sock_file_perms;";
	const char *body;
	size_t len;

	TEST("selinux: a status client may stat the agent socket");

	if (!slurp_shipped("selinux/lota.if", policy, sizeof(policy))) {
		FAIL("could not read selinux/lota.if");
		return;
	}
	if (!iface_body(policy, "lota_query_status", &body, &len)) {
		FAIL("lota_query_status is not defined");
		return;
	}
	for (size_t i = 0; i + strlen(want) <= len; i++) {
		if (strncmp(body + i, want, strlen(want)) == 0) {
			PASS();
			return;
		}
	}
	FAIL("lota_query_status does not grant getattr on the socket");
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
 * Fedora resolves groups with "files [SUCCESS=merge] systemd", so a lota group
 * found in /etc/group still walks the userdb sockets the policy keeps shut.
 */
static void test_agent_unit_skips_userdb(void)
{
	static char src[65536];

	TEST("packaging: the agent unit skips the userdb lookup");

	if (!slurp_shipped("systemd/lota-agent.service", src, sizeof(src))) {
		FAIL("could not read lota-agent.service");
		return;
	}
	if (!strstr(src, "\nEnvironment=SYSTEMD_BYPASS_USERDB=1\n")) {
		FAIL("a group lookup logs an AVC per userdb socket");
		return;
	}
	PASS();
}

/*
 * ExecStop waits up to 60 s for the daemon to exit; Fedora's default stop
 * timeout is 45 s and aborts the unit when it runs out.
 */
static void test_agent_unit_outwaits_the_shutdown(void)
{
	static char src[65536];
	const char *p;
	unsigned int secs = 0;

	TEST("packaging: the agent unit's stop timeout outlasts --shutdown");

	if (!slurp_shipped("systemd/lota-agent.service", src, sizeof(src))) {
		FAIL("could not read lota-agent.service");
		return;
	}
	p = strstr(src, "\nTimeoutStopSec=");
	if (!p || sscanf(p, "\nTimeoutStopSec=%us\n", &secs) != 1) {
		FAIL("no TimeoutStopSec= in seconds");
		return;
	}
	if (secs <= 60) {
		FAIL("systemd stops waiting before --shutdown does");
		return;
	}
	PASS();
}

/*
 * An upgrade replaces lota.pp under a module the policy store keeps its own copy
 * of, so a rule the new agent depends on stays out until something reloads it.
 */
static void test_upgrade_reloads_the_selinux_module(void)
{
	static const char *const hooks[] = {
		"packaging/nfpm/scripts/agent-postinstall.sh",
		"packaging/rpm/lota.spec"
	};
	static char src[65536];

	TEST("packaging: an upgrade reloads a loaded SELinux module");

	for (size_t i = 0; i < sizeof(hooks) / sizeof(hooks[0]); i++) {
		const char *loaded;

		if (!slurp_shipped(hooks[i], src, sizeof(src))) {
			FAIL("could not read a post-install hook");
			return;
		}
		loaded = strstr(src, "semodule -l");
		if (!loaded || !strstr(loaded, "semodule -i ")) {
			FAIL("a post-install hook leaves the old module loaded");
			return;
		}
	}
	PASS();
}

/*
 * Both packages hand bring-up to the stage engine, so an upgrade restores
 * fs-verity on the new binary whichever manifest built it.
 */
static void test_both_hooks_drive_bringup(void)
{
	static const char *const hooks[] = {
		"packaging/nfpm/scripts/agent-postinstall.sh",
		"packaging/rpm/lota.spec"
	};
	static char src[65536];

	TEST("packaging: both post-install hooks run lota-install --unattended");

	for (size_t i = 0; i < sizeof(hooks) / sizeof(hooks[0]); i++) {
		if (!slurp_shipped(hooks[i], src, sizeof(src))) {
			FAIL("could not read a post-install hook");
			return;
		}
		if (!strstr(src, "lota-install --unattended")) {
			FAIL("a post-install hook leaves bring-up to the reader");
			return;
		}
		if (strstr(src, "ships unsigned") ||
		    strstr(src, "sign the BPF object")) {
			FAIL("a package says lota-install signs the BPF object");
			return;
		}
	}
	PASS();
}

/*
 * lota.conf lives in /etc/lota, and every writer of it (--add-publisher, the
 * installer, lota-steam-setup) expects the directory to be there.
 */
static void test_both_manifests_own_the_config_directory(void)
{
	static char src[65536];

	TEST("packaging: both manifests own /etc/lota");

	if (!slurp_shipped("packaging/rpm/lota.spec", src, sizeof(src))) {
		FAIL("could not read lota.spec");
		return;
	}
	if (!strstr(src, "\n%dir %{_sysconfdir}/lota\n")) {
		FAIL("the spec leaves /etc/lota to whoever writes first");
		return;
	}
	if (!slurp_shipped("packaging/nfpm/lota-agent.yaml", src,
			   sizeof(src))) {
		FAIL("could not read lota-agent.yaml");
		return;
	}
	if (!strstr(src, "\n  - dst: /etc/lota\n    type: dir\n")) {
		FAIL("the nfpm package leaves /etc/lota to whoever writes first");
		return;
	}
	PASS();
}

/*
 * Ports are labelled by st_selinux_apply(), which a host that passed the stage
 * once never reaches unless the probe asks about the ports of this run.
 */
static void test_installer_probe_asks_about_ports(void)
{
	static char src[262144];
	const char *start, *end, *call;

	TEST("installer: the SELinux stage probes the ports of this run");

	if (!slurp_shipped("installer/stages.c", src, sizeof(src))) {
		FAIL("could not open installer/stages.c");
		return;
	}
	start = strstr(src, "static enum stage_state st_selinux_probe(");
	end = start ? strstr(start, "\n}\n") : NULL;
	call = start ? strstr(start, "selinux_port_unmet(") : NULL;
	if (!end || !call || call > end) {
		FAIL("a later run with a new port skips the labelling");
		return;
	}
	PASS();
}

/*
 * semanage port -a on a port another type names writes a local record that
 * shadows that type for every domain, so apply labels only what the probe
 * reports as unnamed.
 */
static void test_installer_leaves_a_named_port_alone(void)
{
	static char src[262144];
	const char *start, *end, *call, *add;

	TEST("installer: the SELinux stage leaves a port a type names alone");

	if (!slurp_shipped("installer/stages.c", src, sizeof(src))) {
		FAIL("could not open installer/stages.c");
		return;
	}
	start = strstr(src, "static int st_selinux_apply(");
	end = start ? strstr(start, "\n}\n") : NULL;
	call = start ? strstr(start, "probe_port_needs_label(") : NULL;
	add = start ? strstr(start, "\"lota_port_t\"") : NULL;
	if (!end || !add || add > end || !call || call > end) {
		FAIL("apply relabels a port another type already names");
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
 * The fleet CLI page calls the binary static. With a C toolchain present,
 * go build picks the cgo resolvers for net and os/user and links libc,
 * so the binary fails on an older glibc.
 * A static claim needs CGO_ENABLED=0 in the recipe.
 */
static void test_static_cli_is_built_without_cgo(void)
{
	static const char *const page =
		"Documentation/admin-guide/fleet-cli.rst";
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

	verb = strstr(buf, "static int reenroll_profile(");
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

/* An expired certificate is refreshed with the installer's anchor. */
static void test_installer_reenrolls_with_its_anchor(void)
{
	static char buf[262144];
	const char *verb, *end;

	TEST("installer: --reenroll names the anchor it was given");

	if (!slurp_shipped("installer/stages.c", buf, sizeof(buf))) {
		FAIL("could not read the installer stages");
		return;
	}

	verb = strstr(buf, "\"--reenroll\"");
	end = verb ? strstr(verb, "NULL };") : NULL;
	if (!verb || !end) {
		FAIL("could not find the re-enrollment command");
		return;
	}
	if (!memmem(verb, (size_t)(end - verb), "ctx->opts.ca_cert",
		    strlen("ctx->opts.ca_cert"))) {
		FAIL("an anchor moved since enrollment fails the refresh");
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
	test_selinux_container_listener_is_shipped();
	test_selinux_gaming_client_reaches_container_socket();
	test_selinux_status_client_stats_socket();
	test_selinux_agent_skips_security_files();
	test_selinux_agent_reaches_user_namespaces();
	test_selinux_agent_reads_filesystem_types();
	test_selinux_agent_skips_the_symbol_table();
	test_every_binary_links_hardened();
	test_installer_labels_the_config_directory();
	test_upgrade_reloads_the_selinux_module();
	test_both_hooks_drive_bringup();
	test_both_manifests_own_the_config_directory();
	test_agent_unit_skips_userdb();
	test_agent_unit_outwaits_the_shutdown();
	test_installer_probe_asks_about_ports();
	test_installer_leaves_a_named_port_alone();
	test_installer_relabel_reapplies_the_device_labels();
	test_static_cli_is_built_without_cgo();
	test_shared_key_refusal_survives_several_publishers();
	test_probe_quotes_the_keys_the_host_attests_with();
	test_enrollment_reaches_the_ca_before_it_spends_a_key();
	test_reenroll_dials_what_the_command_line_named();
	test_installer_reenrolls_with_its_anchor();

	printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
	return (tests_passed == tests_run) ? 0 : 1;
}
