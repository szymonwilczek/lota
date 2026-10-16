/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for the sentence a refused connect carries.
 *
 * The confined agent may reach only ports labelled lota_port_t, and the denial
 * is dontaudit'ed: connect() returns EACCES, no AVC is logged, and the operator
 * is left with "Permission denied" against a server that is running and reachable
 * from a shell on the same host.
 *
 * Two causes, opposite remedies: a port without the LOTA label,
 * or lota_network_attest off. With the boolean off the port advice misleads:
 * semanage answers "already defined, modifying instead" and exits 0.
 *
 * The hint is given only while SELinux enforces; elsewhere EACCES has another
 * cause. Every input lives under one selinuxfs root, which the caller passes
 * and these tests fake.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../src/agent/net.h"

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

static int put(const char *path, const char *content)
{
	FILE *f = fopen(path, "we");

	if (!f)
		return -errno;
	fputs(content, f);
	fclose(f);
	return 0;
}

/*
 * A stand-in selinuxfs: enforce, and the boolean directory when @boolean is
 * not NULL. A root without the directory is the host whose policy module is
 * not loaded, where neither cause can be established.
 */
static int make_root(char *path, size_t cap, const char *enforce,
		     const char *boolean)
{
	char file[256];

	snprintf(path, cap, "/tmp/lota-selinuxfs-XXXXXX");
	if (!mkdtemp(path))
		return -errno;
	snprintf(file, sizeof(file), "%s/enforce", path);
	if (put(file, enforce) < 0)
		return -EIO;
	if (!boolean)
		return 0;
	snprintf(file, sizeof(file), "%s/booleans", path);
	if (mkdir(file, 0700) != 0)
		return -errno;
	snprintf(file, sizeof(file), "%s/booleans/lota_network_attest", path);
	return put(file, boolean);
}

int main(void)
{
	char enforcing[64], permissive[64], tunable_off[64], no_module[64];
	char buf[512];
	const char *hint;

	printf("=== refused connect hint tests ===\n\n");

	if (make_root(enforcing, sizeof(enforcing), "1\n", "1 1") < 0 ||
	    make_root(permissive, sizeof(permissive), "0\n", "1 1") < 0 ||
	    make_root(tunable_off, sizeof(tunable_off), "1\n", "0 0") < 0 ||
	    make_root(no_module, sizeof(no_module), "1\n", NULL) < 0) {
		fprintf(stderr, "FAIL: could not create temp files\n");
		return 1;
	}

	hint = net_connect_refusal_hint(EACCES, 8573, enforcing, buf,
					sizeof(buf));
	CHECK(hint != NULL, "an enforcing host gets a cause for EACCES");
	if (hint) {
		CHECK(strstr(hint, "semanage port -a -t lota_port_t -p tcp "
				   "8573") != NULL,
		      "the command names the port that was refused");
		CHECK(strstr(hint, "dontaudit") != NULL ||
			      strstr(hint, "no AVC") != NULL,
		      "the sentence says why nothing was logged");
		CHECK(strstr(hint, "setsebool") == NULL,
		      "a labelled-port cause does not offer the boolean");
	}

	/*
	 * The tunable is off, so the port label is not what refuses this
	 * and the semanage command exits 0 having changed nothing.
	 */
	hint = net_connect_refusal_hint(EACCES, 8573, tunable_off, buf,
					sizeof(buf));
	CHECK(hint != NULL, "the tunable being off is a cause worth naming");
	if (hint) {
		CHECK(strstr(hint, "lota_network_attest") != NULL,
		      "the sentence names the tunable that refuses the connect");
		CHECK(strstr(hint, "setsebool -P lota_network_attest on") !=
			      NULL,
		      "the command turns the tunable back on");
		CHECK(strstr(hint, "semanage port -a") == NULL,
		      "the operator is not sent to relabel a port instead");
	}

	/* Neither cause can be established, so both are named and neither is asserted */
	hint = net_connect_refusal_hint(EACCES, 8573, no_module, buf,
					sizeof(buf));
	CHECK(hint != NULL,
	      "a host with no readable tunable still gets a cause");
	if (hint) {
		CHECK(strstr(hint, "semanage port -a -t lota_port_t -p tcp "
				   "8573") != NULL &&
			      strstr(hint, "setsebool -P lota_network_attest "
					   "on") != NULL,
		      "both candidates are named when neither can be read");
	}

	/* Permissive means the denial did not happen, so this EACCES came from
	 * somewhere else and the port label is the wrong thing to name */
	CHECK(net_connect_refusal_hint(EACCES, 8573, permissive, buf,
				       sizeof(buf)) == NULL,
	      "a permissive host is not told to label a port");

	CHECK(net_connect_refusal_hint(EACCES, 8573,
				       "/tmp/lota-selinuxfs-does-not-exist",
				       buf, sizeof(buf)) == NULL,
	      "a host without SELinux is not told to label a port");

	CHECK(net_connect_refusal_hint(ECONNREFUSED, 8573, enforcing, buf,
				       sizeof(buf)) == NULL,
	      "a refused connection is not blamed on the policy");
	CHECK(net_connect_refusal_hint(EHOSTUNREACH, 8573, enforcing, buf,
				       sizeof(buf)) == NULL,
	      "an unreachable host is not blamed on the policy");

	/* half a semanage command is worse than none: the operator would run it */
	CHECK(net_connect_refusal_hint(EACCES, 8573, enforcing, buf, 32) ==
		      NULL,
	      "a truncated command is not offered");

	printf("\n%s\n", g_failures ? "FAILURES" : "All tests passed");
	return g_failures ? 1 : 0;
}
