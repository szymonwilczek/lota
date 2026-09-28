/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for the sentence a refused connect carries.
 *
 * The confined agent may reach only ports labelled lota_port_t, and the denial
 * is dontaudit'ed: connect() returns EACCES, no AVC is logged, and the operator
 * is left with "Permission denied" against a server that is running and reachable
 * from a shell on the same host.
 *
 * There is nothing to search for -- not SELinux, not the port, not semanage
 * -- so the agent has to say it.
 *
 * The hint is only true where SELinux is enforcing, so the state is read:
 * on a permissive or SELinux-less host an EACCES at connect is something else,
 * and naming the wrong cause is worse than naming none.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
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

/* stand-in for /sys/fs/selinux/enforce */
static int write_enforce(char *path, size_t cap, const char *state)
{
	int fd;

	snprintf(path, cap, "/tmp/lota-enforce-XXXXXX");
	fd = mkstemp(path);
	if (fd < 0)
		return -errno;
	if (write(fd, state, strlen(state)) != (ssize_t)strlen(state)) {
		close(fd);
		unlink(path);
		return -EIO;
	}
	close(fd);
	return 0;
}

int main(void)
{
	char enforcing[64], permissive[64];
	char buf[512];
	const char *hint;

	printf("=== refused connect hint tests ===\n\n");

	if (write_enforce(enforcing, sizeof(enforcing), "1\n") < 0 ||
	    write_enforce(permissive, sizeof(permissive), "0\n") < 0) {
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
	}

	/* Permissive means the denial did not happen, so this EACCES came from
	 * somewhere else and the port label is the wrong thing to name */
	CHECK(net_connect_refusal_hint(EACCES, 8573, permissive, buf,
				       sizeof(buf)) == NULL,
	      "a permissive host is not told to label a port");

	CHECK(net_connect_refusal_hint(EACCES, 8573,
				       "/tmp/lota-enforce-does-not-exist", buf,
				       sizeof(buf)) == NULL,
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

	unlink(enforcing);
	unlink(permissive);

	printf("\n%s\n", g_failures ? "FAILURES" : "All tests passed");
	return g_failures ? 1 : 0;
}
