/* SPDX-License-Identifier: MIT */
/*
 * lota-protect - Start a program already protected
 *
 *   lota-protect [--] PROGRAM [ARG]...
 *
 * Asks the agent to protect this process, then becomes PROGRAM.
 * Protection survives the exec and passes to every process PROGRAM
 * creates, so nothing runs in the tree before it is protected.
 *
 * The agent refuses a process a tracer already holds: PROGRAM does
 * not start. Any other failure starts PROGRAM unprotected: no token
 * lists it among the protected processes.
 *
 * Reads LOTA_HOOK_SOCKET and LOTA_HOOK_PUBLISHER, as the Wine hook does.
 *
 * Exit status: 125 refused or misused, 126 PROGRAM cannot run,
 * 127 PROGRAM not found; otherwise PROGRAM's own.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../../include/lota_gaming.h"
#include "../../include/lota_wine_hook.h"

#define PROTECT_EXIT_REFUSED 125
#define PROTECT_EXIT_CANNOT_RUN 126
#define PROTECT_EXIT_NOT_FOUND 127

static const char *publisher_or_null(const char *env)
{
	size_t i;

	if (!env || !*env)
		return NULL;

	if (strlen(env) != LOTA_PUBLISHER_PROFILE_LEN)
		goto invalid;

	for (i = 0; i < LOTA_PUBLISHER_PROFILE_LEN; i++) {
		if (!isxdigit((unsigned char)env[i]))
			goto invalid;
	}
	return env;

invalid:
	fprintf(stderr,
		"lota-protect: %s is not 64 hex characters: ignoring it\n",
		LOTA_HOOK_ENV_PUBLISHER);
	return NULL;
}

/* LOTA_OK, or the reason this process is not protected */
static int protect_self(void)
{
	struct lota_connect_opts opts;
	struct lota_client *client;
	const char *env;
	int ret;

	memset(&opts, 0, sizeof(opts));
	opts.struct_size = sizeof(opts);
	opts.timeout_ms = LOTA_HOOK_CONNECT_TIMEOUT_MS;

	env = getenv(LOTA_HOOK_ENV_SOCKET);
	if (env && *env)
		opts.socket_path = env;

	/* unnamed: refused on a multi-enrollment host, reported below */
	opts.publisher_profile =
		publisher_or_null(getenv(LOTA_HOOK_ENV_PUBLISHER));

	client = lota_connect_opts(&opts);
	if (!client)
		return lota_connect_last_error();

	lota_set_request_timeout(client, LOTA_HOOK_REQUEST_TIMEOUT_MS);
	ret = lota_protect_self(client);
	lota_disconnect(client);
	return ret;
}

int main(int argc, char **argv)
{
	int first = 1;
	int ret;

	if (argc > 1 && strcmp(argv[1], "--") == 0)
		first = 2;

	if (first >= argc) {
		fprintf(stderr, "usage: lota-protect [--] PROGRAM [ARG]...\n");
		return PROTECT_EXIT_REFUSED;
	}

	ret = protect_self();
	if (ret == LOTA_ERR_ACCESS_DENIED) {
		fprintf(stderr,
			"lota-protect: the agent refused to protect this process "
			"(a tracer may hold it): not starting %s\n",
			argv[first]);
		return PROTECT_EXIT_REFUSED;
	}
	if (ret != LOTA_OK)
		fprintf(stderr, "lota-protect: %s: starting %s unprotected\n",
			lota_strerror(ret), argv[first]);

	execvp(argv[first], argv + first);

	ret = errno;
	fprintf(stderr, "lota-protect: %s: %s\n", argv[first], strerror(ret));
	return ret == ENOENT ? PROTECT_EXIT_NOT_FOUND : PROTECT_EXIT_CANNOT_RUN;
}
