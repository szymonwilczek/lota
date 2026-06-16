/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * LOTA block-demo: victim process that opts itself into the
 * runtime enforcement layer and then asks the dynamic loader to
 * map an unauthorised .so.
 *
 * Exit codes:
 *    0  evil.so was blocked (dlopen returned NULL with EPERM/EACCES)
 *    1  evil.so loaded successfully (block did NOT fire -- failure)
 *    2  invocation / IPC / runtime error (test inconclusive)
 *
 * Stage timeline:
 *    1. Connect to the agent.
 *    2. Call lota_protect_self() so this PID enters protected_pids.
 *    3. Verify the registration with lota_get_status().
 *    4. dlopen() the evil .so; expect failure when the agent is
 *       in enforce + strict_mmap and the operator built the trust
 *       set such that evil.so is not allowed.
 *
 * The expected-failure dlopen path is the demonstrable contract:
 * the runtime gate must reject the load before the .so's
 * constructor runs.
 */

#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "../../include/lota_gaming.h"

static const char *DEFAULT_EVIL_PATH = "/tmp/evil.so";

int main(int argc, char *argv[])
{
	int sleep_mode = 0;
	const char *evil_path = DEFAULT_EVIL_PATH;
	struct lota_client *client;
	int ret;
	void *handle;
	const char *err;

	if (argc > 1) {
		if (strcmp(argv[1], "--sleep") == 0)
			sleep_mode = 1;
		else
			evil_path = argv[1];
	}

	if (sleep_mode)
		printf("[victim] pid=%d mode=sleep\n", (int)getpid());
	else
		printf("[victim] pid=%d evil=%s\n", (int)getpid(), evil_path);

	client = lota_connect();
	if (!client) {
		fprintf(stderr,
			"[victim] lota_connect failed (is the agent up?)\n");
		return 2;
	}

	ret = lota_protect_self(client);
	if (ret != LOTA_OK) {
		fprintf(stderr, "[victim] lota_protect_self: %s\n",
			lota_strerror(ret));
		lota_disconnect(client);
		return 2;
	}
	printf("[victim] registered self into protected_pids\n");
	fflush(stdout);

	/*
	 * --sleep keeps the protected task alive for the
	 * ptrace_access_check and task_kill integration stages.
	 * Block on stdin, not a signal: the task_kill gate rejects
	 * every foreign-task signal to a protected PID (that is the
	 * property the task_kill stage asserts), so a kill -TERM from
	 * the harness can never reach this process. The harness closes
	 * our stdin to request teardown; read() then returns EOF and we
	 * exit, letting lota_task_free reap the protected-PID entry.
	 */
	if (sleep_mode) {
		char c;
		ssize_t n;

		do {
			n = read(STDIN_FILENO, &c, 1);
		} while (n > 0 || (n < 0 && errno == EINTR));
		lota_disconnect(client);
		return 0;
	}

	/*
	 * dlopen runs through ld.so which calls mmap(PROT_EXEC) on
	 * each segment of evil.so. In ENFORCE + strict_mmap the BPF
	 * mmap_file hook returns -EPERM, dlopen() sees the loader's
	 * propagated failure, and dlerror() reports
	 * "Operation not permitted" or similar. The constructor
	 * never runs, so evil_init() never writes to stderr.
	 */
	handle = dlopen(evil_path, RTLD_NOW);
	if (!handle) {
		err = dlerror();
		printf("[victim] dlopen blocked: %s\n",
		       err ? err : "(no dlerror)");
		lota_disconnect(client);
		return 0;
	}

	fprintf(stderr,
		"[victim] FAIL: dlopen succeeded, evil.so constructor ran\n");
	dlclose(handle);
	lota_disconnect(client);
	return 1;
}
