/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * LOTA block-demo: a protected process that dlopen()s an object
 * outside the trust set.
 *
 * Exit status: 0 the load failed, 1 it succeeded, 2 the demo could
 * not run.
 */

#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <lota/lota_gaming.h>

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
	 * --sleep holds a protected process for the ptrace and signal stages
	 * of tests/integration/test_bpf_gates.sh until stdin closes.
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

	/* enforce, strict_mmap: exec segment refused, no constructor runs */
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
