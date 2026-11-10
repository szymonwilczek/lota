/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * LOTA block-demo: a protected process that dlopen()s an object
 * outside the trust set.
 *
 * Exit status: 0 the mapping was refused once the process was
 * protected, 1 the load succeeded, 2 the demo could not run.
 */

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <lota/lota_gaming.h>

static int evil_path_beside_self(char *buf, size_t len)
{
	static const char name[] = "evil.so";
	ssize_t n = readlink("/proc/self/exe", buf, len);
	char *slash;

	if (n < 0)
		return -1;
	if ((size_t)n >= len) {
		errno = ENAMETOOLONG;
		return -1;
	}
	buf[n] = '\0';
	slash = strrchr(buf, '/');
	if (!slash || (size_t)(slash + 1 - buf) + sizeof(name) > len) {
		errno = ENAMETOOLONG;
		return -1;
	}
	memcpy(slash + 1, name, sizeof(name));
	return 0;
}

/* 0, or the errno of an executable mapping of @path while unprotected */
static int exec_map_error(const char *path)
{
	long page = sysconf(_SC_PAGESIZE);
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	void *p;
	int err = 0;

	if (fd < 0)
		return errno;
	p = mmap(NULL, (size_t)page, PROT_READ | PROT_EXEC, MAP_PRIVATE, fd, 0);
	if (p == MAP_FAILED)
		err = errno;
	else
		munmap(p, (size_t)page);
	close(fd);
	return err;
}

int main(int argc, char *argv[])
{
	int sleep_mode = 0;
	char evil_path[PATH_MAX];
	struct lota_client *client;
	int ret;
	void *handle;
	const char *err;

	if (argc > 2 || (argc == 2 && strcmp(argv[1], "--sleep") != 0)) {
		fprintf(stderr, "usage: %s [--sleep]\n", argv[0]);
		return 2;
	}
	sleep_mode = argc == 2;
	if (evil_path_beside_self(evil_path, sizeof(evil_path)) < 0) {
		fprintf(stderr, "[victim] cannot locate evil.so: %s\n",
			strerror(errno));
		return 2;
	}

	if (sleep_mode)
		printf("[victim] pid=%d mode=sleep\n", (int)getpid());
	else
		printf("[victim] pid=%d evil=%s\n", (int)getpid(), evil_path);

	if (!sleep_mode) {
		int map_err = exec_map_error(evil_path);

		if (map_err) {
			fprintf(stderr,
				"[victim] %s cannot be mapped executable "
				"even unprotected: %s\n",
				evil_path, strerror(map_err));
			return 2;
		}
	}

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
		lota_disconnect(client);
		if (err && strstr(err, "failed to map segment")) {
			printf("[victim] dlopen blocked: %s\n", err);
			return 0;
		}
		fprintf(stderr, "[victim] dlopen failed: %s\n",
			err ? err : "(no dlerror)");
		return 2;
	}

	fprintf(stderr,
		"[victim] FAIL: dlopen succeeded, evil.so constructor ran\n");
	dlclose(handle);
	lota_disconnect(client);
	return 1;
}
