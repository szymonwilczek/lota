/* SPDX-License-Identifier: MIT */
/*
 * Source scan: no test may take a file the running agent owns as a fixture.
 * The refused calls resolve the path internally, so such a case only breaks
 * on a host running an agent. No root, no agent.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <dirent.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int tests_run;
static int tests_passed;

#define TEST(name)                                         \
	do {                                               \
		tests_run++;                               \
		printf("  [%2d] %-55s ", tests_run, name); \
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
 * Calls that resolve to an agent-owned file; assembled at runtime,
 * so this file never matches itself.
 */
static const struct {
	const char *fn;
	const char *arg;
	const char *file;
} refused[] = {
	{ "pidfile_create", "NULL", "/run/lota/lota-agent.pid" },
	{ "pidfile_remove", "NULL", "/run/lota/lota-agent.pid" },
	{ "probe_pcr14_lock_value", "", "/run/lota/pcr14_baseline" },
	{ "probe_pcr14_lock_ran", "", "/run/lota/pcr14_baseline" },
};

/* runner outside the tree: build/<name> -> ../tests */
static bool exe_relative_tests_dir(char *out, size_t len)
{
	char exe[PATH_MAX];
	ssize_t n;
	char *slash;

	n = readlink("/proc/self/exe", exe, sizeof(exe) - 1);
	if (n <= 0)
		return false;
	exe[n] = '\0';

	slash = strrchr(exe, '/');
	if (!slash)
		return false;
	*slash = '\0';

	if (snprintf(out, len, "%s/../tests", exe) >= (int)len)
		return false;
	return true;
}

static void scan_source(const char *dir, const char *name, unsigned *hits)
{
	char path[PATH_MAX + 256];
	char line[512];
	FILE *fp;
	size_t i;
	unsigned lineno = 0;

	snprintf(path, sizeof(path), "%s/%s", dir, name);
	fp = fopen(path, "re");
	if (!fp)
		return;

	while (fgets(line, sizeof(line), fp)) {
		lineno++;
		for (i = 0; i < sizeof(refused) / sizeof(refused[0]); i++) {
			char needle[96];

			snprintf(needle, sizeof(needle), "%s(%s", refused[i].fn,
				 refused[i].arg);
			if (!strstr(line, needle))
				continue;
			printf("\n       %s:%u: %s -> %s", name, lineno, needle,
			       refused[i].file);
			(*hits)++;
		}
	}

	fclose(fp);
}

static void test_no_case_reaches_a_live_runtime_file(void)
{
	static const char *const roots[] = { "tests", "../tests",
					     "../../tests" };
	char from_exe[PATH_MAX];
	struct dirent *ent;
	const char *dir = NULL;
	unsigned hits = 0;
	size_t i;
	DIR *d = NULL;

	TEST("no test case resolves a fixture the agent owns");

	for (i = 0; i < sizeof(roots) / sizeof(roots[0]); i++) {
		d = opendir(roots[i]);
		if (d) {
			dir = roots[i];
			break;
		}
	}
	/* run from elsewhere: the sources sit beside the build directory */
	if (!d && exe_relative_tests_dir(from_exe, sizeof(from_exe))) {
		d = opendir(from_exe);
		if (d)
			dir = from_exe;
	}
	if (!d) {
		FAIL("could not open the tests directory");
		return;
	}

	while ((ent = readdir(d)) != NULL) {
		const char *dot = strrchr(ent->d_name, '.');

		if (!dot || strcmp(dot, ".c") != 0)
			continue;
		scan_source(dir, ent->d_name, &hits);
	}
	closedir(d);

	if (hits) {
		printf("\n       ");
		FAIL("a case takes a live runtime file as its fixture");
		return;
	}
	PASS();
}

int main(void)
{
	printf("=== Live-fixture Tests ===\n\n");

	test_no_case_reaches_a_live_runtime_file();

	printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
	return (tests_passed == tests_run) ? 0 : 1;
}
