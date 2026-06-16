/* SPDX-License-Identifier: MIT */
/*
 * LOTA runtime image mapping enumeration - Unit Tests
 *
 * Exercises the /proc/<pid>/maps line parser (which mappings are selected
 * for measurement) and the live collector against the test process's own
 * address space.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>

#include "../src/agent/runtime_image_measure.h"
#include "lota_runtime_image_measure.h"

static int tests_run;
static int tests_passed;

#define TEST(name)                                        \
	do {                                              \
		tests_run++;                              \
		printf("  [%2d] %-55s", tests_run, name); \
	} while (0)

#define PASS()                    \
	do {                      \
		tests_passed++;   \
		printf("PASS\n"); \
	} while (0)

#define FAIL(reason)                           \
	do {                                   \
		printf("FAIL (%s)\n", reason); \
	} while (0)

static const char *self_basename(char *buf, size_t len)
{
	ssize_t n = readlink("/proc/self/exe", buf, len - 1);
	const char *slash;

	if (n < 0)
		return NULL;
	buf[n] = '\0';
	slash = strrchr(buf, '/');
	return slash ? slash + 1 : buf;
}

int main(void)
{
	struct lota_rt_map_entry e;
	struct lota_rt_map_entry entries[LOTA_RUNTIME_IMAGE_MAX_MODULES];
	char exe[PATH_MAX];
	const char *self;
	size_t n = 0;
	int rc;

	printf("Runtime image mapping enumeration tests:\n");

	TEST("file-backed executable mapping is selected");
	rc = lota_rt_parse_maps_line(
		"55a3c0e00000-55a3c0e21000 r-xp 00001000 fd:01 1234567 "
		"/usr/bin/foo\n",
		&e);
	if (rc == 1 && strcmp(e.soname, "foo") == 0 && e.ino == 1234567ULL &&
	    e.dev_major == 0xfd && e.dev_minor == 0x01 &&
	    e.start == 0x55a3c0e00000UL && e.end == 0x55a3c0e21000UL)
		PASS();
	else
		FAIL("not selected / wrong fields");

	TEST("read-only mapping is skipped");
	rc = lota_rt_parse_maps_line(
		"7f0000000000-7f0000001000 r--p 00000000 fd:01 2222 "
		"/usr/lib/libc.so.6\n",
		&e);
	if (rc == 0)
		PASS();
	else
		FAIL("selected non-exec mapping");

	TEST("writable data mapping is skipped");
	rc = lota_rt_parse_maps_line(
		"7f0000002000-7f0000003000 rw-p 00002000 fd:01 2222 "
		"/usr/lib/libc.so.6\n",
		&e);
	if (rc == 0)
		PASS();
	else
		FAIL("selected writable mapping");

	TEST("anonymous executable mapping is skipped");
	rc = lota_rt_parse_maps_line(
		"7f0000004000-7f0000005000 r-xp 00000000 00:00 0 \n", &e);
	if (rc == 0)
		PASS();
	else
		FAIL("selected anonymous exec");

	TEST("vDSO region is skipped");
	rc = lota_rt_parse_maps_line(
		"7ffff7fc1000-7ffff7fc3000 r-xp 00000000 00:00 0 [vdso]\n", &e);
	if (rc == 0)
		PASS();
	else
		FAIL("selected vdso");

	TEST("special bracketed region is skipped");
	rc = lota_rt_parse_maps_line(
		"7f0000006000-7f0000007000 r-xp 00000000 fd:01 55 [heap]\n",
		&e);
	if (rc == 0)
		PASS();
	else
		FAIL("selected bracketed region");

	TEST("deleted suffix is stripped from soname");
	rc = lota_rt_parse_maps_line(
		"55a3c0e00000-55a3c0e21000 r-xp 00001000 fd:01 1234567 "
		"/tmp/game.bin (deleted)\n",
		&e);
	if (rc == 1 && strcmp(e.soname, "game.bin") == 0)
		PASS();
	else
		FAIL("deleted suffix not stripped");

	TEST("basename keeps embedded spaces");
	rc = lota_rt_parse_maps_line(
		"55a3c0e00000-55a3c0e21000 r-xp 00001000 fd:01 1234567 "
		"/opt/game dir/game bin\n",
		&e);
	if (rc == 1 && strcmp(e.soname, "game bin") == 0)
		PASS();
	else
		FAIL("basename with spaces not preserved");

	TEST("malformed line is rejected");
	rc = lota_rt_parse_maps_line("not a maps line\n", &e);
	if (rc < 0)
		PASS();
	else
		FAIL("accepted malformed line");

	TEST("collector finds the process's own executable");
	self = self_basename(exe, sizeof(exe));
	rc = lota_rt_collect_exec_maps(getpid(), entries,
				       LOTA_RUNTIME_IMAGE_MAX_MODULES, &n);
	if (rc == 0 && self && n >= 1) {
		int found = 0;
		for (size_t i = 0; i < n; i++) {
			if (strcmp(entries[i].soname, self) == 0)
				found = 1;
		}
		if (found)
			PASS();
		else
			FAIL("own exe not in collected set");
	} else {
		FAIL("collect failed");
	}

	TEST("collector deduplicates by backing inode");
	{
		int dup = 0;
		for (size_t i = 0; i < n; i++) {
			for (size_t j = i + 1; j < n; j++) {
				if (entries[i].dev_major ==
					    entries[j].dev_major &&
				    entries[i].dev_minor ==
					    entries[j].dev_minor &&
				    entries[i].ino == entries[j].ino)
					dup = 1;
			}
		}
		if (!dup)
			PASS();
		else
			FAIL("duplicate inode in set");
	}

	printf("\n%d/%d runtime image enumeration tests passed\n", tests_passed,
	       tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
