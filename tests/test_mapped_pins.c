/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for the write guard's release rule. A pin never released lets
 * any process fill the map and block new measurement until reboot.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <stdio.h>
#include <string.h>

#include "../src/agent/mapped_pins.h"

static int tests_run;
static int tests_passed;

#define TEST(name)                                         \
	do {                                               \
		tests_run++;                               \
		printf("  [%2d] %-58s ", tests_run, name); \
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

static void check(const char *name, int ok, const char *why)
{
	TEST(name);
	if (ok)
		PASS();
	else
		FAIL(why);
}

static int kept_has(const struct mapped_exec_pin *pins, size_t kept,
		    uint64_t dev, uint64_t ino)
{
	return mapped_pins_find(pins, kept, dev, ino) != kept;
}

static void test_find(void)
{
	struct mapped_exec_pin pins[3] = {
		{ .dev = 64, .ino = 100, .round = 1 },
		{ .dev = 64, .ino = 200, .round = 1 },
		{ .dev = 65, .ino = 100, .round = 1 },
	};

	check("an empty registry pins nothing",
	      mapped_pins_find(pins, 0, 64, 100) == 0, "found something in it");

	check("a pinned inode is found",
	      mapped_pins_find(pins, 3, 64, 200) == 1, "wrong index");

	/* btrfs subvolumes reuse inode numbers across devices */
	check("the same inode on another device is another file",
	      mapped_pins_find(pins, 3, 65, 100) == 2, "wrong index");

	check("an inode nobody pinned is absent",
	      mapped_pins_find(pins, 3, 64, 300) == 3, "found something");
}

static void test_release(void)
{
	struct mapped_exec_pin pins[4] = {
		{ .dev = 64, .ino = 100, .round = 7 },
		{ .dev = 64, .ino = 200, .round = 6 },
		{ .dev = 64, .ino = 300, .round = 7 },
		{ .dev = 64, .ino = 400, .round = 5 },
	};
	size_t kept;

	kept = mapped_pins_partition(pins, 4, 7);

	check("a round releases what it did not reach", kept == 2,
	      "the registry kept entries no round wants");

	check("what this round reached is still pinned",
	      kept_has(pins, kept, 64, 100) && kept_has(pins, kept, 64, 300),
	      "an object still being measured lost its guard");

	check("an object no round reaches is let go of",
	      !kept_has(pins, kept, 64, 200) && !kept_has(pins, kept, 64, 400),
	      "a guard outlived every process that wanted it");
}

static void test_shared_library(void)
{
	struct mapped_exec_pin pins[2] = {
		/* libc, mapped by two protected titles */
		{ .dev = 64, .ino = 100, .round = 9 },
		/* a library only the title that just exited mapped */
		{ .dev = 64, .ino = 500, .round = 8 },
	};
	size_t kept;

	kept = mapped_pins_partition(pins, 2, 9);

	check("a library another protected process still maps stays pinned",
	      kept == 1 && kept_has(pins, kept, 64, 100),
	      "the exit of one title unguarded a library another one runs");
}

static void test_everything_reached(void)
{
	struct mapped_exec_pin pins[3] = {
		{ .dev = 64, .ino = 100, .round = 3 },
		{ .dev = 64, .ino = 200, .round = 3 },
		{ .dev = 64, .ino = 300, .round = 3 },
	};
	size_t kept;

	kept = mapped_pins_partition(pins, 3, 3);
	check("a round that reaches everything releases nothing", kept == 3,
	      "an object being measured lost its guard");

	kept = mapped_pins_partition(pins, kept, 3);
	check("sweeping again changes nothing", kept == 3,
	      "the second sweep released what the first kept");
}

static void test_nothing_reached(void)
{
	struct mapped_exec_pin pins[2] = {
		{ .dev = 64, .ino = 100, .round = 11 },
		{ .dev = 64, .ino = 200, .round = 11 },
	};
	size_t kept;

	/* every protected process exited */
	kept = mapped_pins_partition(pins, 2, 12);
	check("a round that reaches nothing empties the registry", kept == 0,
	      "guards survived with no process left to want them");
}

int main(void)
{
	printf("\n=== mapped pin release tests ===\n\n");

	test_find();
	test_release();
	test_shared_library();
	test_everything_reached();
	test_nothing_reached();

	printf("\n%d/%d passed\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
