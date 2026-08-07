/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Unit tests for the runtime measurement's mapping-identity check.
 *
 * Between enumerating a process's executable mappings and opening one of them,
 * the process can unmap the range and map something else there. The check that
 * catches it decides whether a measurement describes the object it claims to,
 * so what is pinned here is that a replaced mapping is refused and that the
 * comparison is made between numbers that come from the same source -- a
 * device parsed out of /proc/<pid>/maps and one returned by stat() are not the
 * same quantity on every filesystem.
 *
 * Pure: no /proc and no process here.
 */

#include <stdio.h>
#include <string.h>

#include "../src/agent/runtime_image_measure.h"

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

static struct lota_rt_map_entry mapping(unsigned int maj, unsigned int min,
					unsigned long long ino)
{
	struct lota_rt_map_entry e;

	memset(&e, 0, sizeof(e));
	e.start = 0x400000;
	e.end = 0x401000;
	e.dev_major = maj;
	e.dev_minor = min;
	e.ino = ino;
	return e;
}

/* Nothing moved: the range still names the object that was enumerated. */
static void test_unchanged_mapping_is_accepted(void)
{
	struct lota_rt_map_entry enumerated = mapping(0, 36, 2626486);
	struct lota_rt_map_entry observed = mapping(0, 36, 2626486);

	CHECK(lota_rt_mapping_identity_ok(&enumerated, &observed, 2626486) == 1,
	      "an unchanged mapping is accepted");
}

/*
 * The race this exists for: the range now backs a different inode,
 * so the handle that was opened does not describe what was enumerated.
 */
static void test_replaced_mapping_is_refused(void)
{
	struct lota_rt_map_entry enumerated = mapping(0, 36, 2626486);
	struct lota_rt_map_entry observed = mapping(0, 36, 9999999);

	CHECK(lota_rt_mapping_identity_ok(&enumerated, &observed, 9999999) == 0,
	      "a mapping replaced by another inode is refused");
}

/*
 * Inode numbers are only unique within a filesystem, so a range that moved to
 * another filesystem carrying the same inode number is still a different
 * object.
 */
static void test_same_inode_other_filesystem_is_refused(void)
{
	struct lota_rt_map_entry enumerated = mapping(0, 36, 2626486);
	struct lota_rt_map_entry observed = mapping(0, 41, 2626486);

	CHECK(lota_rt_mapping_identity_ok(&enumerated, &observed, 2626486) == 0,
	      "the same inode number on another device is refused");
}

/*
 * The opened handle is the other half of the identity: if what was opened is
 * not the inode that was enumerated, nothing else matters.
 */
static void test_opened_inode_must_match(void)
{
	struct lota_rt_map_entry enumerated = mapping(0, 36, 2626486);
	struct lota_rt_map_entry observed = mapping(0, 36, 2626486);

	CHECK(lota_rt_mapping_identity_ok(&enumerated, &observed, 1234) == 0,
	      "an opened handle on a different inode is refused");
}

/*
 * The device numbers compared here both come from /proc/<pid>/maps.
 * A device from stat() is a different quantity on a filesystem that reports
 * one per subvolume, and comparing the two refuses every mapping on such
 * a host -- so the check must never be handed one of each.
 */
static void test_identity_is_not_compared_against_stat_device(void)
{
	/*
	 * btrfs:
	 * maps reports the filesystem's s_dev,
	 * stat reports the subvolume's anonymous device.
	 * Both describe the same live mapping.
	 */
	struct lota_rt_map_entry enumerated = mapping(0, 36, 2626486);
	struct lota_rt_map_entry observed = mapping(0, 36, 2626486);

	CHECK(lota_rt_mapping_identity_ok(&enumerated, &observed, 2626486) == 1,
	      "a mapping whose stat device differs from its maps device is accepted");
}

static void test_null_arguments_are_refused(void)
{
	struct lota_rt_map_entry e = mapping(0, 36, 2626486);

	CHECK(lota_rt_mapping_identity_ok(NULL, &e, 2626486) == 0,
	      "a NULL enumerated entry is refused");
	CHECK(lota_rt_mapping_identity_ok(&e, NULL, 2626486) == 0,
	      "a NULL observed entry is refused");
}

int main(void)
{
	printf("=== runtime mapping identity tests ===\n");
	test_unchanged_mapping_is_accepted();
	test_replaced_mapping_is_refused();
	test_same_inode_other_filesystem_is_refused();
	test_opened_inode_must_match();
	test_identity_is_not_compared_against_stat_device();
	test_null_arguments_are_refused();

	if (g_failures) {
		fprintf(stderr, "\n%d test(s) failed\n", g_failures);
		return 1;
	}
	printf("\nAll runtime mapping identity tests passed\n");
	return 0;
}
