/* SPDX-License-Identifier: MIT */
/*
 * Which road may answer for one mapped object - Unit Tests
 *
 * fs-verity wins wherever present. Only the process's own executable may
 * be hashed, as a mapped library stays writable under it.
 * Filesystems served by userspace or a peer are refused: the hasher
 * and the page fault may be served different bytes.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <stdio.h>

#include "../src/agent/runtime_image_measure.h"

static int tests_run;
static int tests_passed;

#define TEST(name)                                        \
	do {                                              \
		tests_run++;                              \
		printf("  [%2d] %-58s", tests_run, name); \
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

/* local filesystems */
#define MAGIC_BTRFS 0x9123683EUL
#define MAGIC_EXT4 0xEF53UL
#define MAGIC_XFS 0x58465342UL
#define MAGIC_OVERLAYFS 0x794C7630UL
#define MAGIC_TMPFS 0x01021994UL
#define MAGIC_HUGETLBFS 0x958458F6UL

/* served by userspace or a peer */
#define MAGIC_FUSE 0x65735546UL
#define MAGIC_NFS 0x6969UL
#define MAGIC_CIFS 0xFF534D42UL
#define MAGIC_SMB2 0xFE534D42UL
#define MAGIC_9P 0x01021997UL
#define MAGIC_CEPH 0x00C36400UL

static void expect_guarded(const char *name, enum lota_rt_identity_road want,
			   int role, int verity_present, unsigned long magic,
			   int write_guarded)
{
	enum lota_rt_identity_road got;

	TEST(name);
	got = lota_rt_identity_road(role, verity_present, magic, write_guarded);
	if (got != want) {
		char reason[96];

		snprintf(reason, sizeof(reason), "road %d, wanted %d", (int)got,
			 (int)want);
		FAIL(reason);
		return;
	}
	PASS();
}

/* unguarded object */
static void expect(const char *name, enum lota_rt_identity_road want, int role,
		   int verity_present, unsigned long magic)
{
	expect_guarded(name, want, role, verity_present, magic, 0);
}

/* a verity digest is never traded for a hash, whatever the role or fs */
static void test_verity_wins(void)
{
	expect("an executable with a verity digest takes it",
	       LOTA_RT_ROAD_VERITY, LOTA_RT_ROLE_EXECUTABLE, 1, MAGIC_BTRFS);
	expect("a mapped object with a verity digest takes it",
	       LOTA_RT_ROAD_VERITY, LOTA_RT_ROLE_MAPPED_OBJECT, 1, MAGIC_EXT4);
	expect("verity on a filesystem that may not be hashed still counts",
	       LOTA_RT_ROAD_VERITY, LOTA_RT_ROLE_EXECUTABLE, 1, MAGIC_FUSE);
}

static void test_own_executable_is_hashed(void)
{
	expect("a stock executable on btrfs is hashed",
	       LOTA_RT_ROAD_CONTENT_HASH, LOTA_RT_ROLE_EXECUTABLE, 0,
	       MAGIC_BTRFS);
	expect("a stock executable on ext4 is hashed",
	       LOTA_RT_ROAD_CONTENT_HASH, LOTA_RT_ROLE_EXECUTABLE, 0,
	       MAGIC_EXT4);
	expect("a stock executable on xfs is hashed", LOTA_RT_ROAD_CONTENT_HASH,
	       LOTA_RT_ROLE_EXECUTABLE, 0, MAGIC_XFS);
	expect("an executable on overlayfs is hashed",
	       LOTA_RT_ROAD_CONTENT_HASH, LOTA_RT_ROLE_EXECUTABLE, 0,
	       MAGIC_OVERLAYFS);
	expect("an executable on tmpfs is hashed", LOTA_RT_ROAD_CONTENT_HASH,
	       LOTA_RT_ROLE_EXECUTABLE, 0, MAGIC_TMPFS);
}

/* MAP_DENYWRITE is a no-op: a mapped library stays writable */
static void test_libraries_are_not_hashed(void)
{
	expect("a stock library is left out of the fold", LOTA_RT_ROAD_NONE,
	       LOTA_RT_ROLE_MAPPED_OBJECT, 0, MAGIC_BTRFS);
	expect("a stock library on ext4 is left out too", LOTA_RT_ROAD_NONE,
	       LOTA_RT_ROLE_MAPPED_OBJECT, 0, MAGIC_EXT4);
}

/*
 * The kernel hashes these without complaint, so the refusal is ours:
 * the hasher's read and the page fault may be served different bytes.
 */
static void test_served_filesystems_are_refused(void)
{
	expect("an executable on fuse is refused", LOTA_RT_ROAD_NONE,
	       LOTA_RT_ROLE_EXECUTABLE, 0, MAGIC_FUSE);
	expect("an executable on nfs is refused", LOTA_RT_ROAD_NONE,
	       LOTA_RT_ROLE_EXECUTABLE, 0, MAGIC_NFS);
	expect("an executable on cifs is refused", LOTA_RT_ROAD_NONE,
	       LOTA_RT_ROLE_EXECUTABLE, 0, MAGIC_CIFS);
	expect("an executable on smb2 is refused", LOTA_RT_ROAD_NONE,
	       LOTA_RT_ROLE_EXECUTABLE, 0, MAGIC_SMB2);
	expect("an executable on 9p is refused", LOTA_RT_ROAD_NONE,
	       LOTA_RT_ROLE_EXECUTABLE, 0, MAGIC_9P);
	expect("an executable on ceph is refused", LOTA_RT_ROAD_NONE,
	       LOTA_RT_ROLE_EXECUTABLE, 0, MAGIC_CEPH);
}

/* unknown role: the executable check never ran; unknown fs: not listed */
static void test_unknown_role_is_refused(void)
{
	expect("an object of unknown role is refused", LOTA_RT_ROAD_NONE,
	       LOTA_RT_ROLE_UNKNOWN, 0, MAGIC_BTRFS);
	expect("an unknown filesystem is refused", LOTA_RT_ROAD_NONE,
	       LOTA_RT_ROLE_EXECUTABLE, 0, 0);
}

/*
 * Write opens refused while mapped make a library as stable as a running
 * executable, which the kernel alone guards.
 */
static void test_a_guarded_library_is_hashed(void)
{
	expect_guarded("a guarded library on btrfs is hashed",
		       LOTA_RT_ROAD_CONTENT_HASH, LOTA_RT_ROLE_MAPPED_OBJECT, 0,
		       MAGIC_BTRFS, 1);
	expect_guarded("a guarded library on ext4 is hashed",
		       LOTA_RT_ROAD_CONTENT_HASH, LOTA_RT_ROLE_MAPPED_OBJECT, 0,
		       MAGIC_EXT4, 1);
	expect_guarded("a guarded library with a verity digest still takes it",
		       LOTA_RT_ROAD_VERITY, LOTA_RT_ROLE_MAPPED_OBJECT, 1,
		       MAGIC_BTRFS, 1);
}

/* a served fs answers the hasher and the page fault separately */
static void test_a_guarded_library_on_a_served_fs_is_refused(void)
{
	expect_guarded("a guarded library on fuse is still refused",
		       LOTA_RT_ROAD_NONE, LOTA_RT_ROLE_MAPPED_OBJECT, 0,
		       MAGIC_FUSE, 1);
	expect_guarded("a guarded library on nfs is still refused",
		       LOTA_RT_ROAD_NONE, LOTA_RT_ROLE_MAPPED_OBJECT, 0,
		       MAGIC_NFS, 1);
}

static void test_a_guard_does_not_rescue_an_unknown_role(void)
{
	expect_guarded("a guarded object of unknown role is refused",
		       LOTA_RT_ROAD_NONE, LOTA_RT_ROLE_UNKNOWN, 0, MAGIC_BTRFS,
		       1);
}

static void expect_no_file(const char *name, int want, unsigned long magic,
			   unsigned long nlink)
{
	TEST(name);
	if (lota_rt_object_has_no_file(magic, nlink) != want) {
		FAIL(want ? "read as a file" : "read as memory");
		return;
	}
	PASS();
}

/*
 * Wine maps PE images out of nameless memory (memfd, unlinked shm),
 * which no digest or write guard can reach: a coverage gap, not a failed
 * measurement. A named file, or one on disk, is an ordinary object.
 */
static void test_memory_with_no_name_is_no_file(void)
{
	expect_no_file("an unlinked tmpfs object is no file", 1, MAGIC_TMPFS,
		       0);
	expect_no_file("an unlinked hugetlbfs object is no file", 1,
		       MAGIC_HUGETLBFS, 0);
	expect_no_file("a named tmpfs file is a file", 0, MAGIC_TMPFS, 1);
	expect_no_file("an unlinked file on disk is a file", 0, MAGIC_EXT4, 0);
	expect_no_file("an unlinked file on btrfs is a file", 0, MAGIC_BTRFS,
		       0);
}

int main(void)
{
	printf("\n=== LOTA runtime identity road tests ===\n\n");

	test_verity_wins();
	test_own_executable_is_hashed();
	test_libraries_are_not_hashed();
	test_served_filesystems_are_refused();
	test_unknown_role_is_refused();
	test_a_guarded_library_is_hashed();
	test_a_guarded_library_on_a_served_fs_is_refused();
	test_a_guard_does_not_rescue_an_unknown_role();
	test_memory_with_no_name_is_no_file();

	printf("\n=== Results: %d/%d passed ===\n\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
