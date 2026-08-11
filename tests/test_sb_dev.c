/* SPDX-License-Identifier: MIT */
/*
 * The device number the loader writes into the trusted-library map keys has
 * to be the one the BPF programs read back: inode->i_sb->s_dev, the device of
 * the filesystem's superblock.
 *
 * stat(2) is not that number everywhere. btrfs hands out a per-subvolume
 * anonymous device, so a file in a subvolume has one device in stat(2)
 * and a different one in its superblock, and a key built from stat(2) can never
 * be looked up by a hook.
 *
 * The oracle here is /proc/self/mountinfo, which prints the superblock device
 * the kernel itself keys on, for the mount the file was resolved through.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include "../include/lota_devt.h"

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

/* Mount id of an open file, the id /proc/self/mountinfo lists in field 1 */
static int oracle_mnt_id(int fd, unsigned long long *out_id)
{
	struct statx stx = { 0 };

	if (statx(fd, "", AT_EMPTY_PATH, STATX_MNT_ID, &stx) != 0)
		return -errno;

	if (!(stx.stx_mask & STATX_MNT_ID))
		return -ENOTSUP;

	*out_id = (unsigned long long)stx.stx_mnt_id;
	return 0;
}

/* Superblock device of that mount, in the kernel layout the BPF side reads */
static int oracle_sb_dev(unsigned long long mnt_id, unsigned long long *out_dev)
{
	char line[4096];
	FILE *f;

	f = fopen("/proc/self/mountinfo", "re");
	if (!f)
		return -errno;

	while (fgets(line, sizeof(line), f)) {
		unsigned long long id = 0;
		unsigned int parent = 0;
		unsigned int major = 0;
		unsigned int minor = 0;

		if (sscanf(line, "%llu %u %u:%u", &id, &parent, &major,
			   &minor) != 4)
			continue;

		if (id != mnt_id)
			continue;

		fclose(f);
		*out_dev = LOTA_DEVT_MKDEV(major, minor);
		return 0;
	}

	fclose(f);
	return -ENOENT;
}

static int oracle_sb_dev_for_path(const char *path, unsigned long long *out_dev)
{
	unsigned long long mnt_id = 0;
	int fd;
	int ret;

	fd = open(path, O_RDONLY | O_CLOEXEC | O_PATH);
	if (fd < 0)
		return -errno;

	ret = oracle_mnt_id(fd, &mnt_id);
	close(fd);
	if (ret < 0)
		return ret;

	return oracle_sb_dev(mnt_id, out_dev);
}

/*
 * What the loader keys on today: bpf_loader_trust_lib()
 * and update_trusted_mountpoint_ref() both build key.dev this way.
 */
static int loader_key_dev(const char *path, unsigned long long *out_dev)
{
	struct stat st = { 0 };

	if (stat(path, &st) != 0)
		return -errno;

	*out_dev = lota_devt_from_st(st.st_dev);
	return 0;
}

static void test_file_key_matches_superblock(const char *path)
{
	unsigned long long expected = 0;
	unsigned long long actual = 0;
	char msg[PATH_MAX + 128];

	if (oracle_sb_dev_for_path(path, &expected) < 0) {
		fprintf(stderr, "FAIL: no superblock device for %s\n", path);
		g_failures++;
		return;
	}

	if (loader_key_dev(path, &actual) < 0) {
		fprintf(stderr, "FAIL: no loader key for %s\n", path);
		g_failures++;
		return;
	}

	snprintf(
		msg, sizeof(msg),
		"a file's map key uses the superblock device (%s: key %u:%u, superblock %u:%u)",
		path, LOTA_DEVT_MAJOR(actual), LOTA_DEVT_MINOR(actual),
		LOTA_DEVT_MAJOR(expected), LOTA_DEVT_MINOR(expected));
	CHECK(actual == expected, msg);
}

static void test_dir_key_matches_superblock(const char *path)
{
	unsigned long long expected = 0;
	unsigned long long actual = 0;
	char msg[PATH_MAX + 128];

	if (oracle_sb_dev_for_path(path, &expected) < 0) {
		fprintf(stderr, "FAIL: no superblock device for %s\n", path);
		g_failures++;
		return;
	}

	if (loader_key_dev(path, &actual) < 0) {
		fprintf(stderr, "FAIL: no loader key for %s\n", path);
		g_failures++;
		return;
	}

	snprintf(
		msg, sizeof(msg),
		"a mountpoint's map key uses the superblock device (%s: key %u:%u, superblock %u:%u)",
		path, LOTA_DEVT_MAJOR(actual), LOTA_DEVT_MINOR(actual),
		LOTA_DEVT_MAJOR(expected), LOTA_DEVT_MINOR(expected));
	CHECK(actual == expected, msg);
}

static int read_record(FILE *f, char *buf, size_t size)
{
	size_t len = 0;
	int c;

	while ((c = getc(f)) != EOF && c != '\n') {
		if (len + 1 < size)
			buf[len++] = (char)c;
	}
	buf[len] = '\0';
	return c != EOF || len > 0;
}

/*
 * The trusted set is armed by path, so every filesystem a library can live on
 * has to agree: /proc/self/mountinfo names them all, and each one's own
 * mountpoint is a path the loader would key on.
 */
static void test_every_mounted_filesystem(void)
{
	char line[4096];
	unsigned int checked = 0;
	unsigned int mismatched = 0;
	FILE *f;

	f = fopen("/proc/self/mountinfo", "re");
	if (!f) {
		fprintf(stderr, "FAIL: cannot read /proc/self/mountinfo\n");
		g_failures++;
		return;
	}

	while (read_record(f, line, sizeof(line))) {
		unsigned long long id = 0;
		unsigned long long expected = 0;
		unsigned long long actual = 0;
		unsigned int parent = 0;
		unsigned int major = 0;
		unsigned int minor = 0;
		char mount_point[PATH_MAX];

		if (sscanf(line, "%llu %u %u:%u %*s %4095s", &id, &parent,
			   &major, &minor, mount_point) != 5)
			continue;

		/* octal escapes in a mount point are not worth decoding here */
		if (strchr(mount_point, '\\'))
			continue;

		if (loader_key_dev(mount_point, &actual) < 0)
			continue;

		expected = LOTA_DEVT_MKDEV(major, minor);
		checked++;
		if (actual != expected) {
			fprintf(stderr,
				"     %s: key %u:%u, superblock %u:%u\n",
				mount_point, LOTA_DEVT_MAJOR(actual),
				LOTA_DEVT_MINOR(actual), major, minor);
			mismatched++;
		}
	}

	fclose(f);

	CHECK(checked > 0, "at least one mounted filesystem was checked");
	CHECK(mismatched == 0,
	      "no mounted filesystem keys on a device the BPF side cannot read");
}

int main(void)
{
	char self[PATH_MAX];
	char *dir;
	ssize_t len;

	printf("=== trusted-library map key device tests ===\n");

	len = readlink("/proc/self/exe", self, sizeof(self) - 1);
	if (len <= 0) {
		fprintf(stderr, "FAIL: cannot resolve /proc/self/exe\n");
		return 1;
	}
	self[len] = '\0';

	test_file_key_matches_superblock(self);

	dir = strrchr(self, '/');
	if (dir && dir != self) {
		*dir = '\0';
		test_dir_key_matches_superblock(self);
	}

	test_every_mounted_filesystem();

	if (g_failures) {
		fprintf(stderr, "\n%d test(s) failed\n", g_failures);
		return 1;
	}
	printf("\nAll trusted-library map key device tests passed\n");
	return 0;
}
