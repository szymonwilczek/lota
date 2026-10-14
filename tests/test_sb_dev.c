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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../include/lota_devt.h"
#include "../src/agent/sb_dev.h"

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
	int fd;
	int ret;

	fd = open(path, O_RDONLY | O_CLOEXEC | O_PATH);
	if (fd < 0)
		return -errno;

	ret = sb_dev_from_fd(fd, out_dev);
	close(fd);
	return ret;
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

/* Mount a path resolves to, or 0 when it cannot be read */
static unsigned long long path_mnt_id(const char *path)
{
	unsigned long long id = 0;
	int fd;
	int ret;

	fd = open(path, O_RDONLY | O_CLOEXEC | O_PATH);
	if (fd < 0)
		return 0;

	ret = oracle_mnt_id(fd, &id);
	close(fd);
	return ret == 0 ? id : 0;
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

		/*
		 * A mount point can be mounted over -- /proc/sys/fs/binfmt_misc
		 * is autofs with binfmt_misc on top -- and then the path leads
		 * to the mount above, whose device this line does not name.
		 */
		if (path_mnt_id(mount_point) != id)
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

static const char *g_fixture =
	/* a btrfs filesystem mounted twice: two mount ids, one superblock */
	"43 1 0:35 /root / rw,relatime shared:1 - btrfs /dev/sdb3 rw,compress=zstd:1,subvol=/root\n"
	"61 43 0:35 /home /home rw,relatime shared:31 - btrfs /dev/sdb3 rw,compress=zstd:1,subvol=/home\n"
	"27 25 259:4 / /boot rw,relatime shared:22 - ext4 /dev/nvme0n1p4 rw\n"
	"not a mountinfo line at all\n";

static void write_fixture(int fd, const char *path, const char *body)
{
	FILE *f = fdopen(fd, "w");

	if (!f) {
		fprintf(stderr, "FAIL: cannot write fixture %s\n", path);
		close(fd);
		g_failures++;
		return;
	}
	fputs(body, f);
	fclose(f);
}

/*
 * Two subvolumes of one filesystem answer with the same superblock device
 * -- the case stat(2) gets wrong -- and a mount that is not listed is refused.
 */
static void test_mountinfo_parse(void)
{
	char path[] = "/tmp/lota-test-mountinfo-XXXXXX";
	unsigned long long dev = 0;
	int fd = mkstemp(path);

	if (fd < 0) {
		fprintf(stderr, "FAIL: cannot create a fixture file\n");
		g_failures++;
		return;
	}
	write_fixture(fd, path, g_fixture);

	CHECK(sb_dev_from_mountinfo(path, 43, &dev) == 0 &&
		      dev == LOTA_DEVT_MKDEV(0, 35),
	      "a subvolume mount resolves to its superblock device");

	dev = 0;
	CHECK(sb_dev_from_mountinfo(path, 61, &dev) == 0 &&
		      dev == LOTA_DEVT_MKDEV(0, 35),
	      "a second subvolume of the same filesystem resolves to the same device");

	dev = 0;
	CHECK(sb_dev_from_mountinfo(path, 27, &dev) == 0 &&
		      dev == LOTA_DEVT_MKDEV(259, 4),
	      "a real block device keeps its major and minor");

	dev = 0xdeadbeefULL;
	CHECK(sb_dev_from_mountinfo(path, 999, &dev) == -ENODEV &&
		      dev == 0xdeadbeefULL,
	      "an unlisted mount is refused and writes nothing");

	CHECK(sb_dev_from_mountinfo("/proc/self/no-such-mountinfo", 43, &dev) <
		      0,
	      "a mountinfo that cannot be read is refused");

	unlink(path);
}

/*
 * A line longer than the reader's buffer must not have its tail taken for
 * a record of its own: a mount point can be as long as a path,
 * and the fields after it are longer still.
 */
static void test_long_line_is_not_split(void)
{
	char path[] = "/tmp/lota-test-mountinfo-XXXXXX";
	char body[16384];
	char pad[9000];
	unsigned long long dev = 0;
	int fd = mkstemp(path);

	if (fd < 0) {
		fprintf(stderr, "FAIL: cannot create a fixture file\n");
		g_failures++;
		return;
	}

	memset(pad, 'a', sizeof(pad) - 1);
	pad[sizeof(pad) - 1] = '\0';

	snprintf(body, sizeof(body),
		 "43 1 0:35 / /%s rw,relatime - btrfs /dev/sdb3 rw\n"
		 "61 43 0:36 / /home rw,relatime - btrfs /dev/sdb3 rw\n",
		 pad);
	write_fixture(fd, path, body);

	CHECK(sb_dev_from_mountinfo(path, 61, &dev) == 0 &&
		      dev == LOTA_DEVT_MKDEV(0, 36),
	      "the record after an over-long line is read as one record");

	unlink(path);
}

int main(void)
{
	char self[PATH_MAX];
	char *dir;
	ssize_t len;

	printf("=== trusted-library map key device tests ===\n");

	test_mountinfo_parse();
	test_long_line_is_not_split();

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
