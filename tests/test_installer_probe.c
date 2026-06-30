/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Unit tests for the guided installer's pure probe helpers.
 *
 * File-backed probes are exercised end to end by the installer's -status mode
 * on a live host.
 *
 * These tests pin the parsers and the PCR14 lock-constant derivation that
 * the reboot-resume logic depends on.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../installer/probe.h"

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

/* Known answer for SHA256(0^32 || SHA256("LOTA-PCR14-INITRAMFS-LOCK-v1")),
 * the post-extend PCR14 the lock helper installs from a zero PCR.
 * Must stay in sync with src/initramfs/lota-pcr14-lock.c and the verifier's
 * DeriveInitramfsLockPCR14 */
static const char lock_kat_hex[] =
	"d550fa44ab2d1ee9227a3502fcf44698681ab13dfb6cd468da488f01fbbda8bb";

static void test_pcr14_lock_constant_kat(void)
{
	uint8_t expect[PROBE_HASH_SIZE];
	uint8_t got[PROBE_HASH_SIZE];

	TEST("PCR14 lock constant matches the cross-component KAT");
	if (probe_hex_to_bytes(lock_kat_hex, expect, sizeof(expect)) != 0) {
		FAIL("KAT hex did not parse");
		return;
	}
	probe_pcr14_lock_value(got);
	if (memcmp(got, expect, sizeof(expect)) != 0) {
		FAIL("derived constant differs from KAT");
		return;
	}
	PASS();
}

/* Cross-component KAT taken from live UEFI Secure Boot host:
 * shim extends PCR14 before the initramfs lock runs, so the persisted baseline
 * is nonzero and the post-lock PCR14 is SHA256(baseline || commit).
 * These exact values were measured on the validation VM (baseline -> live PCR14).
 * Must stay in sync with src/initramfs/lota-pcr14-lock.c and the verifier's
 * DeriveInitramfsLockPCR14. */
static const char baseline_kat_hex[] =
	"17cdefd9548f4383b67a37a901673bf3c8ded6f619d36c8007562de1d93c81cc";
static const char locked_over_baseline_kat_hex[] =
	"046235f86682f585211ebfc580372280c61782df8c98b4d5039436cfbda9f2d9";

static void write_raw_file(const char *path, const uint8_t *buf, size_t n)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);

	if (fd < 0)
		return;
	if (write(fd, buf, n) != (ssize_t)n)
		fprintf(stderr, "warning: short write to %s\n", path);
	close(fd);
}

static void test_pcr14_lock_value_baseline_aware(void)
{
	uint8_t baseline[PROBE_HASH_SIZE];
	uint8_t expect[PROBE_HASH_SIZE];
	uint8_t zero_expect[PROBE_HASH_SIZE];
	uint8_t got[PROBE_HASH_SIZE];
	char path[256];

	snprintf(path, sizeof(path), "/tmp/lota-inst-base.%d", (int)getpid());

	TEST("PCR14 lock value folds in a nonzero (shim) baseline");
	if (probe_hex_to_bytes(baseline_kat_hex, baseline, sizeof(baseline)) !=
		    0 ||
	    probe_hex_to_bytes(locked_over_baseline_kat_hex, expect,
			       sizeof(expect)) != 0) {
		FAIL("KAT hex did not parse");
		return;
	}
	write_raw_file(path, baseline, sizeof(baseline));
	probe_pcr14_lock_value_at(path, got);
	unlink(path);
	if (memcmp(got, expect, sizeof(expect)) != 0) {
		FAIL("derived value ignores the persisted baseline");
		return;
	}
	PASS();

	TEST("PCR14 lock value falls back to a zero baseline when absent");
	if (probe_hex_to_bytes(lock_kat_hex, zero_expect,
			       sizeof(zero_expect)) != 0) {
		FAIL("KAT hex did not parse");
		return;
	}
	probe_pcr14_lock_value_at("/nonexistent/lota-pcr14-baseline", got);
	if (memcmp(got, zero_expect, sizeof(zero_expect)) != 0) {
		FAIL("absent baseline should derive the zero-based constant");
		return;
	}
	PASS();
}

static void test_hex_to_bytes(void)
{
	uint8_t out[4];

	TEST("hex parser accepts mixed case and exact length");
	if (probe_hex_to_bytes("DEadBEef", out, sizeof(out)) != 0 ||
	    out[0] != 0xde || out[1] != 0xad || out[2] != 0xbe ||
	    out[3] != 0xef) {
		FAIL("mixed-case parse");
		return;
	}
	PASS();

	TEST("hex parser rejects bad length and non-hex chars");
	if (probe_hex_to_bytes("deadbe", out, sizeof(out)) != -EINVAL ||
	    probe_hex_to_bytes("deadbeefaa", out, sizeof(out)) != -EINVAL ||
	    probe_hex_to_bytes("deadbezz", out, sizeof(out)) != -EINVAL) {
		FAIL("bad input accepted");
		return;
	}
	PASS();
}

static void test_cmdline_ima(void)
{
	TEST("ima_appraise=enforce satisfies the floor");
	if (probe_cmdline_ima_ok("ro root=UUID=x ima=on ima_appraise=enforce "
				 "rhgb") != 0) {
		FAIL("enforce rejected");
		return;
	}
	PASS();

	TEST("ima_appraise=fix satisfies the floor");
	if (probe_cmdline_ima_ok("ima_appraise=fix") != 0) {
		FAIL("fix rejected");
		return;
	}
	PASS();

	TEST("log, off and absent ima_appraise fail the floor");
	if (probe_cmdline_ima_ok("ima_appraise=log") != -EPERM ||
	    probe_cmdline_ima_ok("ima_appraise=off") != -EPERM ||
	    probe_cmdline_ima_ok("ro root=UUID=x rhgb quiet") != -EPERM) {
		FAIL("non-enforcing mode accepted");
		return;
	}
	PASS();

	TEST("first ima_appraise token wins, mirroring the agent gate");
	if (probe_cmdline_ima_ok("ima_appraise=log ima_appraise=enforce") !=
	    -EPERM) {
		FAIL("second token consulted");
		return;
	}
	PASS();

	TEST("prefix tokens do not match (ima_appraise_x=enforce)");
	if (probe_cmdline_ima_ok("ima_appraise_x=enforce") != -EPERM) {
		FAIL("prefix matched");
		return;
	}
	PASS();
}

static void test_cmdline_token(void)
{
	TEST("exact token match in a whitespace-separated cmdline");
	if (probe_cmdline_has_token("ro ima=on quiet", "ima=on") != 1 ||
	    probe_cmdline_has_token("ro ima=onx quiet", "ima=on") != 0 ||
	    probe_cmdline_has_token("", "ima=on") != 0 ||
	    probe_cmdline_has_token("ro\tima=on", "ima=on") != 1) {
		FAIL("token matching");
		return;
	}
	PASS();
}

static void test_conf_key(void)
{
	TEST("conf scan finds an uncommented key = value line");
	if (probe_conf_buf_has_key("# policy_pubkey = /x\n"
				   "  policy_pubkey = /etc/lota/policy.pub\n",
				   "policy_pubkey") != 1) {
		FAIL("key not found");
		return;
	}
	PASS();

	TEST("conf scan ignores comments, prefixes and bare words");
	if (probe_conf_buf_has_key("# policy_pubkey = /x\n", "policy_pubkey") !=
		    0 ||
	    probe_conf_buf_has_key("policy_pubkey_extra = /x\n",
				   "policy_pubkey") != 0 ||
	    probe_conf_buf_has_key("policy_pubkey\n", "policy_pubkey") != 0) {
		FAIL("false positive");
		return;
	}
	PASS();
}

static void write_text_file(const char *dir, const char *name, const char *val)
{
	char path[512];
	int fd;
	FILE *f;

	snprintf(path, sizeof(path), "%s/%s", dir, name);
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0)
		return;
	f = fdopen(fd, "w");
	if (f) {
		fputs(val, f);
		fclose(f);
	} else {
		close(fd);
	}
}

static void test_esrt_present(void)
{
	char base[256];
	char dir[320];
	char cmd[320];

	snprintf(base, sizeof(base), "/tmp/lota-inst-esrt.%d", (int)getpid());

	TEST("ESRT: absent entries dir reports not-present");
	if (probe_esrt_system_firmware_present_at(base) != 0) {
		FAIL("nonexistent base should be 0");
		return;
	}
	PASS();

	mkdir(base, 0755);
	snprintf(dir, sizeof(dir), "%s/entry0", base);
	mkdir(dir, 0755);
	write_text_file(dir, "fw_type", "2\n"); /* device firmware */

	TEST("ESRT: only device-firmware entries reports not-present");
	if (probe_esrt_system_firmware_present_at(base) != 0) {
		FAIL("device-only should be 0");
		goto cleanup;
	}
	PASS();

	snprintf(dir, sizeof(dir), "%s/entry1", base);
	mkdir(dir, 0755);
	write_text_file(dir, "fw_type", "1\n"); /* system firmware */

	TEST("ESRT: a system-firmware entry reports present");
	if (probe_esrt_system_firmware_present_at(base) != 1) {
		FAIL("system fw entry should be 1");
		goto cleanup;
	}
	PASS();

cleanup:
	snprintf(cmd, sizeof(cmd), "rm -rf '%s'", base);
	if (system(cmd) != 0)
		fprintf(stderr, "warning: cleanup failed\n");
}

/* statfs f_type magics, mirroring <linux/magic.h> */
#define KAT_EXT_MAGIC 0xEF53
#define KAT_XFS_MAGIC 0x58465342
#define KAT_BTRFS_MAGIC 0x9123683E
#define KAT_F2FS_MAGIC 0xF2F52010
#define KAT_ZFS_MAGIC 0x2FC12FC1

static void test_fstype_magic_mapping(void)
{
	TEST("statfs magic maps to the right filesystem class");
	if (probe_fstype_from_magic(KAT_EXT_MAGIC) != PROBE_FS_EXT4 ||
	    probe_fstype_from_magic(KAT_XFS_MAGIC) != PROBE_FS_XFS ||
	    probe_fstype_from_magic(KAT_BTRFS_MAGIC) != PROBE_FS_BTRFS ||
	    probe_fstype_from_magic(KAT_F2FS_MAGIC) != PROBE_FS_F2FS ||
	    probe_fstype_from_magic(KAT_ZFS_MAGIC) != PROBE_FS_ZFS) {
		FAIL("known magic misclassified");
		return;
	}
	if (probe_fstype_from_magic(0x12345) != PROBE_FS_UNKNOWN) {
		FAIL("unknown magic not reported as UNKNOWN");
		return;
	}
	PASS();
}

static void test_fs_verity_capability(void)
{
	TEST("verity-capable filesystems are ext4/btrfs/f2fs only");
	if (!probe_fs_supports_fsverity(PROBE_FS_EXT4) ||
	    !probe_fs_supports_fsverity(PROBE_FS_BTRFS) ||
	    !probe_fs_supports_fsverity(PROBE_FS_F2FS)) {
		FAIL("a verity-capable filesystem reported as incapable");
		return;
	}
	if (probe_fs_supports_fsverity(PROBE_FS_XFS) ||
	    probe_fs_supports_fsverity(PROBE_FS_ZFS) ||
	    probe_fs_supports_fsverity(PROBE_FS_UNKNOWN)) {
		FAIL("a non-verity filesystem reported as capable");
		return;
	}
	PASS();
}

static void test_verity_remediation_per_fs(void)
{
	char ext[512];
	char xfs[512];
	char zfs[512];

	TEST("remediation steers ext4 to verity and XFS/ZFS to IMA");
	probe_verity_remediation(PROBE_FS_EXT4, "/usr/bin/lota-agent", ext,
				 sizeof(ext));
	probe_verity_remediation(PROBE_FS_XFS, "/usr/bin/lota-agent", xfs,
				 sizeof(xfs));
	probe_verity_remediation(PROBE_FS_ZFS, "/usr/bin/lota-agent", zfs,
				 sizeof(zfs));
	if (!strstr(ext, "tune2fs")) {
		FAIL("ext4 hint omits the tune2fs verity path");
		return;
	}
	if (strstr(xfs, "tune2fs") || !strstr(xfs, "security.ima")) {
		FAIL("XFS hint must drop tune2fs and name the IMA route");
		return;
	}
	if (strstr(zfs, "tune2fs") || !strstr(zfs, "security.ima")) {
		FAIL("ZFS hint must drop tune2fs and name the IMA route");
		return;
	}
	PASS();
}

int main(void)
{
	printf("installer probe helpers:\n");

	test_pcr14_lock_constant_kat();
	test_pcr14_lock_value_baseline_aware();
	test_hex_to_bytes();
	test_cmdline_ima();
	test_cmdline_token();
	test_conf_key();
	test_esrt_present();
	test_fstype_magic_mapping();
	test_fs_verity_capability();
	test_verity_remediation_per_fs();

	printf("%d/%d tests passed\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
