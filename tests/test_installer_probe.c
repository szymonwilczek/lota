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

#include "../installer/install.h"
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
 * the post-extend PCR14 the lock helper installs from zero PCR --
 * the baseline of UEFI host whose boot chain never measured PCR14.
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

static void test_machine_description(void)
{
	char dir[256];
	char cmd[320];
	char desc[192];

	snprintf(dir, sizeof(dir), "/tmp/lota-inst-dmi.%d", (int)getpid());
	mkdir(dir, 0755);

	TEST("a DMI tree with nothing usable describes no machine");
	probe_machine_description_at(dir, desc, sizeof(desc));
	if (desc[0] != '\0') {
		FAIL("empty DMI tree produced a description");
		goto cleanup;
	}
	PASS();

	TEST("vendor and product are joined as DMI spells them");
	write_text_file(dir, "sys_vendor", "Example Corp\n");
	write_text_file(dir, "product_name", "Example Board X1\n");
	probe_machine_description_at(dir, desc, sizeof(desc));
	if (strcmp(desc, "Example Corp Example Board X1") != 0) {
		FAIL("description is not the two DMI fields");
		goto cleanup;
	}
	PASS();

	TEST("an unfilled DMI field is left out, not read back");
	/* boards ship these placeholders unfilled;
	 * naming one describes no machine anybody owns */
	write_text_file(dir, "product_name", "To Be Filled By O.E.M.\n");
	probe_machine_description_at(dir, desc, sizeof(desc));
	if (strcmp(desc, "Example Corp") != 0) {
		FAIL("placeholder used as a machine name");
		goto cleanup;
	}
	write_text_file(dir, "sys_vendor", "System manufacturer\n");
	probe_machine_description_at(dir, desc, sizeof(desc));
	if (desc[0] != '\0') {
		FAIL("two placeholders still produced a description");
		goto cleanup;
	}
	PASS();

cleanup:
	snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
	if (system(cmd) != 0)
		fprintf(stderr, "warning: cleanup failed\n");
}

/* efivarfs payloads: 4 attribute bytes, then the value */
static void write_efivar(const char *dir, const char *name, const uint8_t *val,
			 size_t len)
{
	static const uint8_t attrs[4] = { 0x07, 0, 0, 0 };
	char path[512];
	int fd;

	snprintf(path, sizeof(path), "%s/%s", dir, name);
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0)
		return;
	if (write(fd, attrs, sizeof(attrs)) != (ssize_t)sizeof(attrs) ||
	    write(fd, val, len) != (ssize_t)len)
		fprintf(stderr, "warning: efivar fixture write failed\n");
	close(fd);
}

static void test_efivar_payload(void)
{
	char dir[256];
	char path[320];
	char cmd[320];
	uint8_t one = 1;
	uint8_t zero = 0;
	uint8_t mask[8] = { 0x03, 0, 0, 0, 0, 0, 0, 0 };
	uint8_t nofwui[8] = { 0x02, 0, 0, 0, 0, 0, 0, 0 };

	snprintf(dir, sizeof(dir), "/tmp/lota-inst-efivar.%d", (int)getpid());
	mkdir(dir, 0755);

	/*
	 * missing SecureBoot variable has two causes and they need different
	 * instructions: legacy BIOS boot, where "switch the firmware to UEFI mode"
	 * is the fix, and UEFI firmware built without Secure Boot support,
	 * where the machine is *already* in UEFI mode and that instruction
	 * is dead end.
	 * Telling the second case to do the first is the kind of confidently
	 * wrong step this project refuses to ship.
	 */
	TEST("UEFI is detected from the firmware directory, not from SecureBoot");
	if (probe_firmware_is_uefi_at(dir) != 1) {
		FAIL("an existing firmware directory not read as UEFI");
		goto cleanup;
	}
	{
		char absent[380];

		snprintf(absent, sizeof(absent), "%s/no-such-firmware", dir);
		if (probe_firmware_is_uefi_at(absent) != 0) {
			FAIL("a missing firmware directory not read as legacy BIOS");
			goto cleanup;
		}
	}
	PASS();

	TEST("efivar flag reads past the attribute header");
	write_efivar(dir, "on", &one, sizeof(one));
	write_efivar(dir, "off", &zero, sizeof(zero));
	snprintf(path, sizeof(path), "%s/on", dir);
	if (probe_efivar_flag_at(path) != 1) {
		FAIL("set flag not read as 1");
		goto cleanup;
	}
	snprintf(path, sizeof(path), "%s/off", dir);
	if (probe_efivar_flag_at(path) != 0) {
		FAIL("clear flag not read as 0");
		goto cleanup;
	}
	PASS();

	TEST("a header-only or missing variable is not read as a value");
	write_efivar(dir, "empty", &one, 0);
	snprintf(path, sizeof(path), "%s/empty", dir);
	if (probe_efivar_flag_at(path) != -EBADMSG) {
		FAIL("truncated variable accepted");
		goto cleanup;
	}
	snprintf(path, sizeof(path), "%s/absent", dir);
	if (probe_efivar_flag_at(path) != -ENOENT) {
		FAIL("missing variable not reported as -ENOENT");
		goto cleanup;
	}
	PASS();

	TEST("OsIndicationsSupported is masked to the boot-to-setup bit");
	write_efivar(dir, "mask", mask, sizeof(mask));
	write_efivar(dir, "nofwui", nofwui, sizeof(nofwui));
	snprintf(path, sizeof(path), "%s/mask", dir);
	if (probe_efivar_bit0_at(path) != 1) {
		FAIL("bit 0 set but not reported");
		goto cleanup;
	}
	snprintf(path, sizeof(path), "%s/nofwui", dir);
	if (probe_efivar_bit0_at(path) != 0) {
		FAIL("other bits read as boot-to-setup support");
		goto cleanup;
	}
	PASS();

cleanup:
	snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
	if (system(cmd) != 0)
		fprintf(stderr, "warning: cleanup failed\n");
}

static void test_secureboot_remediation(void)
{
	char msg[STAGE_NOTE_CAP];
	char small[64];

	TEST("firmware that takes the request gets the command, not a key");
	probe_secureboot_remediation("Example Corp Example Board X1", 0, 0, 1,
				     msg, sizeof(msg));
	if (!strstr(msg, "systemctl reboot --firmware-setup")) {
		FAIL("boot-to-setup command missing");
		return;
	}
	if (strstr(msg, "vendor logo")) {
		FAIL("a keystroke was offered where the command works");
		return;
	}
	PASS();

	TEST("the machine DMI names is echoed back");
	if (!strstr(msg, "Example Corp Example Board X1")) {
		FAIL("machine description dropped");
		return;
	}
	probe_secureboot_remediation(NULL, 0, 0, 1, msg, sizeof(msg));
	if (!strstr(msg, "Secure Boot")) {
		FAIL("no description left no instructions either");
		return;
	}
	PASS();

	TEST("firmware without boot-to-setup defers to its startup screen");
	/* key differs between firmware revisions of one model,
	 * so the firmware's own screen is the only source worth naming */
	probe_secureboot_remediation("Example Corp Example Board X1", 0, 0, 0,
				     msg, sizeof(msg));
	if (strstr(msg, "systemctl reboot --firmware-setup")) {
		FAIL("command offered on firmware that refuses it");
		return;
	}
	if (!strstr(msg, "startup screen")) {
		FAIL("no route into setup offered as the fallback");
		return;
	}
	PASS();

	TEST("every case names the setting and where it sits");
	if (!strstr(msg, "Secure Boot") || !strstr(msg, "Security or Boot")) {
		FAIL("the setting was not named");
		return;
	}
	PASS();

	TEST("setup mode adds the factory-keys step");
	probe_secureboot_remediation("Example Corp", 0, 1, 1, msg, sizeof(msg));
	if (!strstr(msg, "factory keys")) {
		FAIL("setup mode did not mention restoring the keys");
		return;
	}
	probe_secureboot_remediation("Example Corp", 0, 0, 1, msg, sizeof(msg));
	if (strstr(msg, "factory keys")) {
		FAIL("user mode told to restore keys it already has");
		return;
	}
	PASS();

	TEST("a guest is sent to the VM definition, not into a menu");
	probe_secureboot_remediation("QEMU Standard PC", 1, 0, 1, msg,
				     sizeof(msg));
	if (!strstr(msg, "OVMF") ||
	    strstr(msg, "systemctl reboot --firmware-setup") ||
	    strstr(msg, "Security or Boot")) {
		FAIL("guest told to open a menu it does not have");
		return;
	}
	PASS();

	TEST("an unreadable probe reads as 'could not tell', not as yes");
	/* -errno from either efivar must not claim setup mode or promise
	 * boot-to-setup request the firmware never advertised */
	probe_secureboot_remediation("Example Corp", 0, -ENOENT, -ENOENT, msg,
				     sizeof(msg));
	if (strstr(msg, "factory keys") ||
	    strstr(msg, "systemctl reboot --firmware-setup")) {
		FAIL("a failed probe was read as a positive answer");
		return;
	}
	PASS();

	TEST("the worst-case message fits a stage note whole");
	probe_secureboot_remediation("Example Corp Example Board X1", 0, 1, 0,
				     msg, sizeof(msg));
	if (strlen(msg) >= sizeof(msg) - 1) {
		FAIL("message fills STAGE_NOTE_CAP and is cut short");
		return;
	}
	PASS();

	TEST("a short buffer truncates without overrunning");
	memset(small, 'X', sizeof(small));
	probe_secureboot_remediation("Example Corp", 0, 1, 0, small,
				     sizeof(small) - 8);
	if (strlen(small) >= sizeof(small) - 8) {
		FAIL("truncated message is not NUL-terminated in place");
		return;
	}
	if (small[sizeof(small) - 1] != 'X') {
		FAIL("wrote past the buffer it was given");
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
	test_machine_description();
	test_efivar_payload();
	test_secureboot_remediation();

	printf("%d/%d tests passed\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
