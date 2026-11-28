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

#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "test.h"
#include "../installer/install.h"
#include "../installer/probe.h"
#include "../src/agent/tpm.h"

/* Known answer for SHA256(0^32 || SHA256("LOTA-PCR14-INITRAMFS-LOCK-v1")),
 * the post-extend PCR14 the lock helper installs from zero PCR --
 * the baseline of UEFI host whose boot chain never measured PCR14.
 * Must stay in sync with src/initramfs/lota-pcr14-lock.c and the verifier's
 * DeriveInitramfsLockPCR14 */
static const char lock_kat_hex[] =
	"d550fa44ab2d1ee9227a3502fcf44698681ab13dfb6cd468da488f01fbbda8bb";

/*
 * Resolve only: as root on a host with an agent,
 * the fixed-path wrapper reads that host's real PCR 14 baseline
 */
static void test_pcr14_baseline_path_is_the_shipped_one(void)
{
	const char *path;

	TEST("the fixed-path helpers read the shipped baseline path");

	path = probe_pcr14_baseline_path();
	if (!path) {
		FAIL("no baseline path is named");
		return;
	}
	if (strcmp(path, "/run/lota/pcr14_baseline") != 0) {
		char msg[256];

		snprintf(msg, sizeof(msg), "baseline path is %s", path);
		FAIL("%s", msg);
		return;
	}
	/* a relative path would follow whichever directory started us */
	if (path[0] != '/') {
		FAIL("the baseline path is not absolute");
		return;
	}
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

	TEST("PCR14 lock value reads a baseline one byte too long as absent");
	{
		uint8_t longer[PROBE_HASH_SIZE + 1];

		memcpy(longer, baseline, sizeof(baseline));
		longer[PROBE_HASH_SIZE] = 0x0a;
		write_raw_file(path, longer, sizeof(longer));
	}
	probe_pcr14_lock_value_at(path, got);
	unlink(path);
	if (memcmp(got, zero_expect, sizeof(zero_expect)) != 0) {
		FAIL("a 33-byte baseline was taken from its first 32 bytes");
		return;
	}
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

	TEST("hex parser rejects bad length and non-hex chars");
	if (probe_hex_to_bytes("deadbe", out, sizeof(out)) != -EINVAL ||
	    probe_hex_to_bytes("deadbeefaa", out, sizeof(out)) != -EINVAL ||
	    probe_hex_to_bytes("deadbezz", out, sizeof(out)) != -EINVAL) {
		FAIL("bad input accepted");
		return;
	}
}

static void test_cmdline_ima(void)
{
	TEST("ima_appraise=enforce satisfies the floor");
	if (probe_cmdline_ima_ok("ro root=UUID=x ima=on ima_appraise=enforce "
				 "rhgb") != 0) {
		FAIL("enforce rejected");
		return;
	}

	TEST("absent ima_appraise leaves the kernel default, enforce");
	if (probe_cmdline_ima_ok("ro root=UUID=x rhgb quiet") != 0) {
		FAIL("the default mode rejected");
		return;
	}

	TEST("fix, log and off fail the floor");
	if (probe_cmdline_ima_ok("ima_appraise=fix") != -EPERM ||
	    probe_cmdline_ima_ok("ima_appraise=log") != -EPERM ||
	    probe_cmdline_ima_ok("ima_appraise=off") != -EPERM) {
		FAIL("non-enforcing mode accepted");
		return;
	}

	TEST("last ima_appraise token wins, as in the kernel");
	if (probe_cmdline_ima_ok("ima_appraise=log ima_appraise=enforce") !=
		    0 ||
	    probe_cmdline_ima_ok("ima_appraise=enforce ima_appraise=fix") !=
		    -EPERM) {
		FAIL("an earlier token decided");
		return;
	}

	TEST("ima_appraise= past -- and unknown values read as in the kernel");
	if (probe_cmdline_ima_ok("ima_appraise=off -- ima_appraise=enforce") !=
		    -EPERM ||
	    probe_cmdline_ima_ok("ima_appraise=enforcex") != 0 ||
	    probe_cmdline_ima_ok("ima_appraise=fixme") != -EPERM) {
		FAIL("the mode differs from the kernel's");
		return;
	}

	TEST("prefix tokens do not match (ima_appraise_x=off)");
	if (probe_cmdline_ima_ok("ima_appraise_x=off") != 0) {
		FAIL("prefix matched");
		return;
	}
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

	mkdir(base, 0755);
	snprintf(dir, sizeof(dir), "%s/entry0", base);
	mkdir(dir, 0755);
	write_text_file(dir, "fw_type", "2\n"); /* device firmware */

	TEST("ESRT: only device-firmware entries reports not-present");
	if (probe_esrt_system_firmware_present_at(base) != 0) {
		FAIL("device-only should be 0");
		goto cleanup;
	}

	snprintf(dir, sizeof(dir), "%s/entry1", base);
	mkdir(dir, 0755);
	write_text_file(dir, "fw_type", "1\n"); /* system firmware */

	TEST("ESRT: a system-firmware entry reports present");
	if (probe_esrt_system_firmware_present_at(base) != 1) {
		FAIL("system fw entry should be 1");
		goto cleanup;
	}

cleanup:
	snprintf(cmd, sizeof(cmd), "rm -rf '%s'", base);
	if (system(cmd) != 0)
		fprintf(stderr, "warning: cleanup failed\n");
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

	TEST("vendor and product are joined as DMI spells them");
	write_text_file(dir, "sys_vendor", "Example Corp\n");
	write_text_file(dir, "product_name", "Example Board X1\n");
	probe_machine_description_at(dir, desc, sizeof(desc));
	if (strcmp(desc, "Example Corp Example Board X1") != 0) {
		FAIL("description is not the two DMI fields");
		goto cleanup;
	}

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
	TEST("UEFI is detected from the firmware directory, not SecureBoot");
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

cleanup:
	snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
	if (system(cmd) != 0)
		fprintf(stderr, "warning: cleanup failed\n");
}

/*
 * The reboot-into-setup request is an EFI variable write, which a full store
 * refuses even when the firmware supports it. The startup screen needs no
 * write, so it follows the command.
 */
static void test_secureboot_remediation_when_the_request_fails(void)
{
	char msg[STAGE_NOTE_CAP];
	const char *cmd;
	const char *screen;

	TEST("a refused request still leaves the startup screen");
	probe_secureboot_remediation("Example Corp Example Board X1", 0, 0, 1,
				     msg, sizeof(msg));
	cmd = strstr(msg, "systemctl reboot --firmware-setup");
	screen = strstr(msg, "startup screen");
	if (!cmd || !screen || !strstr(msg, "vendor logo")) {
		FAIL("%s", msg);
		return;
	}
	if (screen < cmd) {
		FAIL("the keystroke is offered before the command");
		return;
	}
	if (!strstr(msg, "Cannot allocate memory")) {
		FAIL("the refusal a full store gives is not named");
		return;
	}
}

/*
 * Longest message: the longest DMI machine name, setup mode, request taken.
 * Truncation drops the last instructions first.
 */
static void test_secureboot_remediation_fits_a_note(void)
{
	char msg[STAGE_NOTE_CAP];
	char machine[192];
	size_t len;

	TEST("the longest Secure Boot route fits in a stage note");
	memset(machine, 'M', sizeof(machine) - 1);
	machine[sizeof(machine) - 1] = '\0';
	probe_secureboot_remediation(machine, 0, 1, 1, msg, sizeof(msg));
	len = strlen(msg);
	if (len + 1 >= sizeof(msg) ||
	    strcmp(msg + len - 19, "'mokutil --import'.") != 0) {
		FAIL("%s", msg + (len > 60 ? len - 60 : 0));
		return;
	}
}

static void test_secureboot_remediation(void)
{
	char msg[STAGE_NOTE_CAP];
	char small[64];

	TEST("firmware that takes the request gets the command first");
	probe_secureboot_remediation("Example Corp Example Board X1", 0, 0, 1,
				     msg, sizeof(msg));
	if (!strstr(msg, "systemctl reboot --firmware-setup")) {
		FAIL("boot-to-setup command missing");
		return;
	}

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

	TEST("every case names the setting and where it sits");
	if (!strstr(msg, "Secure Boot") || !strstr(msg, "Security or Boot")) {
		FAIL("the setting was not named");
		return;
	}

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

	TEST("a guest is sent to its OVMF image");
	probe_secureboot_remediation("QEMU Standard PC", 1, 0, 1, msg,
				     sizeof(msg));
	if (!strstr(msg, "OVMF") ||
	    strstr(msg, "systemctl reboot --firmware-setup") ||
	    strstr(msg, "Security or Boot")) {
		FAIL("guest given the physical-machine advice");
		return;
	}

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

	TEST("the worst-case message fits a stage note whole");
	probe_secureboot_remediation("Example Corp Example Board X1", 0, 1, 0,
				     msg, sizeof(msg));
	if (strlen(msg) >= sizeof(msg) - 1) {
		FAIL("message fills STAGE_NOTE_CAP and is cut short");
		return;
	}

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
}

static void test_auto_bringup_opt_in(void)
{
	char dir[256];
	char marker[320];
	char cmd[320];

	snprintf(dir, sizeof(dir), "/tmp/lota-inst-optin.%d", (int)getpid());
	mkdir(dir, 0755);
	snprintf(marker, sizeof(marker), "%s/auto-bringup", dir);
	unsetenv("LOTA_AUTO_BRINGUP");

	TEST("no marker and no variable is not consent");
	if (probe_auto_bringup_at(marker) != 0) {
		FAIL("bring-up opted in with nothing saying so");
		goto cleanup;
	}

	TEST("the marker file opts this host in");
	write_text_file(dir, "auto-bringup", "");
	if (probe_auto_bringup_at(marker) != 1) {
		FAIL("marker file ignored");
		goto cleanup;
	}

	TEST("only an exact 1 in the environment counts as consent");
	unlink(marker);
	setenv("LOTA_AUTO_BRINGUP", "1", 1);
	if (probe_auto_bringup_at(marker) != 1) {
		FAIL("LOTA_AUTO_BRINGUP=1 ignored");
		goto cleanup;
	}

	/* package hook inherits whatever environment the transaction had,
	 * so anything but the exact value is not an answer */
	setenv("LOTA_AUTO_BRINGUP", "0", 1);
	if (probe_auto_bringup_at(marker) != 0) {
		FAIL("LOTA_AUTO_BRINGUP=0 read as consent");
		goto cleanup;
	}
	setenv("LOTA_AUTO_BRINGUP", "true", 1);
	if (probe_auto_bringup_at(marker) != 0) {
		FAIL("a non-1 value read as consent");
		goto cleanup;
	}

cleanup:
	unsetenv("LOTA_AUTO_BRINGUP");
	snprintf(cmd, sizeof(cmd), "rm -rf '%s'", dir);
	if (system(cmd) != 0)
		fprintf(stderr, "warning: cleanup failed\n");
}

/*
 * A port only a range covers looks typed but the agent is refused there,
 * and a port another service owns cannot be taken with semanage port -a.
 */
static void test_selinux_unmet_note(void)
{
	struct probe_selinux_unmet u = { 0 };
	char note[512];

	TEST("selinux: a missing port label names the port alone");
	u.ca_port = "8444";
	if (probe_selinux_unmet_note(&u, note, sizeof(note)) != 1 ||
	    !strstr(note, "CA port 8444") || !strstr(note, "semanage port") ||
	    strstr(note, "binary") || strstr(note, "TPM")) {
		FAIL("%s", note);
		return;
	}

	TEST("selinux: each unmet check is named");
	memset(&u, 0, sizeof(u));
	u.tpm = 1;
	u.conf = 1;
	u.ver_port = "8443";
	if (probe_selinux_unmet_note(&u, note, sizeof(note)) != 3 ||
	    !strstr(note, "TPM device") || !strstr(note, "config directory") ||
	    !strstr(note, "verifier port 8443") || strstr(note, "state")) {
		FAIL("%s", note);
		return;
	}

	TEST("selinux: a port that cannot be checked is unmet");
	memset(&u, 0, sizeof(u));
	u.port_check = "semanage is not installed";
	if (probe_selinux_unmet_note(&u, note, sizeof(note)) != 1 ||
	    !strstr(note, "Cannot check the port labels: semanage is not "
			  "installed.")) {
		FAIL("%s", note);
		return;
	}

	TEST("selinux: every check met is no note");
	memset(&u, 0, sizeof(u));
	if (probe_selinux_unmet_note(&u, note, sizeof(note)) != 0 ||
	    note[0] != '\0') {
		FAIL("%s", note);
		return;
	}
}

static void test_port_needs_label(void)
{
	static const char listing[] =
		"SELinux Port Type              Proto    Port Number\n"
		"\n"
		"http_port_t                    tcp      80, 443, 8443\n"
		"http_port_t                    udp      7443\n"
		"lota_port_t                    tcp      8545\n"
		"ssh_port_t                     tcp      22\n"
		"amqp_port_t                    tcp      15672, 5671-5672\n"
		"unreserved_port_t              tcp      61000-65535, 1024-32767\n";

	TEST("a port the agent cannot reach needs a label");

	if (probe_port_needs_label(listing, "8443") != 0 ||
	    probe_port_needs_label(listing, "8545") != 0) {
		FAIL("a type the agent reaches needs no label");
		return;
	}
	if (probe_port_needs_label(listing, "22") != 0) {
		FAIL("a port with a type of its own cannot be labelled");
		return;
	}
	if (probe_port_needs_label(listing, "8444") != 1 ||
	    probe_port_needs_label(listing, "5671") != 1 ||
	    probe_port_needs_label(listing, "62000") != 1) {
		FAIL("a port under a range only is refused at connect");
		return;
	}
	if (probe_port_needs_label(listing, "7443") != 1) {
		FAIL("a udp row says nothing about the tcp port");
		return;
	}
	if (probe_port_needs_label(listing, "") != -EINVAL ||
	    probe_port_needs_label(listing, "84x") != -EINVAL ||
	    probe_port_needs_label(listing, "70000") != -EINVAL ||
	    probe_port_needs_label(listing, "-1") != -EINVAL) {
		FAIL("not a port number");
		return;
	}
}

/*
 * Runtime manifest is acted on with privilege, so what counts as a path matters
 * more than convenience: comments and blank lines are skipped, and anything that
 * is not an absolute path -- including one walking back out through '..'
 * -- is refused.
 */
static void test_manifest_line(void)
{
	char out[64];

	TEST("a manifest line yields its path");
	if (!(probe_manifest_line("/usr/lib64/libc.so.6\n", out, sizeof(out)) ==
		      1 &&
	      strcmp(out, "/usr/lib64/libc.so.6") == 0))
		FAIL("path not parsed");

	TEST("surrounding whitespace is trimmed");
	if (!(probe_manifest_line("  /usr/bin/title \t\n", out, sizeof(out)) ==
		      1 &&
	      strcmp(out, "/usr/bin/title") == 0))
		FAIL("whitespace kept");

	TEST("a comment and a blank line are skipped");
	if (!(probe_manifest_line("# /usr/bin/title\n", out, sizeof(out)) ==
		      0 &&
	      probe_manifest_line("   \n", out, sizeof(out)) == 0 &&
	      probe_manifest_line("", out, sizeof(out)) == 0))
		FAIL("comment or blank line taken as a path");

	TEST("a relative path is refused");
	if (!(probe_manifest_line("lib/libfoo.so\n", out, sizeof(out)) ==
		      -EINVAL &&
	      probe_manifest_line("../../etc/shadow\n", out, sizeof(out)) ==
		      -EINVAL))
		FAIL("accepted a relative path");

	TEST("an absolute path carrying '..' is refused");
	if (!(probe_manifest_line("/usr/../etc/shadow\n", out, sizeof(out)) ==
		      -EINVAL &&
	      probe_manifest_line("/usr/lib64/..\n", out, sizeof(out)) ==
		      -EINVAL &&
	      probe_manifest_line("/..\n", out, sizeof(out)) == -EINVAL))
		FAIL("accepted a path walking out with '..'");

	TEST("a name that merely starts with dots is kept");
	if (!(probe_manifest_line("/opt/title/..data/lib.so\n", out,
				  sizeof(out)) == 1 &&
	      strcmp(out, "/opt/title/..data/lib.so") == 0 &&
	      probe_manifest_line("/opt/title/.hidden\n", out, sizeof(out)) ==
		      1))
		FAIL("refused a legitimate dotted name");

	TEST("a path longer than the buffer is refused");
	{
		char small[8];
		if (!(probe_manifest_line("/usr/lib64/libc.so.6\n", small,
					  sizeof(small)) == -EINVAL &&
		      small[0] == '\0'))
			FAIL("overran the buffer");
	}
}

/*
 * Every installed kernel has to be covered, not just the running one.
 *
 * Stage 6 arms the cmdline with `grubby --update-kernel=ALL` while stage 5 ran
 * a bare `dracut -f`, which rebuilds one image.
 * On a Fedora host keeping three kernels that left two of them without the PCR 14
 * lock, and selecting either from the GRUB menu -- which is the reason more
 * than one is kept -- produces a boot with no commitment on a machine
 * the operator was told is installed.
 *
 * The enumeration is what the coverage is stated against: a kernel counts when
 * /lib/modules holds it and /boot holds its initramfs.
 */
static void test_installed_kernels(void)
{
	char root[64];
	char cmd[512];
	char path[128];
	struct probe_kernel_image images[PROBE_MAX_KERNELS];
	size_t count = 0;
	int rc;

	snprintf(root, sizeof(root), "/tmp/lota-inst-kernels.%d",
		 (int)getpid());
	snprintf(cmd, sizeof(cmd), "rm -rf '%s'", root);
	if (system(cmd) != 0)
		fprintf(stderr, "warning: fixture reset failed\n");

	snprintf(cmd, sizeof(cmd),
		 "mkdir -p '%s/lib/modules/7.0.13-200.fc44.x86_64' "
		 "'%s/lib/modules/7.0.12-201.fc44.x86_64' "
		 "'%s/lib/modules/7.0.9-205.fc44.x86_64' '%s/boot'",
		 root, root, root, root);
	if (system(cmd) != 0) {
		fprintf(stderr, "warning: fixture setup failed\n");
		return;
	}

	/* two kernels have an image; the third is a modules tree with none,
	 * which is what a half-removed kernel leaves behind */
	snprintf(path, sizeof(path), "%s/boot", root);
	write_text_file(path, "initramfs-7.0.13-200.fc44.x86_64.img", "image");
	write_text_file(path, "initramfs-7.0.12-201.fc44.x86_64.img", "image");
	/* a rescue image belongs to no /lib/modules entry of its own */
	write_text_file(path, "initramfs-0-rescue-abc.img", "image");

	TEST("every installed kernel with an initramfs is enumerated");
	{
		char modules[96];
		char boot[96];

		snprintf(modules, sizeof(modules), "%s/lib/modules", root);
		snprintf(boot, sizeof(boot), "%s/boot", root);
		rc = probe_installed_kernels_at(modules, boot, images,
						PROBE_MAX_KERNELS, &count);
	}
	if (rc != 0 || count != 2) {
		FAIL("expected the two kernels that have an image");
		goto cleanup;
	}

	TEST("each entry names the image the lock has to be in");
	{
		int seen13 = 0;
		int seen12 = 0;

		for (size_t i = 0; i < count; i++) {
			if (strcmp(images[i].release,
				   "7.0.13-200.fc44.x86_64") == 0 &&
			    strstr(images[i].image,
				   "initramfs-7.0.13-200.fc44.x86_64.img"))
				seen13 = 1;
			if (strcmp(images[i].release,
				   "7.0.12-201.fc44.x86_64") == 0 &&
			    strstr(images[i].image,
				   "initramfs-7.0.12-201.fc44.x86_64.img"))
				seen12 = 1;
		}
		if (!seen13 || !seen12) {
			FAIL("an entry does not name its own image");
			goto cleanup;
		}
	}

	TEST("a host with no modules tree enumerates nothing, not an error");
	rc = probe_installed_kernels_at("/nonexistent/modules",
					"/nonexistent/boot", images,
					PROBE_MAX_KERNELS, &count);
	if (rc != 0 || count != 0) {
		FAIL("absence should read as no kernels");
		goto cleanup;
	}

cleanup:
	snprintf(cmd, sizeof(cmd), "rm -rf '%s'", root);
	if (system(cmd) != 0)
		fprintf(stderr, "warning: cleanup failed\n");
}

/*
 * A first install is not leftover state from an install that never happened.
 *
 * PCR 14 is non-zero on every Secure Boot host before LOTA exists:
 * shim measures the MOK variables into it. The stage classified any non-zero
 * value it could not derive as residue from an earlier agent run, so the first
 * thing a new operator or player was told on the default consumer host was
 * to go looking for state to clean up, of which there is none.
 *
 * The absence of the lock helper's baseline handoff is the available signal:
 * no lock ran this boot, so nothing in PCR 14 is LOTA's, whatever it holds.
 */
static void test_barrier_stage_verdicts(void)
{
	char note[256];

	TEST("a platform-extended PCR14 before any lock is not stale state");
	if (probe_pcr14_barrier_stage(PROBE_PCR14_OTHER, 0, 0, 0, 0, note,
				      sizeof(note)) != STAGE_REBOOT) {
		FAIL("a first install still needs a reboot");
		return;
	}
	if (strstr(note, "earlier agent run") || strstr(note, "stale")) {
		FAIL("the note blames LOTA state that does not exist");
		return;
	}

	TEST("a genuinely stale commitment keeps its wording");
	if (probe_pcr14_barrier_stage(PROBE_PCR14_OTHER, 1, 0, 0, 0, note,
				      sizeof(note)) != STAGE_REBOOT) {
		FAIL("stale state still needs a reboot");
		return;
	}
	if (!strstr(note, "earlier agent run")) {
		FAIL("the stale case lost its explanation");
		return;
	}

	TEST("a running agent's own commitment is satisfied");
	if (probe_pcr14_barrier_stage(PROBE_PCR14_OTHER, 1, 1, 0, 0, note,
				      sizeof(note)) != STAGE_DONE) {
		FAIL("this boot's commitment is the satisfied state");
		return;
	}

	TEST("the lock value alone is satisfied");
	if (probe_pcr14_barrier_stage(PROBE_PCR14_LOCK_ONLY, 1, 0, 0, 0, note,
				      sizeof(note)) != STAGE_DONE) {
		FAIL("a locked register is what this stage waits for");
		return;
	}

	TEST("an agent that already refused is not sent to another reboot");
	if (probe_pcr14_barrier_stage(PROBE_PCR14_OTHER, 1, 0, 1, 0, note,
				      sizeof(note)) != STAGE_BLOCKED) {
		FAIL("a reboot cannot satisfy a refused startup gate");
		return;
	}
	if (!strstr(note, "journalctl")) {
		FAIL("the note does not say where the refusal is written");
		return;
	}

	TEST("a running agent is not read as a failed one");
	if (probe_pcr14_barrier_stage(PROBE_PCR14_OTHER, 1, 1, 1, 0, note,
				      sizeof(note)) != STAGE_DONE) {
		FAIL("an earlier failed start outweighed the running agent");
		return;
	}

	TEST("a pristine register still says the lock has not run");
	if (probe_pcr14_barrier_stage(PROBE_PCR14_ZERO, 0, 0, 0, 0, note,
				      sizeof(note)) != STAGE_REBOOT) {
		FAIL("no lock this boot needs a reboot");
		return;
	}
}

/*
 * A pause is the one refusal a reboot clears: --pause spends PCR 14 and the
 * agent refuses every later start that boot. The snapshot is written through
 * the agent's struct, so the layout the installer reads cannot drift.
 */
_Static_assert(sizeof(struct lota_clock_state) == 120,
	       "installer/probe.c reads the snapshot as 120 bytes");

static int write_snapshot(const char *path, const uint8_t *pcr14, uint8_t flags)
{
	struct lota_clock_state snap = { 0 };
	int fd;
	ssize_t n;

	snap.magic = htole32(TPM_CLOCK_STATE_MAGIC);
	snap.version = htole32(TPM_CLOCK_STATE_VERSION);
	snap.reset_count = htole32(7);
	snap.restart_count = htole32(3);
	memcpy(snap.pcr14, pcr14, sizeof(snap.pcr14));
	memset(snap.self_hash, 0x5a, sizeof(snap.self_hash));
	snap.saved_at = (int64_t)htole64(1700000000);
	snap.flags = flags;

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		return -1;
	n = write(fd, &snap, sizeof(snap));
	close(fd);
	return n == (ssize_t)sizeof(snap) ? 0 : -1;
}

static void test_agent_paused_reader(void)
{
	uint8_t spent[PROBE_HASH_SIZE];
	uint8_t other[PROBE_HASH_SIZE];
	char path[64];
	int fd;

	memset(spent, 0xa7, sizeof(spent));
	memset(other, 0x3c, sizeof(other));
	snprintf(path, sizeof(path), "/tmp/lota-inst-clock.%d", (int)getpid());

	TEST("a pause the register still carries is read as one");
	if (write_snapshot(path, spent,
			   LOTA_CLOCK_STATE_FLAG_INITRAMFS_LOCK |
				   LOTA_CLOCK_STATE_FLAG_SHUTDOWN_POISON) !=
	    0) {
		FAIL("cannot write the snapshot");
		return;
	}
	if (probe_agent_paused_at(path, spent) != PROBE_AGENT_PAUSED)
		FAIL("the agent's own pause record is not recognised");

	TEST("a commitment spent by a failed run is not read as a pause");
	if (write_snapshot(path, spent,
			   LOTA_CLOCK_STATE_FLAG_INITRAMFS_LOCK |
				   LOTA_CLOCK_STATE_FLAG_ERROR_POISON) != 0 ||
	    probe_agent_paused_at(path, spent) != PROBE_AGENT_SPENT_BY_ERROR)
		FAIL("a failed run's poison reads as a pause");
	if (write_snapshot(path, spent,
			   LOTA_CLOCK_STATE_FLAG_INITRAMFS_LOCK |
				   LOTA_CLOCK_STATE_FLAG_SHUTDOWN_POISON) !=
	    0) {
		FAIL("cannot write the snapshot");
		return;
	}

	TEST("a register moved on since the pause is not a pause");
	if (probe_agent_paused_at(path, other) != 0)
		FAIL("a later extend still reads as paused");

	TEST("a snapshot without the pause flag is not a pause");
	if (write_snapshot(path, spent, LOTA_CLOCK_STATE_FLAG_INITRAMFS_LOCK) !=
		    0 ||
	    probe_agent_paused_at(path, spent) != 0)
		FAIL("an ordinary commitment reads as paused");

	TEST("a short or missing snapshot is not a pause");
	fd = open(path, O_WRONLY | O_TRUNC);
	if (fd >= 0) {
		if (write(fd, "LCLK", 4) != 4)
			fd = -2;
		close(fd);
	}
	if (fd < 0 || probe_agent_paused_at(path, spent) != 0) {
		FAIL("a truncated snapshot reads as paused");
		unlink(path);
		return;
	}
	unlink(path);
	if (probe_agent_paused_at(path, spent) != 0)
		FAIL("no snapshot reads as paused");
}

static int barrier_says(int agent_active, int agent_failed, int agent_paused,
			enum stage_state want, const char *has,
			const char *lacks)
{
	char note[512];

	if (probe_pcr14_barrier_stage(PROBE_PCR14_OTHER, 1, agent_active,
				      agent_failed, agent_paused, note,
				      sizeof(note)) != want) {
		FAIL("%s", note);
		return 0;
	}
	if ((has && !strstr(note, has)) || (lacks && strstr(note, lacks))) {
		FAIL("%s", note);
		return 0;
	}
	return 1;
}

static void test_barrier_after_a_pause(void)
{
	TEST("a paused agent's refused start is cleared by a reboot");
	barrier_says(0, 1, 1, STAGE_REBOOT, "--resume", "does not clear");

	TEST("a paused agent nobody restarted is not stale state");
	barrier_says(0, 0, 1, STAGE_REBOOT, "paused", "earlier agent run");

	TEST("a refusal without a pause still names the log");
	barrier_says(0, 1, 0, STAGE_BLOCKED, "journalctl", NULL);

	TEST("a commitment spent by an error points to the log, not --resume");
	barrier_says(0, 1, PROBE_AGENT_SPENT_BY_ERROR, STAGE_BLOCKED,
		     "journalctl", "paused");

	TEST("a running agent outweighs an old pause record");
	barrier_says(1, 0, 1, STAGE_DONE, NULL, NULL);
}

/*
 * Publisher profiles are the agent's target list, and a configuration that
 * carries them is the ordinary state of a machine that has been used:
 * the agent enrolls with each publisher the first time a title of theirs asks.
 */
static void test_conf_profile_count(void)
{
	TEST("profile sections are counted, comments are not");
	if (probe_conf_buf_profile_count("log_level = debug\n"
					 "[profile \"pubA\"]\n"
					 "ca = 10.0.0.1\n"
					 "# [profile \"commented\"]\n"
					 "[profile \"pubB\"]\n") != 2) {
		FAIL("wrong count");
		return;
	}

	TEST("a configuration naming no publisher counts none");
	if (probe_conf_buf_profile_count("log_level = debug\n") != 0 ||
	    probe_conf_buf_profile_count("[verifier]\n") != 0 ||
	    probe_conf_buf_profile_count(NULL) != 0) {
		FAIL("false positive");
		return;
	}
}

static void test_read_text(void)
{
	char path[64];
	char buf[16];
	int fd;

	snprintf(path, sizeof(path), "/tmp/lota-inst-read.%d", (int)getpid());

	TEST("read_text: a missing file is -ENOENT");
	unlink(path);
	if (probe_read_text(path, buf, sizeof(buf)) != -ENOENT) {
		FAIL("missing file not -ENOENT");
		return;
	}

	TEST("read_text: a file that fills the buffer exactly is read");
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0 || write(fd, "0123456789abcde", 15) != 15) {
		FAIL("cannot write the file");
		goto out;
	}
	close(fd);
	if (probe_read_text(path, buf, sizeof(buf)) != 15 ||
	    strcmp(buf, "0123456789abcde") != 0) {
		FAIL("exact fit not read whole");
		goto out;
	}

	TEST("read_text: a file larger than the buffer is -EFBIG");
	fd = open(path, O_WRONLY | O_APPEND);
	if (fd < 0 || write(fd, "f", 1) != 1) {
		FAIL("cannot extend the file");
		goto out;
	}
	close(fd);
	if (probe_read_text(path, buf, sizeof(buf)) != -EFBIG) {
		FAIL("oversized file not -EFBIG");
		goto out;
	}

	TEST("read_text: a directory is an error");
	unlink(path);
	if (mkdir(path, 0700) < 0 ||
	    probe_read_text(path, buf, sizeof(buf)) >= 0) {
		FAIL("directory read as text");
		goto out;
	}
out:
	unlink(path);
	rmdir(path);
}

/*
 * The self-check proves the host attests. It did that by spawning the agent
 * with --server, which names one verifier -- a combination the agent refuses
 * whenever profiles are configured, because the profiles name several and
 * there is then no single answer to where the host reports.
 *
 * So on any machine that has met a publisher, the self-check asked for
 * something that cannot be given and reported the refusal as the host failing
 * to attest: "Self-check failed. Install is laid down but the host is not
 * attesting yet", exit 1, on a host that was installed, enrolled and
 * attesting. Re-running, which is what that message advises, repeats it.
 */
static void test_selfcheck_plan(void)
{
	TEST("a verifier and no publishers is one round against it");
	if (probe_selfcheck_plan("verifier.example", 0, false) !=
	    SELFCHECK_ONE_ROUND) {
		FAIL("named verifier did not produce a round");
		return;
	}

	TEST("no verifier named leaves the round to the first title");
	if (probe_selfcheck_plan(NULL, 0, false) !=
		    SELFCHECK_SKIP_NO_VERIFIER ||
	    probe_selfcheck_plan("", 0, false) != SELFCHECK_SKIP_NO_VERIFIER) {
		FAIL("an unnamed verifier was treated as named");
		return;
	}

	TEST("configured publishers are the targets, so no verifier is named");
	if (probe_selfcheck_plan("verifier.example", 5, false) !=
	    SELFCHECK_PUBLISHERS_REPORT) {
		FAIL("the self-check still names one verifier");
		return;
	}

	TEST("publishers decide even when no verifier was given");
	if (probe_selfcheck_plan(NULL, 5, false) !=
	    SELFCHECK_PUBLISHERS_REPORT) {
		FAIL("a host with publishers was told a title would do it");
		return;
	}

	/*
	 * A fleet install records its verifier as a profile, and the loop is
	 * what reports to it from then on: a one-shot round proves a process
	 * that does not run after the installer exits.
	 */
	TEST("the fleet profile is proven by the loop that reports to it");
	if (probe_selfcheck_plan("verifier.example", 1, true) !=
	    SELFCHECK_LOOP_REPORTS) {
		FAIL("the fleet verifier was not waited on through the loop");
		return;
	}

	TEST("a fleet profile without a verifier has nobody to report to");
	if (probe_selfcheck_plan(NULL, 1, true) !=
	    SELFCHECK_PUBLISHERS_REPORT) {
		FAIL("a token-only fleet was waited on");
		return;
	}
}

/*
 * A fleet install enrolled with the operator's CA and wrote nothing into
 * lota.conf, so after the reboot the loop had no target and the publisher
 * it had enrolled with was invisible to the daemon.
 * Whether the anchor is recorded is read from each profile's ca_cert.
 */
static void test_conf_profile_anchor(void)
{
	static const char conf[] = "log_level = debug\n"
				   "ca_cert = /etc/lota/top.pem\n"
				   "[profile \"pubA\"]\n"
				   "ca = ca.a.example\n"
				   "ca_cert = /etc/lota/a.pem\n"
				   "[profile \"pubB\"]\n"
				   "# ca_cert = /etc/lota/commented.pem\n"
				   "ca-cert = /etc/lota/b.pem  \n"
				   "[profile \"pubC\"]\n"
				   "ca = ca.c.example\n";
	char out[256];

	TEST("each profile's anchor is read from its own section");
	if (probe_conf_buf_profile_anchor(conf, 0, out, sizeof(out)) != 1 ||
	    strcmp(out, "/etc/lota/a.pem") != 0) {
		FAIL("first profile's anchor");
		return;
	}
	if (probe_conf_buf_profile_anchor(conf, 1, out, sizeof(out)) != 1 ||
	    strcmp(out, "/etc/lota/b.pem") != 0) {
		FAIL("hyphenated key, comment or trailing blank");
		return;
	}

	TEST("a profile without an anchor, or past the last, has none");
	if (probe_conf_buf_profile_anchor(conf, 2, out, sizeof(out)) != 0 ||
	    probe_conf_buf_profile_anchor(conf, 3, out, sizeof(out)) != 0 ||
	    probe_conf_buf_profile_anchor(NULL, 0, out, sizeof(out)) != 0) {
		FAIL("an anchor was invented");
		return;
	}

	TEST("the top-level anchor is not a profile's");
	if (probe_conf_buf_profile_anchor("ca_cert = /etc/lota/top.pem\n", 0,
					  out, sizeof(out)) != 0) {
		FAIL("top-level key read as a profile");
		return;
	}
}

/*
 * The loop's status names how many publishers it attested to.
 * Until it has picked up the profile the installer wrote, that count is
 * short of the profiles that report continuously, so a status left over
 * from before the reload is not taken for the fleet's.
 */
static void test_conf_continuous_count(void)
{
	TEST("only continuous profiles with a verifier are counted");
	if (probe_conf_buf_continuous_count("[profile \"session\"]\n"
					    "verifier = v.session.example\n"
					    "[profile \"fleet\"]\n"
					    "reporting = continuous\n"
					    "verifier = v.fleet.example\n"
					    "[profile \"tokens\"]\n"
					    "reporting = continuous\n"
					    "verifier = none\n"
					    "[profile \"fleet2\"]\n"
					    "verifier = v.fleet2.example\n"
					    "reporting = continuous\n") != 2) {
		FAIL("wrong count");
		return;
	}

	TEST("top-level keys are not a profile");
	if (probe_conf_buf_continuous_count("reporting = continuous\n"
					    "verifier = v.example\n") != 0 ||
	    probe_conf_buf_continuous_count(NULL) != 0) {
		FAIL("false positive");
		return;
	}
}

static void test_attest_status_covers(void)
{
	TEST("an attested status covering every publisher is accepted");
	if (!probe_attest_status_covers(
		    "Attested (1 publisher), valid until 1700000000", NULL,
		    1) ||
	    !probe_attest_status_covers(
		    "Attested (3 publishers), valid until 1700000000", NULL,
		    2)) {
		FAIL("attested status refused");
		return;
	}

	TEST("a status short of the expected count is not the fleet's");
	if (probe_attest_status_covers(
		    "Attested (1 publisher), valid until 1700000000", NULL,
		    2) ||
	    probe_attest_status_covers("Idle: no publisher configured", NULL,
				       1) ||
	    probe_attest_status_covers("Attestation incomplete", NULL, 1) ||
	    probe_attest_status_covers("Attested (x publishers)", NULL, 1) ||
	    probe_attest_status_covers("", NULL, 1) ||
	    probe_attest_status_covers(NULL, NULL, 1)) {
		FAIL("unattested status accepted");
		return;
	}

	/*
	 * A host that already attested to one publisher reads the same count
	 * after the reload that swaps it for the fleet's, until the loop has
	 * taken the reload: only a status other than the one read before it
	 * is the fleet's round.
	 */
	TEST("the status from before the reload is not taken for a new round");
	if (probe_attest_status_covers(
		    "Attested (1 publisher), valid until 1700000000",
		    "Attested (1 publisher), valid until 1700000000", 1)) {
		FAIL("stale status accepted");
		return;
	}
	if (!probe_attest_status_covers(
		    "Attested (1 publisher), valid until 1700000300",
		    "Attested (1 publisher), valid until 1700000000", 1) ||
	    !probe_attest_status_covers(
		    "Attested (1 publisher), valid until 1700000300", "", 1)) {
		FAIL("new round refused");
		return;
	}
}

/*
 * A path the operator typed, checked before anything runs.
 *
 * The three cases the option table produces: an option nobody used, one whose
 * file is there, and one whose file is not. Only the last is a mistake,
 * and the refusal has to carry both the flag and the path, since an operator
 * with four file-taking options and one message needs to know which of them
 * it is about.
 */
static void test_named_files(void)
{
	char note[STAGE_NOTE_CAP];
	char tmp[] = "/tmp/lota_named_XXXXXX";
	int fd;

	TEST("an option the operator did not use is not checked");
	{
		const struct probe_named_file files[] = {
			{ "--ca-cert", NULL },
			{ "--policy-pubkey", NULL },
		};

		note[0] = '\0';
		if (probe_named_files(files, 2, note, sizeof(note)) != 0)
			FAIL("a NULL path was treated as a missing file");
	}

	fd = mkstemp(tmp);
	if (fd >= 0)
		close(fd);

	TEST("a file that is there is accepted");
	{
		const struct probe_named_file files[] = {
			{ "--ca-cert", tmp },
		};

		if (fd < 0) {
			FAIL("cannot create a temporary file");
		} else if (probe_named_files(files, 1, note, sizeof(note)) !=
			   0) {
			FAIL("a readable file was refused");
		}
	}

	TEST("a file that is not there is refused by flag and path");
	{
		const struct probe_named_file files[] = {
			{ "--ca-cert", tmp },
			{ "--policy-pubkey", "/nonexistent/lota-key.pub" },
		};
		int rc;

		note[0] = '\0';
		rc = probe_named_files(files, 2, note, sizeof(note));
		if (rc != -ENOENT)
			FAIL("a missing file did not report ENOENT");
		else if (!strstr(note, "--policy-pubkey"))
			FAIL("the refusal does not name the flag");
		else if (!strstr(note, "/nonexistent/lota-key.pub"))
			FAIL("the refusal does not name the path");
	}

	if (fd >= 0)
		unlink(tmp);
}

/*
 * The initrd stage holds an image current only when its helper is the
 * installed one byte for byte; an upgrade changes the bytes, not the name.
 */
static void test_file_equals(void)
{
	char tmp[] = "/tmp/lota_equals_XXXXXX";
	static char body[6000];
	static char other[6000];
	int fd;

	for (size_t i = 0; i < sizeof(body); i++)
		body[i] = (char)(i * 7);
	memcpy(other, body, sizeof(other));
	other[5000] ^= 1;

	fd = mkstemp(tmp);
	if (fd >= 0) {
		if (write(fd, body, sizeof(body)) != (ssize_t)sizeof(body)) {
			close(fd);
			unlink(tmp);
			fd = -1;
		} else {
			close(fd);
		}
	}

	TEST("a file equal to the buffer matches");
	if (fd < 0)
		FAIL("cannot create a temporary file");
	else if (probe_file_equals(tmp, body, sizeof(body)) != 1)
		FAIL("equal bytes were reported as different");

	TEST("a file of another length does not match");
	if (fd < 0)
		FAIL("cannot create a temporary file");
	else if (probe_file_equals(tmp, body, sizeof(body) - 1) != 0 ||
		 probe_file_equals(tmp, body, 0) != 0)
		FAIL("a length mismatch was reported as equal");

	TEST("one byte changed past the first read does not match");
	if (fd < 0)
		FAIL("cannot create a temporary file");
	else if (probe_file_equals(tmp, other, sizeof(other)) != 0)
		FAIL("a changed byte was reported as equal");

	TEST("a missing file is an error");
	if (probe_file_equals("/nonexistent/lota-pcr14-lock", body,
			      sizeof(body)) != -ENOENT)
		FAIL("a missing file did not report ENOENT");

	TEST("a directory does not match");
	if (probe_file_equals("/", body, 0) != 0)
		FAIL("a directory was reported as equal");

	if (fd >= 0)
		unlink(tmp);
}

/*
 * The mode half of the floor. A Secure Boot kernel refuses to be told the mode,
 * so on the hosts LOTA supports the parameter describes nothing and the installer
 * has no business writing it.
 */
static void test_ima_mode_blocking(void)
{
	TEST("a Secure Boot host appraises whatever the cmdline says");
	if (!probe_ima_mode_blocking(1, "ro quiet ima_appraise=off"))
		FAIL("the discarded parameter decided the mode");

	TEST("a Secure Boot host with no parameter still appraises");
	if (!probe_ima_mode_blocking(1, "ro quiet"))
		FAIL("the kernel's own default was read as absent");

	TEST("without Secure Boot the parameter is the answer");
	if (!probe_ima_mode_blocking(0, "ro quiet ima_appraise=enforce"))
		FAIL("a honoured enforce mode was refused");
	else if (probe_ima_mode_blocking(0, "ro quiet ima_appraise=fix"))
		FAIL("a non-blocking mode passed");
}

/*
 * The scope stage reports what tokens will say about exec appraisal.
 * The agent starts on any scope, so only a probe that could not look
 * is an error.
 */
static void test_ima_scope_stage_verdicts(void)
{
	struct probe_ima_scope scope;
	char note[STAGE_NOTE_CAP];

	TEST("a policy that appraises an executable satisfies the stage");
	scope = (struct probe_ima_scope){ .scope = PROBE_IMA_SCOPE_EXEC,
					  .is_root = 1 };
	if (probe_ima_scope_stage(&scope, note, sizeof(note)) != STAGE_DONE)
		FAIL("an appraised scope was reported as work");

	TEST("an unappraised host is reported, not stopped");
	scope = (struct probe_ima_scope){ .scope = PROBE_IMA_SCOPE_NONE,
					  .is_root = 1 };
	if (probe_ima_scope_stage(&scope, note, sizeof(note)) != STAGE_DONE)
		FAIL("an install the agent would complete was stopped");
	else if (!strstr(note, "KERNEL_APPRAISAL"))
		FAIL("the note does not name the bit that carries the state");
	else if (!strstr(note, "signatures"))
		FAIL("the note does not name what the host is missing");

	TEST("an unsigned host is told a rule set would refuse everything");
	scope = (struct probe_ima_scope){ .scope = PROBE_IMA_SCOPE_NONE,
					  .secureboot = 1,
					  .is_root = 1 };
	if (probe_ima_scope_stage(&scope, note, sizeof(note)) != STAGE_DONE)
		FAIL("the verdict changed with the reason");
	else if (!strstr(note, "enforce"))
		FAIL("the note does not say which mode a Secure Boot host "
		     "appraises in");
	else if (!strstr(note, "next boot would refuse them"))
		FAIL("the note does not say what widening the scope costs");

	TEST("a host that already signs its executables is told so");
	scope = (struct probe_ima_scope){ .scope = PROBE_IMA_SCOPE_NONE,
					  .agent_signed = 1,
					  .is_root = 1 };
	if (probe_ima_scope_stage(&scope, note, sizeof(note)) != STAGE_DONE)
		FAIL("the verdict changed with the reason");
	else if (strstr(note, "carry no signature"))
		FAIL("a signing host was told it signs nothing");

	TEST("the longest report still fits the note");
	scope = (struct probe_ima_scope){ .scope = PROBE_IMA_SCOPE_NONE,
					  .policy_signed = 1,
					  .secureboot = 1,
					  .agent_signed = 1,
					  .is_root = 1 };
	probe_ima_scope_stage(&scope, note, sizeof(note));
	if (strlen(note) >= sizeof(note) - 1)
		FAIL("the note was truncated, losing its last clause");
	else if (!strstr(note, ".ima keyring"))
		FAIL("the route out did not survive to the end of the note");

	TEST("a signed-policy host is told why a rule set cannot be loaded");
	scope = (struct probe_ima_scope){ .scope = PROBE_IMA_SCOPE_NONE,
					  .policy_signed = 1,
					  .is_root = 1 };
	if (probe_ima_scope_stage(&scope, note, sizeof(note)) != STAGE_DONE)
		FAIL("the verdict changed with the reason");
	else if (!strstr(note, "POLICY_CHECK"))
		FAIL("the note does not name the rule that refuses the write");

	TEST("a kernel without IMA appraisal is reported, not stopped");
	scope = (struct probe_ima_scope){ .scope = PROBE_IMA_SCOPE_EXEC,
					  .no_appraisal = 1,
					  .is_root = 1 };
	if (probe_ima_scope_stage(&scope, note, sizeof(note)) != STAGE_DONE)
		FAIL("a host the agent starts on was blocked by the installer");
	else if (!strstr(note, "no IMA appraisal") ||
		 strstr(note, "tokens can say"))
		FAIL("appraise read as appraisal on a kernel without it");

	TEST("a kernel publishing no policy is reported, not stopped");
	scope = (struct probe_ima_scope){ .scope = -ENOTSUP, .is_root = 1 };
	if (probe_ima_scope_stage(&scope, note, sizeof(note)) != STAGE_DONE)
		FAIL("a host the agent starts on was blocked by the installer");
	else if (!strstr(note, "cannot be checked"))
		FAIL("the note does not say the scope went unchecked");

	TEST("an unprivileged read is a caller problem, not a host verdict");
	scope = (struct probe_ima_scope){ .scope = -EACCES, .is_root = 0 };
	if (probe_ima_scope_stage(&scope, note, sizeof(note)) != STAGE_ERROR)
		FAIL("a probe that could not look reported about the host");
	else if (!strstr(note, "root"))
		FAIL("the note does not say how to get an answer");
}

/* The reader behind that verdict, over the two policies a host actually loads */
static void test_ima_policy_scope_reader(void)
{
	static const char arch_policy[] =
		"measure func=KEXEC_KERNEL_CHECK \n"
		"appraise func=POLICY_CHECK appraise_type=imasig \n"
		"measure func=MODULE_CHECK\n";
	static const char builtin_appraise[] = "dont_appraise fsmagic=0x9fa0\n"
					       "appraise fowner=0\n";
	char path[64];
	int signed_policy = -1;
	int fd;

	snprintf(path, sizeof(path), "/tmp/lota-inst-ima-%d", (int)getpid());

	TEST("the stock policy appraises no executable and signs its writes");
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0 || write(fd, arch_policy, sizeof(arch_policy) - 1) < 0) {
		FAIL("could not write the fixture");
		if (fd >= 0)
			close(fd);
		return;
	}
	close(fd);
	if (probe_ima_policy_scope(path, &signed_policy) !=
	    PROBE_IMA_SCOPE_NONE)
		FAIL("a measure-only policy was read as appraising exec");
	else if (signed_policy != 1)
		FAIL("the POLICY_CHECK rule was not seen");

	TEST("the built-in appraisal policy answers the scope question");
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0 ||
	    write(fd, builtin_appraise, sizeof(builtin_appraise) - 1) < 0) {
		FAIL("could not write the fixture");
		if (fd >= 0)
			close(fd);
		unlink(path);
		return;
	}
	close(fd);
	if (probe_ima_policy_scope(path, &signed_policy) !=
	    PROBE_IMA_SCOPE_EXEC)
		FAIL("a rule naming no hook was not counted for exec");
	else if (signed_policy != 0)
		FAIL("a policy that signs nothing was reported as signing");

	TEST("a policy nothing publishes is told apart from an empty one");
	if (probe_ima_policy_scope("/nonexistent/ima/policy", &signed_policy) !=
	    -ENOENT)
		FAIL("the read failure was not passed up as an errno");

	TEST("any appraise rule, on any hook, keeps enforce off the cmdline");
	{
		static const struct {
			const char *policy;
			int want;
		} cases[] = {
			{ "measure func=BPRM_CHECK\n"
			  "dont_appraise fsmagic=0x9fa0\n",
			  0 },
			{ "appraise func=MMAP_CHECK mask=MAY_EXEC "
			  "appraise_type=imasig \n",
			  1 },
			{ "appraise func=POLICY_CHECK appraise_type=imasig \n",
			  1 },
			{ "appraise fowner=0\n", 1 },
			{ "", 0 },
		};
		int bad = -1;

		for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
			size_t len = strlen(cases[i].policy);

			fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
			if (fd < 0 ||
			    write(fd, cases[i].policy, len) != (ssize_t)len ||
			    probe_ima_policy_appraises(path) != cases[i].want) {
				bad = (int)i;
				if (fd >= 0)
					close(fd);
				break;
			}
			close(fd);
		}
		if (bad >= 0)
			FAIL("a policy was read wrong for its appraise rules");
		else if (probe_ima_policy_appraises(
				 "/nonexistent/ima/policy") != -ENOENT)
			FAIL("an unreadable policy gave no errno");
	}

	unlink(path);
}

static void test_cmdline_next_boot_verdicts(void)
{
	static const struct {
		struct probe_floor st;
		const char *args;
		enum stage_state want;
		const char *note;
	} cases[] = {
		{ { .sig_ok = 1,
		    .lockdown_ok = 1,
		    .ima_built = 1,
		    .appraises = 1 },
		  "ro ima_appraise=enforce",
		  STAGE_BLOCKED,
		  "puts IMA appraisal in enforce" },
		{ { .sig_ok = 1,
		    .lockdown_ok = 1,
		    .ima_built = 1,
		    .appraises = 1 },
		  "ro quiet",
		  STAGE_BLOCKED,
		  "puts IMA appraisal in enforce" },
		{ { .lockdown_ok = 1, .ima_built = 1, .appraises = 1 },
		  "ro ima_appraise=enforce",
		  STAGE_BLOCKED,
		  "rerunning the installer adds: module.sig_enforce=1." },
		{ { .ima_built = 1, .appraises = 1 },
		  "ro ima_appraise=enforce lockdown=integrity",
		  STAGE_BLOCKED,
		  "adds: module.sig_enforce=1." },
		{ { .ima_built = 1, .appraises = 1 },
		  "ro ima_appraise=enforce",
		  STAGE_BLOCKED,
		  "adds: module.sig_enforce=1 lockdown=integrity." },
		{ { .sig_ok = 1,
		    .lockdown_ok = 1,
		    .ima_built = 1,
		    .appraises = 1 },
		  "ro ima_appraise=fix",
		  STAGE_BLOCKED,
		  "so it is not added" },
		{ { .lockdown_ok = 1, .ima_built = 1, .appraises = 1 },
		  "ro ima_appraise=fix",
		  STAGE_PENDING,
		  "is not added" },
		{ { .sig_ok = 1, .lockdown_ok = 1, .ima_built = 1 },
		  "ro ima_appraise=enforce",
		  STAGE_REBOOT,
		  "is configured" },
		{ { .ima_ok = 1,
		    .lockdown_ok = 1,
		    .secureboot = 1,
		    .ima_built = 1,
		    .appraises = 1 },
		  "ro module.sig_enforce=1",
		  STAGE_REBOOT,
		  "is configured" },
		{ { .lockdown_ok = 1, .ima_built = 1 },
		  NULL,
		  STAGE_PENDING,
		  "lacks: ima_appraise module" },
	};
	static const struct probe_floor sig_in_args = { .lockdown_ok = 1,
							.ima_built = 1,
							.appraises = 1 };
	char note[512];
	int bad = -1;

	TEST("cmdline stage never sends a policy that appraises into enforce");
	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		note[0] = '\0';
		if (probe_cmdline_next_boot_stage(&cases[i].st, cases[i].args,
						  note, sizeof(note)) !=
			    cases[i].want ||
		    !strstr(note, cases[i].note)) {
			bad = (int)i;
			break;
		}
	}
	if (bad >= 0)
		FAIL("a floor and cmdline got the wrong verdict");
	else if (probe_cmdline_next_boot_stage(&cases[0].st, cases[0].args,
					       note,
					       sizeof(note)) != STAGE_BLOCKED ||
		 strstr(note, "rerunning"))
		FAIL("a blocked floor with nothing missing named an addition");
	else if (probe_cmdline_next_boot_stage(&sig_in_args,
					       "ro ima_appraise=enforce "
					       "module.sig_enforce=1",
					       note,
					       sizeof(note)) != STAGE_BLOCKED ||
		 strstr(note, "rerunning"))
		FAIL("a parameter on the cmdline was named an addition");
	else if (probe_cmdline_next_boot_stage(NULL, "ro", note,
					       sizeof(note)) != STAGE_ERROR)
		FAIL("a missing floor was not an error");
}

int main(void)
{
	test_begin("installer probe");

	test_pcr14_baseline_path_is_the_shipped_one();
	test_pcr14_lock_value_baseline_aware();
	test_hex_to_bytes();
	test_cmdline_ima();
	test_cmdline_token();
	test_conf_profile_count();
	test_read_text();
	test_selfcheck_plan();
	test_conf_profile_anchor();
	test_conf_continuous_count();
	test_attest_status_covers();
	test_esrt_present();
	test_machine_description();
	test_efivar_payload();
	test_secureboot_remediation();
	test_secureboot_remediation_when_the_request_fails();
	test_secureboot_remediation_fits_a_note();
	test_auto_bringup_opt_in();
	test_manifest_line();
	test_port_needs_label();
	test_selinux_unmet_note();
	test_installed_kernels();
	test_barrier_stage_verdicts();
	test_agent_paused_reader();
	test_barrier_after_a_pause();
	test_ima_mode_blocking();
	test_ima_scope_stage_verdicts();
	test_ima_policy_scope_reader();
	test_cmdline_next_boot_verdicts();
	test_named_files();
	test_file_equals();

	return test_end();
}
