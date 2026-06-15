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

int main(void)
{
	printf("installer probe helpers:\n");

	test_pcr14_lock_constant_kat();
	test_hex_to_bytes();
	test_cmdline_ima();
	test_cmdline_token();
	test_conf_key();
	test_esrt_present();

	printf("%d/%d tests passed\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
