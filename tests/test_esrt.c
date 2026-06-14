/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for the ESRT System Firmware reader (esrt.c).
 *
 * Builds a fixture mirroring /sys/firmware/efi/esrt/entries and checks that
 * the System Firmware entry (fw_type == 1) is picked, device entries are
 * skipped, and a missing table is reported as not-present (not an error) so
 * the verifier can route the host onto the Low-Firmware-Assurance path.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../src/agent/esrt.h"
#include "attestation.h"

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

static void write_file(const char *dir, const char *name, const char *val)
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

static const char *tmp_base(void)
{
	static char base[256];
	snprintf(base, sizeof(base), "/tmp/lota-esrt-test.%d", getpid());
	return base;
}

static void make_entry(const char *base, const char *entry, const char *fw_type,
		       const char *fw_version, const char *lowest,
		       const char *fw_class)
{
	char dir[512];

	snprintf(dir, sizeof(dir), "%s/%s", base, entry);
	mkdir(dir, 0755);
	write_file(dir, "fw_type", fw_type);
	write_file(dir, "fw_version", fw_version);
	write_file(dir, "lowest_supported_fw_version", lowest);
	write_file(dir, "fw_class", fw_class);
}

static void rm_rf(const char *base)
{
	char cmd[512];
	snprintf(cmd, sizeof(cmd), "rm -rf '%s'", base);
	if (system(cmd) != 0)
		fprintf(stderr, "warning: cleanup of %s failed\n", base);
}

static void test_picks_system_firmware(void)
{
	const char *base = tmp_base();
	struct lota_esrt e;

	mkdir(base, 0755);
	/* device-firmware entry first; must be skipped */
	make_entry(base, "entry0", "2", "164", "0",
		   "69585d92-b50a-4ad7-b265-2eb1ae066574");
	/* system-firmware entry */
	make_entry(base, "entry1", "1", "785", "785",
		   "b53e82ee-2b53-5829-9756-68e1e4eff873");

	CHECK(esrt_read_system_firmware_path(base, &e) == 0, "read returns 0");
	CHECK(e.present == 1, "system firmware present");
	CHECK(e.fw_version == 785, "fw_version picked from fw_type=1 entry");
	CHECK(e.lowest_supported == 785, "lowest_supported parsed");

	/* GUID b53e82ee-... -> first byte 0xb5 */
	CHECK(e.fw_class[0] == 0xb5 && e.fw_class[1] == 0x3e,
	      "fw_class GUID parsed to raw bytes");

	rm_rf(base);
}

static void test_missing_is_not_present(void)
{
	struct lota_esrt e;
	CHECK(esrt_read_system_firmware_path("/tmp/lota-esrt-absent.XXXXXX",
					     &e) == 0,
	      "absent ESRT dir returns 0");
	CHECK(e.present == 0, "absent ESRT reported as not-present");
}

static void test_only_device_entries(void)
{
	const char *base = tmp_base();
	struct lota_esrt e;

	mkdir(base, 0755);
	make_entry(base, "entry0", "2", "100", "0",
		   "69585d92-b50a-4ad7-b265-2eb1ae066574");

	CHECK(esrt_read_system_firmware_path(base, &e) == 0, "read returns 0");
	CHECK(e.present == 0, "device-only ESRT reported as not-present");

	rm_rf(base);
}

static void test_null_args(void)
{
	struct lota_esrt e;
	CHECK(esrt_read_system_firmware_path(NULL, &e) == -EINVAL,
	      "NULL base rejected");
	CHECK(esrt_read_system_firmware_path("/tmp", NULL) == -EINVAL,
	      "NULL out rejected");
}

int main(void)
{
	test_picks_system_firmware();
	test_missing_is_not_present();
	test_only_device_entries();
	test_null_args();

	if (g_failures) {
		fprintf(stderr, "\n%d test(s) FAILED\n", g_failures);
		return 1;
	}
	printf("\nAll ESRT tests passed\n");
	return 0;
}
