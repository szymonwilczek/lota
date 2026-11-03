/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Unit tests for lota-bench's machine reader, on a synthetic root.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "test.h"
#include "../tools/lota-bench/machine.h"

static char root[] = "/tmp/lota-bench-machine-XXXXXX";

static void mkdirs(const char *rel)
{
	char path[512];

	snprintf(path, sizeof(path), "%s/%s", root, rel);
	for (char *p = path + strlen(root) + 1; *p; p++) {
		if (*p != '/')
			continue;
		*p = '\0';
		if (mkdir(path, 0700) && errno != EEXIST) {
			perror(path);
			exit(1);
		}
		*p = '/';
	}
	if (mkdir(path, 0700) && errno != EEXIST) {
		perror(path);
		exit(1);
	}
}

static void put(const char *rel, const char *body)
{
	char path[512], dir[512], *slash;
	FILE *f;
	int fd;

	snprintf(dir, sizeof(dir), "%s", rel);
	slash = strrchr(dir, '/');
	if (slash) {
		*slash = '\0';
		mkdirs(dir);
	}
	snprintf(path, sizeof(path), "%s/%s", root, rel);
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	f = fd < 0 ? NULL : fdopen(fd, "w");
	if (!f) {
		perror(path);
		exit(1);
	}
	fputs(body, f);
	fclose(f);
}

static void link_to(const char *rel, const char *target)
{
	char path[512], dir[512], *slash;

	snprintf(dir, sizeof(dir), "%s", rel);
	slash = strrchr(dir, '/');
	if (slash) {
		*slash = '\0';
		mkdirs(dir);
	}
	snprintf(path, sizeof(path), "%s/%s", root, rel);
	unlink(path);
	if (symlink(target, path)) {
		perror(path);
		exit(1);
	}
}

/* a file, a link or an empty directory */
static void unput(const char *rel)
{
	char path[512];

	snprintf(path, sizeof(path), "%s/%s", root, rel);
	if (unlink(path))
		rmdir(path);
}

static int open_root(void)
{
	int fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);

	if (fd < 0) {
		perror(root);
		exit(1);
	}
	return fd;
}

static void make_machine(void)
{
	char ids[2048];
	char longname[700];

	/* the tail of a line past the reader's buffer must not end the vendor */
	memset(longname, 'x', sizeof(longname) - 1);
	longname[sizeof(longname) - 1] = '\0';
	memcpy(longname + 520, "2222  Tail", 10);
	put("proc/cpuinfo", "processor\t: 0\n"
			    "vendor_id\t: ExampleVendor\n"
			    "model name\t: Example CPU 8-Core @ 3.00GHz\n"
			    "\n"
			    "processor\t: 1\n"
			    "model name\t: Example CPU 8-Core @ 3.00GHz\n"
			    "\n");
	put("proc/meminfo", "MemTotal:       16000000 kB\n"
			    "MemFree:         8000000 kB\n");
	put("proc/sys/kernel/osrelease", "6.0.0-example\n");
	put("etc/os-release", "NAME=\"Example Linux\"\n"
			      "ID=examplelinux\n"
			      "VERSION_ID=\"42\"\n"
			      "PRETTY_NAME=\"Example Linux 42\"\n");
	put("sys/class/drm/card1/device/vendor", "0x1234\n");
	put("sys/class/drm/card1/device/device", "0x5678\n");
	link_to("sys/class/drm/card1/device/driver",
		"../../../bus/pci/drivers/examplegpu");
	put("sys/class/drm/card1-DP-1/status", "connected\n");
	/* a display without a bus device is not a GPU */
	put("sys/class/drm/card0/dev", "226:0\n");
	put("sys/class/drm/card2/device/vendor", "0x1234\n");
	put("sys/class/drm/card2/device/device", "0x9999\n");
	snprintf(ids, sizeof(ids),
		 "# comment\n"
		 "1111  Other Vendor\n"
		 "\t5678  Not This One\n"
		 "1234  Example Vendor\n"
		 "\t0001  Example Other\n"
		 "# a comment inside the vendor\n"
		 "\n"
		 "\t0002  %s\n"
		 "\t\t5678 5678  Example Subsystem\n"
		 "\t5678  Example GPU [Model 1/2]\n"
		 "2222  Later Vendor\n"
		 "C 03  Display controller\n",
		 longname);
	put(BENCH_PCI_IDS, ids);
	link_to("sys/class/tpm/tpm0/device/driver",
		"../../../bus/platform/drivers/tpm_example");
	put("sys/fs/selinux/enforce", "1");
}

static void test_machine(void)
{
	struct bench_machine m;
	int fd = open_root();

	TEST("machine fields read from a synthetic root");
	bench_machine_read(fd, &m);
	close(fd);
	if (!m.cpu_model.set ||
	    strcmp(m.cpu_model.s, "Example CPU 8-Core @ 3.00GHz") != 0 ||
	    m.cpu_threads != 2 || m.memory_bytes != 16000000ull * 1024) {
		FAIL("cpu or memory");
		return;
	}
	if (strcmp(m.kernel.s, "6.0.0-example") != 0 ||
	    strcmp(m.distro.s, "examplelinux 42") != 0 ||
	    strcmp(m.tpm.s, "tpm_example") != 0 || m.selinux != BSE_ENFORCING) {
		FAIL("kernel, distro, tpm or selinux");
		return;
	}
	if (m.ngpus != 2 || m.gpu[0].vendor_id != 0x1234 ||
	    m.gpu[0].device_id != 0x5678 ||
	    strcmp(m.gpu[0].name.s, "Example GPU [Model 1_2]") != 0 ||
	    strcmp(m.gpu[0].driver.s, "examplegpu") != 0) {
		FAIL("first gpu");
		return;
	}
	if (m.gpu[1].device_id != 0x9999 || m.gpu[1].name.set ||
	    m.gpu[1].driver.set) {
		FAIL("unnamed gpu");
		return;
	}
	PASS();
}

static void test_missing(void)
{
	struct bench_machine m;
	char empty[] = "/tmp/lota-bench-empty-XXXXXX";
	int fd;

	TEST("an empty root leaves every field unset");
	if (!mkdtemp(empty)) {
		FAIL("mkdtemp");
		return;
	}
	fd = open(empty, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	bench_machine_read(fd, &m);
	close(fd);
	rmdir(empty);
	if (m.cpu_model.set || m.cpu_threads || m.memory_bytes || m.ngpus ||
	    m.kernel.set || m.distro.set || strcmp(m.tpm.s, "none") != 0 ||
	    m.selinux != BSE_DISABLED) {
		FAIL("field set");
		return;
	}
	PASS();
}

static void test_virtual_tpm(void)
{
	struct bench_machine m;
	int fd;

	TEST("a TPM without a bus device reads as virtual");
	unput("sys/class/tpm/tpm0/device/driver");
	unput("sys/class/tpm/tpm0/device");
	unput("sys/class/tpm/tpm0");
	mkdirs("sys/devices/virtual/misc/vtpmx/tpm0");
	link_to("sys/class/tpm/tpm0", "../../devices/virtual/misc/vtpmx/tpm0");
	put("sys/fs/selinux/enforce", "0");
	fd = open_root();
	bench_machine_read(fd, &m);
	close(fd);
	if (strcmp(m.tpm.s, "virtual") != 0 || m.selinux != BSE_PERMISSIVE) {
		FAIL(m.tpm.s);
		return;
	}
	PASS();
}

static void test_diff(void)
{
	struct bench_machine a, b;
	int fd = open_root();

	TEST("a changed kernel or GPU is named, memory size is not");
	bench_machine_read(fd, &a);
	close(fd);
	b = a;
	b.memory_bytes += 4096;
	if (bench_machine_diff(&a, &b)) {
		FAIL("memory compared");
		return;
	}
	strcpy(b.kernel.s, "6.0.1-example");
	if (!bench_machine_diff(&a, &b) ||
	    strcmp(bench_machine_diff(&a, &b), "kernel") != 0) {
		FAIL("kernel");
		return;
	}
	b = a;
	b.gpu[1].device_id++;
	if (!bench_machine_diff(&a, &b) ||
	    strcmp(bench_machine_diff(&a, &b), "GPU") != 0) {
		FAIL("gpu");
		return;
	}
	PASS();
}

static void test_power(void)
{
	struct bench_power p;
	int fd;

	TEST("governor, profile and a discharging battery");
	put("sys/devices/system/cpu/cpu0/cpufreq/scaling_governor",
	    "powersave\n");
	put("sys/firmware/acpi/platform_profile", "balanced\n");
	put("sys/class/power_supply/AC0/type", "Mains\n");
	put("sys/class/power_supply/AC0/online", "0\n");
	put("sys/class/power_supply/BAT0/type", "Battery\n");
	put("sys/class/power_supply/BAT0/status", "Discharging\n");
	fd = open_root();
	bench_power_read(fd, &p);
	if (strcmp(p.governor.s, "powersave") != 0 ||
	    strcmp(p.profile.s, "balanced") != 0 || p.supply != BSU_BATTERY) {
		close(fd);
		FAIL("power");
		return;
	}
	put("sys/class/power_supply/BAT0/status", "Charging\n");
	put("sys/class/power_supply/AC0/online", "1\n");
	bench_power_read(fd, &p);
	close(fd);
	if (p.supply != BSU_AC) {
		FAIL("on ac");
		return;
	}
	PASS();
}

static void test_no_supply(void)
{
	struct bench_power p;
	char empty[] = "/tmp/lota-bench-empty-XXXXXX";
	int fd;

	TEST("no power supply at all reads as unknown");
	if (!mkdtemp(empty)) {
		FAIL("mkdtemp");
		return;
	}
	fd = open(empty, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	bench_power_read(fd, &p);
	close(fd);
	rmdir(empty);
	if (p.supply != BSU_UNKNOWN || p.governor.set || p.profile.set) {
		FAIL("set");
		return;
	}
	PASS();
}

int main(void)
{
	char cmd[256];

	if (!mkdtemp(root)) {
		perror("mkdtemp");
		return 1;
	}

	printf("lota-bench machine reader:\n");

	make_machine();
	test_machine();
	test_missing();
	test_diff();
	test_power();
	test_no_supply();
	test_virtual_tpm();

	snprintf(cmd, sizeof(cmd), "rm -rf -- '%s'", root);
	if (system(cmd) != 0)
		fprintf(stderr, "cleanup of %s failed\n", root);

	printf("%d/%d tests passed\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
