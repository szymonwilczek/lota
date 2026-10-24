/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for the evidence behind the IOMMU report flags.
 *
 * The attesting unit runs with ProtectKernelLogs=yes and the ring buffer
 * wraps, so the flags must come from sysfs (IOMMU groups and their domain
 * types) and /proc/interrupts. Each case builds its own tree.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../include/iommu_types.h"
#include "../src/agent/iommu.h"

static int tests_run;
static int tests_passed;

#define TEST(name)                                         \
	do {                                               \
		tests_run++;                               \
		printf("  [%2d] %-62s ", tests_run, name); \
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

static char g_root[64];

static int mkpath(const char *rel)
{
	char path[512];

	snprintf(path, sizeof(path), "%s/%s", g_root, rel);
	if (mkdir(path, 0755) < 0 && errno != EEXIST)
		return -errno;
	return 0;
}

static int mkfile(const char *rel, const char *contents)
{
	char path[512];
	FILE *f;
	int fd;

	snprintf(path, sizeof(path), "%s/%s", g_root, rel);
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0)
		return -errno;
	f = fdopen(fd, "w");
	if (!f) {
		int err = errno;

		close(fd);
		return -err;
	}
	fputs(contents, f);
	fclose(f);
	return 0;
}

/* Tear the tree down between cases so one case cannot inherit another's */
static void rmtree(const char *path)
{
	struct dirent *entry;
	DIR *dir = opendir(path);

	if (!dir)
		return;

	while ((entry = readdir(dir)) != NULL) {
		char child[512];

		if (strcmp(entry->d_name, ".") == 0 ||
		    strcmp(entry->d_name, "..") == 0)
			continue;

		snprintf(child, sizeof(child), "%s/%s", path, entry->d_name);
		if (entry->d_type == DT_DIR)
			rmtree(child);
		else
			unlink(child);
	}

	closedir(dir);
	rmdir(path);
}

static void tree_reset(void)
{
	rmtree(g_root);
	mkdir(g_root, 0755);
	mkpath("sys");
	mkpath("sys/class");
	mkpath("sys/class/iommu");
	mkpath("sys/kernel");
	mkpath("sys/kernel/iommu_groups");
	mkpath("proc");
	mkfile("proc/cmdline", "BOOT_IMAGE=/vmlinuz ro quiet\n");
	mkfile("proc/interrupts",
	       "           CPU0\n"
	       "  1:         44   IO-APIC    1-edge      i8042\n");
}

/* Intel VT-d with its units registered, which is what the class carries */
static void tree_units_present(void)
{
	mkpath("sys/class/iommu/dmar0");
	mkpath("sys/class/iommu/dmar1");
}

/* One group, in the domain type named, holding one device */
static void tree_group(const char *id, const char *type)
{
	char rel[256];

	snprintf(rel, sizeof(rel), "sys/kernel/iommu_groups/%s", id);
	mkpath(rel);
	snprintf(rel, sizeof(rel), "sys/kernel/iommu_groups/%s/type", id);
	mkfile(rel, type);
	snprintf(rel, sizeof(rel), "sys/kernel/iommu_groups/%s/devices", id);
	mkpath(rel);
	snprintf(rel, sizeof(rel),
		 "sys/kernel/iommu_groups/%s/devices/0000:00:1f.0", id);
	mkfile(rel, "");
}

/* translating domains are DMA remapping, read from sysfs alone */
static void test_translating_domains_are_dma_remapping(void)
{
	struct iommu_status status;

	TEST("devices in translating domains prove DMA remapping");

	tree_reset();
	tree_units_present();
	tree_group("0", "DMA\n");
	tree_group("1", "DMA-FQ\n");

	if (!iommu_verify_full_at(&status, g_root)) {
		FAIL("a host whose devices are translated is reported unverified");
		return;
	}
	if (!(status.flags & IOMMU_FLAG_DMA_REMAP)) {
		FAIL("DMA remapping is not established from the domains");
		return;
	}
	PASS();
}

/* identity (passthrough) domains remap nothing, units or not */
static void test_identity_domains_are_not_dma_remapping(void)
{
	struct iommu_status status;

	TEST("a passthrough host is not reported as remapping DMA");

	tree_reset();
	tree_units_present();
	tree_group("0", "identity\n");
	tree_group("1", "identity\n");

	if (iommu_verify_full_at(&status, g_root)) {
		FAIL("a passthrough host passed verification");
		return;
	}
	if (status.flags & IOMMU_FLAG_DMA_REMAP) {
		FAIL("passthrough was reported as DMA remapping");
		return;
	}
	PASS();
}

/* No units, no groups: the honest answer is that nothing was verified */
static void test_a_host_without_an_iommu_verifies_nothing(void)
{
	struct iommu_status status;

	TEST("a host with no IOMMU sets neither flag");

	tree_reset();

	if (iommu_verify_full_at(&status, g_root)) {
		FAIL("a host with no IOMMU passed verification");
		return;
	}
	if (status.flags & (IOMMU_FLAG_SYSFS_PRESENT | IOMMU_FLAG_DMA_REMAP)) {
		FAIL("a flag was set with no evidence for it");
		return;
	}
	PASS();
}

/* interrupt remapping is read from the chip names in /proc/interrupts */
static void test_irq_remapping_comes_from_the_interrupt_table(void)
{
	struct iommu_status status;

	TEST("interrupt remapping is established from the interrupt table");

	tree_reset();
	tree_units_present();
	tree_group("0", "DMA\n");
	mkfile("proc/interrupts",
	       "           CPU0\n"
	       "  1:         44   IR-IO-APIC    1-edge      i8042\n"
	       "  9:         85   IR-IO-APIC    9-fasteoi   acpi\n");

	iommu_verify_full_at(&status, g_root);

	if (!(status.flags & IOMMU_FLAG_IRQ_REMAP)) {
		FAIL("remapped interrupts were not recognised");
		return;
	}
	PASS();
}

/* And the same table with no remapped chip says so */
static void test_unremapped_interrupts_say_so(void)
{
	struct iommu_status status;

	TEST("an unremapped interrupt table sets no interrupt-remap flag");

	tree_reset();
	tree_units_present();
	tree_group("0", "DMA\n");

	iommu_verify_full_at(&status, g_root);

	if (status.flags & IOMMU_FLAG_IRQ_REMAP) {
		FAIL("interrupt remapping was claimed without evidence");
		return;
	}
	PASS();
}

int main(void)
{
	printf("=== IOMMU evidence tests ===\n\n");

	snprintf(g_root, sizeof(g_root), "/tmp/lota-iommu-%d", (int)getpid());

	test_translating_domains_are_dma_remapping();
	test_identity_domains_are_not_dma_remapping();
	test_a_host_without_an_iommu_verifies_nothing();
	test_irq_remapping_comes_from_the_interrupt_table();
	test_unremapped_interrupts_say_so();

	rmtree(g_root);

	printf("\n=== %d/%d passed ===\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
