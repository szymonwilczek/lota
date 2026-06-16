/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for the canonical dev_t encoding helpers (include/lota_devt.h).
 *
 * They pin the kernel MKDEV layout the BPF programs rely on and the
 * stat(2) -> kernel conversion the loader uses to build trusted-library
 * map keys.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <stdint.h>
#include <stdio.h>
#include <sys/sysmacros.h>

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

/*
 * kernel stores dev_t as major = dev >> 20, minor = dev & 0xFFFFF
 * /dev/mem is character major 1, minor 1, so i_rdev is 0x100001;
 * regression that motivated these helpers decoded that major as 0
 */
static void test_kernel_mkdev_layout(void)
{
	CHECK(LOTA_DEVT_MKDEV(1, 1) == 0x100001ULL,
	      "MKDEV(1,1) is the kernel /dev/mem layout");
	CHECK(LOTA_DEVT_MAJOR(0x100001ULL) == 1,
	      "MAJOR decodes /dev/mem major as 1");
	CHECK(LOTA_DEVT_MINOR(0x100001ULL) == 1,
	      "MINOR decodes /dev/mem minor as 1");
	CHECK(LOTA_DEVT_MAJOR(LOTA_DEVT_MKDEV(1, 2)) == 1 &&
		      LOTA_DEVT_MINOR(LOTA_DEVT_MKDEV(1, 2)) == 2,
	      "MKDEV(1,2) round-trips (/dev/kmem)");
	CHECK(LOTA_DEVT_MAJOR(LOTA_DEVT_MKDEV(1, 4)) == 1 &&
		      LOTA_DEVT_MINOR(LOTA_DEVT_MKDEV(1, 4)) == 4,
	      "MKDEV(1,4) round-trips (/dev/port)");
}

static void test_mkdev_round_trip(void)
{
	static const struct {
		unsigned int major;
		unsigned int minor;
	} cases[] = {
		{ 0, 0 },      { 0, 37 },	  { 1, 1 },   { 8, 0 },
		{ 8, 16 },     { 253, 5 },	  { 259, 3 }, { 1, 291 },
		{ 7, 0xFFFF }, { 4095, 0xFFFFF },
	};
	size_t i;

	for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		unsigned long long dev =
			LOTA_DEVT_MKDEV(cases[i].major, cases[i].minor);
		char msg[96];

		snprintf(msg, sizeof(msg),
			 "MKDEV(%u,%u) round-trips through MAJOR/MINOR",
			 cases[i].major, cases[i].minor);
		CHECK(LOTA_DEVT_MAJOR(dev) == cases[i].major &&
			      LOTA_DEVT_MINOR(dev) == cases[i].minor,
		      msg);
	}
}

/*
 * loader feeds stat(2) st_dev through lota_devt_from_st()
 * the result must equal the kernel layout the BPF side builds from s_dev.
 * For a non-zero major the raw glibc st_dev differs, which is exactly
 * the mismatch the conversion removes
 */
static void test_st_dev_conversion(void)
{
	dev_t st = makedev(8, 1);

	CHECK(lota_devt_from_st(st) == LOTA_DEVT_MKDEV(8, 1),
	      "from_st(makedev(8,1)) yields the kernel layout");
	CHECK(lota_devt_from_st(st) == 0x800001ULL,
	      "from_st(makedev(8,1)) is 0x800001");
	CHECK(lota_devt_from_st(st) != (unsigned long long)st,
	      "conversion changes a non-zero-major st_dev");
	CHECK(lota_devt_from_st(makedev(1, 291)) == LOTA_DEVT_MKDEV(1, 291),
	      "from_st preserves minor bits above 0xFF");
}

/*
 * Document why the mismatch hid in development:
 * for a major-0 (anon-bdev) device the glibc and kernel layouts coincide,
 * so st_dev already matched the BPF-side key before the conversion existed
 */
static void test_major_zero_coincidence(void)
{
	dev_t st = makedev(0, 37);

	CHECK(lota_devt_from_st(st) == (unsigned long long)st,
	      "major-0 st_dev is unchanged by the conversion");
}

int main(void)
{
	printf("=== dev_t encoding tests ===\n");
	test_kernel_mkdev_layout();
	test_mkdev_round_trip();
	test_st_dev_conversion();
	test_major_zero_coincidence();

	if (g_failures) {
		fprintf(stderr, "\n%d test(s) failed\n", g_failures);
		return 1;
	}
	printf("\nAll dev_t encoding tests passed\n");
	return 0;
}
