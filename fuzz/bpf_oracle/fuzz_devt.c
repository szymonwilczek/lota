/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Zero-copy BPF decision-logic fuzzer.
 *
 * include/lota_devt.h is the canonical dev_t encoding shared by the BPF LSM
 * and the user-space loader:
 *
 * 	LSM reads inode->i_rdev verbatim and the loader must write map keys in the
 * 	same layout, so an encoding bug here desynchronises /dev-node identity from
 * 	its trusted-map key.
 * 	Header is user-space-includable, so this harness fuzzes the REAL macros
 * 	(no copy, no drift) against an independent reference derived from the header's
 * 	own documented rule (major = dev >> 20, minor = dev & mask) and from glibc's
 * 	makedev/major/minor.
*/

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sysmacros.h>
#include <sys/types.h>

#include "lota_devt.h"

/* Independent reference:
 * 20-bit split as the header documents it, written out by hand */
#define REF_MINORBITS 20
#define REF_MINORMASK ((1ULL << REF_MINORBITS) - 1)

static unsigned ref_major(unsigned long long dev)
{
	return (unsigned)(dev >> REF_MINORBITS);
}

static unsigned ref_minor(unsigned long long dev)
{
	return (unsigned)(dev & REF_MINORMASK);
}

static unsigned long long ref_mkdev(unsigned maj, unsigned min)
{
	return ((unsigned long long)maj << REF_MINORBITS) |
	       ((unsigned long long)min & REF_MINORMASK);
}

#define FZ_CHECK(cond)           \
	do {                     \
		if (!(cond))     \
			abort(); \
	} while (0)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint32_t dev = 0;
	uint32_t maj = 0;
	uint32_t min = 0;

	/* kernel dev_t is 32-bit
	 * carve dev + major/minor pair */
	if (size >= 4)
		memcpy(&dev, data, 4);
	if (size >= 8)
		memcpy(&maj, data + 4, 4);
	if (size >= 12)
		memcpy(&min, data + 8, 4);

	/* decode: production macro must match the documented split */
	FZ_CHECK(LOTA_DEVT_MAJOR(dev) == ref_major(dev));
	FZ_CHECK(LOTA_DEVT_MINOR(dev) == ref_minor(dev));

	/* encode: production MKDEV must match the documented composition */
	FZ_CHECK(LOTA_DEVT_MKDEV(maj, min) == ref_mkdev(maj, min));

	/* decode . encode roundtrip on a composed value
	 * (minor is masked to 20 bits by construction, so it must survive intact) */
	{
		unsigned long long d = LOTA_DEVT_MKDEV(maj, min);
		FZ_CHECK(LOTA_DEVT_MAJOR(d) == maj);
		FZ_CHECK(LOTA_DEVT_MINOR(d) == (min & REF_MINORMASK));
	}

	/*
	 * lota_devt_from_st converts a glibc-encoded st_dev into the kernel layout;
	 * for a value glibc itself composed, the result must equal the kernel-layout
	 * encoding of the same major/minor
	*/
	{
		unsigned gmaj = maj & 0xFFFu; // 12-bit major, glibc-safe range
		unsigned gmin = min & 0xFFFFFu; // 20-bit minor
		dev_t st = makedev(gmaj, gmin);
		FZ_CHECK(lota_devt_from_st(st) == LOTA_DEVT_MKDEV(gmaj, gmin));
	}

	return 0;
}
