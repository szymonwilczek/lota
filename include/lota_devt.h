/* SPDX-License-Identifier: MIT */
/*
 * Canonical device-number (dev_t) encoding shared by the BPF programs
 * and the user-space loader.
 *
 * Kernel stores inode->i_rdev and super_block->s_dev in its internal
 * MKDEV layout:
 *
 * 	20-bit minor with the major above it
 * 	(major = dev >> 20, minor = dev & 0xFFFFF)
 *
 * BPF programs read those fields verbatim, so any device identity that has to
 * compare against a BPF-side value
 * 	-- a /dev node major/minor or a trusted-library map key --
 * must be expressed in this same layout.
 *
 * stat(2) hands user space a different layout
 * (the glibc gnu_dev encoding that
 * mirrors the kernel's new_encode_dev()), so the loader converts st_dev into
 * the kernel layout before it writes map keys.
 */

#ifndef LOTA_DEVT_H
#define LOTA_DEVT_H

#define LOTA_DEVT_MINORBITS 20
#define LOTA_DEVT_MINORMASK ((1ULL << LOTA_DEVT_MINORBITS) - 1)

/* Decode major/minor from a kernel-layout dev_t */
#define LOTA_DEVT_MAJOR(dev) \
	((unsigned int)((unsigned long long)(dev) >> LOTA_DEVT_MINORBITS))
#define LOTA_DEVT_MINOR(dev) \
	((unsigned int)((unsigned long long)(dev) & LOTA_DEVT_MINORMASK))

/* Compose a kernel-layout dev_t from major/minor */
#define LOTA_DEVT_MKDEV(major, minor)                           \
	(((unsigned long long)(major) << LOTA_DEVT_MINORBITS) | \
	 ((unsigned long long)(minor) & LOTA_DEVT_MINORMASK))

#ifndef __BPF_PROGRAM__
#include <sys/sysmacros.h>
#include <sys/types.h>

/*
 * Convert a stat(2) st_dev (glibc encoding) into the kernel MKDEV layout used
 * by the BPF map keys.
 */
static inline unsigned long long lota_devt_from_st(dev_t st_dev)
{
	return LOTA_DEVT_MKDEV(major(st_dev), minor(st_dev));
}
#endif /* __BPF_PROGRAM__ */

#endif /* LOTA_DEVT_H */
