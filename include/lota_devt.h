/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Device numbers in the kernel's MKDEV layout, as BPF programs read them from
 * inode->i_rdev and super_block->s_dev: 20-bit minor with the major above it.
 *
 * stat(2) is no source for a key compared against them. Its st_dev has the
 * new_encode_dev() layout and, on btrfs, names a per-subvolume anonymous device
 * (see src/agent/sb_dev.h).
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

#endif /* LOTA_DEVT_H */
