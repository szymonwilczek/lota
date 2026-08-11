/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
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
 * stat(2) is not a source for it. Its layout differs (the glibc gnu_dev encoding
 * that mirrors the kernel's new_encode_dev()), and on btrfs it reports
 * a per-subvolume anonymous device the superblock never had, so a key built from
 * st_dev is one the kernel cannot look up.
 * src/agent/sb_dev.h resolves the superblock device instead, already in this layout.
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
