/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
#ifndef LOTA_AGENT_SB_DEV_H
#define LOTA_AGENT_SB_DEV_H

/*
 * The device number a BPF program reads for an inode is its superblock's,
 * inode->i_sb->s_dev. stat(2) does not always report that number: btrfs gives
 * every subvolume its own anonymous device, so a file under one has a different
 * device in stat(2) than in its superblock. A map key built from stat(2) is then
 * a key no hook can look up.
 *
 * These resolve the superblock device instead, in the kernel MKDEV layout of
 * include/lota_devt.h, by way of the mount the file was resolved through:
 * statx() names that mount, /proc/self/mountinfo prints its superblock device.
 */

/*
 * Superblock device of the filesystem behind @fd.
 * @fd may be an O_PATH descriptor.
 * Returns 0 and fills @out_dev, or a negative errno:
 *      -ENOTSUP if the kernel does not report a mount id,
 *      -ENODEV if the mount is not listed.
 */
int sb_dev_from_fd(int fd, unsigned long long *out_dev);

/*
 * Superblock device of mount @mnt_id as listed in the mountinfo file at
 * @mountinfo_path.
 * Separated from sb_dev_from_fd() so the parse can be driven against
 * a mountinfo a test supplies.
 */
int sb_dev_from_mountinfo(const char *mountinfo_path, unsigned long long mnt_id,
			  unsigned long long *out_dev);

#endif
