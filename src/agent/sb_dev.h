/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - superblock device of a file.
 *
 * BPF hooks key a file by inode->i_sb->s_dev, and stat(2) reports a btrfs
 * subvolume's anonymous device. These read the device mountinfo prints for
 * the mount statx() names, in the layout of include/lota_devt.h.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#ifndef LOTA_AGENT_SB_DEV_H
#define LOTA_AGENT_SB_DEV_H

/**
 * sb_dev_from_fd() - Superblock device of the filesystem behind a file.
 * @fd: the file; may be O_PATH.
 * @out_dev: the device.
 *
 * Return: 0, -EINVAL for a bad argument, -ENOTSUP when statx() reports no
 * mount id, -ENODEV when mountinfo does not list the mount, or another
 * negative errno.
 */
int sb_dev_from_fd(int fd, unsigned long long *out_dev);

/**
 * sb_dev_from_mountinfo() - Superblock device of a mount in a mountinfo file.
 * @mountinfo_path: the file.
 * @mnt_id: the mount.
 * @out_dev: the device.
 *
 * Return: 0, -EINVAL for a bad argument, -ENODEV when the file does not list
 * the mount, or the errno of opening the file.
 */
int sb_dev_from_mountinfo(const char *mountinfo_path, unsigned long long mnt_id,
			  unsigned long long *out_dev);

#endif
