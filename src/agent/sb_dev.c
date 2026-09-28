/* SPDX-License-Identifier: MIT */
/*
 * LOTA - superblock device resolution
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#include "../../include/lota_devt.h"
#include "sb_dev.h"

/* mountinfo lines carry two paths, so one path's worth of slack is not enough */
#define SB_DEV_LINE_MAX 8192

/*
 * A mountinfo record starts with "<mount id> <parent id> <major>:<minor> ",
 * and the fields after it are the only ones that can be long.
 * A line that does not fit is still read to its end, so the remainder is never
 * taken for a record of its own.
 */
static int parse_mountinfo_line(const char *line, unsigned long long *out_id,
				unsigned long long *out_dev)
{
	unsigned long long id = 0;
	unsigned int parent = 0;
	unsigned int major = 0;
	unsigned int minor = 0;

	if (sscanf(line, "%llu %u %u:%u", &id, &parent, &major, &minor) != 4)
		return -EINVAL;

	*out_id = id;
	*out_dev = LOTA_DEVT_MKDEV(major, minor);
	return 0;
}

int sb_dev_from_mountinfo(const char *mountinfo_path, unsigned long long mnt_id,
			  unsigned long long *out_dev)
{
	char line[SB_DEV_LINE_MAX];
	FILE *f;
	int found = -ENODEV;

	if (!mountinfo_path || !out_dev)
		return -EINVAL;

	f = fopen(mountinfo_path, "re");
	if (!f)
		return -errno;

	while (fgets(line, sizeof(line), f)) {
		unsigned long long id = 0;
		unsigned long long dev = 0;
		int truncated = strchr(line, '\n') == NULL;

		if (truncated) {
			int c;

			while ((c = fgetc(f)) != EOF && c != '\n')
				;
		}

		if (parse_mountinfo_line(line, &id, &dev) < 0)
			continue;

		if (id != mnt_id)
			continue;

		*out_dev = dev;
		found = 0;
		break;
	}

	fclose(f);
	return found;
}

int sb_dev_from_fd(int fd, unsigned long long *out_dev)
{
	struct statx stx = { 0 };

	if (fd < 0 || !out_dev)
		return -EINVAL;

	/*
	 * STATX_MNT_ID, not STATX_MNT_ID_UNIQUE: mountinfo lists the old 32-bit
	 * mount id, and asking for the unique one gets a number that appears
	 * nowhere in it.
	 */
	if (statx(fd, "", AT_EMPTY_PATH, STATX_MNT_ID, &stx) != 0)
		return -errno;

	if (!(stx.stx_mask & STATX_MNT_ID))
		return -ENOTSUP;

	return sb_dev_from_mountinfo("/proc/self/mountinfo",
				     (unsigned long long)stx.stx_mnt_id,
				     out_dev);
}
