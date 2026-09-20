/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Whether the hook's token directory is readable from outside its container.
 * Header-only and pure: the caller reads /proc/self/mountinfo and the
 * environment, so a test needs no container.
 */

#ifndef LOTA_SDK_HOOK_CONTAINER_H
#define LOTA_SDK_HOOK_CONTAINER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

/*
 * Is @dir a mount point (field 5) in /proc/self/mountinfo @mountinfo?
 * A bind from the host is one; a container-private directory is not.
 * \040-escaped whitespace is not unescaped, so such a path reads as unshared.
 */
static inline bool hook_dir_is_mount(const char *mountinfo, const char *dir)
{
	const char *line;
	size_t dir_len;

	if (!mountinfo || !dir || !dir[0])
		return false;

	dir_len = strlen(dir);

	for (line = mountinfo; line && *line;) {
		const char *p = line;
		const char *end = strchr(line, '\n');
		int field;

		/* skip to the fifth field: the mount point */
		for (field = 1; field < 5 && p; field++) {
			p = strchr(p, ' ');
			if (p)
				p++;
		}

		if (p && (!end || p < end) && strncmp(p, dir, dir_len) == 0 &&
		    (p[dir_len] == ' ' || p[dir_len] == '\0' ||
		     p[dir_len] == '\n'))
			return true;

		line = end ? end + 1 : NULL;
	}

	return false;
}

/*
 * @container_env is $container, set by any container manager for what runs
 * inside it. PRESSURE_VESSEL_* does not count: it is set on the host too.
 */
static inline bool hook_in_container(const char *container_env)
{
	return container_env && container_env[0];
}

/*
 * Names the directory to share and the wrapper that shares it.
 * Writes a NUL-terminated sentence without a trailing newline.
 */
static inline void hook_container_private_message(const char *dir, char *out,
						  size_t cap)
{
	if (!out || cap == 0)
		return;

	snprintf(out, cap,
		 "%s is inside this container, so the host cannot read the "
		 "status or the token written there; launch the title through "
		 "lota-proton-hook, which shares it",
		 dir && dir[0] ? dir : "the token directory");
}

#endif /* LOTA_SDK_HOOK_CONTAINER_H */
