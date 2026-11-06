/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * LOTA block-demo: the shared object the victim dlopen()s.
 *
 * The constructor only prints, so a load that gets through is harmless and
 * visible. In enforce mode with strict_mmap the mmap_file hook refuses a
 * protected task's executable mapping of an object outside the trust set,
 * before any constructor runs.
 */

#include <stdio.h>
#include <unistd.h>

__attribute__((constructor)) static void evil_init(void)
{
	fprintf(stderr, "evil.so: loaded into pid %d\n", (int)getpid());
}
