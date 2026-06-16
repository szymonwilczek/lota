/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * LOTA block-demo: dummy "evil" shared object.
 *
 * Loaded via dlopen() from the demo victim. The constructor only
 * writes to stderr so the demo cannot be mistaken for a real
 * payload, and so the operator can tell whether the loader was
 * permitted to execute the .so or not. The BPF LSM mmap_file
 * gate runs *before* the constructor, so on a successful block
 * the message below never appears.
 */

#include <stdio.h>
#include <unistd.h>

__attribute__((constructor)) static void evil_init(void)
{
	fprintf(stderr, "evil.so: loaded into pid %d\n", (int)getpid());
}
