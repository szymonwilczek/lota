/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Independent reference verdicts for the LSM decision logic.
 *
 * These reimplement the INTENDED policy from the design, deliberately NOT copied
 * from the mirrored helper bodies, and sourced from the system ABI headers rather
 * than the BPF program's hand-defined constants.
 *
 * fuzzer that diffs the mirror against these surfaces both a logic drift in the
 * helper and a wrong hand-defined constant.
 */

#ifndef LOTA_FUZZ_REFERENCE_H
#define LOTA_FUZZ_REFERENCE_H

#include <fcntl.h> /* O_ACCMODE, O_WRONLY, O_RDWR, O_TRUNC */
#include <sys/stat.h> /* S_IFMT, S_IFCHR */

/*
 * File is opened for write when the access mode is write-capable or the open truncates.
 * Uses the real kernel ABI flag values.
 */
static inline int reference_is_write_open(int flags)
{
	int acc = flags & O_ACCMODE;

	return acc == O_WRONLY || acc == O_RDWR || (flags & O_TRUNC) != 0;
}

/*
 * Kernel memory devices are character nodes on major 1:
 * /dev/mem (1), /dev/kmem (2) and /dev/port (4)
 * Decodes the kernel-layout dev_t with an explicit 20-bit split.
 */
static inline int reference_is_kernel_mem_device(unsigned int i_mode,
						 unsigned long long i_rdev)
{
	unsigned int major = (unsigned int)(i_rdev >> 20);
	unsigned int minor = (unsigned int)(i_rdev & ((1ULL << 20) - 1));

	if ((i_mode & S_IFMT) != S_IFCHR)
		return 0;

	return major == 1 && (minor == 1 || minor == 2 || minor == 4);
}

#endif /* LOTA_FUZZ_REFERENCE_H */
