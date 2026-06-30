/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * MIRROR of decision logic from src/bpf/lota_lsm.bpf.c.
 *
 * The originals are `static __always_inline` and read their inputs from kernel
 * structs via BPF_CORE_READ, so they cannot be compiled or linked in user space.
 *
 * These mirrors carry the logic VERBATIM with the kernel reads lifted out:
 * each takes the scalar value the original pulled from the struct, so the fuzzers
 * can drive the real verdict logic in user space.
 *
 * The macro values match the BPF program's own definitions.
 *
 * This is a copy, so it can drift from production:
 * MIRROR.md records the source lines and a check guards against silent divergence.
 *
 * Eventual production change ("lota_devt.h" both sides include) removes the copy.
 */

#ifndef LOTA_FUZZ_LSM_LOGIC_H
#define LOTA_FUZZ_LSM_LOGIC_H

#include "lota_devt.h"

/* --- src/bpf/lota_lsm.bpf.c:83-94 --- */
#define LOTA_O_ACCMODE 00000003
#define LOTA_O_WRONLY 00000001
#define LOTA_O_RDWR 00000002
#define LOTA_O_TRUNC 00001000

/* --- src/bpf/lota_lsm.bpf.c:96-101 --- */
#define LOTA_S_IFMT 00170000
#define LOTA_S_IFCHR 0020000

/*
 * MIRROR of is_write_open_flags (src/bpf/lota_lsm.bpf.c:737)
 * body verbatim
 */
static inline int mirror_is_write_open_flags(int flags)
{
	int acc_mode = flags & LOTA_O_ACCMODE;

	if (acc_mode == LOTA_O_WRONLY || acc_mode == LOTA_O_RDWR)
		return 1;

	if (flags & LOTA_O_TRUNC)
		return 1;

	return 0;
}

/*
 * MIRROR of is_kernel_mem_device (src/bpf/lota_lsm.bpf.c:760), with the
 * BPF_CORE_READ(file -> inode -> {i_mode,i_rdev}) reads lifted to the caller.
 * Post-read body is verbatim, including the lota_dev_major/minor wrappers
 * over the real LOTA_DEVT_* macros.
 */
static inline int mirror_is_kernel_mem_device(unsigned int i_mode,
					      unsigned long long i_rdev)
{
	unsigned int major;
	unsigned int minor;

	if ((i_mode & LOTA_S_IFMT) != LOTA_S_IFCHR)
		return 0;

	major = LOTA_DEVT_MAJOR(i_rdev);
	minor = LOTA_DEVT_MINOR(i_rdev);

	/* char major 1: mem=1, kmem=2, port=4 */
	if (major != 1)
		return 0;

	return minor == 1 || minor == 2 || minor == 4;
}

/* --- src/bpf/lota_lsm.bpf.c:64-65 --- */
#define LOTA_BINPRM_FLAGS_PATH_INACCESSIBLE (1U << 2)

/*
 * MIRROR of is_inaccessible_exec_path (src/bpf/lota_lsm.bpf.c:801),
 * with the BPF_CORE_READ(bprm -> {interp_flags,fdpath}) reads lifted
 * to the caller.
 * fdpath_present is the truth of the original's non-NULL fdpath pointer.
 */
static inline int mirror_is_inaccessible_exec(unsigned int interp_flags,
					      int fdpath_present)
{
	if (interp_flags & LOTA_BINPRM_FLAGS_PATH_INACCESSIBLE)
		return 1;

	return fdpath_present ? 1 : 0;
}

/*
 * MIRROR of is_shebang_binprm (src/bpf/lota_lsm.bpf.c:788),
 * with the BPF_CORE_READ(bprm -> buf[0..1]) reads lifted to the caller.
 */
static inline int mirror_is_shebang(char c0, char c1)
{
	return c0 == '#' && c1 == '!';
}

#endif /* LOTA_FUZZ_LSM_LOGIC_H */
