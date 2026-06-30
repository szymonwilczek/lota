/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Mirror BPF decision-logic fuzzer: kernel-memory device match.
 *
 * 	is_kernel_mem_device (src/bpf/lota_lsm.bpf.c) flags /dev/mem,
 * 	/dev/kmem and /dev/port so the LSM can block writable opens of
 * 	raw kernel memory.
 * 	Mirror carries the post-read logic verbatim (it reuses the real
 * 	LOTA_DEVT_* macros); the reference recomputes the verdict with
 * 	explicit dev_t split and the kernel ABI mode bits.
 * 	Fuzzer drives the inode mode and rdev the original reads from
 * 	the struct.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "lota_lsm_logic.h"
#include "reference.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint32_t i_mode = 0;
	uint32_t i_rdev = 0;

	if (size >= 4)
		memcpy(&i_mode, data, 4);
	if (size >= 8)
		memcpy(&i_rdev, data + 4, 4);

	if (mirror_is_kernel_mem_device(i_mode, i_rdev) !=
	    reference_is_kernel_mem_device(i_mode, i_rdev))
		abort();

	return 0;
}
