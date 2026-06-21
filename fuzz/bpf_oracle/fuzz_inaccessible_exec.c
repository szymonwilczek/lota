/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Mirror BPF decision-logic fuzzer: inaccessible-exec detection.
 *
 * 	is_inaccessible_exec_path (src/bpf/lota_lsm.bpf.c) flags an exec whose
 * 	binary is reached through an inaccessible or anonymous /dev/fd path,
 * 	which the bprm_check policy treats specially.
 * 	Mirror carries the post-read logic verbatim with the BPF program's
 * 	PATH_INACCESSIBLE bit; the reference restates the bit from the kernel
 * 	uapi value.
 * 	Divergence is logic bug or wrong flag bit.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "lota_lsm_logic.h"
#include "reference.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint32_t interp_flags = 0;
	uint8_t fdpath_present = 0;

	if (size >= 4)
		memcpy(&interp_flags, data, 4);
	if (size >= 5)
		fdpath_present = data[4] & 1u;

	if (mirror_is_inaccessible_exec(interp_flags, fdpath_present) !=
	    reference_is_inaccessible_exec(interp_flags, fdpath_present))
		abort();

	return 0;
}
