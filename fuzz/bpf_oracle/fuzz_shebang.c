/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Mirror BPF decision-logic fuzzer: shebang detection.
 *
 * 	is_shebang_binprm (src/bpf/lota_lsm.bpf.c) recognises "#!"
 * 	interpreter script from the first two bytes of the binary.
 * 	Mirror uses the helper's char literals; the reference
 * 	restates the code points as 0x23 0x21, so non-ASCII
 * 	char-encoding assumption would diverge.
 */

#include <stdint.h>
#include <stdlib.h>

#include "lota_lsm_logic.h"
#include "reference.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	char c0 = size >= 1 ? (char)data[0] : 0;
	char c1 = size >= 2 ? (char)data[1] : 0;

	if (mirror_is_shebang(c0, c1) != reference_is_shebang(c0, c1))
		abort();

	return 0;
}
