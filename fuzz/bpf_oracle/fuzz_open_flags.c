/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Mirror BPF decision-logic fuzzer: open-for-write classification.
 *
 * 	is_write_open_flags (src/bpf/lota_lsm.bpf.c) decides whether
 * 	a file_open LSM hook is a write, which gates the write-protection
 * 	policy.
 * 	Mirror carries the helper verbatim with the BPF program's hand-defined
 * 	O_* octals; the reference recomputes the verdict from the kernel ABI flags.
 * 	Divergence is either a logic bug in the helper or a wrong O_* constant.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "lota_lsm_logic.h"
#include "reference.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	int flags = 0;

	if (size >= sizeof(flags))
		memcpy(&flags, data, sizeof(flags));

	if (mirror_is_write_open_flags(flags) != reference_is_write_open(flags))
		abort();

	return 0;
}
