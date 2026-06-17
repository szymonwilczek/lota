// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA - TPM NV read chunk validation test
//
// EK-certificate NV read loop copies each chunk the TPM returns into a fixed
// destination buffer.
// Spec-compliant TPM never returns more than the agent requested and never
// returns a zero-length chunk mid-read, but the agent may talk to a firmware,
// virtual, or socket-attached TPM.
// Chunk larger than requested overruns the buffer; zero-length chunk stalls
// the loop forever.
// lota_tpm_nv_chunk_check() must reject both.

#include "lota_tpm_nv.h"

#include <stdio.h>

int main(void)
{
	/* zero-length chunk makes no progress: the read loop would spin */
	if (lota_tpm_nv_chunk_check(0, 100) >= 0) {
		fprintf(stderr, "FAIL: zero-length chunk accepted\n");
		return 1;
	}

	/* chunk larger than requested would overrun the destination */
	if (lota_tpm_nv_chunk_check(200, 100) >= 0) {
		fprintf(stderr, "FAIL: oversized chunk accepted\n");
		return 1;
	}

	/* chunks at or below the requested size are safe to copy */
	if (lota_tpm_nv_chunk_check(100, 100) != 0) {
		fprintf(stderr, "FAIL: full-size chunk rejected\n");
		return 1;
	}
	if (lota_tpm_nv_chunk_check(50, 100) != 0) {
		fprintf(stderr, "FAIL: partial chunk rejected\n");
		return 1;
	}

	printf("tpm nv chunk check: ok\n");
	return 0;
}
