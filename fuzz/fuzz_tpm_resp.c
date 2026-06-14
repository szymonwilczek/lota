// SPDX-License-Identifier: MIT
//
// Fuzz the TPM2B structure unmarshalling the agent runs on enrollment
// and TPM responses.
//
// Beyond the signed TPMS_ATTEST (covered by fuzz_tpm_attest), the agent
// unmarshals several TPM2B blobs with tss2-mu: the credential-activation pair
// the CA returns over the enrollment socket (TPM2B_ID_OBJECT and
// TPM2B_ENCRYPTED_SECRET), the AIK/EK public area (TPM2B_PUBLIC) and the sealed
// private part (TPM2B_PRIVATE).
//
// The id-object and encrypted-secret in particular are attacker-reachable --
// they arrive from the network during enrollment -- so the unmarshal must
// reject every malformed blob without reading out of bounds. This drives each
// unmarshal on raw input under ASan.
//
// tss2-mu ships without coverage instrumentation, so libFuzzer is blind past
// this harness; the value is ASan over the real unmarshal on whatever bytes
// the fuzzer feeds.
//
// TPM2B structures are self-describing (a 2-byte size prefix, no magic),
// so no fixed prefix is needed to reach the body.
//
// Build:
//   clang -fsanitize=fuzzer,address -g -O1 \
//     fuzz/fuzz_tpm_resp.c \
//     -o build/fuzz-tpm-resp -ltss2-mu
//
// Run:
//   ./build/fuzz-tpm-resp -max_len=4096
//
// Copyright (C) 2026 Szymon Wilczek

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_tpm2_types.h>

int LLVMFuzzerInitialize(int *argc, char ***argv);

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;
	/* silence the MU library's per-rejection logging without swallowing
	 * libFuzzer's own stderr output */
	setenv("TSS2_LOG", "all+NONE", 1);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	size_t off;

	{
		TPM2B_PUBLIC v;
		off = 0;
		memset(&v, 0, sizeof(v));
		Tss2_MU_TPM2B_PUBLIC_Unmarshal(data, size, &off, &v);
	}
	{
		TPM2B_PRIVATE v;
		off = 0;
		memset(&v, 0, sizeof(v));
		Tss2_MU_TPM2B_PRIVATE_Unmarshal(data, size, &off, &v);
	}
	{
		TPM2B_ID_OBJECT v;
		off = 0;
		memset(&v, 0, sizeof(v));
		Tss2_MU_TPM2B_ID_OBJECT_Unmarshal(data, size, &off, &v);
	}
	{
		TPM2B_ENCRYPTED_SECRET v;
		off = 0;
		memset(&v, 0, sizeof(v));
		Tss2_MU_TPM2B_ENCRYPTED_SECRET_Unmarshal(data, size, &off, &v);
	}
	return 0;
}
