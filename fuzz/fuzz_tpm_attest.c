// SPDX-License-Identifier: MIT
//
// Fuzz the TPM attestation-structure unmarshalling the agent relies on.
//
// TPM2_Quote returns a signed TPMS_ATTEST blob; the agent parses that blob
// with Tss2_MU_TPMS_ATTEST_Unmarshal() (parse_signed_clockinfo() in tpm.c
// reads clockInfo.resetCount / restartCount out of it) and the verifier-facing
// token carries the raw attest bytes. The unmarshal runs over bytes the agent
// does not control end to end, so it must reject every truncated or hostile
// blob without reading out of bounds. This drives the exact MU entry point on
// raw input, then reads back the same fields the agent consumes so the deref
// is exercised on every accepted blob.
//
// tss2-mu ships precompiled without coverage instrumentation, so libFuzzer is
// blind past this harness; the value here is ASan watching the real unmarshal
// over structured input. Every run is prefixed with the TPM2_GENERATED magic
// so the parser clears its first gate and walks the tagged attestation union
// instead of bailing on byte 0.
//
// Build:
//   clang -fsanitize=fuzzer,address -g -O1 \
//     fuzz/fuzz_tpm_attest.c \
//     -o build/fuzz-tpm-attest -ltss2-mu
//
// Run:
//   ./build/fuzz-tpm-attest -max_len=4096
//
// Copyright (C) 2026 Szymon Wilczek

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_common.h>
#include <tss2/tss2_tpm2_types.h>

/* TPM2_GENERATED magic the structure must lead with ("TCG", big-endian) */
static const uint8_t kAttestMagic[4] = { 0xff, 0x54, 0x43, 0x47 };

#define ATTEST_FUZZ_MAX 4096

int LLVMFuzzerInitialize(int *argc, char ***argv);

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	(void)argc;
	(void)argv;
	/*
	 * MU library logs every rejected blob:
	 * silence it through its own knob instead of redirecting stderr,
	 * which would also swallow libFuzzer's progress output
	 */
	setenv("TSS2_LOG", "all+NONE", 1);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	uint8_t buf[sizeof(kAttestMagic) + ATTEST_FUZZ_MAX];
	TPMS_ATTEST attest;
	size_t offset = 0;
	volatile uint32_t sink;
	TSS2_RC rc;

	if (size > ATTEST_FUZZ_MAX)
		size = ATTEST_FUZZ_MAX;

	memcpy(buf, kAttestMagic, sizeof(kAttestMagic));
	memcpy(buf + sizeof(kAttestMagic), data, size);

	memset(&attest, 0, sizeof(attest));

	rc = Tss2_MU_TPMS_ATTEST_Unmarshal(buf, sizeof(kAttestMagic) + size,
					   &offset, &attest);
	if (rc != TSS2_RC_SUCCESS)
		return 0;

	/* touch the fields parse_signed_clockinfo() pulls from the blob */
	sink = attest.clockInfo.resetCount;
	sink = attest.clockInfo.restartCount;
	(void)sink;

	/*
	 * signed structure carries a tagged union (attestationData);
	 * walk the quote variant the agent's quote path produces so
	 * the magic/type dependent members are dereferenced too
	 */
	if (attest.type == TPM2_ST_ATTEST_QUOTE) {
		volatile uint16_t count = attest.attested.quote.pcrSelect.count;
		volatile uint16_t digest_size =
			attest.attested.quote.pcrDigest.size;
		(void)count;
		(void)digest_size;
	}

	return 0;
}
