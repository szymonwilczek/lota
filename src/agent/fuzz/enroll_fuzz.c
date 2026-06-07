// SPDX-License-Identifier: MIT
//
// Fuzz the agent-side decoders for the CA's enrollment replies. The CA
// sends the challenge reply (session id, credential blob, encrypted secret)
// and the result reply (AIK certificate, device id) over the wire; the
// agent decodes those untrusted bytes. Neither decoder may read out of
// bounds or otherwise misbehave on a hostile or malformed reply.

#include <stddef.h>
#include <stdint.h>

#include "../enroll.c"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct enroll_challenge ch;
	struct enroll_result res;

	enroll_decode_challenge(data, size, &ch);
	enroll_decode_result(data, size, &res);

	return 0;
}
