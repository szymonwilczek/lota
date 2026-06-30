// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
//
// Fuzz the agent-side decoders for the CA's enrollment replies.
//
// The CA sends the challenge reply (session id, credential blob, encrypted
// secret) and the result reply (AIK certificate, device id) over the wire;
// the agent decodes those untrusted bytes.
//
// Neither decoder may read out of bounds (ASan) nor, on a reported success,
// hand back a length that overruns its destination buffer or a string that
// is not NUL-terminated -- length-field bug that does not happen to trip
// ASan would otherwise let a later consumer over-read.

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../src/agent/enroll.c"
#include "../src/agent/enroll.h"

#define FZ_CHECK(cond)           \
	do {                     \
		if (!(cond))     \
			abort(); \
	} while (0)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct enroll_challenge ch;
	struct enroll_result res;

	if (enroll_decode_challenge(data, size, &ch) == 0) {
		FZ_CHECK(ch.cred_blob_len <= LOTA_ENROLL_MAX_CRED_BLOB);
		FZ_CHECK(ch.enc_secret_len <= LOTA_ENROLL_MAX_ENC_SECRET);
		/* session_id is a fixed buffer with one extra NUL slot;
		 * decoder must always terminate it within bounds */
		FZ_CHECK(memchr(ch.session_id, '\0', sizeof(ch.session_id)) !=
			 NULL);
	}

	if (enroll_decode_result(data, size, &res) == 0) {
		FZ_CHECK(res.aik_cert_len <= LOTA_ENROLL_MAX_AIK_CERT);
		FZ_CHECK(memchr(res.device_id, '\0', sizeof(res.device_id)) !=
			 NULL);
	}

	return 0;
}
