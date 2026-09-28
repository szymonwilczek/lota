// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
//
// Fuzz the agent-side decoders for the CA's enrollment replies,
// and the walk over the certificate chain a TPM stores in NV.
//
// The CA sends the challenge reply (session id, credential blob, encrypted
// secret) and the result reply (AIK certificate, device id) over the wire;
// the agent decodes those untrusted bytes. The chain blob is untrusted from
// the other direction -- it is vendor data the host does not control, read
// straight off the chip and walked before anything has validated it.
//
// Neither decoder may read out of bounds (ASan) nor, on a reported success,
// hand back a length that overruns its destination buffer or a string that
// is not NUL-terminated -- length-field bug that does not happen to trip
// ASan would otherwise let a later consumer over-read. The chain walk must
// return only certificates that lie inside the blob it was given, and only
// ones the enrollment frame can carry.

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

	struct enroll_cert_ref chain[LOTA_ENROLL_MAX_EK_CHAIN_CERTS];
	size_t chain_len = 0;

	if (size > 0 && enroll_split_cert_chain(data, size, chain,
						LOTA_ENROLL_MAX_EK_CHAIN_CERTS,
						&chain_len) == 0) {
		size_t total = 0;

		FZ_CHECK(chain_len <= LOTA_ENROLL_MAX_EK_CHAIN_CERTS);
		for (size_t i = 0; i < chain_len; i++) {
			/* every element lies wholly inside the blob */
			FZ_CHECK(chain[i].der >= data);
			FZ_CHECK(chain[i].len > 0);
			FZ_CHECK((size_t)(chain[i].der - data) <= size);
			FZ_CHECK(chain[i].len <=
				 size - (size_t)(chain[i].der - data));
			/* and is one the enrollment frame can carry */
			FZ_CHECK(chain[i].len <= LOTA_ENROLL_MAX_EK_CERT);
			total += chain[i].len;
		}
		FZ_CHECK(total <= LOTA_ENROLL_MAX_EK_CHAIN_BYTES);

		/*
		 * whatever the walk produced has to be encodable:
		 * the split is the only thing standing between vendor NV
		 * and the wire
		 */
		if (chain_len > 0) {
			static uint8_t frame[LOTA_ENROLL_MAX_FRAME];
			const uint8_t ek[] = { 0x30, 0x00 };
			const uint8_t aik[] = { 0x00 };

			FZ_CHECK(enroll_encode_begin(frame, sizeof(frame), ek,
						     sizeof(ek), aik,
						     sizeof(aik), NULL, 0,
						     chain, chain_len) > 0);
		}
	}

	return 0;
}
