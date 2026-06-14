// SPDX-License-Identifier: MIT
//
// Fuzz the sealed-envelope wire format and its AES-256-GCM core.
//
// Two attacker-controlled surfaces live here.
//
// lota_envelope_parse_header() validates an on-disk envelope blob
// (magic, version, reserved bytes, the length fields, and that the declared
// bodies fit exactly); it must reject every malformed header without reading
// out of bounds.
//
// lota_envelope_aead_open() is the OpenSSL AES-256-GCM open that
// tpm_unseal_secret_envelope() drives over the parsed ciphertext; it must never
// misbehave on a tampered blob and must faithfully round-trip whatever the
// matching seal produced.
//
// Build:
//   clang -fsanitize=fuzzer,address -g -O1 -Iinclude \
//     fuzz/fuzz_seal_envelope.c src/agent/seal_envelope.c \
//     -o build/fuzz-seal-envelope -lcrypto
//
// Run:
//   ./build/fuzz-seal-envelope -max_len=131072
//
// Copyright (C) 2026 Szymon Wilczek

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../include/lota_envelope.h"
#include "lota_seal.h"

/*
 * Mirror tpm_unseal_secret_envelope()'s open path: rebuild the AAD exactly
 * as the seal authenticated it (header with the tag field zeroed, followed
 * by the sealed-KEK blob), then AEAD-open the embedded ciphertext under a
 * fixed KEK. The tag will not verify for a fuzzer-supplied blob, so this is
 * a no-crash check on the OpenSSL decrypt path, not a correctness one.
 */
static void open_parsed(const uint8_t *blob, const struct lota_envelope_meta *m,
			size_t body_off)
{
	static const uint8_t kek[LOTA_ENVELOPE_KEK_SIZE] = { 0 };
	uint8_t aad[LOTA_ENVELOPE_HEADER_SIZE + LOTA_SEAL_MAX_BLOB];
	const uint8_t *ct = blob + body_off + m->kek_blob_len;
	size_t aad_len = body_off + m->kek_blob_len;
	uint8_t *pt_out;

	pt_out = malloc(m->payload_len);
	if (!pt_out)
		return;

	memcpy(aad, blob, aad_len);
	memset(aad + 28, 0, LOTA_ENVELOPE_TAG_SIZE);

	lota_envelope_aead_open(kek, m->nonce, aad, aad_len, ct, m->payload_len,
				m->tag, pt_out);

	free(pt_out);
}

/*
 * Seal a payload carved from the fuzz input and immediately open it under the
 * same KEK/nonce/AAD. This exercises the GCM path on every run (random input
 * rarely yields a valid envelope header) and asserts the round-trip invariant:
 * a faithful open of our own seal must succeed and recover the plaintext.
 */
static void roundtrip(const uint8_t *data, size_t size)
{
	static const uint8_t kek[LOTA_ENVELOPE_KEK_SIZE] = { 0 };
	uint8_t nonce[LOTA_ENVELOPE_NONCE_SIZE];
	uint8_t tag[LOTA_ENVELOPE_TAG_SIZE];
	const uint8_t *aad;
	size_t aad_len;
	const uint8_t *pt;
	size_t pt_len;
	uint8_t *ct;
	uint8_t *rt;

	if (size < LOTA_ENVELOPE_NONCE_SIZE + 1)
		return;

	memcpy(nonce, data, LOTA_ENVELOPE_NONCE_SIZE);
	data += LOTA_ENVELOPE_NONCE_SIZE;
	size -= LOTA_ENVELOPE_NONCE_SIZE;

	/* split the remainder into AAD and plaintext */
	aad_len = size / 2;
	aad = data;
	pt = data + aad_len;
	pt_len = size - aad_len;
	if (pt_len == 0 || pt_len > LOTA_ENVELOPE_MAX_PAYLOAD)
		return;

	ct = malloc(pt_len);
	rt = malloc(pt_len);
	if (!ct || !rt)
		goto out;

	if (lota_envelope_aead_seal(kek, nonce, aad, aad_len, pt, pt_len, ct,
				    tag) != 0)
		goto out;

	if (lota_envelope_aead_open(kek, nonce, aad, aad_len, ct, pt_len, tag,
				    rt) != 0)
		abort(); /* a faithful open of our own seal must verify */

	if (memcmp(pt, rt, pt_len) != 0)
		abort(); /* round-trip must recover the exact plaintext */

	/* single-bit flip in the tag must fail the integrity check */
	tag[0] ^= 1;
	if (lota_envelope_aead_open(kek, nonce, aad, aad_len, ct, pt_len, tag,
				    rt) == 0)
		abort();

out:
	free(ct);
	free(rt);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct lota_envelope_meta meta;
	size_t body_off = 0;

	if (size > LOTA_ENVELOPE_MAX_BLOB)
		return 0;

	if (lota_envelope_parse_header(data, size, &meta, &body_off) == 0)
		open_parsed(data, &meta, body_off);

	roundtrip(data, size);
	return 0;
}
