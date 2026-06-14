// SPDX-License-Identifier: MIT
//
// Fuzz the server SDK's attestation-token verifier.
//
// lota_server_verify_token() is the entry point a game server calls on the
// token an (untrusted) client hands it: it parses the wire header, walks the
// variable-length protected-PID / image-digest / attest / signature sections,
// verifies the RSA signature over the TPMS_ATTEST blob, and parses that blob
// for the nonce and PCR digest. Every one of those steps runs on bytes the
// server does not control, so none may read out of bounds or otherwise
// misbehave on a truncated or hostile token. This is the C counterpart of the
// Go FuzzVerifyToken target.
//
// Real RSA key is generated once so the signature path is exercised with
// a well-formed public key (the signature will not verify for fuzzer bytes,
// but the parse and the OpenSSL verify call still run); the token itself is
// the fuzz input.
//
// Build:
//   clang -fsanitize=fuzzer,address -g -O1 -Iinclude \
//     fuzz/fuzz_server_sdk.c src/sdk/lota_server.c \
//     -o build/fuzz-server-sdk -lcrypto
//
// Run:
//   ./build/fuzz-server-sdk -max_len=8192
//
// Copyright (C) 2026 Szymon Wilczek

#include <stdint.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/types.h>

#include "../include/lota_server.h"

static uint8_t *g_aik_der;
static int g_aik_len;

int LLVMFuzzerInitialize(int *argc, char ***argv);

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *pctx;

	(void)argc;
	(void)argv;

	/*
	 * one RSA-2048 key, exported as SubjectPublicKeyInfo DER
	 * -- the form lota_server_verify_token() expects for
	 * the AIK public key
	 */
	pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	if (!pctx || EVP_PKEY_keygen_init(pctx) <= 0 ||
	    EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) <= 0 ||
	    EVP_PKEY_keygen(pctx, &pkey) <= 0)
		abort();

	g_aik_len = i2d_PUBKEY(pkey, &g_aik_der);
	if (g_aik_len <= 0)
		abort();

	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(pctx);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct lota_server_claims claims;
	uint8_t nonce[32] = { 0 };

	/* bound the input the way a real caller would (token buff is small) */
	if (size > 16 * 1024)
		return 0;

	lota_server_verify_token(data, size, g_aik_der, (size_t)g_aik_len,
				 nonce, &claims);
	return 0;
}
