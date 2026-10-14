/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * A signed LOTA token, forged for tests.
 *
 * Two suites need one: the server SDK tests, which verify tokens directly,
 * and the anti-cheat tests, which wrap a token in a heartbeat and verify that.
 * A token that reaches the verdict has to carry a real RSA signature over a real
 * TPMS_ATTEST whose extraData binds the nonce, so this is not something either
 * suite can fake in a line -- and two copies of it would drift.
 */

#ifndef LOTA_TESTS_TOKEN_FORGE_H
#define LOTA_TESTS_TOKEN_FORGE_H

#include <openssl/types.h>
#include <stddef.h>
#include <stdint.h>

/* An RSA key to sign with, and its SubjectPublicKeyInfo DER for the verifier */
EVP_PKEY *forge_rsa_key(void);
uint8_t *forge_pubkey_der(EVP_PKEY *pkey, size_t *out_len);

/*
 * A complete token: TPMS_ATTEST with extraData over the quote nonce, signed
 * with @key.
 * @hash_alg is the TPM algorithm id the token declares and @md the digest
 * that matches it.
 */
int forge_token(EVP_PKEY *key, uint16_t hash_alg, const EVP_MD *md,
		uint64_t valid_until, uint32_t flags, const uint8_t nonce[32],
		uint8_t *tokbuf, size_t tokbuf_size, size_t *tok_written);

/* SHA-256, the shape a stock agent issues */
int forge_token_sha256(EVP_PKEY *key, uint64_t valid_until, uint32_t flags,
		       const uint8_t nonce[32], uint8_t *tokbuf,
		       size_t tokbuf_size, size_t *tok_written);

/* Runtime-protect v2: the same token carrying a per-PID image digest */
int forge_token_v2(EVP_PKEY *key, uint64_t valid_until, uint32_t flags,
		   const uint8_t nonce[32], uint8_t *tokbuf, size_t tokbuf_size,
		   size_t *tok_written);

/*
 * The pieces below build a token by hand, for the tests that need one shaped
 * wrongly on purpose: a signature over the wrong bytes, two PCR banks where
 * the verifier expects one.
 */
uint8_t *forge_tpms_attest_mixed_banks(const uint8_t *extra_data,
				       size_t extra_len, uint32_t sha1_mask,
				       uint32_t sha256_mask,
				       const uint8_t *pcr_digest,
				       size_t pcr_digest_len, size_t *out_len);

int forge_quote_nonce(uint64_t valid_until, uint32_t flags, uint32_t pcr_mask,
		      const uint8_t nonce[32], const uint8_t policy_digest[32],
		      const uint8_t runtime_protect_digest[32],
		      uint64_t runtime_protect_epoch, uint8_t out[32]);

uint8_t *forge_sign(EVP_PKEY *pkey, const EVP_MD *md, const uint8_t *data,
		    size_t data_len, size_t *sig_len);

#endif /* LOTA_TESTS_TOKEN_FORGE_H */
