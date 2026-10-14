/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * A signed LOTA token, forged for tests.
 * See token_forge.h for why it is shared rather than written twice.
 */

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/types.h>
#include <stddef.h>
#include <stdint.h>

#include "lota_gaming.h"
#include "lota_runtime_protect_digest.h"
#include "lota_token.h"
#include "lota_token_quote_nonce.h"
#include "token_forge.h"

#define TPM_GENERATED_VALUE 0xff544347
#define TPM_ST_ATTEST_QUOTE 0x8018

static size_t tpm_hash_digest_len(uint16_t hash_alg)
{
	switch (hash_alg) {
	case 0x000B:
		return 32;
	case 0x000C:
		return 48;
	case 0x000D:
		return 64;
	default:
		return 0;
	}
}

static void write_be16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v >> 8);
	p[1] = (uint8_t)(v);
}

static void write_be32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v >> 24);
	p[1] = (uint8_t)(v >> 16);
	p[2] = (uint8_t)(v >> 8);
	p[3] = (uint8_t)(v);
}

/*
 * Build a fake TPMS_ATTEST blob with given extraData (nonce) and pcr digest.
 * Returns allocated buffer, caller must free.
 */
static uint8_t *build_fake_tpms_attest(const uint8_t *extra_data,
				       size_t extra_len, uint32_t pcr_mask,
				       const uint8_t *pcr_digest,
				       size_t pcr_digest_len, size_t *out_len)
{
	/* generous buffer */
	uint8_t *buf = calloc(1, 512);
	size_t off = 0;

	/* magic */
	write_be32(buf + off, TPM_GENERATED_VALUE);
	off += 4;

	/* type = QUOTE */
	write_be16(buf + off, TPM_ST_ATTEST_QUOTE);
	off += 2;

	/* qualifiedSigner: TPM2B_NAME (size=4, dummy data) */
	write_be16(buf + off, 4);
	off += 2;
	buf[off++] = 0x00;
	buf[off++] = 0x0B;
	buf[off++] = 0xAA;
	buf[off++] = 0xBB;

	/* extraData: TPM2B_DATA */
	write_be16(buf + off, (uint16_t)extra_len);
	off += 2;
	memcpy(buf + off, extra_data, extra_len);
	off += extra_len;

	/* clockInfo: 17 bytes zeros */
	off += 17;

	/* firmwareVersion: 8 bytes */
	off += 8;

	/* TPMS_QUOTE_INFO */
	/* TPML_PCR_SELECTION: count=1 */
	write_be32(buf + off, 1);
	off += 4;
	/* TPMS_PCR_SELECTION: hash=SHA-256(0x000B), sizeOfSelect=3 */
	write_be16(buf + off, 0x000B);
	off += 2;
	buf[off++] = 3;
	buf[off++] = (uint8_t)(pcr_mask & 0xFF);
	buf[off++] = (uint8_t)((pcr_mask >> 8) & 0xFF);
	buf[off++] = (uint8_t)((pcr_mask >> 16) & 0xFF);

	/* pcrDigest: TPM2B_DIGEST */
	write_be16(buf + off, (uint16_t)pcr_digest_len);
	off += 2;
	if (pcr_digest_len > 0) {
		memcpy(buf + off, pcr_digest, pcr_digest_len);
		off += pcr_digest_len;
	}

	*out_len = off;
	return buf;
}

uint8_t *forge_tpms_attest_mixed_banks(const uint8_t *extra_data,
				       size_t extra_len, uint32_t sha1_mask,
				       uint32_t sha256_mask,
				       const uint8_t *pcr_digest,
				       size_t pcr_digest_len, size_t *out_len)
{
	uint8_t *buf = calloc(1, 512);
	size_t off = 0;

	write_be32(buf + off, TPM_GENERATED_VALUE);
	off += 4;
	write_be16(buf + off, TPM_ST_ATTEST_QUOTE);
	off += 2;

	write_be16(buf + off, 4);
	off += 2;
	buf[off++] = 0x00;
	buf[off++] = 0x0B;
	buf[off++] = 0xAA;
	buf[off++] = 0xBB;

	write_be16(buf + off, (uint16_t)extra_len);
	off += 2;
	memcpy(buf + off, extra_data, extra_len);
	off += extra_len;

	off += 17; /* clockInfo */
	off += 8; /* firmwareVersion */

	write_be32(buf + off, 2); /* two PCR selections */
	off += 4;

	/* selection 0: SHA-1 bank */
	write_be16(buf + off, 0x0004);
	off += 2;
	buf[off++] = 3;
	buf[off++] = (uint8_t)(sha1_mask & 0xFF);
	buf[off++] = (uint8_t)((sha1_mask >> 8) & 0xFF);
	buf[off++] = (uint8_t)((sha1_mask >> 16) & 0xFF);

	/* selection 1: SHA-256 bank */
	write_be16(buf + off, 0x000B);
	off += 2;
	buf[off++] = 3;
	buf[off++] = (uint8_t)(sha256_mask & 0xFF);
	buf[off++] = (uint8_t)((sha256_mask >> 8) & 0xFF);
	buf[off++] = (uint8_t)((sha256_mask >> 16) & 0xFF);

	write_be16(buf + off, (uint16_t)pcr_digest_len);
	off += 2;
	if (pcr_digest_len > 0) {
		memcpy(buf + off, pcr_digest, pcr_digest_len);
		off += pcr_digest_len;
	}

	*out_len = off;
	return buf;
}

int forge_quote_nonce(uint64_t valid_until, uint32_t flags, uint32_t pcr_mask,
		      const uint8_t nonce[32], const uint8_t policy_digest[32],
		      const uint8_t runtime_protect_digest[32],
		      uint64_t runtime_protect_epoch, uint8_t out[32])
{
	return lota_compute_token_quote_nonce(valid_until, flags, pcr_mask,
					      nonce, policy_digest,
					      runtime_protect_digest,
					      runtime_protect_epoch, out);
}

/*
 * Generate RSA-2048 key pair, return EVP_PKEY (caller frees)
 */
EVP_PKEY *forge_rsa_key(void)
{
	EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	EVP_PKEY *pkey = NULL;

	EVP_PKEY_keygen_init(ctx);
	EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
	EVP_PKEY_keygen(ctx, &pkey);
	EVP_PKEY_CTX_free(ctx);

	return pkey;
}

uint8_t *forge_sign(EVP_PKEY *pkey, const EVP_MD *md, const uint8_t *data,
		    size_t data_len, size_t *sig_len)
{
	EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();

	EVP_DigestSignInit(md_ctx, NULL, md, NULL, pkey);
	EVP_DigestSignUpdate(md_ctx, data, data_len);

	/* get required size */
	EVP_DigestSignFinal(md_ctx, NULL, sig_len);
	uint8_t *sig = malloc(*sig_len);
	EVP_DigestSignFinal(md_ctx, sig, sig_len);

	EVP_MD_CTX_free(md_ctx);
	return sig;
}

uint8_t *forge_pubkey_der(EVP_PKEY *pkey, size_t *out_len)
{
	int len = i2d_PUBKEY(pkey, NULL);
	if (len <= 0)
		return NULL;

	uint8_t *der = malloc((size_t)len);
	uint8_t *p = der;
	i2d_PUBKEY(pkey, &p);
	*out_len = (size_t)len;
	return der;
}

/*
 * Build a complete test token: metadata -> expected nonce -> TPMS_ATTEST ->
 * sign -> serialize
 */
int forge_token(EVP_PKEY *key, uint16_t hash_alg, const EVP_MD *md,
		uint64_t valid_until, uint32_t flags, const uint8_t nonce[32],
		uint8_t *tokbuf, size_t tokbuf_size, size_t *tok_written)
{
	/* compute expected nonce */
	uint8_t exp_nonce[32];
	uint8_t runtime_digest[32];
	uint32_t pcr_mask = 0x4001;
	uint8_t policy_digest[32] = { 0x11, 0x22, 0x33 };
	if (lota_compute_runtime_protect_digest(NULL, 0, runtime_digest) != 0)
		return LOTA_ERR_INVALID_ARG;
	if (forge_quote_nonce(valid_until, flags, pcr_mask, nonce,
			      policy_digest, runtime_digest, 0,
			      exp_nonce) != 0) {
		return LOTA_ERR_INVALID_ARG;
	}

	/* build TPMS_ATTEST with expected_nonce as extraData */
	uint8_t pcr_digest[64] = { 0 };
	size_t pcr_digest_len = tpm_hash_digest_len(hash_alg);
	if (pcr_digest_len == 0)
		return LOTA_ERR_INVALID_ARG;
	memset(pcr_digest, 0xDD, pcr_digest_len);
	size_t attest_len = 0;
	uint8_t *attest = build_fake_tpms_attest(exp_nonce, 32, pcr_mask,
						 pcr_digest, pcr_digest_len,
						 &attest_len);

	/* sign attest_data */
	size_t sig_len = 0;
	uint8_t *sig = forge_sign(key, md, attest, attest_len, &sig_len);

	struct lota_token token;
	memset(&token, 0, sizeof(token));
	token.runtime_protect_version = LOTA_RUNTIME_PROTECT_V1;
	token.valid_until = valid_until;
	token.flags = flags;
	memcpy(token.nonce, nonce, 32);
	token.sig_alg = 0x0014; /* RSASSA */
	token.hash_alg = hash_alg;
	token.pcr_mask = pcr_mask; /* PCR 0 + 14 */
	memcpy(token.policy_digest, policy_digest, sizeof(token.policy_digest));
	memcpy(token.runtime_protect_digest, runtime_digest,
	       sizeof(token.runtime_protect_digest));
	token.runtime_protect_epoch = 0;
	token.protect_pid_count = 0;
	token.protected_pids = NULL;
	token.attest_data = attest;
	token.attest_size = attest_len;
	token.signature = sig;
	token.signature_len = sig_len;

	/* serialize */
	int ret =
		lota_token_serialize(&token, tokbuf, tokbuf_size, tok_written);

	free(attest);
	free(sig);

	return ret;
}

/*
 * Build a complete test token: metadata -> expected nonce -> TPMS_ATTEST ->
 * sign -> serialize
 */
int forge_token_sha256(EVP_PKEY *key, uint64_t valid_until, uint32_t flags,
		       const uint8_t nonce[32], uint8_t *tokbuf,
		       size_t tokbuf_size, size_t *tok_written)
{
	return forge_token(key, 0x000B, EVP_sha256(), valid_until, flags, nonce,
			   tokbuf, tokbuf_size, tok_written);
}

/*
 * Same, but with one protected process and its image digest,
 * so the relying-party side has a v2 runtime measurement to recompute.
 */
int forge_token_v2(EVP_PKEY *key, uint64_t valid_until, uint32_t flags,
		   const uint8_t nonce[32], uint8_t *tokbuf, size_t tokbuf_size,
		   size_t *tok_written)
{
	uint8_t exp_nonce[32];
	uint8_t runtime_digest[32];
	uint8_t policy_digest[32] = { 0x11, 0x22, 0x33 };
	uint8_t pcr_digest[32];
	uint32_t pcr_mask = 0x4001;
	uint32_t pids[1] = { 4242 };
	uint8_t image_digests[1][32];
	struct lota_token token;
	size_t attest_len = 0;
	size_t sig_len = 0;
	uint8_t *attest;
	uint8_t *sig;
	int ret;

	memset(image_digests[0], 0x5A, sizeof(image_digests[0]));
	memset(pcr_digest, 0xDD, sizeof(pcr_digest));

	if (lota_compute_runtime_protect_digest_v2(
		    pids, (const uint8_t (*)[32])image_digests, 1,
		    runtime_digest) != 0)
		return LOTA_ERR_INVALID_ARG;
	if (forge_quote_nonce(valid_until, flags, pcr_mask, nonce,
			      policy_digest, runtime_digest, 0, exp_nonce) != 0)
		return LOTA_ERR_INVALID_ARG;

	attest = build_fake_tpms_attest(exp_nonce, 32, pcr_mask, pcr_digest,
					sizeof(pcr_digest), &attest_len);
	if (!attest)
		return LOTA_ERR_INVALID_ARG;
	sig = forge_sign(key, EVP_sha256(), attest, attest_len, &sig_len);
	if (!sig) {
		free(attest);
		return LOTA_ERR_INVALID_ARG;
	}

	memset(&token, 0, sizeof(token));
	token.runtime_protect_version = LOTA_RUNTIME_PROTECT_V2;
	token.valid_until = valid_until;
	token.flags = flags;
	memcpy(token.nonce, nonce, 32);
	token.sig_alg = 0x0014; /* RSASSA */
	token.hash_alg = 0x000B; /* SHA-256 */
	token.pcr_mask = pcr_mask;
	memcpy(token.policy_digest, policy_digest, sizeof(token.policy_digest));
	memcpy(token.runtime_protect_digest, runtime_digest,
	       sizeof(token.runtime_protect_digest));
	token.runtime_protect_epoch = 0;
	token.protect_pid_count = 1;
	token.protected_pids = pids;
	token.protected_image_digests = image_digests;
	token.attest_data = attest;
	token.attest_size = attest_len;
	token.signature = sig;
	token.signature_len = sig_len;

	ret = lota_token_serialize(&token, tokbuf, tokbuf_size, tok_written);

	free(attest);
	free(sig);
	return ret;
}
