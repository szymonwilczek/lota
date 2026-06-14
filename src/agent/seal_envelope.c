/* SPDX-License-Identifier: MIT */
/*
 * LOTA sealed-envelope AES-256-GCM helpers.
 *
 * Portable framing lives in include/lota_envelope.h; this file is the
 * OpenSSL-backed authenticated encryption that wraps the bulk payload under
 * the TPM-sealed KEK. No TPM is touched here.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/types.h>

#include "../../include/lota_envelope.h"

int lota_envelope_aead_seal(const uint8_t kek[LOTA_ENVELOPE_KEK_SIZE],
			    const uint8_t nonce[LOTA_ENVELOPE_NONCE_SIZE],
			    const uint8_t *aad, size_t aad_len,
			    const uint8_t *pt, size_t pt_len, uint8_t *ct_out,
			    uint8_t tag_out[LOTA_ENVELOPE_TAG_SIZE])
{
	EVP_CIPHER_CTX *ctx;
	int len = 0;
	int ret = -EIO;

	if (!kek || !nonce || !pt || !ct_out || !tag_out)
		return -EINVAL;
	if (pt_len == 0 || pt_len > LOTA_ENVELOPE_MAX_PAYLOAD)
		return -EINVAL;
	if (aad_len > 0 && !aad)
		return -EINVAL;
	/* pt_len is bounded above; only the caller-supplied aad_len is open */
	if (aad_len > INT_MAX)
		return -EINVAL;

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return -ENOMEM;

	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
		goto out;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
				LOTA_ENVELOPE_NONCE_SIZE, NULL) != 1)
		goto out;
	if (EVP_EncryptInit_ex(ctx, NULL, NULL, kek, nonce) != 1)
		goto out;
	if (aad_len > 0 &&
	    EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1)
		goto out;
	if (EVP_EncryptUpdate(ctx, ct_out, &len, pt, (int)pt_len) != 1)
		goto out;
	/* GCM is a stream cipher: no block padding, EncryptFinal emits 0. */
	if (EVP_EncryptFinal_ex(ctx, ct_out + len, &len) != 1)
		goto out;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
				LOTA_ENVELOPE_TAG_SIZE, tag_out) != 1)
		goto out;
	ret = 0;
out:
	EVP_CIPHER_CTX_free(ctx);
	return ret;
}

int lota_envelope_aead_open(const uint8_t kek[LOTA_ENVELOPE_KEK_SIZE],
			    const uint8_t nonce[LOTA_ENVELOPE_NONCE_SIZE],
			    const uint8_t *aad, size_t aad_len,
			    const uint8_t *ct, size_t ct_len,
			    const uint8_t tag[LOTA_ENVELOPE_TAG_SIZE],
			    uint8_t *pt_out)
{
	EVP_CIPHER_CTX *ctx;
	uint8_t tag_copy[LOTA_ENVELOPE_TAG_SIZE];
	int len = 0;
	int ret = -EIO;

	if (!kek || !nonce || !ct || !tag || !pt_out)
		return -EINVAL;
	if (ct_len == 0 || ct_len > LOTA_ENVELOPE_MAX_PAYLOAD)
		return -EINVAL;
	if (aad_len > 0 && !aad)
		return -EINVAL;
	/* ct_len is bounded above; only the caller-supplied aad_len is open */
	if (aad_len > INT_MAX)
		return -EINVAL;

	/* EVP_CTRL_GCM_SET_TAG takes a non-const pointer. */
	memcpy(tag_copy, tag, sizeof(tag_copy));

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return -ENOMEM;

	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
		goto out;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
				LOTA_ENVELOPE_NONCE_SIZE, NULL) != 1)
		goto out;
	if (EVP_DecryptInit_ex(ctx, NULL, NULL, kek, nonce) != 1)
		goto out;
	if (aad_len > 0 &&
	    EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1)
		goto out;
	if (EVP_DecryptUpdate(ctx, pt_out, &len, ct, (int)ct_len) != 1)
		goto out;
	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG,
				LOTA_ENVELOPE_TAG_SIZE, tag_copy) != 1)
		goto out;
	/*
	 * DecryptFinal returns failure when the tag does not verify; that is
	 * the integrity check, surfaced as -EBADMSG so callers can tell a
	 * tampered/wrong-KEK payload from an I/O fault.
	 */
	if (EVP_DecryptFinal_ex(ctx, pt_out + len, &len) != 1) {
		ret = -EBADMSG;
		goto out;
	}
	ret = 0;
out:
	EVP_CIPHER_CTX_free(ctx);
	return ret;
}
