/* SPDX-License-Identifier: MIT */
/*
 * LOTA sealed-envelope wire format.
 *
 * A direct seal holds LOTA_SEAL_MAX_SECRET bytes. A larger payload is encrypted
 * with AES-256-GCM under a random KEK and the KEK is sealed to the PCR state,
 * so the TPM gates the KEK and the payload stays outside it.
 *
 * Layout (little-endian):
 *
 *   offset size field
 *   0      4    magic        LOTA_ENVELOPE_MAGIC
 *   4      2    version      LOTA_ENVELOPE_VERSION
 *   6      2    reserved     must be 0
 *   8      2    kek_blob_len embedded sealed-KEK blob length
 *   10     2    reserved     must be 0
 *   12     4    payload_len  plaintext length, equal to the ciphertext's
 *   16     12   nonce        AES-256-GCM nonce
 *   28     16   tag          AES-256-GCM tag
 *   44     4    reserved     must be 0
 *   48     var  kek_blob[kek_blob_len] || ct[payload_len]
 *
 * The header with its tag zeroed, followed by the sealed-KEK blob, is the GCM
 * additional authenticated data, so neither the framing nor the KEK can be
 * swapped without failing the tag check.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_ENVELOPE_H
#define LOTA_ENVELOPE_H

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "lota_seal.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LOTA_ENVELOPE_MAGIC 0x564E454Cu /* "LENV" on disk, little-endian */
#define LOTA_ENVELOPE_VERSION 1u

#define LOTA_ENVELOPE_KEK_SIZE 32u
#define LOTA_ENVELOPE_NONCE_SIZE 12u
#define LOTA_ENVELOPE_TAG_SIZE 16u

#define LOTA_ENVELOPE_HEADER_SIZE 48u

/* Bounds the memory a single seal or unseal touches. */
#define LOTA_ENVELOPE_MAX_PAYLOAD 65536u

#define LOTA_ENVELOPE_MAX_BLOB                                            \
	((size_t)LOTA_ENVELOPE_HEADER_SIZE + (size_t)LOTA_SEAL_MAX_BLOB + \
	 (size_t)LOTA_ENVELOPE_MAX_PAYLOAD)

/* Header fields that vary between envelopes. */
struct lota_envelope_meta {
	uint16_t kek_blob_len;
	uint32_t payload_len;
	uint8_t nonce[LOTA_ENVELOPE_NONCE_SIZE];
	uint8_t tag[LOTA_ENVELOPE_TAG_SIZE];
};

/**
 * lota_envelope_serialize_header() - Write the fixed header.
 * @out: LOTA_ENVELOPE_HEADER_SIZE bytes.
 * @m:   lengths, nonce and tag to write.
 *
 * The caller appends the sealed-KEK blob, then the ciphertext.
 *
 * Return: 0 on success, -EINVAL on a NULL argument or an out-of-range length.
 */
static inline int
lota_envelope_serialize_header(uint8_t *out, const struct lota_envelope_meta *m)
{
	if (!out || !m)
		return -EINVAL;
	if (m->kek_blob_len == 0 || m->kek_blob_len > LOTA_SEAL_MAX_BLOB)
		return -EINVAL;
	if (m->payload_len == 0 || m->payload_len > LOTA_ENVELOPE_MAX_PAYLOAD)
		return -EINVAL;

	memset(out, 0, LOTA_ENVELOPE_HEADER_SIZE);
	lota__seal_write_le32(out + 0, LOTA_ENVELOPE_MAGIC);
	lota__seal_write_le16(out + 4, (uint16_t)LOTA_ENVELOPE_VERSION);
	lota__seal_write_le16(out + 8, m->kek_blob_len);
	lota__seal_write_le32(out + 12, m->payload_len);
	memcpy(out + 16, m->nonce, LOTA_ENVELOPE_NONCE_SIZE);
	memcpy(out + 28, m->tag, LOTA_ENVELOPE_TAG_SIZE);
	return 0;
}

/**
 * lota_envelope_parse_header_why() - Parse and validate the fixed header.
 * @buf: the whole envelope.
 * @len: length of @buf; the declared bodies must fill it exactly.
 * @m: receives the header fields on success.
 * @body_off: if non-NULL, receives the offset of the sealed-KEK blob.
 * @why: if non-NULL, receives the refused field.
 *
 * Return: 0 on success, -EINVAL on a malformed header, -EMSGSIZE on a length
 * mismatch.
 */
static inline int lota_envelope_parse_header_why(const uint8_t *buf, size_t len,
						 struct lota_envelope_meta *m,
						 size_t *body_off,
						 struct lota_blob_refusal *why)
{
	lota__blob_refuse(why, LOTA_BLOB_OK, 0, 0);

	if (!buf || !m)
		return -EINVAL;
	if (len < LOTA_ENVELOPE_HEADER_SIZE) {
		lota__blob_refuse(why, LOTA_BLOB_SHORT, (uint32_t)len,
				  LOTA_ENVELOPE_HEADER_SIZE);
		return -EMSGSIZE;
	}

	if (lota__seal_read_le32(buf + 0) != LOTA_ENVELOPE_MAGIC) {
		lota__blob_refuse(why, LOTA_BLOB_MAGIC, 0, 0);
		return -EINVAL;
	}
	uint16_t version = lota__seal_read_le16(buf + 4);
	if (version != (uint16_t)LOTA_ENVELOPE_VERSION) {
		lota__blob_refuse(why, LOTA_BLOB_VERSION, version,
				  LOTA_ENVELOPE_VERSION);
		return -EINVAL;
	}
	if (lota__seal_read_le16(buf + 6) != 0 ||
	    lota__seal_read_le16(buf + 10) != 0 || buf[44] != 0 ||
	    buf[45] != 0 || buf[46] != 0 || buf[47] != 0) {
		lota__blob_refuse(why, LOTA_BLOB_RESERVED, 0, 0);
		return -EINVAL;
	}

	uint16_t kek_blob_len = lota__seal_read_le16(buf + 8);
	uint32_t payload_len = lota__seal_read_le32(buf + 12);
	if (kek_blob_len == 0 || kek_blob_len > LOTA_SEAL_MAX_BLOB) {
		lota__blob_refuse(why, LOTA_BLOB_KEK_LEN, kek_blob_len,
				  (uint32_t)LOTA_SEAL_MAX_BLOB);
		return -EINVAL;
	}
	if (payload_len == 0 || payload_len > LOTA_ENVELOPE_MAX_PAYLOAD) {
		lota__blob_refuse(why, LOTA_BLOB_PAYLOAD_LEN, payload_len,
				  LOTA_ENVELOPE_MAX_PAYLOAD);
		return -EINVAL;
	}

	size_t need = (size_t)LOTA_ENVELOPE_HEADER_SIZE + (size_t)kek_blob_len +
		      (size_t)payload_len;
	if (need != len) {
		lota__blob_refuse(why, LOTA_BLOB_BODY_LENGTH, (uint32_t)len,
				  (uint32_t)need);
		return -EMSGSIZE;
	}

	m->kek_blob_len = kek_blob_len;
	m->payload_len = payload_len;
	memcpy(m->nonce, buf + 16, LOTA_ENVELOPE_NONCE_SIZE);
	memcpy(m->tag, buf + 28, LOTA_ENVELOPE_TAG_SIZE);
	if (body_off)
		*body_off = LOTA_ENVELOPE_HEADER_SIZE;
	return 0;
}

/**
 * lota_envelope_parse_header() - lota_envelope_parse_header_why() without @why.
 * @buf:      as for lota_envelope_parse_header_why().
 * @len:      as for lota_envelope_parse_header_why().
 * @m:        as for lota_envelope_parse_header_why().
 * @body_off: as for lota_envelope_parse_header_why().
 *
 * Return: as lota_envelope_parse_header_why().
 */
static inline int lota_envelope_parse_header(const uint8_t *buf, size_t len,
					     struct lota_envelope_meta *m,
					     size_t *body_off)
{
	return lota_envelope_parse_header_why(buf, len, m, body_off, NULL);
}

/**
 * lota_envelope_is_envelope() - Tell an envelope from a direct sealed blob.
 * @buf: the blob.
 * @len: bytes in @buf; under four is not an envelope.
 *
 * Return: non-zero if the leading magic is LOTA_ENVELOPE_MAGIC.
 */
static inline int lota_envelope_is_envelope(const uint8_t *buf, size_t len)
{
	if (!buf || len < 4)
		return 0;
	return lota__seal_read_le32(buf + 0) == LOTA_ENVELOPE_MAGIC;
}

/**
 * lota_envelope_aead_seal() - Encrypt a payload under the KEK.
 * @kek:     AES-256-GCM key.
 * @nonce:   GCM nonce.
 * @aad:     additional data the tag covers; may be NULL when @aad_len is 0.
 * @aad_len: bytes in @aad, at most INT_MAX.
 * @pt:      plaintext.
 * @pt_len:  bytes in @pt, 1 to LOTA_ENVELOPE_MAX_PAYLOAD.
 * @ct_out: receives @pt_len bytes of ciphertext.
 * @tag_out: receives the GCM tag.
 *
 * Return: 0 on success, -EINVAL on a bad argument, -ENOMEM, -EIO on a crypto
 * error.
 */
int lota_envelope_aead_seal(const uint8_t kek[LOTA_ENVELOPE_KEK_SIZE],
			    const uint8_t nonce[LOTA_ENVELOPE_NONCE_SIZE],
			    const uint8_t *aad, size_t aad_len,
			    const uint8_t *pt, size_t pt_len, uint8_t *ct_out,
			    uint8_t tag_out[LOTA_ENVELOPE_TAG_SIZE]);

/**
 * lota_envelope_aead_open() - Verify and decrypt a payload under the KEK.
 * @kek:     as for lota_envelope_aead_seal().
 * @nonce:   the nonce the payload was sealed with.
 * @aad:     the additional data it was sealed with.
 * @aad_len: as for lota_envelope_aead_seal().
 * @ct:      ciphertext.
 * @ct_len:  bytes in @ct, 1 to LOTA_ENVELOPE_MAX_PAYLOAD.
 * @tag:     GCM tag to verify.
 * @pt_out: receives @ct_len bytes of plaintext; zeroed on -EBADMSG and -EIO.
 *
 * Return: 0 on success, -EINVAL on a bad argument, -ENOMEM, -EBADMSG on a tag
 * mismatch, -EIO on a crypto error.
 */
int lota_envelope_aead_open(const uint8_t kek[LOTA_ENVELOPE_KEK_SIZE],
			    const uint8_t nonce[LOTA_ENVELOPE_NONCE_SIZE],
			    const uint8_t *aad, size_t aad_len,
			    const uint8_t *ct, size_t ct_len,
			    const uint8_t tag[LOTA_ENVELOPE_TAG_SIZE],
			    uint8_t *pt_out);

#ifdef __cplusplus
}
#endif

#endif /* LOTA_ENVELOPE_H */
