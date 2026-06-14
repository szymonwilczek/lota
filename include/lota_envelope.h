/* SPDX-License-Identifier: MIT */
/*
 * LOTA sealed-envelope wire format.
 *
 * TPM2_Seal bounds the sensitive data it can wrap (LOTA caps a direct seal
 * at LOTA_SEAL_MAX_SECRET bytes). To seal a larger payload -- an asset
 * blob, a save file, a bundle of per-title keys -- LOTA uses an envelope:
 * a fresh random key-encryption key (KEK) is sealed to the PCR state with
 * the ordinary sealed-blob path, and the payload is encrypted under that
 * KEK with AES-256-GCM. The TPM still enforces the boot/PCR binding (it
 * gates release of the KEK); the bulk payload rides outside the TPM under
 * authenticated encryption.
 *
 * This header carries only the portable, TPM- and crypto-independent
 * framing: the magic/version, the lengths of the embedded sealed-KEK blob
 * and ciphertext, and the GCM nonce and tag. The KEK blob body is an
 * opaque LOTA_SEAL_MAGIC blob (see lota_seal.h); the ciphertext body is
 * opaque AES-256-GCM output. tpm.c produces and consumes both.
 *
 * On-disk layout:
 *
 *   [ envelope header (48 B) ][ sealed-KEK blob ][ AES-256-GCM ciphertext ]
 *
 * The header (with its tag field zeroed) followed by the sealed-KEK blob is
 * fed to GCM as additional authenticated data, so neither the framing nor
 * the bound KEK can be swapped without failing the tag check.
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

#define LOTA_ENVELOPE_MAGIC 0x564E454Cu /* "LENV" little-endian */
#define LOTA_ENVELOPE_VERSION 1u

/* AES-256-GCM parameters. */
#define LOTA_ENVELOPE_KEK_SIZE 32u   /* AES-256 key sealed to the PCR state */
#define LOTA_ENVELOPE_NONCE_SIZE 12u /* 96-bit GCM nonce */
#define LOTA_ENVELOPE_TAG_SIZE 16u   /* 128-bit GCM tag */

/* Fixed header size on disk (little-endian, packed). */
#define LOTA_ENVELOPE_HEADER_SIZE 48u

/*
 * Largest payload an envelope may carry. 64 KiB comfortably covers the
 * intended at-rest use cases (asset/key bundles, small save files) while
 * bounding the memory a single seal/unseal touches. Larger objects belong
 * in a streaming format, which this primitive deliberately is not.
 */
#define LOTA_ENVELOPE_MAX_PAYLOAD 65536u

/* Upper bound on a whole envelope blob: header + sealed KEK + ciphertext. */
#define LOTA_ENVELOPE_MAX_BLOB                                                 \
	((size_t)LOTA_ENVELOPE_HEADER_SIZE + (size_t)LOTA_SEAL_MAX_BLOB +      \
	 (size_t)LOTA_ENVELOPE_MAX_PAYLOAD)

/*
 * Parsed/buildable header fields.
 *
 *   offset size field
 *   0      4    magic        LOTA_ENVELOPE_MAGIC
 *   4      2    version      LOTA_ENVELOPE_VERSION
 *   6      2    reserved     must be 0
 *   8      2    kek_blob_len embedded sealed-KEK blob length
 *   10     2    reserved     must be 0
 *   12     4    payload_len  plaintext length (== ciphertext length for GCM)
 *   16     12   nonce        AES-256-GCM nonce
 *   28     16   tag          AES-256-GCM tag
 *   44     4    reserved     must be 0
 *   48     var  kek_blob[kek_blob_len] || ct[payload_len]
 */
struct lota_envelope_meta {
	uint16_t kek_blob_len;
	uint32_t payload_len;
	uint8_t nonce[LOTA_ENVELOPE_NONCE_SIZE];
	uint8_t tag[LOTA_ENVELOPE_TAG_SIZE];
};

/*
 * Serialize the fixed header into out[0..LOTA_ENVELOPE_HEADER_SIZE).
 * The caller appends the sealed-KEK blob then the ciphertext.
 * Returns 0 on success, -EINVAL on a NULL argument or an out-of-range length.
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
	/* out+6..7 reserved = 0 */
	lota__seal_write_le16(out + 8, m->kek_blob_len);
	/* out+10..11 reserved = 0 */
	lota__seal_write_le32(out + 12, m->payload_len);
	memcpy(out + 16, m->nonce, LOTA_ENVELOPE_NONCE_SIZE);
	memcpy(out + 28, m->tag, LOTA_ENVELOPE_TAG_SIZE);
	/* out+44..47 reserved = 0 */
	return 0;
}

/*
 * Parse and validate the fixed header from a blob of total length len.
 * Fills *m and, if body_off is non-NULL, the offset where the sealed-KEK
 * blob begins.
 * Verifies magic, version, reserved bytes, the length fields, and that
 * the declared bodies fit exactly within len.
 * Returns 0 on success, -EINVAL on a malformed header, -EMSGSIZE on
 * a length mismatch.
 */
static inline int lota_envelope_parse_header(const uint8_t *buf, size_t len,
					     struct lota_envelope_meta *m,
					     size_t *body_off)
{
	if (!buf || !m)
		return -EINVAL;
	if (len < LOTA_ENVELOPE_HEADER_SIZE)
		return -EMSGSIZE;

	if (lota__seal_read_le32(buf + 0) != LOTA_ENVELOPE_MAGIC)
		return -EINVAL;
	if (lota__seal_read_le16(buf + 4) != (uint16_t)LOTA_ENVELOPE_VERSION)
		return -EINVAL;
	if (lota__seal_read_le16(buf + 6) != 0)
		return -EINVAL;
	if (lota__seal_read_le16(buf + 10) != 0)
		return -EINVAL;
	if (buf[44] != 0 || buf[45] != 0 || buf[46] != 0 || buf[47] != 0)
		return -EINVAL;

	uint16_t kek_blob_len = lota__seal_read_le16(buf + 8);
	uint32_t payload_len = lota__seal_read_le32(buf + 12);
	if (kek_blob_len == 0 || kek_blob_len > LOTA_SEAL_MAX_BLOB)
		return -EINVAL;
	if (payload_len == 0 || payload_len > LOTA_ENVELOPE_MAX_PAYLOAD)
		return -EINVAL;

	/* bodies must fit exactly: no trailing slack, no overflow */
	size_t need = (size_t)LOTA_ENVELOPE_HEADER_SIZE + (size_t)kek_blob_len +
		      (size_t)payload_len;
	if (need != len)
		return -EMSGSIZE;

	m->kek_blob_len = kek_blob_len;
	m->payload_len = payload_len;
	memcpy(m->nonce, buf + 16, LOTA_ENVELOPE_NONCE_SIZE);
	memcpy(m->tag, buf + 28, LOTA_ENVELOPE_TAG_SIZE);
	if (body_off)
		*body_off = LOTA_ENVELOPE_HEADER_SIZE;
	return 0;
}

/*
 * Return non-zero if a blob's leading magic identifies it as a sealed
 * envelope (LOTA_ENVELOPE_MAGIC) instead of direct sealed blob.
 * Lets the unseal path pick the right decoder without a mode flag.
 */
static inline int lota_envelope_is_envelope(const uint8_t *buf, size_t len)
{
	if (!buf || len < 4)
		return 0;
	return lota__seal_read_le32(buf + 0) == LOTA_ENVELOPE_MAGIC;
}

/*
 * AES-256-GCM seal: encrypt pt[0..pt_len) under kek with nonce, binding
 * aad[0..aad_len) as additional authenticated data. Writes pt_len bytes of
 * ciphertext to ct_out and the LOTA_ENVELOPE_TAG_SIZE tag to tag_out.
 * Returns 0 on success, -EINVAL on a bad argument, -EIO on a crypto error.
 * Implemented in seal_envelope.c (OpenSSL).
 */
int lota_envelope_aead_seal(const uint8_t kek[LOTA_ENVELOPE_KEK_SIZE],
			    const uint8_t nonce[LOTA_ENVELOPE_NONCE_SIZE],
			    const uint8_t *aad, size_t aad_len,
			    const uint8_t *pt, size_t pt_len, uint8_t *ct_out,
			    uint8_t tag_out[LOTA_ENVELOPE_TAG_SIZE]);

/*
 * AES-256-GCM open: verify tag over aad + ct and decrypt ct[0..ct_len) under
 * kek with nonce. Writes ct_len bytes of plaintext to pt_out only if the tag
 * verifies.
 * Returns 0 on success, -EINVAL on a bad argument, -EBADMSG on a tag mismatch
 * (tampered/wrong KEK), -EIO on a crypto error.
 * Implemented in seal_envelope.c (OpenSSL).
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
