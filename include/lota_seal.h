/* SPDX-License-Identifier: MIT */
/*
 * LOTA sealed-blob wire format.
 *
 * A sealed blob binds a small secret to a TPM and to a chosen PCR state:
 * the TPM only releases the secret (via TPM2_Unseal) when the current PCR
 * values reproduce the PolicyPCR digest the blob was sealed against. The
 * blob is therefore inert at rest -- useless on a different machine, or on
 * the same machine booted into a different (tampered) state.
 *
 * This header carries only the portable, TPM-independent framing: the
 * magic/version, the PCR selection the blob is bound to, a diagnostic copy
 * of the seal-time PCR digest, and the lengths of the marshalled
 * TPM2B_PUBLIC / TPM2B_PRIVATE that follow. The marshalled bodies are
 * opaque here; tpm.c produces and consumes them.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_SEAL_H
#define LOTA_SEAL_H

#include <errno.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define LOTA_SEAL_MAGIC 0x4C53454Cu /* "LSEL" little-endian */
#define LOTA_SEAL_VERSION 1u

/*
 * Largest plaintext secret that may be sealed. TPM2_Seal bounds the
 * sensitive data; 128 bytes comfortably covers symmetric keys, AIK auth
 * values, and per-title key material while staying within every TPM's
 * sealed-data limit.
 */
#define LOTA_SEAL_MAX_SECRET 128u

/* PolicyPCR digest is a single SHA-256. */
#define LOTA_SEAL_PCR_DIGEST_SIZE 32u

/* pcr_alg field values. */
#define LOTA_SEAL_PCR_ALG_SHA256 0u

/* Valid PCR indices are 0..23; the mask is one bit per PCR. */
#define LOTA_SEAL_PCR_MASK_ALL 0x00FFFFFFu

/*
 * Default PCR set: the firmware/kernel boot PCRs 0-7 plus LOTA's PCR14
 * boot-commitment. This binds a sealed secret both to the platform boot
 * chain and to the exact LOTA agent identity, so a firmware, kernel, or
 * agent change intentionally invalidates the seal (anti-tamper).
 */
#define LOTA_SEAL_DEFAULT_PCR_MASK (0xFFu | (1u << 14))

/* Fixed header size on disk (little-endian, packed). */
#define LOTA_SEAL_HEADER_SIZE 52u

/* Upper bounds on the marshalled TPM2B bodies and the whole blob. */
#define LOTA_SEAL_MAX_PUB 1024u
#define LOTA_SEAL_MAX_PRIV 1024u
#define LOTA_SEAL_MAX_BLOB                                                     \
	(LOTA_SEAL_HEADER_SIZE + LOTA_SEAL_MAX_PUB + LOTA_SEAL_MAX_PRIV)

/*
 * Parsed/buildable header fields.
 *
 *   offset size field
 *   0      4    magic        LOTA_SEAL_MAGIC
 *   4      2    version      LOTA_SEAL_VERSION
 *   6      2    reserved     must be 0
 *   8      4    pcr_mask     PCR selection the blob is sealed against
 *   12     1    pcr_alg      LOTA_SEAL_PCR_ALG_SHA256
 *   13     3    reserved     must be 0
 *   16     32   pcr_digest   seal-time PolicyPCR pcr digest (diagnostic)
 *   48     2    pub_len      marshalled TPM2B_PUBLIC length
 *   50     2    priv_len     marshalled TPM2B_PRIVATE length
 *   52     var  pub[pub_len] || priv[priv_len]
 */
struct lota_seal_meta {
	uint32_t pcr_mask;
	uint8_t pcr_alg;
	uint8_t pcr_digest[LOTA_SEAL_PCR_DIGEST_SIZE];
	uint16_t pub_len;
	uint16_t priv_len;
};

static inline uint16_t lota__seal_read_le16(const uint8_t *p)
{
	return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static inline uint32_t lota__seal_read_le32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
	       ((uint32_t)p[3] << 24);
}

static inline void lota__seal_write_le16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
}

static inline void lota__seal_write_le32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)v;
	p[1] = (uint8_t)(v >> 8);
	p[2] = (uint8_t)(v >> 16);
	p[3] = (uint8_t)(v >> 24);
}

/*
 * Reject a PCR mask that selects no PCR or any index above 23. Sealing to
 * an empty selection would bind the secret to nothing (it would unseal in
 * any state), so it is refused.
 */
static inline int lota_seal_validate_pcr_mask(uint32_t pcr_mask)
{
	if (pcr_mask == 0)
		return -EINVAL;
	if (pcr_mask & ~LOTA_SEAL_PCR_MASK_ALL)
		return -EINVAL;
	return 0;
}

/*
 * Serialize the fixed header into out[0..LOTA_SEAL_HEADER_SIZE). The
 * caller appends pub[pub_len] then priv[priv_len].
 * Returns 0 on success, EINVAL on a NULL argument or an invalid mask/alg.
 */
static inline int lota_seal_serialize_header(uint8_t *out,
					     const struct lota_seal_meta *m)
{
	if (!out || !m)
		return -EINVAL;
	if (lota_seal_validate_pcr_mask(m->pcr_mask) != 0)
		return -EINVAL;
	if (m->pcr_alg != LOTA_SEAL_PCR_ALG_SHA256)
		return -EINVAL;
	if (m->pub_len == 0 || m->pub_len > LOTA_SEAL_MAX_PUB)
		return -EINVAL;
	if (m->priv_len == 0 || m->priv_len > LOTA_SEAL_MAX_PRIV)
		return -EINVAL;

	memset(out, 0, LOTA_SEAL_HEADER_SIZE);
	lota__seal_write_le32(out + 0, LOTA_SEAL_MAGIC);
	lota__seal_write_le16(out + 4, (uint16_t)LOTA_SEAL_VERSION);
	/* out+6..7 reserved = 0 */
	lota__seal_write_le32(out + 8, m->pcr_mask);
	out[12] = m->pcr_alg;
	/* out+13..15 reserved = 0 */
	memcpy(out + 16, m->pcr_digest, LOTA_SEAL_PCR_DIGEST_SIZE);
	lota__seal_write_le16(out + 48, m->pub_len);
	lota__seal_write_le16(out + 50, m->priv_len);
	return 0;
}

/*
 * Parse and validate the fixed header from a blob of total length len.
 * Fills *m and, if body_off is non-NULL, the offset where pub[] begins.
 * Verifies magic, version, reserved bytes, mask, alg, the length fields,
 * and that the declared bodies fit exactly within len.
 *
 * Returns 0 on success, -EINVAL on a malformed header,
 * -EMSGSIZE on a length mismatch.
 */
static inline int lota_seal_parse_header(const uint8_t *buf, size_t len,
					 struct lota_seal_meta *m,
					 size_t *body_off)
{
	if (!buf || !m)
		return -EINVAL;
	if (len < LOTA_SEAL_HEADER_SIZE)
		return -EMSGSIZE;

	if (lota__seal_read_le32(buf + 0) != LOTA_SEAL_MAGIC)
		return -EINVAL;
	if (lota__seal_read_le16(buf + 4) != (uint16_t)LOTA_SEAL_VERSION)
		return -EINVAL;
	if (lota__seal_read_le16(buf + 6) != 0)
		return -EINVAL;

	uint32_t pcr_mask = lota__seal_read_le32(buf + 8);
	uint8_t pcr_alg = buf[12];
	if (buf[13] != 0 || buf[14] != 0 || buf[15] != 0)
		return -EINVAL;
	if (lota_seal_validate_pcr_mask(pcr_mask) != 0)
		return -EINVAL;
	if (pcr_alg != LOTA_SEAL_PCR_ALG_SHA256)
		return -EINVAL;

	uint16_t pub_len = lota__seal_read_le16(buf + 48);
	uint16_t priv_len = lota__seal_read_le16(buf + 50);
	if (pub_len == 0 || pub_len > LOTA_SEAL_MAX_PUB)
		return -EINVAL;
	if (priv_len == 0 || priv_len > LOTA_SEAL_MAX_PRIV)
		return -EINVAL;

	/* bodies must fit exactly: no trailing slack, no overflow */
	size_t need =
	    (size_t)LOTA_SEAL_HEADER_SIZE + (size_t)pub_len + (size_t)priv_len;
	if (need != len)
		return -EMSGSIZE;

	m->pcr_mask = pcr_mask;
	m->pcr_alg = pcr_alg;
	memcpy(m->pcr_digest, buf + 16, LOTA_SEAL_PCR_DIGEST_SIZE);
	m->pub_len = pub_len;
	m->priv_len = priv_len;
	if (body_off)
		*body_off = LOTA_SEAL_HEADER_SIZE;
	return 0;
}

#ifdef __cplusplus
}
#endif

#endif /* LOTA_SEAL_H */
