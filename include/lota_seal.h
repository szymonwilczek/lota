/* SPDX-License-Identifier: MIT */
/*
 * LOTA sealed-blob wire format.
 *
 * A sealed blob binds a small secret to a TPM and a PCR state: TPM2_Unseal
 * releases it only when the current PCR values reproduce the PolicyPCR digest
 * it was sealed against.
 *
 * Layout (little-endian):
 *
 *   offset size field
 *   0      4    magic        LOTA_SEAL_MAGIC
 *   4      2    version      LOTA_SEAL_VERSION
 *   6      2    reserved     must be 0
 *   8      4    pcr_mask     PCR selection the blob is sealed against
 *   12     1    pcr_alg      LOTA_SEAL_PCR_ALG_SHA256
 *   13     3    reserved     must be 0
 *   16     32   pcr_digest   seal-time PCR digest, unused on unseal
 *   48     2    pub_len      marshalled TPM2B_PUBLIC length
 *   50     2    priv_len     marshalled TPM2B_PRIVATE length
 *   52     var  pub[pub_len] || priv[priv_len]
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

#define LOTA_SEAL_MAGIC 0x4C45534Cu /* "LSEL" on disk, little-endian */
#define LOTA_SEAL_VERSION 1u

/*
 * Largest plaintext secret that may be sealed: MAX_SYM_DATA of the TPM 2.0
 * reference implementation bounds the sensitive data of TPM2_Create.
 */
#define LOTA_SEAL_MAX_SECRET 128u

#define LOTA_SEAL_PCR_DIGEST_SIZE 32u

#define LOTA_SEAL_PCR_ALG_SHA256 0u

/* Valid PCR indices are 0..23; the mask is one bit per PCR. */
#define LOTA_SEAL_PCR_MASK_ALL 0x00FFFFFFu

/* Copy of LOTA_PCR_SELF from agent.h, which this header may not depend on. */
#define LOTA_SEAL_BOOT_COMMITMENT_PCR 14u

/*
 * Default PCR set: PCRs 0-7, the firmware and boot-path measurements, Secure
 * Boot included. A change in any of them invalidates the seal, and on a shim
 * and GRUB host PCR 4 holds the kernel image, so a kernel upgrade does. A
 * powered-off disk in someone else's hands unseals nothing: the blob loads only
 * under this TPM's primary key.
 *
 * PCR 14 is left out: it moves when the agent is updated, so binding it would
 * cost every sealed secret on the host at every upgrade.
 */
#define LOTA_SEAL_DEFAULT_PCR_MASK 0xFFu

/*
 * The default set plus PCR 14, the agent's boot commitment. This binds a boot
 * state, not a process: any process with TPM access unseals while the registers
 * match. An agent upgrade costs the secret.
 */
#define LOTA_SEAL_AGENT_BOUND_PCR_MASK \
	(LOTA_SEAL_DEFAULT_PCR_MASK | (1u << LOTA_SEAL_BOOT_COMMITMENT_PCR))

#define LOTA_SEAL_HEADER_SIZE 52u

#define LOTA_SEAL_MAX_PUB 1024u
#define LOTA_SEAL_MAX_PRIV 1024u
#define LOTA_SEAL_MAX_BLOB \
	(LOTA_SEAL_HEADER_SIZE + LOTA_SEAL_MAX_PUB + LOTA_SEAL_MAX_PRIV)

/* Header fields that vary between blobs. */
struct lota_seal_meta {
	uint32_t pcr_mask;
	uint8_t pcr_alg;
	uint8_t pcr_digest[LOTA_SEAL_PCR_DIGEST_SIZE];
	uint16_t pub_len;
	uint16_t priv_len;
};

/*
 * Header field a blob or envelope parse refused; the errno alone cannot tell
 * a truncated file from a foreign one.
 */
enum lota_blob_reason {
	LOTA_BLOB_OK = 0,
	LOTA_BLOB_SHORT,
	LOTA_BLOB_MAGIC,
	LOTA_BLOB_VERSION,
	LOTA_BLOB_RESERVED,
	LOTA_BLOB_PCR_MASK,
	LOTA_BLOB_PCR_ALG,
	LOTA_BLOB_PUB_LEN,
	LOTA_BLOB_PRIV_LEN,
	LOTA_BLOB_KEK_LEN,
	LOTA_BLOB_PAYLOAD_LEN,
	LOTA_BLOB_BODY_LENGTH,
};

/**
 * struct lota_blob_refusal - Why a blob or envelope parse refused.
 * @reason: which field was refused.
 * @value: that field as read, where it is a number worth printing.
 * @expected: what the format requires, 0 where no single number applies.
 */
struct lota_blob_refusal {
	enum lota_blob_reason reason;
	uint32_t value;
	uint32_t expected;
};

/**
 * lota_blob_reason_str() - Word a refusal.
 * @reason: the refused field.
 *
 * Return: a phrase about the file, as the blob never reached a TPM.
 */
static inline const char *lota_blob_reason_str(enum lota_blob_reason reason)
{
	switch (reason) {
	case LOTA_BLOB_OK:
		return "the header parsed";
	case LOTA_BLOB_SHORT:
		return "it is shorter than the fixed header";
	case LOTA_BLOB_MAGIC:
		return "it does not open with the magic bytes of a LOTA blob";
	case LOTA_BLOB_VERSION:
		return "it names a format version this build does not read";
	case LOTA_BLOB_RESERVED:
		return "a reserved header byte is set";
	case LOTA_BLOB_PCR_MASK:
		return "the PCR selection is empty or names a PCR above 23";
	case LOTA_BLOB_PCR_ALG:
		return "the PCR digest algorithm is not SHA-256";
	case LOTA_BLOB_PUB_LEN:
		return "the declared public-area length is out of range";
	case LOTA_BLOB_PRIV_LEN:
		return "the declared private-area length is out of range";
	case LOTA_BLOB_KEK_LEN:
		return "the declared sealed-key length is out of range";
	case LOTA_BLOB_PAYLOAD_LEN:
		return "the declared payload length is out of range";
	case LOTA_BLOB_BODY_LENGTH:
		return "the declared bodies do not fill the file exactly";
	}
	return "the header was refused";
}

static inline void lota__blob_refuse(struct lota_blob_refusal *why,
				     enum lota_blob_reason reason,
				     uint32_t value, uint32_t expected)
{
	if (!why)
		return;
	why->reason = reason;
	why->value = value;
	why->expected = expected;
}

static inline uint16_t lota__seal_read_le16(const uint8_t *p)
{
	return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static inline uint32_t lota__seal_read_le32(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
	       ((uint32_t)p[3] << 24);
}

/* Each byte is masked before the cast, for the reason in lota_endian.h. */
static inline void lota__seal_write_le16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v & 0xffu);
	p[1] = (uint8_t)((v >> 8) & 0xffu);
}

static inline void lota__seal_write_le32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v & 0xffu);
	p[1] = (uint8_t)((v >> 8) & 0xffu);
	p[2] = (uint8_t)((v >> 16) & 0xffu);
	p[3] = (uint8_t)((v >> 24) & 0xffu);
}

/**
 * lota_seal_validate_pcr_mask() - Check a PCR selection.
 * @pcr_mask: bit n selects PCR n.
 *
 * An empty selection would bind the secret to nothing, so it is refused.
 *
 * Return: 0 if valid, -EINVAL if empty or naming a PCR above 23.
 */
static inline int lota_seal_validate_pcr_mask(uint32_t pcr_mask)
{
	if (pcr_mask == 0)
		return -EINVAL;
	if (pcr_mask & ~LOTA_SEAL_PCR_MASK_ALL)
		return -EINVAL;
	return 0;
}

/**
 * lota_seal_serialize_header() - Write the fixed header.
 * @out: LOTA_SEAL_HEADER_SIZE bytes.
 * @m:   PCR binding and body lengths to write.
 *
 * The caller appends pub[pub_len], then priv[priv_len].
 *
 * Return: 0 on success, -EINVAL on a NULL argument or an invalid field.
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
	lota__seal_write_le32(out + 8, m->pcr_mask);
	out[12] = m->pcr_alg;
	memcpy(out + 16, m->pcr_digest, LOTA_SEAL_PCR_DIGEST_SIZE);
	lota__seal_write_le16(out + 48, m->pub_len);
	lota__seal_write_le16(out + 50, m->priv_len);
	return 0;
}

/**
 * lota_seal_parse_header_why() - Parse and validate the fixed header.
 * @buf: the whole blob.
 * @len: length of @buf; the declared bodies must fill it exactly.
 * @m: receives the header fields on success.
 * @body_off: if non-NULL, receives the offset of pub[].
 * @why: if non-NULL, receives the refused field.
 *
 * Return: 0 on success, -EINVAL on a malformed header, -EMSGSIZE on a length
 * mismatch.
 */
static inline int lota_seal_parse_header_why(const uint8_t *buf, size_t len,
					     struct lota_seal_meta *m,
					     size_t *body_off,
					     struct lota_blob_refusal *why)
{
	lota__blob_refuse(why, LOTA_BLOB_OK, 0, 0);

	if (!buf || !m)
		return -EINVAL;
	if (len < LOTA_SEAL_HEADER_SIZE) {
		lota__blob_refuse(why, LOTA_BLOB_SHORT, (uint32_t)len,
				  LOTA_SEAL_HEADER_SIZE);
		return -EMSGSIZE;
	}

	if (lota__seal_read_le32(buf + 0) != LOTA_SEAL_MAGIC) {
		lota__blob_refuse(why, LOTA_BLOB_MAGIC, 0, 0);
		return -EINVAL;
	}
	uint16_t version = lota__seal_read_le16(buf + 4);
	if (version != (uint16_t)LOTA_SEAL_VERSION) {
		lota__blob_refuse(why, LOTA_BLOB_VERSION, version,
				  LOTA_SEAL_VERSION);
		return -EINVAL;
	}
	if (lota__seal_read_le16(buf + 6) != 0) {
		lota__blob_refuse(why, LOTA_BLOB_RESERVED, 0, 0);
		return -EINVAL;
	}

	uint32_t pcr_mask = lota__seal_read_le32(buf + 8);
	uint8_t pcr_alg = buf[12];
	if (buf[13] != 0 || buf[14] != 0 || buf[15] != 0) {
		lota__blob_refuse(why, LOTA_BLOB_RESERVED, 0, 0);
		return -EINVAL;
	}
	if (lota_seal_validate_pcr_mask(pcr_mask) != 0) {
		lota__blob_refuse(why, LOTA_BLOB_PCR_MASK, pcr_mask, 0);
		return -EINVAL;
	}
	if (pcr_alg != LOTA_SEAL_PCR_ALG_SHA256) {
		lota__blob_refuse(why, LOTA_BLOB_PCR_ALG, pcr_alg,
				  LOTA_SEAL_PCR_ALG_SHA256);
		return -EINVAL;
	}

	uint16_t pub_len = lota__seal_read_le16(buf + 48);
	uint16_t priv_len = lota__seal_read_le16(buf + 50);
	if (pub_len == 0 || pub_len > LOTA_SEAL_MAX_PUB) {
		lota__blob_refuse(why, LOTA_BLOB_PUB_LEN, pub_len,
				  LOTA_SEAL_MAX_PUB);
		return -EINVAL;
	}
	if (priv_len == 0 || priv_len > LOTA_SEAL_MAX_PRIV) {
		lota__blob_refuse(why, LOTA_BLOB_PRIV_LEN, priv_len,
				  LOTA_SEAL_MAX_PRIV);
		return -EINVAL;
	}

	size_t need = (size_t)LOTA_SEAL_HEADER_SIZE + (size_t)pub_len +
		      (size_t)priv_len;
	if (need != len) {
		lota__blob_refuse(why, LOTA_BLOB_BODY_LENGTH, (uint32_t)len,
				  (uint32_t)need);
		return -EMSGSIZE;
	}

	m->pcr_mask = pcr_mask;
	m->pcr_alg = pcr_alg;
	memcpy(m->pcr_digest, buf + 16, LOTA_SEAL_PCR_DIGEST_SIZE);
	m->pub_len = pub_len;
	m->priv_len = priv_len;
	if (body_off)
		*body_off = LOTA_SEAL_HEADER_SIZE;
	return 0;
}

/**
 * lota_seal_parse_header() - lota_seal_parse_header_why() without @why.
 * @buf:      as for lota_seal_parse_header_why().
 * @len:      as for lota_seal_parse_header_why().
 * @m:        as for lota_seal_parse_header_why().
 * @body_off: as for lota_seal_parse_header_why().
 *
 * Return: as lota_seal_parse_header_why().
 */
static inline int lota_seal_parse_header(const uint8_t *buf, size_t len,
					 struct lota_seal_meta *m,
					 size_t *body_off)
{
	return lota_seal_parse_header_why(buf, len, m, body_off, NULL);
}

#ifdef __cplusplus
}
#endif

#endif /* LOTA_SEAL_H */
