/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * LOTA attestation-CA enrollment client - wire codec.
 *
 * Encodes the agent's BeginRequest/CompleteRequest and decodes the CA's
 * ChallengeReply/ResultReply. The byte layout mirrors src/attestca/wire:
 * a magic/version preamble followed by big-endian, length-prefixed
 * fields, each bounded before it is copied.
 */

#include <errno.h>
#include <string.h>

#include "enroll.h"
#include "lota_enroll.h"

/* Bounded big-endian reader over a decoded frame body. */
struct rd {
	const uint8_t *buf;
	size_t len;
	size_t pos;
};

static int rd_u16(struct rd *r, uint16_t *out)
{
	if (r->pos + 2 > r->len)
		return -EBADMSG;
	*out = (uint16_t)((uint16_t)r->buf[r->pos] << 8 | r->buf[r->pos + 1]);
	r->pos += 2;
	return 0;
}

static int rd_u32(struct rd *r, uint32_t *out)
{
	if (r->pos + 4 > r->len)
		return -EBADMSG;
	*out = (uint32_t)r->buf[r->pos] << 24 |
	       (uint32_t)r->buf[r->pos + 1] << 16 |
	       (uint32_t)r->buf[r->pos + 2] << 8 | (uint32_t)r->buf[r->pos + 3];
	r->pos += 4;
	return 0;
}

/* Read a u16-length-prefixed field, bounded by max, into dst. */
static int rd_bytes16(struct rd *r, uint8_t *dst, size_t max, size_t *out_len)
{
	uint16_t n;
	int ret = rd_u16(r, &n);
	if (ret < 0)
		return ret;
	if (n > max)
		return -EMSGSIZE;
	if (r->pos + n > r->len)
		return -EBADMSG;
	memcpy(dst, r->buf + r->pos, n);
	r->pos += n;
	*out_len = n;
	return 0;
}

static int rd_preamble(struct rd *r)
{
	uint32_t magic;
	uint16_t version;
	int ret;

	ret = rd_u32(r, &magic);
	if (ret < 0)
		return ret;
	if (magic != LOTA_ENROLL_MAGIC)
		return -EPROTO;
	ret = rd_u16(r, &version);
	if (ret < 0)
		return ret;
	/* CA mirrors the request's version;
	 * replies carry no version-specific fields, so both are acceptable here */
	if (version != LOTA_ENROLL_VERSION &&
	    version != LOTA_ENROLL_VERSION_TOKEN)
		return -EPROTONOSUPPORT;
	return 0;
}

/* Bounded big-endian writer. */
struct wr {
	uint8_t *buf;
	size_t max;
	size_t pos;
};

static int wr_u16(struct wr *w, uint16_t v)
{
	if (w->pos + 2 > w->max)
		return -ENOSPC;
	w->buf[w->pos++] = (uint8_t)(v >> 8);
	w->buf[w->pos++] = (uint8_t)v;
	return 0;
}

static int wr_u32(struct wr *w, uint32_t v)
{
	if (w->pos + 4 > w->max)
		return -ENOSPC;
	w->buf[w->pos++] = (uint8_t)(v >> 24);
	w->buf[w->pos++] = (uint8_t)(v >> 16);
	w->buf[w->pos++] = (uint8_t)(v >> 8);
	w->buf[w->pos++] = (uint8_t)v;
	return 0;
}

static int wr_bytes16(struct wr *w, const uint8_t *data, size_t len)
{
	int ret;
	if (len > 0xFFFF)
		return -EMSGSIZE;
	ret = wr_u16(w, (uint16_t)len);
	if (ret < 0)
		return ret;
	if (w->pos + len > w->max)
		return -ENOSPC;
	memcpy(w->buf + w->pos, data, len);
	w->pos += len;
	return 0;
}

static int wr_preamble(struct wr *w, uint16_t version)
{
	int ret = wr_u32(w, LOTA_ENROLL_MAGIC);
	if (ret < 0)
		return ret;
	return wr_u16(w, version);
}

ssize_t enroll_encode_begin(uint8_t *out, size_t out_max,
			    const uint8_t *ek_cert, size_t ek_cert_len,
			    const uint8_t *aik_public, size_t aik_public_len,
			    const uint8_t *token, size_t token_len)
{
	struct wr w = { .buf = out, .max = out_max, .pos = 0 };
	int ret;

	if (!out || !ek_cert || !aik_public)
		return -EINVAL;
	if (!token && token_len > 0)
		return -EINVAL;
	if (ek_cert_len > LOTA_ENROLL_MAX_EK_CERT ||
	    aik_public_len > LOTA_ENROLL_MAX_AIK_PUBLIC ||
	    token_len > LOTA_ENROLL_MAX_TOKEN)
		return -EMSGSIZE;

	/* a token-less request stays version 1 so old CA accepts it */
	ret = wr_preamble(&w, token_len > 0 ? LOTA_ENROLL_VERSION_TOKEN :
					      LOTA_ENROLL_VERSION);
	if (ret < 0)
		return ret;
	ret = wr_bytes16(&w, ek_cert, ek_cert_len);
	if (ret < 0)
		return ret;
	ret = wr_bytes16(&w, aik_public, aik_public_len);
	if (ret < 0)
		return ret;
	if (token_len > 0) {
		ret = wr_bytes16(&w, token, token_len);
		if (ret < 0)
			return ret;
	}
	return (ssize_t)w.pos;
}

ssize_t enroll_encode_complete(uint8_t *out, size_t out_max,
			       const char *session_id, const uint8_t *secret,
			       size_t secret_len)
{
	struct wr w = { .buf = out, .max = out_max, .pos = 0 };
	size_t sid_len;
	int ret;

	if (!out || !session_id || !secret)
		return -EINVAL;
	sid_len = strlen(session_id);
	if (sid_len > LOTA_ENROLL_MAX_SESSION_ID ||
	    secret_len > LOTA_ENROLL_MAX_SECRET)
		return -EMSGSIZE;

	ret = wr_preamble(&w, LOTA_ENROLL_VERSION);
	if (ret < 0)
		return ret;
	ret = wr_bytes16(&w, (const uint8_t *)session_id, sid_len);
	if (ret < 0)
		return ret;
	ret = wr_bytes16(&w, secret, secret_len);
	if (ret < 0)
		return ret;
	return (ssize_t)w.pos;
}

int enroll_decode_challenge(const uint8_t *body, size_t len,
			    struct enroll_challenge *out)
{
	struct rd r = { .buf = body, .len = len, .pos = 0 };
	size_t sid_len = 0;
	int ret;

	if (!body || !out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));

	ret = rd_preamble(&r);
	if (ret < 0)
		return ret;
	ret = rd_u16(&r, &out->status);
	if (ret < 0)
		return ret;
	ret = rd_bytes16(&r, (uint8_t *)out->session_id,
			 LOTA_ENROLL_MAX_SESSION_ID, &sid_len);
	if (ret < 0)
		return ret;
	out->session_id[sid_len] = '\0';
	ret = rd_bytes16(&r, out->cred_blob, LOTA_ENROLL_MAX_CRED_BLOB,
			 &out->cred_blob_len);
	if (ret < 0)
		return ret;
	ret = rd_bytes16(&r, out->enc_secret, LOTA_ENROLL_MAX_ENC_SECRET,
			 &out->enc_secret_len);
	if (ret < 0)
		return ret;
	return 0;
}

int enroll_decode_result(const uint8_t *body, size_t len,
			 struct enroll_result *out)
{
	struct rd r = { .buf = body, .len = len, .pos = 0 };
	size_t dev_len = 0;
	int ret;

	if (!body || !out)
		return -EINVAL;
	memset(out, 0, sizeof(*out));

	ret = rd_preamble(&r);
	if (ret < 0)
		return ret;
	ret = rd_u16(&r, &out->status);
	if (ret < 0)
		return ret;
	ret = rd_bytes16(&r, out->aik_cert, LOTA_ENROLL_MAX_AIK_CERT,
			 &out->aik_cert_len);
	if (ret < 0)
		return ret;
	ret = rd_bytes16(&r, (uint8_t *)out->device_id,
			 LOTA_ENROLL_MAX_DEVICE_ID, &dev_len);
	if (ret < 0)
		return ret;
	out->device_id[dev_len] = '\0';
	return 0;
}
