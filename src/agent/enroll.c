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
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

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
	 * replies carry no version-specific fields, so all are acceptable here */
	if (version != LOTA_ENROLL_VERSION &&
	    version != LOTA_ENROLL_VERSION_TOKEN &&
	    version != LOTA_ENROLL_VERSION_EK_CHAIN)
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
	/* empty field is a length and nothing else; data may be NULL */
	if (len > 0)
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

/*
 * Total length of the DER certificate starting at buf, or 0 when those bytes
 * do not begin one that fits. Only the definite-length constructed SEQUENCE
 * an X.509 certificate is encoded as is accepted; an indefinite length,
 * a length wider than four bytes and a body running past the blob all end
 * the walk.
 */
static size_t der_cert_len(const uint8_t *buf, size_t len)
{
	size_t hdr, body;

	if (len < 2 || buf[0] != 0x30)
		return 0;

	if (buf[1] < 0x80) {
		hdr = 2;
		body = buf[1];
	} else {
		size_t width = buf[1] & 0x7Fu;

		if (width == 0 || width > 4 || len < 2 + width)
			return 0;
		hdr = 2 + width;
		body = 0;
		for (size_t i = 0; i < width; i++)
			body = (body << 8) | buf[2 + i];
	}

	if (body == 0 || body > len - hdr)
		return 0;
	return hdr + body;
}

int enroll_split_cert_chain(const uint8_t *blob, size_t len,
			    struct enroll_cert_ref *out, size_t out_max,
			    size_t *out_count)
{
	size_t off = 0;
	size_t count = 0;

	if (!blob || !out || !out_count)
		return -EINVAL;
	*out_count = 0;

	while (off < len && count < out_max) {
		size_t cert_len = der_cert_len(blob + off, len - off);

		if (cert_len == 0 || cert_len > LOTA_ENROLL_MAX_EK_CERT)
			break;
		/* keep the walk inside the frame budget the encoder enforces */
		if (cert_len > LOTA_ENROLL_MAX_EK_CHAIN_BYTES - off)
			break;
		out[count].der = blob + off;
		out[count].len = cert_len;
		off += cert_len;
		count++;
	}

	*out_count = count;
	return 0;
}

ssize_t enroll_encode_begin(uint8_t *out, size_t out_max,
			    const uint8_t *ek_cert, size_t ek_cert_len,
			    const uint8_t *aik_public, size_t aik_public_len,
			    const uint8_t *token, size_t token_len,
			    const struct enroll_cert_ref *ek_chain,
			    size_t ek_chain_len)
{
	struct wr w = { .buf = out, .max = out_max, .pos = 0 };
	size_t chain_bytes = 0;
	uint16_t version;
	int ret;

	if (!out || !ek_cert || !aik_public)
		return -EINVAL;
	if (!token && token_len > 0)
		return -EINVAL;
	if (!ek_chain && ek_chain_len > 0)
		return -EINVAL;
	if (ek_cert_len > LOTA_ENROLL_MAX_EK_CERT ||
	    aik_public_len > LOTA_ENROLL_MAX_AIK_PUBLIC ||
	    token_len > LOTA_ENROLL_MAX_TOKEN ||
	    ek_chain_len > LOTA_ENROLL_MAX_EK_CHAIN_CERTS)
		return -EMSGSIZE;

	for (size_t i = 0; i < ek_chain_len; i++) {
		if (!ek_chain[i].der)
			return -EINVAL;
		if (ek_chain[i].len == 0 ||
		    ek_chain[i].len > LOTA_ENROLL_MAX_EK_CERT)
			return -EMSGSIZE;
		chain_bytes += ek_chain[i].len;
	}
	if (chain_bytes > LOTA_ENROLL_MAX_EK_CHAIN_BYTES)
		return -EMSGSIZE;

	/*
	 * what the request carries selects the version:
	 * untenanted request carries neither and is version 1,
	 * tenant request carries a token and is version 2,
	 * device presenting its manufacturer intermediates is version 3.
	 * All three are current modes, so a host with no chain still speaks
	 * to a CA that predates the field.
	 */
	if (ek_chain_len > 0)
		version = LOTA_ENROLL_VERSION_EK_CHAIN;
	else if (token_len > 0)
		version = LOTA_ENROLL_VERSION_TOKEN;
	else
		version = LOTA_ENROLL_VERSION;

	ret = wr_preamble(&w, version);
	if (ret < 0)
		return ret;
	ret = wr_bytes16(&w, ek_cert, ek_cert_len);
	if (ret < 0)
		return ret;
	ret = wr_bytes16(&w, aik_public, aik_public_len);
	if (ret < 0)
		return ret;
	/* version 3 carries the token field whether or not it holds one */
	if (token_len > 0 || version == LOTA_ENROLL_VERSION_EK_CHAIN) {
		ret = wr_bytes16(&w, token, token_len);
		if (ret < 0)
			return ret;
	}
	if (version == LOTA_ENROLL_VERSION_EK_CHAIN) {
		ret = wr_u16(&w, (uint16_t)ek_chain_len);
		if (ret < 0)
			return ret;
		for (size_t i = 0; i < ek_chain_len; i++) {
			ret = wr_bytes16(&w, ek_chain[i].der, ek_chain[i].len);
			if (ret < 0)
				return ret;
		}
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

int enroll_token_from_file(const char *path, char *out, size_t out_size)
{
	/* one extra byte so over-long token is detected, not truncated */
	char buf[LOTA_ENROLL_MAX_TOKEN + 2];
	ssize_t n;
	size_t len;
	int fd, ret;

	if (!path || !out || out_size < LOTA_ENROLL_MAX_TOKEN + 1)
		return -EINVAL;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	n = read(fd, buf, sizeof(buf));
	if (n < 0) {
		ret = -errno;
		close(fd);
		return ret;
	}
	close(fd);

	ret = -EINVAL;
	len = (size_t)n;
	while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r' ||
			   buf[len - 1] == ' ' || buf[len - 1] == '\t'))
		len--;
	if (len == 0)
		goto out;
	if (len > LOTA_ENROLL_MAX_TOKEN) {
		ret = -EMSGSIZE;
		goto out;
	}
	/* printable, non-whitespace ASCII only:
	 * CA hashes the exact bytes, so transport or shell could mangle is refused */
	for (size_t i = 0; i < len; i++) {
		if (buf[i] <= 0x20 || buf[i] >= 0x7F)
			goto out;
	}

	memcpy(out, buf, len);
	out[len] = '\0';
	ret = 0;
out:
	explicit_bzero(buf, sizeof(buf));
	return ret;
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
