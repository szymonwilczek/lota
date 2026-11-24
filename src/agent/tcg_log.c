/* SPDX-License-Identifier: MIT */
/*
 * LOTA - TCG crypto-agile event log reader
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "tcg_log.h"

/* TCG algorithm ids */
#define TCG_ALG_SHA1 0x0004u
#define TCG_ALG_SHA256 0x000Bu
#define TCG_ALG_SHA384 0x000Cu
#define TCG_ALG_SHA512 0x000Du

/* the caps match the verifier's */
#define MAX_HEADER_DATA_SIZE (1u << 20)
#define MAX_EVENT_DATA_SIZE (1u << 20)
#define MAX_DIGEST_COUNT 16u

static bool take(struct tcg_log *c, size_t n, const uint8_t **out)
{
	if (n > c->size - c->off)
		return false;
	if (out)
		*out = c->data + c->off;
	c->off += n;
	return true;
}

static bool take_u16(struct tcg_log *c, uint16_t *out)
{
	const uint8_t *p;

	if (!take(c, sizeof(*out), &p))
		return false;
	*out = (uint16_t)((uint16_t)p[0] | (uint16_t)p[1] << 8);
	return true;
}

static bool take_u32(struct tcg_log *c, uint32_t *out)
{
	const uint8_t *p;

	if (!take(c, sizeof(*out), &p))
		return false;
	*out = (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 |
	       (uint32_t)p[3] << 24;
	return true;
}

static size_t alg_digest_size(uint16_t alg)
{
	switch (alg) {
	case TCG_ALG_SHA1:
		return 20;
	case TCG_ALG_SHA256:
		return 32;
	case TCG_ALG_SHA384:
		return 48;
	case TCG_ALG_SHA512:
		return 64;
	default:
		return 0;
	}
}

/*
 * The first record is the legacy TCG_PCR_EVENT that carries the Spec ID event:
 * PCR 0, EV_NO_ACTION, a SHA-1 digest field, then its data. Every record after
 * it is crypto-agile.
 */
int tcg_log_open(struct tcg_log *log, const uint8_t *data, size_t size)
{
	uint32_t pcr, type, data_size;

	if (!log || !data)
		return -EINVAL;

	*log = (struct tcg_log){ .data = data, .size = size, .off = 0 };

	if (!take_u32(log, &pcr) || !take_u32(log, &type))
		return -EINVAL;
	if (pcr != 0 || type != TCG_EV_NO_ACTION)
		return -EINVAL;
	if (!take(log, 20, NULL) || !take_u32(log, &data_size))
		return -EINVAL;
	if (data_size > MAX_HEADER_DATA_SIZE || !take(log, data_size, NULL))
		return -EINVAL;
	return 0;
}

int tcg_log_next(struct tcg_log *log, struct tcg_event *ev)
{
	uint32_t digest_count;

	if (log->off >= log->size)
		return 0;

	ev->sha256 = NULL;
	if (!take_u32(log, &ev->pcr) || !take_u32(log, &ev->type) ||
	    !take_u32(log, &digest_count))
		return -EINVAL;
	if (digest_count > MAX_DIGEST_COUNT)
		return -EINVAL;

	for (uint32_t i = 0; i < digest_count; i++) {
		uint16_t alg;
		size_t dsize;
		const uint8_t *digest;

		if (!take_u16(log, &alg))
			return -EINVAL;
		dsize = alg_digest_size(alg);
		if (dsize == 0 || !take(log, dsize, &digest))
			return -EINVAL;
		if (alg == TCG_ALG_SHA256)
			ev->sha256 = digest;
	}

	if (!take_u32(log, &ev->data_size))
		return -EINVAL;
	if (ev->data_size > MAX_EVENT_DATA_SIZE ||
	    !take(log, ev->data_size, &ev->data))
		return -EINVAL;
	return 1;
}
