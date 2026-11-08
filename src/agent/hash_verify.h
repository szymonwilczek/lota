/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - fs-verity fingerprint of the file behind an event.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_HASH_VERIFY_H
#define LOTA_HASH_VERIFY_H

#include <stddef.h>
#include <stdint.h>

#include "../../include/lota.h"

/**
 * struct hash_verify_ctx - Counters for the shutdown statistics log.
 * @resolved: fingerprints resolved.
 * @errors: resolutions that failed.
 */
struct hash_verify_ctx {
	uint64_t resolved;
	uint64_t errors;
};

/* Return: 0, or -EINVAL for a NULL ctx */
int hash_verify_init(struct hash_verify_ctx *ctx);

void hash_verify_cleanup(struct hash_verify_ctx *ctx);

/**
 * hash_verify_event() - fs-verity fingerprint of the file behind an event.
 * @ctx: the counters.
 * @event: the event; an exec is read through /proc/<pid>/exe, any other
 *	through its absolute filename.
 * @sha256_out: the first LOTA_HASH_SIZE bytes of the fs-verity digest.
 *
 * Return: 0, -EPERM for a blocked exec, -ENOENT for a filename that is not
 * absolute, -EINVAL for a bad argument or a file that is not regular,
 * -ENODATA without an fs-verity digest, -EPROTO for a digest length out of
 * range, or another negative errno.
 */
int hash_verify_event(struct hash_verify_ctx *ctx,
		      const struct lota_exec_event *event,
		      uint8_t sha256_out[LOTA_HASH_SIZE]);

/**
 * hash_verify_stats() - Read the counters.
 * @ctx: the counters.
 * @resolved: fingerprints resolved, or NULL.
 * @errors: resolutions that failed, or NULL.
 */
void hash_verify_stats(const struct hash_verify_ctx *ctx, uint64_t *resolved,
		       uint64_t *errors);

#endif /* LOTA_HASH_VERIFY_H */
