/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - File integrity fingerprint helper
 *
 * Exposes a 32-byte fingerprint derived from fs-verity measurement.
 * This avoids userspace read-and-hash TOCTOU races for security paths.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_HASH_VERIFY_H
#define LOTA_HASH_VERIFY_H

#include <stddef.h>
#include <stdint.h>

#include "../../include/lota.h"

/*
 * Hash verification context. Tracks running counters for the agent's
 * shutdown statistics log. There is no userspace content-hash cache:
 * every fingerprint comes from the kernel's fs-verity measurement, so
 * a cache layer in userspace would either be redundant (the kernel
 * already serves the digest from its own state) or unsafe (it would
 * have to bypass the kernel and re-open a TOCTOU window).
 */
struct hash_verify_ctx {
	uint64_t resolved;
	uint64_t errors;
};

/*
 * Initialize hash verification context. Returns 0 on success or
 * -EINVAL when ctx is NULL.
 */
int hash_verify_init(struct hash_verify_ctx *ctx);

void hash_verify_cleanup(struct hash_verify_ctx *ctx);

/*
 * Process a BPF ring buffer event and resolve fs-verity fingerprint.
 *
 * @ctx: Hash verification context
 * @event: BPF exec event (must have filename set to full path)
 * @sha256_out: Output buffer for 32-byte integrity fingerprint
 *
 * Returns:  0 on success (sha256_out filled)
 *          -ENOENT if file not found or path is relative/empty
 *          -EINVAL on bad arguments
 *          negative errno on other errors
 */
int hash_verify_event(struct hash_verify_ctx *ctx,
		      const struct lota_exec_event *event,
		      uint8_t sha256_out[LOTA_HASH_SIZE]);

/*
 * Get verification statistics.
 *
 * @ctx: Hash verification context
 * @resolved: Output - successful fingerprint resolutions (NULL to skip)
 * @errors: Output - resolution failures (NULL to skip)
 */
void hash_verify_stats(const struct hash_verify_ctx *ctx, uint64_t *resolved,
		       uint64_t *errors);

#endif /* LOTA_HASH_VERIFY_H */
