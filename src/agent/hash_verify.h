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

/* Default cache size (number of entries) */
#define HASH_CACHE_DEFAULT_SIZE 4096

/* Sentinel: pass as cache_size to hash_verify_init to disable caching */
#define HASH_CACHE_DISABLED SIZE_MAX

/*
 * Single cache entry: maps a file identity to its content hash.
 *
 * Cache key is (dev, ino, meta_fingerprint):
 *  - dev + ino uniquely identify a file on the filesystem
 *  - meta_fingerprint detects content changes (mtime, size, i_version)
 */
struct hash_cache_entry {
  uint64_t dev;                             /* device number (st_dev) */
  uint64_t ino;                             /* inode number (st_ino) */
  uint8_t meta_fingerprint[LOTA_HASH_SIZE]; /* BPF metadata fingerprint */
  uint8_t content_sha256[LOTA_HASH_SIZE];   /* SHA-256 of file content */
  uint64_t last_used;                       /* monotonic timestamp for LRU */
  int valid;                                /* nonzero if entry is populated */
};

/*
 * Hash verification context.
 */
struct hash_verify_ctx {
  struct hash_cache_entry *cache;
  size_t cache_capacity;
  uint64_t hits;
  uint64_t misses;
  uint64_t errors;
};

/*
 * Initialize hash verification context.
 *
 * @ctx: Context to initialize
 * @cache_size: Number of cache entries (0 for default)
 *
 * Returns: 0 on success, negative errno on failure
 */
int hash_verify_init(struct hash_verify_ctx *ctx, size_t cache_size);

/*
 * Clean up hash verification context and free cache.
 */
void hash_verify_cleanup(struct hash_verify_ctx *ctx);

/*
 * Resolve file integrity fingerprint from fs-verity measurement.
 *
 * @path: Absolute path to the file
 * @sha256_out: Output buffer (LOTA_HASH_SIZE bytes)
 *
 * On success, fills sha256_out with the first 32 bytes of the measured
 * fs-verity digest and returns 0. If fs-verity is unavailable or not enabled
 * for the file, returns negative errno (typically -ENODATA).
 */
int hash_verify_file(const char *path, uint8_t sha256_out[LOTA_HASH_SIZE]);

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
 * Get cache statistics.
 *
 * @ctx: Hash verification context
 * @hits: Output - cache hits (NULL to skip)
 * @misses: Output - cache misses (NULL to skip)
 * @errors: Output - hash computation errors (NULL to skip)
 */
void hash_verify_stats(const struct hash_verify_ctx *ctx, uint64_t *hits,
                       uint64_t *misses, uint64_t *errors);

#endif /* LOTA_HASH_VERIFY_H */
