/* SPDX-License-Identifier: MIT */
/*
 * Cache of kernel fs-verity digests, keyed by the inode they were read from.
 *
 * Token folds a measurement of every file-backed executable mapping of every
 * protected process, and heartbeating title asks for one every few seconds.
 *
 * Each object costs an open() and an FS_IOC_MEASURE_VERITY, and process maps
 * its own binary plus every library it loads.
 *
 * Caching is sound because fs-verity is immutable:
 * once enabled on an inode, neither the file's contents nor its digest can change,
 * and the kernel refuses writes to it.
 * What can change underneath is the identity of the inode -- file replaced by
 * package update is a new inode, and an inode number can be reused after deletion
 * -- so the key carries the device, inode number, size and modification time,
 * all read from the same fstat() the measurement already performs on open
 * descriptor.
 * Miss on any of them re-reads from the kernel, so a stale entry is never served.
 *
 * Cache holds no secret: fs-verity digest is public property of a file anyone may read.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_AGENT_RT_VERITY_CACHE_H
#define LOTA_AGENT_RT_VERITY_CACHE_H

#include <stdint.h>
#include <string.h>
#include <sys/stat.h>

#include "lota.h"

/*
 * Entries.
 * Process maps at most LOTA_RUNTIME_IMAGE_MAX_MODULES objects and several
 * protected processes share their libraries, so this holds a typical protected
 * set whole.
 */
#define LOTA_RT_VERITY_CACHE_ENTRIES 512

/* Identity of the inode a digest was read from */
struct lota_rt_verity_key {
	uint64_t dev;
	uint64_t ino;
	uint64_t size;
	int64_t mtime_sec;
	int64_t mtime_nsec;
};

struct lota_rt_verity_entry {
	struct lota_rt_verity_key key;
	struct lota_verity_digest_key digest;
	uint64_t used_at; /* cache clock at the last hit, 0 = free */
};

struct lota_rt_verity_cache {
	struct lota_rt_verity_entry entries[LOTA_RT_VERITY_CACHE_ENTRIES];
	uint64_t clock;
	uint64_t hits;
	uint64_t misses;
};

/* Build a key from a stat of the open descriptor the digest is read from */
static inline void lota_rt_verity_key_from_stat(const struct stat *st,
						struct lota_rt_verity_key *out)
{
	if (!st || !out)
		return;

	memset(out, 0, sizeof(*out));
	out->dev = (uint64_t)st->st_dev;
	out->ino = (uint64_t)st->st_ino;
	out->size = (uint64_t)st->st_size;
	out->mtime_sec = (int64_t)st->st_mtim.tv_sec;
	out->mtime_nsec = (int64_t)st->st_mtim.tv_nsec;
}

static inline int lota_rt_verity_key_eq(const struct lota_rt_verity_key *a,
					const struct lota_rt_verity_key *b)
{
	return a->dev == b->dev && a->ino == b->ino && a->size == b->size &&
	       a->mtime_sec == b->mtime_sec && a->mtime_nsec == b->mtime_nsec;
}

static inline size_t lota_rt_verity_slot(const struct lota_rt_verity_key *key)
{
	uint64_t h = key->dev * 1099511628211ULL;

	h ^= key->ino + 0x9e3779b97f4a7c15ULL + (h << 6) + (h >> 2);
	h ^= key->size + (h << 5);
	h ^= (uint64_t)key->mtime_sec + (h << 3);
	return (size_t)(h % LOTA_RT_VERITY_CACHE_ENTRIES);
}

/*
 * Look up a digest.
 * Returns 1 and fills out on a hit, 0 on a miss.
 *
 * Probing is linear from the hashed slot over a short window,
 * which keeps a lookup bounded no matter how the key set collides.
 */
static inline int lota_rt_verity_cache_get(struct lota_rt_verity_cache *cache,
					   const struct lota_rt_verity_key *key,
					   struct lota_verity_digest_key *out)
{
	size_t start;

	if (!cache || !key || !out)
		return 0;

	start = lota_rt_verity_slot(key);
	for (size_t i = 0; i < 8; i++) {
		struct lota_rt_verity_entry *e =
			&cache->entries[(start + i) % LOTA_RT_VERITY_CACHE_ENTRIES];

		if (e->used_at == 0)
			continue;
		if (!lota_rt_verity_key_eq(&e->key, key))
			continue;

		e->used_at = ++cache->clock;
		*out = e->digest;
		cache->hits++;
		return 1;
	}

	cache->misses++;
	return 0;
}

/*
 * Record a digest, replacing the least recently used entry in the probe window
 * when every slot in it is taken.
 */
static inline void
lota_rt_verity_cache_put(struct lota_rt_verity_cache *cache,
			 const struct lota_rt_verity_key *key,
			 const struct lota_verity_digest_key *digest)
{
	struct lota_rt_verity_entry *victim = NULL;
	size_t start;

	if (!cache || !key || !digest)
		return;
	if (!LOTA_VERITY_DIGEST_LEN_SUPPORTED(digest->len))
		return;

	start = lota_rt_verity_slot(key);
	for (size_t i = 0; i < 8; i++) {
		struct lota_rt_verity_entry *e =
			&cache->entries[(start + i) % LOTA_RT_VERITY_CACHE_ENTRIES];

		if (e->used_at == 0 || lota_rt_verity_key_eq(&e->key, key)) {
			victim = e;
			break;
		}
		if (!victim || e->used_at < victim->used_at)
			victim = e;
	}

	victim->key = *key;
	victim->digest = *digest;
	victim->used_at = ++cache->clock;
}

static inline void lota_rt_verity_cache_clear(struct lota_rt_verity_cache *cache)
{
	if (!cache)
		return;
	memset(cache, 0, sizeof(*cache));
}

#endif /* LOTA_AGENT_RT_VERITY_CACHE_H */
