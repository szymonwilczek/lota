/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - File hash verification
 *
 * Computes SHA-256 content hashes for files reported by BPF ring buffer
 * events. An LRU cache keyed by (device, inode, metadata fingerprint)
 * avoids re-hashing unchanged files.
 *
 * The BPF side sends a metadata fingerprint (splitmix64 mix of inode
 * attributes such as size, mtime, ctime) in event->hash[]. When the
 * fingerprint changes for a given (dev, ino) pair, the cached content
 * hash is invalidated and recomputed from disk.
 *
 * SHA-256 is computed incrementally in 64 KB chunks via OpenSSL EVP,
 * so arbitrarily large files are handled without excessive memory use.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include "hash_verify.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <openssl/evp.h>

/* Read buffer for incremental hashing (64 KB) */
#define HASH_READ_BUF_SIZE (64 * 1024)

/* Sentinel value: pass as cache_size to disable caching entirely */
#define HASH_CACHE_DISABLED SIZE_MAX

/* Monotonic clock for LRU timestamps */
static uint64_t monotonic_now(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/*
 * Direct-mapped cache index for (dev, ino) pair
 */
static inline size_t cache_index(struct hash_verify_ctx *ctx, uint64_t dev,
                                 uint64_t ino) {
  uint64_t h = dev ^ ino;
  h ^= h >> 33;
  h *= 0xff51afd7ed558ccdULL;
  h ^= h >> 33;
  return (size_t)(h % ctx->cache_capacity);
}

/*
 * Find cache entry for (dev, ino).
 * Returns pointer to matching entry, or NULL on miss.
 */
static struct hash_cache_entry *cache_lookup(struct hash_verify_ctx *ctx,
                                             uint64_t dev, uint64_t ino) {
  struct hash_cache_entry *e;
  if (!ctx->cache)
    return NULL;
  e = &ctx->cache[cache_index(ctx, dev, ino)];
  if (e->valid && e->dev == dev && e->ino == ino)
    return e;
  return NULL;
}

/*
 * Get the slot for a new entry.
 * Direct-mapped: always the hashed bucket (evicts on collision)
 */
static struct hash_cache_entry *cache_evict_slot(struct hash_verify_ctx *ctx,
                                                 uint64_t dev, uint64_t ino) {
  if (!ctx->cache)
    return NULL;
  return &ctx->cache[cache_index(ctx, dev, ino)];
}

int hash_verify_init(struct hash_verify_ctx *ctx, size_t cache_size) {
  if (!ctx)
    return -EINVAL;

  memset(ctx, 0, sizeof(*ctx));

  /* HASH_CACHE_DISABLED (SIZE_MAX) -> no cache, always hash from disk */
  if (cache_size == HASH_CACHE_DISABLED)
    return 0;

  if (cache_size == 0)
    cache_size = HASH_CACHE_DEFAULT_SIZE;

  ctx->cache = calloc(cache_size, sizeof(struct hash_cache_entry));
  if (!ctx->cache)
    return -ENOMEM;

  ctx->cache_capacity = cache_size;
  return 0;
}

void hash_verify_cleanup(struct hash_verify_ctx *ctx) {
  if (!ctx)
    return;
  free(ctx->cache);
  ctx->cache = NULL;
  ctx->cache_capacity = 0;
}

/*
 * Compute SHA-256 from an already-open file descriptor.
 * The caller is responsible for opening and closing the fd.
 */
static int hash_fd(int fd, uint8_t sha256_out[LOTA_HASH_SIZE]) {
  uint8_t *buf = NULL;
  EVP_MD_CTX *md_ctx = NULL;
  unsigned int hash_len = 0;
  ssize_t n;
  int ret = 0;

  buf = malloc(HASH_READ_BUF_SIZE);
  if (!buf)
    return -ENOMEM;

  md_ctx = EVP_MD_CTX_new();
  if (!md_ctx) {
    ret = -ENOMEM;
    goto out;
  }

  if (EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) != 1) {
    ret = -EIO;
    goto out;
  }

  while ((n = read(fd, buf, HASH_READ_BUF_SIZE)) > 0) {
    if (EVP_DigestUpdate(md_ctx, buf, (size_t)n) != 1) {
      ret = -EIO;
      goto out;
    }
  }

  if (n < 0) {
    ret = -errno;
    goto out;
  }

  if (EVP_DigestFinal_ex(md_ctx, sha256_out, &hash_len) != 1) {
    ret = -EIO;
    goto out;
  }

  /* sanity: EVP_sha256 always produces 32 bytes */
  if (hash_len != LOTA_HASH_SIZE)
    ret = -EIO;

out:
  EVP_MD_CTX_free(md_ctx);
  free(buf);
  return ret;
}

int hash_verify_file(const char *path, uint8_t sha256_out[LOTA_HASH_SIZE]) {
  int fd;
  int ret;

  if (!path || !sha256_out)
    return -EINVAL;

  /* reject relative paths and empty strings */
  if (path[0] != '/')
    return -ENOENT;

  fd = open(path, O_RDONLY | O_NOFOLLOW | O_NOCTTY);
  if (fd < 0)
    return -errno;

  /* reject non-regular files */
  {
    struct stat st;
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode)) {
      close(fd);
      return -EINVAL;
    }
  }

  ret = hash_fd(fd, sha256_out);
  close(fd);
  return ret;
}

int hash_verify_event(struct hash_verify_ctx *ctx,
                      const struct lota_exec_event *event,
                      uint8_t sha256_out[LOTA_HASH_SIZE]) {
  struct stat st;
  struct hash_cache_entry *entry;
  uint64_t dev, ino;
  int fd;
  int ret;

  if (!ctx || !event || !sha256_out)
    return -EINVAL;

  if (event->filename[0] != '/')
    return -ENOENT;

  /*
   * prefer /proc/PID/exe which references the exact inode the kernel
   * executed, immune to path-based TOCTOU races.
   * fallback to the filename if the process already exited.
   */
  {
    char proc_path[32];
    snprintf(proc_path, sizeof(proc_path), "/proc/%u/exe", event->pid);
    fd = open(proc_path, O_RDONLY | O_NOFOLLOW | O_NOCTTY);
  }

  if (fd < 0) {
    fd = open(event->filename, O_RDONLY | O_NOFOLLOW | O_NOCTTY);
  }

  if (fd < 0) {
    ctx->errors++;
    return -errno;
  }

  if (fstat(fd, &st) < 0) {
    ctx->errors++;
    ret = -errno;
    close(fd);
    return ret;
  }

  if (!S_ISREG(st.st_mode)) {
    ctx->errors++;
    close(fd);
    return -EINVAL;
  }

  dev = (uint64_t)st.st_dev;
  ino = (uint64_t)st.st_ino;

  /* cache lookup */
  entry = cache_lookup(ctx, dev, ino);
  if (entry) {
    /*
     * check if metadata fingerprint still matches
     */
    if (memcmp(entry->meta_fingerprint, event->hash, LOTA_HASH_SIZE) == 0) {
      /* cache hit */
      memcpy(sha256_out, entry->content_sha256, LOTA_HASH_SIZE);
      entry->last_used = monotonic_now();
      ctx->hits++;
      close(fd);
      return 0;
    }
    /* fingerprint mismatch -> recompute */
  }

  /* cache miss or stale -> compute SHA-256 from the already-open fd */
  ret = hash_fd(fd, sha256_out);
  close(fd);
  if (ret < 0) {
    ctx->errors++;
    return ret;
  }

  ctx->misses++;

  /* update or insert cache entry */
  if (!entry)
    entry = cache_evict_slot(ctx, dev, ino);
  if (entry) {
    entry->dev = dev;
    entry->ino = ino;
    memcpy(entry->meta_fingerprint, event->hash, LOTA_HASH_SIZE);
    memcpy(entry->content_sha256, sha256_out, LOTA_HASH_SIZE);
    entry->last_used = monotonic_now();
    entry->valid = 1;
  }

  return 0;
}

void hash_verify_stats(const struct hash_verify_ctx *ctx, uint64_t *hits,
                       uint64_t *misses, uint64_t *errors) {
  if (!ctx)
    return;
  if (hits)
    *hits = ctx->hits;
  if (misses)
    *misses = ctx->misses;
  if (errors)
    *errors = ctx->errors;
}
