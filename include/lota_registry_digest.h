/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Digest of one process's registry: the token's entry for that process.
 *
 *   registry_digest = SHA256("lota-runtime-registry:v1\0" ||
 *                            flags_LE16 || total_LE32 || peer_total_LE32 ||
 *                            for each object, in list order:
 *                              size_LE64 || dev_LE64 || ino_LE64 ||
 *                              road || digest_len ||
 *                              soname_len_LE16 || path_len_LE16 ||
 *                              entry_flags_LE16 ||
 *                              digest[digest_len] || soname || path ||
 *                            for each peer, in list order:
 *                              count_LE64 || start_ticks_LE64 ||
 *                              exe_dev_LE64 || exe_ino_LE64 ||
 *                              tgid_LE32 || uid_LE32 || owner_tgid_LE32 ||
 *                              kind_LE32 || comm[16] || owner_comm[16])
 *
 * A command name is hashed up to its first NUL and zero-padded to 16
 * bytes, so padding left behind it does not count.
 *
 * Every entry is bound, those without a digest included, so dropping or
 * rewriting one changes the value. The agent hashes the list as it sends
 * it; a relying party hashes the list it received.
 */

#ifndef LOTA_REGISTRY_DIGEST_H
#define LOTA_REGISTRY_DIGEST_H

#include <errno.h>
#include <stddef.h>
#include <stdint.h>

#include "lota_endian.h"
#include "lota_ipc.h"

#include <openssl/evp.h>

#define LOTA_REGISTRY_DIGEST_SIZE 32

static inline int lota_registry_digest_begin(EVP_MD_CTX *md, uint16_t flags,
					     uint32_t total,
					     uint32_t peer_total)
{
	static const uint8_t domain[] = "lota-runtime-registry:v1\0";
	uint8_t hdr[10];

	lota__write_le16(hdr, flags);
	lota__write_le32(hdr + 2, total);
	lota__write_le32(hdr + 6, peer_total);
	if (EVP_DigestInit_ex(md, EVP_sha256(), NULL) != 1 ||
	    EVP_DigestUpdate(md, domain, sizeof(domain) - 1) != 1 ||
	    EVP_DigestUpdate(md, hdr, sizeof(hdr)) != 1)
		return -EIO;
	return 0;
}

/* @soname and @path hold e->soname_len and e->path_len bytes */
static inline int
lota_registry_digest_entry(EVP_MD_CTX *md,
			   const struct lota_ipc_registry_entry *e,
			   const char *soname, const char *path)
{
	uint8_t b[32];

	if (e->digest_len > sizeof(e->digest))
		return -EINVAL;

	lota__write_le64(b, e->size);
	lota__write_le64(b + 8, e->dev);
	lota__write_le64(b + 16, e->ino);
	b[24] = e->road;
	b[25] = e->digest_len;
	lota__write_le16(b + 26, e->soname_len);
	lota__write_le16(b + 28, e->path_len);
	lota__write_le16(b + 30, e->flags);
	if (EVP_DigestUpdate(md, b, sizeof(b)) != 1 ||
	    EVP_DigestUpdate(md, e->digest, e->digest_len) != 1 ||
	    EVP_DigestUpdate(md, soname, e->soname_len) != 1 ||
	    EVP_DigestUpdate(md, path, e->path_len) != 1)
		return -EIO;
	return 0;
}

/* @comm up to its first NUL, zero-padded to 16 bytes */
static inline void lota__registry_comm(uint8_t *b, const char *comm)
{
	size_t i = 0;

	for (; i < 16 && comm[i] != '\0'; i++)
		b[i] = (uint8_t)comm[i];
	for (; i < 16; i++)
		b[i] = 0;
}

static inline int
lota_registry_digest_peer(EVP_MD_CTX *md,
			  const struct lota_ipc_registry_peer *p)
{
	uint8_t b[80];

	lota__write_le64(b, p->count);
	lota__write_le64(b + 8, p->start_ticks);
	lota__write_le64(b + 16, p->exe_dev);
	lota__write_le64(b + 24, p->exe_ino);
	lota__write_le32(b + 32, p->tgid);
	lota__write_le32(b + 36, p->uid);
	lota__write_le32(b + 40, p->owner_tgid);
	lota__write_le32(b + 44, p->kind);
	lota__registry_comm(b + 48, p->comm);
	lota__registry_comm(b + 64, p->owner_comm);
	if (EVP_DigestUpdate(md, b, sizeof(b)) != 1)
		return -EIO;
	return 0;
}

static inline int
lota_registry_digest_final(EVP_MD_CTX *md,
			   uint8_t out[LOTA_REGISTRY_DIGEST_SIZE])
{
	unsigned int len = 0;

	if (EVP_DigestFinal_ex(md, out, &len) != 1 ||
	    len != LOTA_REGISTRY_DIGEST_SIZE)
		return -EIO;
	return 0;
}

#endif /* LOTA_REGISTRY_DIGEST_H */
