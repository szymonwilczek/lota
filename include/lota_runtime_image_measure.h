/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Runtime image digest of a process: the file-backed executable objects mapped
 * into it, folded into one value.
 *
 *   image_digest = SHA256("lota-runtime-image-measure:v1\0" ||
 *                         count_LE ||
 *                         for each module, in canonical order:
 *                           soname_len_LE || soname ||
 *                           verity_len_LE || verity_digest)
 *
 * Each module digest comes from the kernel over the backing file, an fs-verity
 * measurement or a content hash (LOTA_STATUS_IMAGE_CONTENT_HASHED), never from
 * the process address space. The fold is keyed by soname and sorted, so neither
 * load order nor library search path affects the result.
 *
 * Callers own the sort. An empty set yields a well-defined digest.
 */

#ifndef LOTA_RUNTIME_IMAGE_MEASURE_H
#define LOTA_RUNTIME_IMAGE_MEASURE_H

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "lota.h"
#include "lota_endian.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#define LOTA_RUNTIME_IMAGE_DIGEST_SIZE 32
#define LOTA_RUNTIME_IMAGE_SONAME_MAX 256
#define LOTA_RUNTIME_IMAGE_MAX_MODULES 512

/* One measured object: its soname (file basename) and digest. */
struct lota_runtime_image_module {
	char soname[LOTA_RUNTIME_IMAGE_SONAME_MAX];
	struct lota_verity_digest_key verity;
};

static inline void lota__runtime_image_bzero(void *ptr, size_t len)
{
	if (!ptr || len == 0)
		return;
	OPENSSL_cleanse(ptr, len);
}

/* Canonical ordering: soname, then verity length, then verity digest. */
static inline int
lota__runtime_image_module_cmp(const struct lota_runtime_image_module *a,
			       const struct lota_runtime_image_module *b)
{
	int c = strncmp(a->soname, b->soname, LOTA_RUNTIME_IMAGE_SONAME_MAX);
	if (c != 0)
		return c;
	if (a->verity.len != b->verity.len)
		return a->verity.len < b->verity.len ? -1 : 1;
	return memcmp(a->verity.digest, b->verity.digest, a->verity.len);
}

/**
 * lota_validate_runtime_image_modules() - Check a module set.
 * @m: the set, may be NULL if @count is 0.
 * @count: entries in @m, at most LOTA_RUNTIME_IMAGE_MAX_MODULES.
 *
 * Each soname must be NUL-terminated and non-empty, each digest a supported
 * size, and the set strictly increasing in canonical order, which also rejects
 * duplicates.
 *
 * Return: 0 if valid, -E2BIG on too many modules, -EINVAL otherwise.
 */
static inline int
lota_validate_runtime_image_modules(const struct lota_runtime_image_module *m,
				    uint32_t count)
{
	if (count == 0)
		return m ? 0 : 0;
	if (!m)
		return -EINVAL;
	if (count > LOTA_RUNTIME_IMAGE_MAX_MODULES)
		return -E2BIG;

	for (uint32_t i = 0; i < count; i++) {
		size_t slen =
			strnlen(m[i].soname, LOTA_RUNTIME_IMAGE_SONAME_MAX);
		if (slen == 0 || slen >= LOTA_RUNTIME_IMAGE_SONAME_MAX)
			return -EINVAL;
		if (!LOTA_VERITY_DIGEST_LEN_SUPPORTED(m[i].verity.len))
			return -EINVAL;
		if (i > 0 &&
		    lota__runtime_image_module_cmp(&m[i - 1], &m[i]) >= 0)
			return -EINVAL;
	}
	return 0;
}

/**
 * lota_compute_runtime_image_digest() - Compute the image digest of a process.
 * @modules: the set, sorted.
 * @count: as for lota_validate_runtime_image_modules().
 * @out_digest: receives the digest; zeroed on -EIO.
 *
 * Return: 0 on success, a validation error, -EINVAL on a NULL @out_digest,
 * -ENOMEM or -EIO from the hash.
 */
static inline int lota_compute_runtime_image_digest(
	const struct lota_runtime_image_module *modules, uint32_t count,
	uint8_t out_digest[LOTA_RUNTIME_IMAGE_DIGEST_SIZE])
{
	static const uint8_t domain[] = "lota-runtime-image-measure:v1\0";
	EVP_MD_CTX *mdctx = NULL;
	unsigned int out_len = 0;
	uint8_t le_u32[4];
	int ret;

	if (!out_digest)
		return -EINVAL;

	ret = lota_validate_runtime_image_modules(modules, count);
	if (ret != 0)
		return ret;

	mdctx = EVP_MD_CTX_new();
	if (!mdctx)
		return -ENOMEM;

	if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1 ||
	    EVP_DigestUpdate(mdctx, domain, sizeof(domain) - 1) != 1) {
		ret = -EIO;
		goto out;
	}

	lota__write_le32(le_u32, count);
	if (EVP_DigestUpdate(mdctx, le_u32, sizeof(le_u32)) != 1) {
		ret = -EIO;
		goto out;
	}

	for (uint32_t i = 0; i < count; i++) {
		uint32_t slen = (uint32_t)strnlen(
			modules[i].soname, LOTA_RUNTIME_IMAGE_SONAME_MAX);

		lota__write_le32(le_u32, slen);
		if (EVP_DigestUpdate(mdctx, le_u32, sizeof(le_u32)) != 1 ||
		    EVP_DigestUpdate(mdctx, modules[i].soname, slen) != 1) {
			ret = -EIO;
			goto out;
		}

		lota__write_le32(le_u32, modules[i].verity.len);
		if (EVP_DigestUpdate(mdctx, le_u32, sizeof(le_u32)) != 1 ||
		    EVP_DigestUpdate(mdctx, modules[i].verity.digest,
				     modules[i].verity.len) != 1) {
			ret = -EIO;
			goto out;
		}
	}

	if (EVP_DigestFinal_ex(mdctx, out_digest, &out_len) != 1 ||
	    out_len != LOTA_RUNTIME_IMAGE_DIGEST_SIZE) {
		ret = -EIO;
		goto out;
	}
	ret = 0;

out:
	if (ret < 0)
		lota__runtime_image_bzero(out_digest,
					  LOTA_RUNTIME_IMAGE_DIGEST_SIZE);
	lota__runtime_image_bzero(le_u32, sizeof(le_u32));
	EVP_MD_CTX_free(mdctx);
	return ret;
}

#endif /* LOTA_RUNTIME_IMAGE_MEASURE_H */
