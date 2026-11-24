/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Digest over the protected PIDs and each one's registry digest (see
 * lota_registry_digest.h), so the quote attests what each process runs:
 *
 *   SHA256("lota-runtime-protect-pids:v1\0" || count_LE ||
 *          pid0_LE || image0[32] || pid1_LE || image1[32] || ...)
 */

#ifndef LOTA_RUNTIME_PROTECT_DIGEST_H
#define LOTA_RUNTIME_PROTECT_DIGEST_H

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/types.h>

#include "lota_endian.h"

static inline void lota__runtime_digest_bzero(void *ptr, size_t len)
{
	if (!ptr || len == 0)
		return;
	OPENSSL_cleanse(ptr, len);
}

/**
 * lota_validate_canonical_protect_pid_list() - Check the order of a PID list.
 * @pids: the list, may be NULL if @pid_count is 0.
 *
 * Return: 0 if strictly increasing, -EINVAL otherwise.
 */
static inline int lota_validate_canonical_protect_pid_list(const uint32_t *pids,
							   uint32_t pid_count)
{
	if (pid_count == 0)
		return pids ? 0 : 0;
	if (!pids)
		return -EINVAL;

	for (uint32_t i = 1; i < pid_count; i++) {
		if (pids[i - 1] >= pids[i])
			return -EINVAL;
	}
	return 0;
}

/**
 * lota_compute_runtime_protect_digest() - Compute the digest of the PID set.
 * @pids: sorted PIDs.
 * @image_digests: one digest per entry of @pids; the agent passes zeroes for a
 *                 process it could not measure and a coverage flag says so.
 * @out_digest: receives the digest; zeroed on -EIO.
 *
 * Return: 0 on success, -EINVAL on a bad argument or an unsorted list, -ENOMEM
 * or -EIO from the hash.
 */
static inline int
lota_compute_runtime_protect_digest(const uint32_t *pids,
				    const uint8_t (*image_digests)[32],
				    uint32_t pid_count, uint8_t out_digest[32])
{
	static const uint8_t domain[] = "lota-runtime-protect-pids:v1\0";
	EVP_MD_CTX *mdctx = NULL;
	unsigned int out_len = 0;
	uint8_t le_u32[4];
	int ret = 0;

	if (!out_digest)
		return -EINVAL;
	if (pid_count > 0 && (!pids || !image_digests))
		return -EINVAL;
	if (lota_validate_canonical_protect_pid_list(pids, pid_count) != 0)
		return -EINVAL;

	mdctx = EVP_MD_CTX_new();
	if (!mdctx)
		return -ENOMEM;

	if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1 ||
	    EVP_DigestUpdate(mdctx, domain, sizeof(domain) - 1) != 1) {
		ret = -EIO;
		goto out;
	}

	lota__write_le32(le_u32, pid_count);
	if (EVP_DigestUpdate(mdctx, le_u32, sizeof(le_u32)) != 1) {
		ret = -EIO;
		goto out;
	}

	for (uint32_t i = 0; i < pid_count; i++) {
		lota__write_le32(le_u32, pids[i]);
		if (EVP_DigestUpdate(mdctx, le_u32, sizeof(le_u32)) != 1 ||
		    EVP_DigestUpdate(mdctx, image_digests[i], 32) != 1) {
			ret = -EIO;
			goto out;
		}
	}

	if (EVP_DigestFinal_ex(mdctx, out_digest, &out_len) != 1 ||
	    out_len != 32) {
		ret = -EIO;
		goto out;
	}

out:
	if (ret < 0)
		lota__runtime_digest_bzero(out_digest, 32);
	lota__runtime_digest_bzero(le_u32, sizeof(le_u32));
	EVP_MD_CTX_free(mdctx);
	return ret;
}

#endif /* LOTA_RUNTIME_PROTECT_DIGEST_H */
