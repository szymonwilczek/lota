// SPDX-License-Identifier: MIT
//
// Runtime protected PID digest helper
//
// Computes a canonical SHA-256 digest over the runtime protected PID set:
//   SHA256("lota-runtime-protect-pids:v1\0" || count_LE || pid0_LE || ...)
//
// The PID list must be sorted in strictly increasing order.

#ifndef LOTA_RUNTIME_PROTECT_DIGEST_H
#define LOTA_RUNTIME_PROTECT_DIGEST_H

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "lota_endian.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#define LOTA_RUNTIME_PROTECT_DIGEST_SIZE 32

static inline void lota__runtime_digest_bzero(void *ptr, size_t len) {
  if (!ptr || len == 0)
    return;
  OPENSSL_cleanse(ptr, len);
}

static inline int lota_validate_canonical_protect_pid_list(const uint32_t *pids,
                                                           uint32_t pid_count) {
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

static inline int lota_compute_runtime_protect_digest(const uint32_t *pids,
                                                      uint32_t pid_count,
                                                      uint8_t out_digest[32]) {
  static const uint8_t domain[] = "lota-runtime-protect-pids:v1\0";
  EVP_MD_CTX *mdctx = NULL;
  unsigned int out_len = 0;
  uint8_t le_u32[4];
  int ret = 0;

  if (!out_digest)
    return -EINVAL;
  if (pid_count > 0 && !pids)
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
    if (EVP_DigestUpdate(mdctx, le_u32, sizeof(le_u32)) != 1) {
      ret = -EIO;
      goto out;
    }
  }

  if (EVP_DigestFinal_ex(mdctx, out_digest, &out_len) != 1 || out_len != 32) {
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
