// SPDX-License-Identifier: MIT
//
// LOTA token quote nonce (token verification domain)
//
// This helper computes the TPM quote nonce used in the *token* path (agent IPC
// GET_TOKEN and server-side token verification).
//
// Scheme:
//   token_quote_nonce = SHA256(valid_until_LE || flags_LE || pcr_mask_LE ||
//                              client_nonce || policy_digest ||
//                              runtime_protect_digest ||
//                              runtime_protect_epoch_LE)
//
// This binds TPMS_ATTEST.extraData (quote nonce) to the token's wire-format
// metadata and the client's challenge nonce.
//
// IMPORTANT:
// - This is intentionally different from the *attestation report binding nonce*
//   used by the remote attestation verifier/agent report path.
// - Do not confuse these two nonce domains; they bind different data and serve
//   different trust models.

#ifndef LOTA_TOKEN_QUOTE_NONCE_H
#define LOTA_TOKEN_QUOTE_NONCE_H

#include <errno.h>
#include <stdint.h>
#include <string.h>

#include "lota_endian.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>

#ifndef LOTA_TOKEN_NONCE_SIZE
#define LOTA_TOKEN_NONCE_SIZE 32
#endif

static inline void lota__secure_bzero(void *ptr, size_t len) {
  if (!ptr || len == 0)
    return;
  OPENSSL_cleanse(ptr, len);
}

// Computes the token quote nonce used as TPMS_ATTEST.extraData in the token
// path. Returns 0 on success, or a negative errno-style value on failure.
static inline int lota_compute_token_quote_nonce(
    uint64_t valid_until, uint32_t flags, uint32_t pcr_mask,
    const uint8_t client_nonce[LOTA_TOKEN_NONCE_SIZE],
    const uint8_t policy_digest[LOTA_TOKEN_NONCE_SIZE],
    const uint8_t runtime_protect_digest[LOTA_TOKEN_NONCE_SIZE],
    uint64_t runtime_protect_epoch, uint8_t out_nonce[LOTA_TOKEN_NONCE_SIZE]) {
  EVP_MD_CTX *mdctx = NULL;
  unsigned int len = 0;
  uint8_t prefix_le[16];
  uint8_t epoch_le[8];
  int ret = 0;

  if (!client_nonce || !policy_digest || !runtime_protect_digest || !out_nonce)
    return -EINVAL;

  lota__write_le64(prefix_le, valid_until);
  lota__write_le32(prefix_le + 8, flags);
  lota__write_le32(prefix_le + 12, pcr_mask);
  lota__write_le64(epoch_le, runtime_protect_epoch);

  mdctx = EVP_MD_CTX_new();
  if (!mdctx) {
    ret = -ENOMEM;
    goto out;
  }

  if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1 ||
      EVP_DigestUpdate(mdctx, prefix_le, sizeof(prefix_le)) != 1 ||
      EVP_DigestUpdate(mdctx, client_nonce, LOTA_TOKEN_NONCE_SIZE) != 1 ||
      EVP_DigestUpdate(mdctx, policy_digest, LOTA_TOKEN_NONCE_SIZE) != 1 ||
      EVP_DigestUpdate(mdctx, runtime_protect_digest, LOTA_TOKEN_NONCE_SIZE) !=
          1 ||
      EVP_DigestUpdate(mdctx, epoch_le, sizeof(epoch_le)) != 1 ||
      EVP_DigestFinal_ex(mdctx, out_nonce, &len) != 1 ||
      len != LOTA_TOKEN_NONCE_SIZE) {
    ret = -EIO;
    goto out;
  }

out:
  EVP_MD_CTX_free(mdctx);
  if (ret < 0)
    lota__secure_bzero(out_nonce, LOTA_TOKEN_NONCE_SIZE);
  lota__secure_bzero(prefix_le, sizeof(prefix_le));
  lota__secure_bzero(epoch_le, sizeof(epoch_le));
  return ret;
}

#endif /* LOTA_TOKEN_QUOTE_NONCE_H */
