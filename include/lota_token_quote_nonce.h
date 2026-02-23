// SPDX-License-Identifier: MIT
//
// LOTA token quote nonce (token verification domain)
//
// This helper computes the TPM quote nonce used in the *token* path (agent IPC
// GET_TOKEN and server-side token verification).
//
// Scheme:
//   token_quote_nonce = SHA256(valid_until_LE || flags_LE || client_nonce)
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

static inline void lota__write_le32(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v);
  p[1] = (uint8_t)(v >> 8);
  p[2] = (uint8_t)(v >> 16);
  p[3] = (uint8_t)(v >> 24);
}

static inline void lota__write_le64(uint8_t *p, uint64_t v) {
  lota__write_le32(p, (uint32_t)v);
  lota__write_le32(p + 4, (uint32_t)(v >> 32));
}

// Computes the token quote nonce used as TPMS_ATTEST.extraData in the token
// path. Returns 0 on success, or a negative errno-style value on failure.
static inline int lota_compute_token_quote_nonce(
    uint64_t valid_until, uint32_t flags,
    const uint8_t client_nonce[LOTA_TOKEN_NONCE_SIZE],
    uint8_t out_nonce[LOTA_TOKEN_NONCE_SIZE]) {
  EVP_MD_CTX *mdctx = NULL;
  unsigned int len = 0;
  uint8_t le_buf[12];
  int ret = 0;

  if (!client_nonce || !out_nonce)
    return -EINVAL;

  lota__write_le64(le_buf, valid_until);
  lota__write_le32(le_buf + 8, flags);

  mdctx = EVP_MD_CTX_new();
  if (!mdctx) {
    ret = -ENOMEM;
    goto out;
  }

  if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1 ||
      EVP_DigestUpdate(mdctx, le_buf, sizeof(le_buf)) != 1 ||
      EVP_DigestUpdate(mdctx, client_nonce, LOTA_TOKEN_NONCE_SIZE) != 1 ||
      EVP_DigestFinal_ex(mdctx, out_nonce, &len) != 1 ||
      len != LOTA_TOKEN_NONCE_SIZE) {
    ret = -EIO;
    goto out;
  }

out:
  EVP_MD_CTX_free(mdctx);
  if (ret < 0)
    lota__secure_bzero(out_nonce, LOTA_TOKEN_NONCE_SIZE);
  lota__secure_bzero(le_buf, sizeof(le_buf));
  return ret;
}

#endif /* LOTA_TOKEN_QUOTE_NONCE_H */
