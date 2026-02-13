/* SPDX-License-Identifier: MIT */
/*
 * LOTA Server-Side Token Verification SDK
 *
 * Verifies attestation tokens using OpenSSL for RSA signature
 * verification and TPMS_ATTEST parsing.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../../include/lota_server.h"

#define VERSION_STRING "1.0.0"

#define TPM_GENERATED_VALUE 0xff544347
#define TPM_ST_ATTEST_QUOTE 0x8018
#define TPM_ALG_RSASSA 0x0014
#define TPM_ALG_RSAPSS 0x0016

/*
 * Read big-endian uint16 from buffer
 */
static uint16_t read_be16(const uint8_t *p) {
  return (uint16_t)((uint16_t)p[0] << 8 | (uint16_t)p[1]);
}

/*
 * Read big-endian uint32 from buffer
 */
static uint32_t read_be32(const uint8_t *p) {
  return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 |
         (uint32_t)p[3];
}

/*
 * Read little-endian uint16 from buffer
 */
static uint16_t read_le16(const uint8_t *p) {
  return (uint16_t)((uint16_t)p[1] << 8 | (uint16_t)p[0]);
}

/*
 * Read little-endian uint32 from buffer
 */
static uint32_t read_le32(const uint8_t *p) {
  return (uint32_t)p[3] << 24 | (uint32_t)p[2] << 16 | (uint32_t)p[1] << 8 |
         (uint32_t)p[0];
}

/*
 * Read little-endian uint64 from buffer
 */
static uint64_t read_le64(const uint8_t *p) {
  return (uint64_t)read_le32(p) | ((uint64_t)read_le32(p + 4) << 32);
}

/*
 * Parse TPMS_ATTEST to extract extraData and PCR digest
 *
 * TPMS_ATTEST layout:
 *   magic:           UINT32 (big-endian, = TPM_GENERATED_VALUE)
 *   type:            TPMI_ST_ATTEST (UINT16, big-endian)
 *   qualifiedSigner: TPM2B_NAME (2-byte size + data)
 *   extraData:       TPM2B_DATA (2-byte size + data): contains nonce
 *   clockInfo:       TPMS_CLOCK_INFO (17 bytes)
 *   firmwareVersion: UINT64 (big-endian)
 *   [attested]:      TPMU_ATTEST (type-specific union)
 *     For QUOTE: TPMS_QUOTE_INFO
 *       pcrSelect:   TPML_PCR_SELECTION (4-byte count + array)
 *       pcrDigest:   TPM2B_DIGEST (2-byte size + data): PCR hash
 *
 * Returns 0 on success, -1 on parse error.
 */
static int parse_tpms_attest(const uint8_t *data, size_t len,
                             const uint8_t **extra_data, size_t *extra_data_len,
                             const uint8_t **pcr_digest,
                             size_t *pcr_digest_len) {
  size_t off = 0;

  /* minimum: magic(4) + type(2) + signer_size(2) + extra_size(2) */
  if (len < 10)
    return -1;

  /* magic */
  uint32_t magic = read_be32(data + off);
  off += 4;
  if (magic != TPM_GENERATED_VALUE)
    return -1;

  /* type */
  uint16_t type = read_be16(data + off);
  off += 2;

  /* qualifiedSigner (TPM2B_NAME) */
  if (off + 2 > len)
    return -1;
  uint16_t signer_size = read_be16(data + off);
  off += 2;
  if (off + signer_size > len)
    return -1;
  off += signer_size;

  /* extraData (TPM2B_DATA) - nonce lives here */
  if (off + 2 > len)
    return -1;
  uint16_t ed_size = read_be16(data + off);
  off += 2;
  if (off + ed_size > len)
    return -1;

  if (extra_data)
    *extra_data = data + off;
  if (extra_data_len)
    *extra_data_len = ed_size;
  off += ed_size;

  /* clockInfo: clock(8) + resetCount(4) + restartCount(4) + safe(1) = 17 */
  if (off + 17 > len)
    return -1;
  off += 17;

  /* firmwareVersion (8 bytes) */
  if (off + 8 > len)
    return -1;
  off += 8;

  if (type == TPM_ST_ATTEST_QUOTE) {
    /* TPML_PCR_SELECTION: count(4) + array */
    if (off + 4 > len)
      return -1;
    uint32_t pcr_sel_count = read_be32(data + off);
    off += 4;

    /* each TPMS_PCR_SELECTION: hash(2) + sizeOfSelect(1) + select[] */
    for (uint32_t i = 0; i < pcr_sel_count; i++) {
      if (off + 3 > len)
        return -1;
      off += 2; /* hash alg */
      uint8_t select_size = data[off];
      off += 1;
      if (off + select_size > len)
        return -1;
      off += select_size;
    }

    /* pcrDigest (TPM2B_DIGEST) */
    if (off + 2 > len)
      return -1;
    uint16_t digest_size = read_be16(data + off);
    off += 2;
    if (off + digest_size > len)
      return -1;

    if (pcr_digest)
      *pcr_digest = data + off;
    if (pcr_digest_len)
      *pcr_digest_len = digest_size;
  } else {
    /* Not a quote - no PCR digest */
    if (pcr_digest)
      *pcr_digest = NULL;
    if (pcr_digest_len)
      *pcr_digest_len = 0;
  }

  return 0;
}

/*
 * Compute expected nonce: SHA256(issued_at || valid_until || flags || nonce)
 * All integers in little-endian byte order.
 */
static int compute_expected_nonce(uint64_t issued_at, uint64_t valid_until,
                                  uint32_t flags, const uint8_t nonce[32],
                                  uint8_t out[32]) {
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx)
    return -1;

  EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
  EVP_DigestUpdate(ctx, &issued_at, 8);
  EVP_DigestUpdate(ctx, &valid_until, 8);
  EVP_DigestUpdate(ctx, &flags, 4);
  EVP_DigestUpdate(ctx, nonce, 32);

  unsigned int len = 32;
  EVP_DigestFinal_ex(ctx, out, &len);
  EVP_MD_CTX_free(ctx);
  return 0;
}

/*
 * Verify RSA signature over SHA-256(attest_data) using AIK public key
 */
static int verify_rsa_signature(const uint8_t *attest_data, size_t attest_len,
                                const uint8_t *signature, size_t sig_len,
                                uint16_t sig_alg, const uint8_t *aik_pub_der,
                                size_t aik_pub_len) {
  EVP_PKEY *pkey = NULL;
  EVP_MD_CTX *md_ctx = NULL;
  EVP_PKEY_CTX *pkey_ctx = NULL;
  const uint8_t *der_ptr;
  int ret = LOTA_SERVER_ERR_SIG_FAIL;

  /* parse DER-encoded public key (PKIX / SubjectPublicKeyInfo) */
  der_ptr = aik_pub_der;
  pkey = d2i_PUBKEY(NULL, &der_ptr, (long)aik_pub_len);
  if (!pkey)
    return LOTA_SERVER_ERR_CRYPTO;

  /* verify RSA type */
  if (EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA) {
    ret = LOTA_SERVER_ERR_CRYPTO;
    goto out;
  }

  md_ctx = EVP_MD_CTX_new();
  if (!md_ctx) {
    ret = LOTA_SERVER_ERR_CRYPTO;
    goto out;
  }

  if (sig_alg == TPM_ALG_RSAPSS) {
    /* RSASSA-PSS verification */
    if (EVP_DigestVerifyInit(md_ctx, &pkey_ctx, EVP_sha256(), NULL, pkey) != 1)
      goto out;

    if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) != 1)
      goto out;

    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, RSA_PSS_SALTLEN_DIGEST) != 1)
      goto out;
  } else if (sig_alg == TPM_ALG_RSASSA) {
    /* RSASSA-PKCS1-v1_5 */
    if (EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, pkey) != 1)
      goto out;
  } else {
    /* reject unknown signature algorithms */
    ret = LOTA_SERVER_ERR_SIG_FAIL;
    goto out;
  }

  if (EVP_DigestVerifyUpdate(md_ctx, attest_data, attest_len) != 1)
    goto out;

  if (EVP_DigestVerifyFinal(md_ctx, signature, sig_len) == 1)
    ret = LOTA_SERVER_OK;

out:
  EVP_MD_CTX_free(md_ctx);
  EVP_PKEY_free(pkey);
  return ret;
}

/*
 * Parse token header from wire format
 */
static int parse_wire_header(const uint8_t *data, size_t len,
                             struct lota_token_wire *hdr) {
  if (len < LOTA_TOKEN_HEADER_SIZE)
    return LOTA_SERVER_ERR_BAD_TOKEN;

  hdr->magic = read_le32(data + 0);
  if (hdr->magic != LOTA_TOKEN_MAGIC)
    return LOTA_SERVER_ERR_BAD_TOKEN;

  hdr->version = read_le16(data + 4);
  if (hdr->version != LOTA_TOKEN_VERSION)
    return LOTA_SERVER_ERR_BAD_VERSION;

  hdr->total_size = read_le16(data + 6);
  if (hdr->total_size > len || hdr->total_size < LOTA_TOKEN_HEADER_SIZE)
    return LOTA_SERVER_ERR_BAD_TOKEN;

  hdr->issued_at = read_le64(data + 8);
  hdr->valid_until = read_le64(data + 16);
  hdr->flags = read_le32(data + 24);
  memcpy(hdr->nonce, data + 28, 32);
  hdr->sig_alg = read_le16(data + 60);
  hdr->hash_alg = read_le16(data + 62);
  hdr->pcr_mask = read_le32(data + 64);
  hdr->attest_size = read_le16(data + 68);
  hdr->sig_size = read_le16(data + 70);

  /* validate sizes */
  size_t expected =
      (size_t)LOTA_TOKEN_HEADER_SIZE + hdr->attest_size + hdr->sig_size;
  if (expected > (size_t)hdr->total_size)
    return LOTA_SERVER_ERR_BAD_TOKEN;
  if (hdr->attest_size > 1024 || hdr->sig_size > 512)
    return LOTA_SERVER_ERR_BAD_TOKEN;

  return LOTA_SERVER_OK;
}

int lota_server_verify_token(const uint8_t *token_data, size_t token_len,
                             const uint8_t *aik_pub_der, size_t aik_pub_len,
                             const uint8_t *expected_nonce,
                             uint32_t max_age_sec,
                             struct lota_server_claims *claims) {
  struct lota_token_wire hdr;
  int ret;
  uint32_t effective_max_age;

  if (!token_data || !aik_pub_der || !claims)
    return LOTA_SERVER_ERR_INVALID_ARG;
  if (token_len == 0 || aik_pub_len == 0)
    return LOTA_SERVER_ERR_INVALID_ARG;

  effective_max_age =
      (max_age_sec > 0) ? max_age_sec : LOTA_TOKEN_DEFAULT_MAX_AGE;

  memset(claims, 0, sizeof(*claims));

  /* parse wire format */
  ret = parse_wire_header(token_data, token_len, &hdr);
  if (ret != LOTA_SERVER_OK)
    return ret;

  const uint8_t *attest_data = token_data + LOTA_TOKEN_HEADER_SIZE;
  const uint8_t *signature = attest_data + hdr.attest_size;

  /* verify RSA signature over attest_data */
  if (hdr.attest_size == 0 || hdr.sig_size == 0)
    return LOTA_SERVER_ERR_BAD_TOKEN;

  ret =
      verify_rsa_signature(attest_data, hdr.attest_size, signature,
                           hdr.sig_size, hdr.sig_alg, aik_pub_der, aik_pub_len);
  if (ret != LOTA_SERVER_OK)
    return ret;

  /* parse TPMS_ATTEST - extract extraData and PCR digest */
  const uint8_t *extra_data = NULL;
  size_t extra_data_len = 0;
  const uint8_t *pcr_digest = NULL;
  size_t pcr_digest_len = 0;

  if (parse_tpms_attest(attest_data, hdr.attest_size, &extra_data,
                        &extra_data_len, &pcr_digest, &pcr_digest_len) != 0) {
    return LOTA_SERVER_ERR_ATTEST_PARSE;
  }

  /* verify nonce binding: extraData ==
   * SHA256(issued_at||valid_until||flags||nonce) */
  uint8_t computed_nonce[32];
  if (compute_expected_nonce(hdr.issued_at, hdr.valid_until, hdr.flags,
                             hdr.nonce, computed_nonce) != 0) {
    return LOTA_SERVER_ERR_NONCE_FAIL;
  }

  if (extra_data_len != 32 || memcmp(extra_data, computed_nonce, 32) != 0) {
    return LOTA_SERVER_ERR_NONCE_FAIL;
  }

  /* verify client nonce if expected_nonce is provided */
  if (expected_nonce) {
    if (memcmp(hdr.nonce, expected_nonce, 32) != 0)
      return LOTA_SERVER_ERR_NONCE_FAIL;
  }

  /* fill claims */
  claims->issued_at = hdr.issued_at;
  claims->valid_until = hdr.valid_until;
  claims->flags = hdr.flags;
  memcpy(claims->nonce, hdr.nonce, 32);
  claims->pcr_mask = hdr.pcr_mask;

  if (pcr_digest && pcr_digest_len > 0 && pcr_digest_len <= 32) {
    memcpy(claims->pcr_digest, pcr_digest, pcr_digest_len);
    claims->pcr_digest_len = pcr_digest_len;
  }

  /* check expiry */
  uint64_t now = (uint64_t)time(NULL);
  claims->expired = (hdr.valid_until > 0 && now > hdr.valid_until) ? 1 : 0;

  /* check freshness against caller-specified max age */
  claims->age_seconds = (int64_t)now - (int64_t)hdr.issued_at;
  claims->too_old = (claims->age_seconds > (int64_t)effective_max_age) ? 1 : 0;
  claims->issued_in_future =
      (claims->age_seconds < -(int64_t)LOTA_TOKEN_MAX_CLOCK_SKEW) ? 1 : 0;

  /* hard rejection: expired, too old, or future */
  if (claims->expired)
    return LOTA_SERVER_ERR_EXPIRED;
  if (claims->too_old)
    return LOTA_SERVER_ERR_TOO_OLD;
  if (claims->issued_in_future)
    return LOTA_SERVER_ERR_FUTURE;

  return LOTA_SERVER_OK;
}

int lota_server_parse_token(const uint8_t *token_data, size_t token_len,
                            uint32_t max_age_sec,
                            struct lota_server_claims *claims) {
  struct lota_token_wire hdr;
  int ret;
  uint32_t effective_max_age;

  if (!token_data || !claims)
    return LOTA_SERVER_ERR_INVALID_ARG;

  effective_max_age =
      (max_age_sec > 0) ? max_age_sec : LOTA_TOKEN_DEFAULT_MAX_AGE;

  memset(claims, 0, sizeof(*claims));

  ret = parse_wire_header(token_data, token_len, &hdr);
  if (ret != LOTA_SERVER_OK)
    return ret;

  claims->issued_at = hdr.issued_at;
  claims->valid_until = hdr.valid_until;
  claims->flags = hdr.flags;
  memcpy(claims->nonce, hdr.nonce, 32);
  claims->pcr_mask = hdr.pcr_mask;

  /* try to extract PCR digest from TPMS_ATTEST */
  if (hdr.attest_size > 0) {
    const uint8_t *attest_data = token_data + LOTA_TOKEN_HEADER_SIZE;
    const uint8_t *pcr_digest = NULL;
    size_t pcr_digest_len = 0;

    if (parse_tpms_attest(attest_data, hdr.attest_size, NULL, NULL, &pcr_digest,
                          &pcr_digest_len) == 0) {
      if (pcr_digest && pcr_digest_len > 0 && pcr_digest_len <= 32) {
        memcpy(claims->pcr_digest, pcr_digest, pcr_digest_len);
        claims->pcr_digest_len = pcr_digest_len;
      }
    }
  }

  uint64_t now = (uint64_t)time(NULL);
  claims->expired = (hdr.valid_until > 0 && now > hdr.valid_until) ? 1 : 0;

  /* check freshness against caller-specified max age */
  claims->age_seconds = (int64_t)now - (int64_t)hdr.issued_at;
  claims->too_old = (claims->age_seconds > (int64_t)effective_max_age) ? 1 : 0;
  claims->issued_in_future =
      (claims->age_seconds < -(int64_t)LOTA_TOKEN_MAX_CLOCK_SKEW) ? 1 : 0;

  return LOTA_SERVER_OK;
}

const char *lota_server_strerror(int error) {
  switch (error) {
  case LOTA_SERVER_OK:
    return "Success";
  case LOTA_SERVER_ERR_INVALID_ARG:
    return "Invalid argument";
  case LOTA_SERVER_ERR_BAD_TOKEN:
    return "Malformed token";
  case LOTA_SERVER_ERR_BAD_VERSION:
    return "Unsupported token version";
  case LOTA_SERVER_ERR_SIG_FAIL:
    return "Signature verification failed";
  case LOTA_SERVER_ERR_NONCE_FAIL:
    return "Nonce mismatch";
  case LOTA_SERVER_ERR_EXPIRED:
    return "Token expired";
  case LOTA_SERVER_ERR_ATTEST_PARSE:
    return "Failed to parse TPMS_ATTEST";
  case LOTA_SERVER_ERR_CRYPTO:
    return "Cryptographic error";
  case LOTA_SERVER_ERR_BUFFER:
    return "Buffer too small";
  case LOTA_SERVER_ERR_TOO_OLD:
    return "Token too old (exceeds max_age_sec)";
  case LOTA_SERVER_ERR_FUTURE:
    return "Token issued in the future";
  default:
    return "Unknown error";
  }
}

const char *lota_server_sdk_version(void) { return VERSION_STRING; }
