/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - Policy File Ed25519 Signing
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include "policy_sign.h"

#include <errno.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * EAUTH is not defined on all platforms ->
 * 80 is a value that does not collide with standard errnos.
 */
#ifndef EAUTH
#define EAUTH 80
#endif

/*
 * Maximum policy file size: 64 KiB.
 */
#define POLICY_MAX_FILE_SIZE (64 * 1024)

/*
 * Read entire file into malloc'd buffer.
 * Returns buffer (caller frees) or NULL on error.
 */
static uint8_t *read_file_contents(const char *path, size_t *out_len) {
  FILE *f;
  long fsize;
  uint8_t *buf;
  size_t nread;

  f = fopen(path, "rb");
  if (!f)
    return NULL;

  if (fseek(f, 0, SEEK_END) != 0) {
    fclose(f);
    return NULL;
  }

  fsize = ftell(f);
  if (fsize < 0 || (size_t)fsize > POLICY_MAX_FILE_SIZE) {
    fclose(f);
    return NULL;
  }

  rewind(f);

  buf = malloc((size_t)fsize);
  if (!buf) {
    fclose(f);
    return NULL;
  }

  nread = fread(buf, 1, (size_t)fsize, f);
  fclose(f);

  if (nread != (size_t)fsize) {
    free(buf);
    return NULL;
  }

  *out_len = (size_t)fsize;
  return buf;
}

/*
 * Load Ed25519 private key from PEM file.
 * Returns EVP_PKEY (caller frees) or NULL on error.
 */
static EVP_PKEY *load_privkey(const char *path) {
  FILE *f;
  EVP_PKEY *pkey;

  f = fopen(path, "r");
  if (!f)
    return NULL;

  pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
  fclose(f);

  if (!pkey)
    return NULL;

  if (EVP_PKEY_id(pkey) != EVP_PKEY_ED25519) {
    EVP_PKEY_free(pkey);
    return NULL;
  }

  return pkey;
}

/*
 * Load Ed25519 public key from PEM file.
 * Returns EVP_PKEY (caller frees) or NULL on error.
 */
static EVP_PKEY *load_pubkey(const char *path) {
  FILE *f;
  EVP_PKEY *pkey;

  f = fopen(path, "r");
  if (!f)
    return NULL;

  pkey = PEM_read_PUBKEY(f, NULL, NULL, NULL);
  fclose(f);

  if (!pkey)
    return NULL;

  if (EVP_PKEY_id(pkey) != EVP_PKEY_ED25519) {
    EVP_PKEY_free(pkey);
    return NULL;
  }

  return pkey;
}

int policy_sign_generate_keypair(const char *privkey_pem_path,
                                 const char *pubkey_pem_path) {
  EVP_PKEY *pkey = NULL;
  EVP_PKEY_CTX *ctx = NULL;
  FILE *f = NULL;
  int ret = -EIO;

  if (!privkey_pem_path || !pubkey_pem_path)
    return -EINVAL;

  ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
  if (!ctx)
    return -ENOMEM;

  if (EVP_PKEY_keygen_init(ctx) <= 0)
    goto out;

  if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
    goto out;

  /* write private key (PKCS#8 PEM, no encryption) */
  f = fopen(privkey_pem_path, "w");
  if (!f) {
    ret = -errno;
    goto out;
  }

  if (!PEM_write_PrivateKey(f, pkey, NULL, NULL, 0, NULL, NULL)) {
    fclose(f);
    goto out;
  }
  fclose(f);
  f = NULL;

  /* write public key (SPKI PEM) */
  f = fopen(pubkey_pem_path, "w");
  if (!f) {
    ret = -errno;
    goto out;
  }

  if (!PEM_write_PUBKEY(f, pkey)) {
    fclose(f);
    goto out;
  }
  fclose(f);
  f = NULL;

  ret = 0;

out:
  EVP_PKEY_free(pkey);
  EVP_PKEY_CTX_free(ctx);
  return ret;
}

int policy_sign_buffer(const uint8_t *data, size_t data_len,
                       const char *privkey_pem_path, uint8_t *sig_out) {
  EVP_PKEY *pkey = NULL;
  EVP_MD_CTX *md_ctx = NULL;
  size_t sig_len = POLICY_SIG_SIZE;
  int ret = -EIO;

  if (!data || !privkey_pem_path || !sig_out)
    return -EINVAL;

  pkey = load_privkey(privkey_pem_path);
  if (!pkey)
    return -ENOENT;

  md_ctx = EVP_MD_CTX_new();
  if (!md_ctx) {
    ret = -ENOMEM;
    goto out;
  }

  /*
   * Ed25519 uses a one-shot DigestSign (md=NULL).
   * Message is passed entirely to DigestSign, not via Update.
   */
  if (EVP_DigestSignInit(md_ctx, NULL, NULL, NULL, pkey) <= 0)
    goto out;

  if (EVP_DigestSign(md_ctx, sig_out, &sig_len, data, data_len) <= 0)
    goto out;

  if (sig_len != POLICY_SIG_SIZE) {
    ret = -EIO;
    goto out;
  }

  ret = 0;

out:
  EVP_MD_CTX_free(md_ctx);
  EVP_PKEY_free(pkey);
  return ret;
}

int policy_verify_buffer(const uint8_t *data, size_t data_len,
                         const char *pubkey_pem_path, const uint8_t *sig) {
  EVP_PKEY *pkey = NULL;
  EVP_MD_CTX *md_ctx = NULL;
  int ret = -EIO;

  if (!data || !pubkey_pem_path || !sig)
    return -EINVAL;

  pkey = load_pubkey(pubkey_pem_path);
  if (!pkey)
    return -ENOENT;

  md_ctx = EVP_MD_CTX_new();
  if (!md_ctx) {
    ret = -ENOMEM;
    goto out;
  }

  if (EVP_DigestVerifyInit(md_ctx, NULL, NULL, NULL, pkey) <= 0)
    goto out;

  if (EVP_DigestVerify(md_ctx, sig, POLICY_SIG_SIZE, data, data_len) == 1) {
    ret = 0;
  } else {
    ret = -EAUTH;
  }

out:
  EVP_MD_CTX_free(md_ctx);
  EVP_PKEY_free(pkey);
  return ret;
}

int policy_sign_file(const char *file_path, const char *privkey_pem_path,
                     const char *sig_path) {
  uint8_t *data = NULL;
  size_t data_len = 0;
  uint8_t sig[POLICY_SIG_SIZE];
  FILE *f = NULL;
  int ret;

  if (!file_path || !privkey_pem_path || !sig_path)
    return -EINVAL;

  data = read_file_contents(file_path, &data_len);
  if (!data)
    return -errno ? -errno : -EIO;

  ret = policy_sign_buffer(data, data_len, privkey_pem_path, sig);
  free(data);

  if (ret != 0)
    return ret;

  /* write raw signature to .sig file */
  f = fopen(sig_path, "wb");
  if (!f)
    return -errno;

  if (fwrite(sig, 1, POLICY_SIG_SIZE, f) != POLICY_SIG_SIZE) {
    fclose(f);
    return -EIO;
  }

  fclose(f);
  return 0;
}

int policy_verify_file(const char *file_path, const char *pubkey_pem_path,
                       const char *sig_path) {
  uint8_t *data = NULL;
  size_t data_len = 0;
  uint8_t sig[POLICY_SIG_SIZE];
  FILE *f = NULL;
  size_t nread;
  int ret;

  if (!file_path || !pubkey_pem_path || !sig_path)
    return -EINVAL;

  /* read signature file */
  f = fopen(sig_path, "rb");
  if (!f)
    return -errno ? -errno : -ENOENT;

  nread = fread(sig, 1, POLICY_SIG_SIZE, f);
  fclose(f);

  if (nread != POLICY_SIG_SIZE)
    return -EAUTH;

  /* read policy file */
  data = read_file_contents(file_path, &data_len);
  if (!data)
    return -errno ? -errno : -EIO;

  ret = policy_verify_buffer(data, data_len, pubkey_pem_path, sig);
  free(data);

  return ret;
}
