/* SPDX-License-Identifier: MIT */
/*
 * LOTA - TPM 2.0 Operations Module
 * Implementation using libtss2-esys
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/encoder.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_tcti.h>
#include <tss2/tss2_tcti_device.h>

#include "quote.h"
#include "tpm.h"

/* Read buffer size for file hashing */
#define HASH_READ_BUF_SIZE (64 * 1024)

/*
 * Helper: Convert TSS2 return code to errno
 */
static int tss2_rc_to_errno(TSS2_RC rc) {
  if (rc == TSS2_RC_SUCCESS)
    return 0;

  /* common errors */
  switch (rc) {
  case TSS2_TCTI_RC_NO_CONNECTION:
    return -ENODEV;
  case TSS2_ESYS_RC_BAD_REFERENCE:
    return -EINVAL;
  case TSS2_ESYS_RC_MEMORY:
    return -ENOMEM;
  default:
    return -EIO;
  }
}

int tpm_init(struct tpm_context *ctx) {
  TSS2_RC rc;
  size_t tcti_size;
  uint32_t saved_handle;

  if (!ctx)
    return -EINVAL;

  /* preserve caller-configured handle across memset */
  saved_handle = ctx->aik_handle;
  memset(ctx, 0, sizeof(*ctx));
  ctx->aik_handle = saved_handle;

  /*
   * Initialize TCTI context for device access.
   * First call with NULL to get required size.
   */
  rc = Tss2_Tcti_Device_Init(NULL, &tcti_size, TPM_DEVICE_PATH);
  if (rc != TSS2_RC_SUCCESS)
    return tss2_rc_to_errno(rc);

  ctx->tcti_ctx = calloc(1, tcti_size);
  if (!ctx->tcti_ctx)
    return -ENOMEM;

  rc = Tss2_Tcti_Device_Init(ctx->tcti_ctx, &tcti_size, TPM_DEVICE_PATH);
  if (rc != TSS2_RC_SUCCESS) {
    free(ctx->tcti_ctx);
    ctx->tcti_ctx = NULL;
    return tss2_rc_to_errno(rc);
  }

  /*
   * Initialize ESYS context using the TCTI.
   * ESYS provides high-level TPM 2.0 API.
   */
  rc = Esys_Initialize(&ctx->esys_ctx, ctx->tcti_ctx, NULL);
  if (rc != TSS2_RC_SUCCESS) {
    Tss2_Tcti_Finalize(ctx->tcti_ctx);
    free(ctx->tcti_ctx);
    ctx->tcti_ctx = NULL;
    return tss2_rc_to_errno(rc);
  }

  ctx->initialized = true;

  /* default AIK handle if not pre-configured */
  if (!ctx->aik_handle)
    ctx->aik_handle = TPM_AIK_HANDLE;

  return 0;
}

void tpm_cleanup(struct tpm_context *ctx) {
  if (!ctx)
    return;

  if (ctx->esys_ctx) {
    Esys_Finalize(&ctx->esys_ctx);
    ctx->esys_ctx = NULL;
  }

  if (ctx->tcti_ctx) {
    Tss2_Tcti_Finalize(ctx->tcti_ctx);
    free(ctx->tcti_ctx);
    ctx->tcti_ctx = NULL;
  }

  ctx->initialized = false;
}

int tpm_self_test(struct tpm_context *ctx) {
  TSS2_RC rc;

  if (!ctx || !ctx->initialized)
    return -EINVAL;

  /*
   * Run TPM self-test.
   * fullTest=YES means run all diagnostics.
   */
  rc = Esys_SelfTest(ctx->esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                     TPM2_YES);

  return tss2_rc_to_errno(rc);
}

int tpm_read_pcr(struct tpm_context *ctx, uint32_t pcr_index,
                 TPM2_ALG_ID hash_alg, uint8_t *value) {
  TSS2_RC rc;
  TPML_PCR_SELECTION pcr_selection;
  TPML_DIGEST *pcr_values = NULL;
  uint32_t pcr_update_counter;
  TPML_PCR_SELECTION *pcr_selection_out = NULL;

  if (!ctx || !ctx->initialized || !value)
    return -EINVAL;

  if (pcr_index >= LOTA_PCR_COUNT)
    return -EINVAL;

  /* PCR selection for single PCR */
  memset(&pcr_selection, 0, sizeof(pcr_selection));
  pcr_selection.count = 1;
  pcr_selection.pcrSelections[0].hash = hash_alg;
  pcr_selection.pcrSelections[0].sizeofSelect = 3; /* 24 PCRs = 3 bytes */

  /* set bit for requested pcr */
  pcr_selection.pcrSelections[0].pcrSelect[pcr_index / 8] =
      (1 << (pcr_index % 8));

  rc = Esys_PCR_Read(ctx->esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                     &pcr_selection, &pcr_update_counter, &pcr_selection_out,
                     &pcr_values);

  if (rc != TSS2_RC_SUCCESS)
    return tss2_rc_to_errno(rc);

  /* copy pcr value to output */
  if (!pcr_values || pcr_values->count == 0) {
    Esys_Free(pcr_values);
    Esys_Free(pcr_selection_out);
    return -ENODATA;
  }

  size_t copy_size = pcr_values->digests[0].size;
  if (copy_size > LOTA_HASH_SIZE)
    copy_size = LOTA_HASH_SIZE;
  memcpy(value, pcr_values->digests[0].buffer, copy_size);

  /* TPM-allocated memory */
  Esys_Free(pcr_values);
  Esys_Free(pcr_selection_out);

  return 0;
}

int tpm_read_pcrs_batch(struct tpm_context *ctx, uint32_t pcr_mask,
                        uint8_t values[LOTA_PCR_COUNT][LOTA_HASH_SIZE]) {
  int ret;
  uint32_t i;

  if (!ctx || !values)
    return -EINVAL;

  memset(values, 0, LOTA_PCR_COUNT * LOTA_HASH_SIZE);

  /*
   * Read PCRs one by one.
   * TPM2_PCR_Read can read multiple PCRs but the response
   * structure is complex. For simplicity, we iterate.
   */
  for (i = 0; i < LOTA_PCR_COUNT; i++) {
    if (!(pcr_mask & (1U << i)))
      continue;

    ret = tpm_read_pcr(ctx, i, TPM_HASH_ALG, values[i]);
    if (ret < 0)
      return ret;
  }

  return 0;
}

/*
 * Check if AIK exists at persistent handle.
 * Returns: 1 if exists, 0 if not, negative errno on error
 */
static int aik_exists(struct tpm_context *ctx, ESYS_TR *handle_out) {
  TSS2_RC rc;
  ESYS_TR key_handle = ESYS_TR_NONE;

  rc = Esys_TR_FromTPMPublic(ctx->esys_ctx, ctx->aik_handle, ESYS_TR_NONE,
                             ESYS_TR_NONE, ESYS_TR_NONE, &key_handle);
  if (rc == TSS2_RC_SUCCESS) {
    if (handle_out)
      *handle_out = key_handle;
    return 1;
  }

  /* TPM2_RC_HANDLE means the object doesn't exist */
  if ((rc & 0xFF) == TPM2_RC_HANDLE)
    return 0;

  return tss2_rc_to_errno(rc);
}

/*
 * create_aik_primary - Create a transient AIK primary key
 * @ctx: Initialized TPM context
 * @out_handle: Receives the transient key handle on success
 *
 * Creates an RSA 2048-bit restricted signing key under the Owner
 * Hierarchy.  The caller is responsible for persisting or flushing
 * the returned transient handle.
 *
 * Returns: 0 on success, negative errno on failure
 */
static int create_aik_primary(struct tpm_context *ctx, ESYS_TR *out_handle) {
  TSS2_RC rc;
  TPM2B_PUBLIC *out_public = NULL;
  TPM2B_CREATION_DATA *creation_data = NULL;
  TPM2B_DIGEST *creation_hash = NULL;
  TPMT_TK_CREATION *creation_ticket = NULL;

  /*
   * RSA 2048-bit signing key template for attestation.
   *
   * Properties overview:
   *   - fixedTPM: Key cannot be duplicated
   *   - fixedParent: Cannot be moved to different parent
   *   - sensitiveDataOrigin: TPM generated the private portion
   *   - userWithAuth: Requires auth for use
   *   - restricted: Can only sign TPM-generated data (quotes)
   *   - sign: Signing key (not encryption)
   */
  TPM2B_PUBLIC in_public = {
      .size = 0,
      .publicArea =
          {
              .type = TPM2_ALG_RSA,
              .nameAlg = TPM2_ALG_SHA256,
              .objectAttributes =
                  (TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
                   TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH |
                   TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_SIGN_ENCRYPT),
              .authPolicy = {.size = 0},
              .parameters.rsaDetail =
                  {
                      .symmetric = {.algorithm = TPM2_ALG_NULL},
                      .scheme =
                          {
                              .scheme = TPM2_ALG_RSASSA,
                              .details.rsassa.hashAlg = TPM2_ALG_SHA256,
                          },
                      .keyBits = 2048,
                      .exponent = 0, /* default: 65537 */
                  },
              .unique.rsa = {.size = 0},
          },
  };

  TPM2B_SENSITIVE_CREATE in_sensitive = {
      .size = 0,
      .sensitive =
          {
              .userAuth = {.size = 0}, /* empty auth */
              .data = {.size = 0},
          },
  };

  TPM2B_DATA outside_info = {.size = 0};
  TPML_PCR_SELECTION creation_pcr = {.count = 0};

  rc = Esys_CreatePrimary(ctx->esys_ctx, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD,
                          ESYS_TR_NONE, ESYS_TR_NONE, &in_sensitive, &in_public,
                          &outside_info, &creation_pcr, out_handle, &out_public,
                          &creation_data, &creation_hash, &creation_ticket);

  Esys_Free(out_public);
  Esys_Free(creation_data);
  Esys_Free(creation_hash);
  Esys_Free(creation_ticket);

  if (rc != TSS2_RC_SUCCESS)
    return tss2_rc_to_errno(rc);

  return 0;
}

int tpm_provision_aik(struct tpm_context *ctx) {
  TSS2_RC rc;
  int ret;
  ESYS_TR primary_handle = ESYS_TR_NONE;
  ESYS_TR persistent_handle = ESYS_TR_NONE;

  if (!ctx || !ctx->initialized)
    return -EINVAL;

  ret = aik_exists(ctx, NULL);
  if (ret < 0)
    return ret;
  if (ret == 1) {
    return 0;
  }

  /*
   * Create primary key under Owner Hierarchy.
   * Owner hierarchy allows unrestricted use of signing keys.
   */
  ret = create_aik_primary(ctx, &primary_handle);
  if (ret < 0)
    return ret;

  /*
   * Make key persistent at ctx->aik_handle.
   * Persistent keys survive TPM reset and power cycles.
   */
  rc = Esys_EvictControl(ctx->esys_ctx, ESYS_TR_RH_OWNER, primary_handle,
                         ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                         ctx->aik_handle, &persistent_handle);

  Esys_FlushContext(ctx->esys_ctx, primary_handle);

  if (rc != TSS2_RC_SUCCESS)
    return tss2_rc_to_errno(rc);

  return 0;
}

int tpm_quote(struct tpm_context *ctx, const uint8_t *nonce, uint32_t pcr_mask,
              struct tpm_quote_response *response) {
  TSS2_RC rc;
  int ret;
  ESYS_TR key_handle = ESYS_TR_NONE;
  TPM2B_DATA qualifying_data;
  TPMT_SIG_SCHEME in_scheme;
  TPML_PCR_SELECTION pcr_selection;
  TPM2B_ATTEST *quoted = NULL;
  TPMT_SIGNATURE *signature = NULL;
  uint32_t i;

  if (!ctx || !ctx->initialized || !nonce || !response)
    return -EINVAL;

  memset(response, 0, sizeof(*response));

  ret = aik_exists(ctx, &key_handle);
  if (ret < 0)
    return ret;
  if (ret == 0)
    return -ENOKEY;

  /*
   * Set empty auth value for the AIK.
   * LOTA AIK was created with empty userAuth.
   */
  {
    TPM2B_AUTH auth_value = {.size = 0};
    rc = Esys_TR_SetAuth(ctx->esys_ctx, key_handle, &auth_value);
    if (rc != TSS2_RC_SUCCESS)
      return tss2_rc_to_errno(rc);
  }

  memcpy(response->nonce, nonce, LOTA_NONCE_SIZE);
  response->pcr_mask = pcr_mask;
  response->hash_alg = TPM_HASH_ALG;

  /* current PCR values */
  ret = tpm_read_pcrs_batch(ctx, pcr_mask, response->pcr_values);
  if (ret < 0)
    return ret;

  /* qualifying data (nonce) */
  qualifying_data.size = LOTA_NONCE_SIZE;
  memcpy(qualifying_data.buffer, nonce, LOTA_NONCE_SIZE);

  /* TPM choose signing scheme based on key */
  in_scheme.scheme = TPM2_ALG_NULL;

  /* PCR selection from mask */
  memset(&pcr_selection, 0, sizeof(pcr_selection));
  pcr_selection.count = 1;
  pcr_selection.pcrSelections[0].hash = TPM_HASH_ALG;
  pcr_selection.pcrSelections[0].sizeofSelect = 3;

  for (i = 0; i < LOTA_PCR_COUNT && i < 24; i++) {
    if (pcr_mask & (1U << i)) {
      pcr_selection.pcrSelections[0].pcrSelect[i / 8] |= (1 << (i % 8));
    }
  }

  /*
   * Generate Quote.
   * TPM signs: TPMS_ATTEST containing:
   *   - magic (TPM_GENERATED)
   *   - type (TPM_ST_ATTEST_QUOTE)
   *   - qualifiedSigner (AIK name)
   *   - extraData (nonce)
   *   - clockInfo
   *   - firmwareVersion
   *   - quote (PCR selection + digest)
   */
  rc = Esys_Quote(ctx->esys_ctx, key_handle, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                  ESYS_TR_NONE, &qualifying_data, &in_scheme, &pcr_selection,
                  &quoted, &signature);
  if (rc != TSS2_RC_SUCCESS)
    return tss2_rc_to_errno(rc);

  /* raw attestation data */
  if (quoted->size > LOTA_MAX_ATTEST_SIZE) {
    Esys_Free(quoted);
    Esys_Free(signature);
    return -ENOSPC;
  }
  memcpy(response->attest_data, quoted->attestationData, quoted->size);
  response->attest_size = quoted->size;

  response->sig_alg = signature->sigAlg;

  if (signature->sigAlg == TPM2_ALG_RSASSA) {
    size_t sig_size = signature->signature.rsassa.sig.size;
    if (sig_size > LOTA_MAX_SIG_SIZE) {
      Esys_Free(quoted);
      Esys_Free(signature);
      return -ENOSPC;
    }
    memcpy(response->signature, signature->signature.rsassa.sig.buffer,
           sig_size);
    response->signature_size = (uint16_t)sig_size;
  } else if (signature->sigAlg == TPM2_ALG_RSAPSS) {
    size_t sig_size = signature->signature.rsapss.sig.size;
    if (sig_size > LOTA_MAX_SIG_SIZE) {
      Esys_Free(quoted);
      Esys_Free(signature);
      return -ENOSPC;
    }
    memcpy(response->signature, signature->signature.rsapss.sig.buffer,
           sig_size);
    response->signature_size = (uint16_t)sig_size;
  } else {
    /* unknown signature algorithm - reject */
    Esys_Free(quoted);
    Esys_Free(signature);
    return -ENOTSUP;
  }

  Esys_Free(quoted);
  Esys_Free(signature);

  return 0;
}

int tpm_hash_fd(int fd, uint8_t *hash) {
  ssize_t n;
  EVP_MD_CTX *md_ctx;
  uint8_t *buf;
  unsigned int hash_len;
  int ret = 0;

  if (fd < 0 || !hash)
    return -EINVAL;

  buf = malloc(HASH_READ_BUF_SIZE);
  if (!buf)
    return -ENOMEM;

  md_ctx = EVP_MD_CTX_new();
  if (!md_ctx) {
    free(buf);
    return -ENOMEM;
  }

  if (EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) != 1) {
    ret = -EIO;
    goto cleanup;
  }

  for (;;) {
    n = read(fd, buf, HASH_READ_BUF_SIZE);
    if (n > 0) {
      if (EVP_DigestUpdate(md_ctx, buf, (size_t)n) != 1) {
        ret = -EIO;
        goto cleanup;
      }
      continue;
    }

    if (n == 0)
      break;

    if (errno == EINTR)
      continue;

    ret = -errno;
    goto cleanup;
  }

  if (EVP_DigestFinal_ex(md_ctx, hash, &hash_len) != 1) {
    ret = -EIO;
    goto cleanup;
  }

cleanup:
  EVP_MD_CTX_free(md_ctx);
  free(buf);

  return ret;
}

int tpm_hash_file(const char *path, uint8_t *hash) {
  int fd;
  int ret;

  if (!path || !hash)
    return -EINVAL;

  fd = open(path, O_RDONLY);
  if (fd < 0)
    return -errno;

  ret = tpm_hash_fd(fd, hash);
  close(fd);

  return ret;
}

int tpm_get_current_kernel_path(char *buf, size_t buf_len) {
  struct utsname uname_buf;
  int ret;

  if (!buf || buf_len == 0)
    return -EINVAL;

  ret = uname(&uname_buf);
  if (ret < 0)
    return -errno;

  ret = snprintf(buf, buf_len, "/boot/vmlinuz-%s", uname_buf.release);
  if (ret < 0 || (size_t)ret >= buf_len)
    return -ENAMETOOLONG;

  /* verify file exists */
  if (access(buf, R_OK) != 0)
    return -errno;

  return 0;
}

int tpm_pcr_extend(struct tpm_context *ctx, uint32_t pcr_index,
                   const uint8_t *digest) {
  TSS2_RC rc;
  ESYS_TR pcr_handle;
  TPML_DIGEST_VALUES digests;

  if (!ctx || !ctx->initialized || !digest)
    return -EINVAL;

  if (pcr_index >= LOTA_PCR_COUNT)
    return -EINVAL;

  /*
   * PCR handles in ESAPI are predefined constants.
   * ESYS_TR_PCR0 through ESYS_TR_PCR31 map directly to PCR indices.
   */
  pcr_handle = ESYS_TR_PCR0 + pcr_index;

  /*
   * Prepare digest structure.
   * Extend with SHA-256 only (matching PCR bank).
   */
  memset(&digests, 0, sizeof(digests));
  digests.count = 1;
  digests.digests[0].hashAlg = TPM_HASH_ALG;
  memcpy(digests.digests[0].digest.sha256, digest, LOTA_HASH_SIZE);

  /*
   * PCR_Extend operation.
   * This cryptographically extends the PCR:
   *   new_value = Hash(old_value || digest)
   *
   * PCRs 0-15 are typically locked after boot (platform auth).
   * PCRs 16-23 are available for OS/application use.
   * PCR 14 for LOTA self-measurement.
   */
  rc = Esys_PCR_Extend(ctx->esys_ctx, pcr_handle, ESYS_TR_PASSWORD,
                       ESYS_TR_NONE, ESYS_TR_NONE, &digests);
  if (rc != TSS2_RC_SUCCESS)
    return tss2_rc_to_errno(rc);

  return 0;
}

int tpm_get_aik_public(struct tpm_context *ctx, uint8_t *buf, size_t buf_size,
                       size_t *out_size) {
  TSS2_RC rc;
  int ret;
  ESYS_TR key_handle = ESYS_TR_NONE;
  TPM2B_PUBLIC *out_public = NULL;
  TPM2B_NAME *name = NULL;
  TPM2B_NAME *qualified_name = NULL;
  EVP_PKEY *pkey = NULL;
  EVP_PKEY_CTX *pctx = NULL;
  OSSL_PARAM_BLD *bld = NULL;
  OSSL_PARAM *params = NULL;
  BIGNUM *n = NULL;
  BIGNUM *e = NULL;
  int der_len = 0;

  if (!ctx || !ctx->initialized || !buf || !out_size)
    return -EINVAL;

  *out_size = 0;

  ret = aik_exists(ctx, &key_handle);
  if (ret < 0)
    return ret;
  if (ret == 0)
    return -ENOKEY;

  /* read public portion of AIK */
  rc = Esys_ReadPublic(ctx->esys_ctx, key_handle, ESYS_TR_NONE, ESYS_TR_NONE,
                       ESYS_TR_NONE, &out_public, &name, &qualified_name);
  if (rc != TSS2_RC_SUCCESS) {
    ret = tss2_rc_to_errno(rc);
    goto cleanup;
  }

  /* verify its RSA */
  if (out_public->publicArea.type != TPM2_ALG_RSA) {
    ret = -EINVAL;
    goto cleanup;
  }

  /*
   * Convert TPM RSA public key to OpenSSL EVP_PKEY.
   */
  n = BN_bin2bn(out_public->publicArea.unique.rsa.buffer,
                out_public->publicArea.unique.rsa.size, NULL);
  if (!n) {
    ret = -ENOMEM;
    goto cleanup;
  }

  uint32_t exp_val = out_public->publicArea.parameters.rsaDetail.exponent;
  if (exp_val == 0)
    exp_val = 65537; /* TPM default */

  e = BN_new();
  if (!e || !BN_set_word(e, exp_val)) {
    ret = -ENOMEM;
    goto cleanup;
  }

  bld = OSSL_PARAM_BLD_new();
  if (!bld) {
    ret = -ENOMEM;
    goto cleanup;
  }

  if (!OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_N, n) ||
      !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_RSA_E, e)) {
    ret = -EINVAL;
    goto cleanup;
  }

  params = OSSL_PARAM_BLD_to_param(bld);
  if (!params) {
    ret = -ENOMEM;
    goto cleanup;
  }

  pctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL);
  if (!pctx) {
    ret = -ENOMEM;
    goto cleanup;
  }

  if (EVP_PKEY_fromdata_init(pctx) <= 0) {
    ret = -EINVAL;
    goto cleanup;
  }

  if (EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
    ret = -EINVAL;
    goto cleanup;
  }

  /*
   * Encode as DER SubjectPublicKeyInfo using i2d_PUBKEY.
   */
  der_len = i2d_PUBKEY(pkey, NULL);
  if (der_len < 0) {
    ret = -EINVAL;
    goto cleanup;
  }

  if ((size_t)der_len > buf_size) {
    ret = -ENOSPC;
    goto cleanup;
  }

  unsigned char *p = buf;
  der_len = i2d_PUBKEY(pkey, &p);
  if (der_len < 0) {
    ret = -EINVAL;
    goto cleanup;
  }

  *out_size = der_len;
  ret = 0;

cleanup:
  if (pctx)
    EVP_PKEY_CTX_free(pctx);
  if (params)
    OSSL_PARAM_free(params);
  if (bld)
    OSSL_PARAM_BLD_free(bld);
  if (pkey)
    EVP_PKEY_free(pkey);
  if (n)
    BN_free(n);
  if (e)
    BN_free(e);
  if (out_public)
    Esys_Free(out_public);
  if (name)
    Esys_Free(name);
  if (qualified_name)
    Esys_Free(qualified_name);

  return ret;
}

/*
 * Standard EK template handle for RSA 2048.
 * TCG EK Credential Profile specifies this as the standard location.
 */
#define TPM_EK_RSA_HANDLE 0x81010001

int tpm_get_hardware_id(struct tpm_context *ctx, uint8_t *hardware_id) {
  TSS2_RC rc;
  ESYS_TR ek_handle = ESYS_TR_NONE;
  TPM2B_PUBLIC *ek_public = NULL;
  TPM2B_NAME *ek_name = NULL;
  TPM2B_NAME *ek_qualified_name = NULL;
  EVP_MD_CTX *md_ctx = NULL;
  unsigned int hash_len;
  int ret = 0;

  if (!ctx || !ctx->initialized || !hardware_id)
    return -EINVAL;

  memset(hardware_id, 0, LOTA_HARDWARE_ID_SIZE);

  /*
   * Try to read EK from standard persistent handle.
   * Most TPMs have EK provisioned at 0x81010001.
   */
  rc = Esys_TR_FromTPMPublic(ctx->esys_ctx, TPM_EK_RSA_HANDLE, ESYS_TR_NONE,
                             ESYS_TR_NONE, ESYS_TR_NONE, &ek_handle);
  if (rc != TSS2_RC_SUCCESS) {
    /*
     * EK not at standard handle - this is common.
     * Fall back to using AIK fingerprint as hardware ID.
     * Less ideal but still unique per TPM installation.
     */
    uint8_t aik_buf[LOTA_MAX_AIK_PUB_SIZE];
    size_t aik_size;

    ret = tpm_get_aik_public(ctx, aik_buf, sizeof(aik_buf), &aik_size);
    if (ret < 0)
      return ret;

    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx)
      return -ENOMEM;

    if (EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(md_ctx, aik_buf, aik_size) != 1 ||
        EVP_DigestFinal_ex(md_ctx, hardware_id, &hash_len) != 1) {
      EVP_MD_CTX_free(md_ctx);
      return -EIO;
    }

    EVP_MD_CTX_free(md_ctx);
    return 1; /* AIK fallback */
  }

  rc = Esys_ReadPublic(ctx->esys_ctx, ek_handle, ESYS_TR_NONE, ESYS_TR_NONE,
                       ESYS_TR_NONE, &ek_public, &ek_name, &ek_qualified_name);
  if (rc != TSS2_RC_SUCCESS) {
    ret = tss2_rc_to_errno(rc);
    goto cleanup;
  }

  /*
   * Hash the EK public key modulus.
   * For RSA, the modulus is the unique part.
   */
  md_ctx = EVP_MD_CTX_new();
  if (!md_ctx) {
    ret = -ENOMEM;
    goto cleanup;
  }

  if (EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) != 1) {
    ret = -EIO;
    goto cleanup;
  }

  if (ek_public->publicArea.type == TPM2_ALG_RSA) {
    if (EVP_DigestUpdate(md_ctx, ek_public->publicArea.unique.rsa.buffer,
                         ek_public->publicArea.unique.rsa.size) != 1) {
      ret = -EIO;
      goto cleanup;
    }
  } else if (ek_public->publicArea.type == TPM2_ALG_ECC) {
    /* ECC: hash both X and Y coordinates */
    if (EVP_DigestUpdate(md_ctx, ek_public->publicArea.unique.ecc.x.buffer,
                         ek_public->publicArea.unique.ecc.x.size) != 1 ||
        EVP_DigestUpdate(md_ctx, ek_public->publicArea.unique.ecc.y.buffer,
                         ek_public->publicArea.unique.ecc.y.size) != 1) {
      ret = -EIO;
      goto cleanup;
    }
  } else {
    ret = -ENOTSUP;
    goto cleanup;
  }

  if (EVP_DigestFinal_ex(md_ctx, hardware_id, &hash_len) != 1) {
    ret = -EIO;
    goto cleanup;
  }

  ret = 0;

cleanup:
  if (md_ctx)
    EVP_MD_CTX_free(md_ctx);
  if (ek_public)
    Esys_Free(ek_public);
  if (ek_name)
    Esys_Free(ek_name);
  if (ek_qualified_name)
    Esys_Free(ek_qualified_name);

  return ret;
}

/*
 * Create directory path recursively.
 */
static int mkdirs(const char *path, mode_t mode) {
  char tmp[PATH_MAX];
  char *p;
  size_t len;

  len = strlen(path);
  if (len == 0 || len >= sizeof(tmp))
    return -EINVAL;

  memcpy(tmp, path, len + 1);

  for (p = tmp + 1; *p; p++) {
    if (*p == '/') {
      *p = '\0';
      if (mkdir(tmp, mode) < 0 && errno != EEXIST)
        return -errno;
      *p = '/';
    }
  }
  return 0;
}

int tpm_aik_load_metadata(struct tpm_context *ctx) {
  const char *path;
  int fd;
  ssize_t n;
  struct aik_metadata meta;

  if (!ctx || !ctx->initialized)
    return -EINVAL;

  path = ctx->aik_meta_path[0] ? ctx->aik_meta_path : TPM_AIK_META_PATH;

  fd = open(path, O_RDONLY);
  if (fd < 0) {
    if (errno != ENOENT)
      return -errno;

    /*
     * file does not exist -> first run after install
     * initialize default metadata with current time
     */
    memset(&ctx->aik_meta, 0, sizeof(ctx->aik_meta));
    ctx->aik_meta.magic = TPM_AIK_META_MAGIC;
    ctx->aik_meta.version = TPM_AIK_META_VERSION;
    ctx->aik_meta.generation = 1;
    ctx->aik_meta.provisioned_at = (int64_t)time(NULL);
    ctx->aik_meta.last_rotated_at = 0;
    ctx->aik_meta_loaded = true;

    return tpm_aik_save_metadata(ctx);
  }

  n = read(fd, &meta, sizeof(meta));
  close(fd);

  if (n != (ssize_t)sizeof(meta))
    return -EIO;

  meta.magic = le32toh(meta.magic);
  meta.version = le32toh(meta.version);
  meta.generation = le64toh(meta.generation);
  meta.provisioned_at = (int64_t)le64toh((uint64_t)meta.provisioned_at);
  meta.last_rotated_at = (int64_t)le64toh((uint64_t)meta.last_rotated_at);

  if (meta.magic != TPM_AIK_META_MAGIC)
    return -EINVAL;

  if (meta.version != TPM_AIK_META_VERSION)
    return -ENOTSUP;

  ctx->aik_meta = meta;
  ctx->aik_meta_loaded = true;
  return 0;
}

int tpm_aik_save_metadata(struct tpm_context *ctx) {
  const char *path;
  int fd;
  ssize_t n;
  int ret;

  if (!ctx)
    return -EINVAL;

  path = ctx->aik_meta_path[0] ? ctx->aik_meta_path : TPM_AIK_META_PATH;

  /* ensure parent directory exists */
  ret = mkdirs(path, 0755);
  if (ret < 0)
    return ret;

  /*
   * write to a temporary file and rename atomically so that a
   * crash between truncation and write cannot leave an empty
   * metadata file
   */
  char tmp[PATH_MAX];
  ret = snprintf(tmp, sizeof(tmp), "%s.tmp", path);
  if (ret < 0 || (size_t)ret >= sizeof(tmp))
    return -ENAMETOOLONG;

  fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (fd < 0)
    return -errno;

  struct aik_metadata wire;
  wire.magic = htole32(ctx->aik_meta.magic);
  wire.version = htole32(ctx->aik_meta.version);
  wire.generation = htole64(ctx->aik_meta.generation);
  wire.provisioned_at =
      (int64_t)htole64((uint64_t)ctx->aik_meta.provisioned_at);
  wire.last_rotated_at =
      (int64_t)htole64((uint64_t)ctx->aik_meta.last_rotated_at);
  memset(wire._reserved, 0, sizeof(wire._reserved));

  n = write(fd, &wire, sizeof(wire));
  if (n != (ssize_t)sizeof(wire)) {
    close(fd);
    unlink(tmp);
    return -EIO;
  }

  fsync(fd);
  close(fd);

  if (rename(tmp, path) != 0) {
    ret = -errno;
    unlink(tmp);
    return ret;
  }

  return 0;
}

int64_t tpm_aik_age(struct tpm_context *ctx) {
  time_t now;

  if (!ctx || !ctx->aik_meta_loaded)
    return -EINVAL;

  now = time(NULL);
  return (int64_t)(now - (time_t)ctx->aik_meta.provisioned_at);
}

int tpm_aik_needs_rotation(struct tpm_context *ctx, uint32_t max_age_sec) {
  int64_t age;

  if (!ctx || !ctx->aik_meta_loaded)
    return -EINVAL;

  if (max_age_sec == 0)
    max_age_sec = TPM_AIK_DEFAULT_TTL_SEC;

  age = tpm_aik_age(ctx);
  if (age < 0)
    return (int)age;

  return (age >= (int64_t)max_age_sec) ? 1 : 0;
}

int tpm_rotate_aik(struct tpm_context *ctx) {
  int ret;
  ESYS_TR old_handle = ESYS_TR_NONE;
  size_t prev_size = 0;

  if (!ctx || !ctx->initialized || !ctx->aik_meta_loaded)
    return -EINVAL;

  /* export current AIK public key for grace period */
  ret = aik_exists(ctx, &old_handle);
  if (ret < 0)
    return ret;

  if (ret == 1) {
    ESYS_TR new_transient = ESYS_TR_NONE;

    ret = tpm_get_aik_public(ctx, ctx->prev_aik_public,
                             sizeof(ctx->prev_aik_public), &prev_size);
    if (ret < 0) {
      /*
       * cannot export old key -> grace period will be empty
       * continue with rotation anyway
       */
      prev_size = 0;
    }
    ctx->prev_aik_public_size = prev_size;

    /*
     * create new AIK as transient BEFORE evicting old key
     */
    ret = create_aik_primary(ctx, &new_transient);
    if (ret < 0)
      return ret;

    /* evict old persistent handle */
    {
      TSS2_RC rc;
      ESYS_TR out_handle;
      rc = Esys_EvictControl(ctx->esys_ctx, ESYS_TR_RH_OWNER, old_handle,
                             ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                             ctx->aik_handle, &out_handle);
      if (rc != TSS2_RC_SUCCESS) {
        Esys_FlushContext(ctx->esys_ctx, new_transient);
        return tss2_rc_to_errno(rc);
      }
    }

    /* persist new transient key at the same handle */
    {
      TSS2_RC rc;
      ESYS_TR persistent;
      rc = Esys_EvictControl(ctx->esys_ctx, ESYS_TR_RH_OWNER, new_transient,
                             ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                             ctx->aik_handle, &persistent);
      Esys_FlushContext(ctx->esys_ctx, new_transient);
      if (rc != TSS2_RC_SUCCESS)
        return tss2_rc_to_errno(rc);
    }
  } else {
    ctx->prev_aik_public_size = 0;

    /* no existing AIK — provision from scratch */
    ret = tpm_provision_aik(ctx);
    if (ret < 0)
      return ret;
  }

  /* update metadata */
  ctx->aik_meta.generation++;
  ctx->aik_meta.last_rotated_at = (int64_t)time(NULL);
  ctx->aik_meta.provisioned_at = ctx->aik_meta.last_rotated_at;

  ret = tpm_aik_save_metadata(ctx);
  if (ret < 0)
    return ret;

  /* start grace period */
  if (ctx->prev_aik_public_size > 0) {
    ctx->grace_deadline = time(NULL) + TPM_AIK_GRACE_PERIOD_SEC;
  } else {
    ctx->grace_deadline = 0;
  }

  return 0;
}

int tpm_aik_in_grace_period(struct tpm_context *ctx) {
  if (!ctx)
    return 0;

  if (ctx->grace_deadline == 0)
    return 0;

  if (time(NULL) >= ctx->grace_deadline) {
    /* grace period expired -> clear state */
    ctx->grace_deadline = 0;
    ctx->prev_aik_public_size = 0;
    return 0;
  }

  return 1;
}

int tpm_aik_get_prev_public(struct tpm_context *ctx, uint8_t *buf,
                            size_t buf_size, size_t *out_size) {
  if (!ctx || !buf || !out_size)
    return -EINVAL;

  *out_size = 0;

  if (!tpm_aik_in_grace_period(ctx))
    return -ENOENT;

  if (ctx->prev_aik_public_size == 0)
    return -ENOENT;

  if (buf_size < ctx->prev_aik_public_size)
    return -ENOSPC;

  memcpy(buf, ctx->prev_aik_public, ctx->prev_aik_public_size);
  *out_size = ctx->prev_aik_public_size;
  return 0;
}

int tpm_read_event_log(uint8_t *buf, size_t buf_size, size_t *out_size) {
  int fd;
  ssize_t n;
  size_t total = 0;

  if (!buf || !out_size || buf_size == 0)
    return -EINVAL;

  *out_size = 0;

  fd = open(TPM_EVENTLOG_PATH_BIOS, O_RDONLY);
  if (fd < 0)
    return -errno;

  while (total < buf_size) {
    n = read(fd, buf + total, buf_size - total);
    if (n < 0) {
      int err = errno;
      close(fd);
      return -err;
    }
    if (n == 0)
      break;
    total += (size_t)n;
  }

  /*
   * if the buffer is completely full, try to read one more byte.
   * if data is available, the log was too large for the buffer
   * and the caller cannot trust the content.
   */
  if (total == buf_size) {
    uint8_t probe;
    n = read(fd, &probe, 1);
    if (n > 0) {
      close(fd);
      *out_size = total;
      return -ENOSPC;
    }
  }

  close(fd);
  *out_size = total;
  return 0;
}

/*
 * Query TPM capability for a property.
 * Returns: 0 on success, negative errno on failure.
 */
static int tpm_get_prop(struct tpm_context *ctx, TPM2_PT prop,
                        uint32_t *out_val) {
  TSS2_RC rc;
  TPMS_CAPABILITY_DATA *cap_data = NULL;
  TPMI_YES_NO more = TPM2_NO;

  if (!ctx || !ctx->initialized || !out_val)
    return -EINVAL;

  rc = Esys_GetCapability(ctx->esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE,
                          ESYS_TR_NONE, TPM2_CAP_TPM_PROPERTIES, prop, 1, &more,
                          &cap_data);
  if (rc != TSS2_RC_SUCCESS)
    return tss2_rc_to_errno(rc);

  if (cap_data->data.tpmProperties.count == 0 ||
      cap_data->data.tpmProperties.tpmProperty[0].property != prop) {
    Esys_Free(cap_data);
    return -ENOENT;
  }

  *out_val = cap_data->data.tpmProperties.tpmProperty[0].value;
  Esys_Free(cap_data);
  return 0;
}

int tpm_get_ek_cert(struct tpm_context *ctx, uint8_t *buf, size_t buf_size,
                    size_t *out_size) {
  TSS2_RC rc;
  ESYS_TR nv_handle = ESYS_TR_NONE;
  TPM2B_NV_PUBLIC *nv_public = NULL;
  TPM2B_NAME *nv_name = NULL;
  uint32_t max_nv_size = 1024; /* conservative default */
  uint32_t prop_val;

  if (!ctx || !ctx->initialized || !buf || !out_size)
    return -EINVAL;

  *out_size = 0;

  /* query unlimited max NV buffer size */
  if (tpm_get_prop(ctx, TPM2_PT_NV_BUFFER_MAX, &prop_val) == 0) {
    max_nv_size = prop_val;
  }

  /* ESYS handle for NV index */
  rc = Esys_TR_FromTPMPublic(ctx->esys_ctx, TPM_EK_CERT_HANDLE, ESYS_TR_NONE,
                             ESYS_TR_NONE, ESYS_TR_NONE, &nv_handle);
  if (rc != TSS2_RC_SUCCESS) {
    if ((rc & 0xFF) == TPM2_RC_HANDLE)
      return -ENOENT; /* no certificate at this handle */
    return tss2_rc_to_errno(rc);
  }

  /* read NV public to get size */
  rc = Esys_NV_ReadPublic(ctx->esys_ctx, nv_handle, ESYS_TR_NONE, ESYS_TR_NONE,
                          ESYS_TR_NONE, &nv_public, &nv_name);
  if (rc != TSS2_RC_SUCCESS) {
    return tss2_rc_to_errno(rc);
  }

  size_t data_size = nv_public->nvPublic.dataSize;
  Esys_Free(nv_public);
  Esys_Free(nv_name);

  if (data_size > buf_size) {
    return -ENOSPC;
  }

  uint16_t offset = 0;
  while (offset < data_size) {
    TPM2B_MAX_NV_BUFFER *nv_data = NULL;
    uint32_t size_to_read = data_size - offset;

    if (size_to_read > max_nv_size)
      size_to_read = max_nv_size;

    rc = Esys_NV_Read(ctx->esys_ctx, ESYS_TR_RH_OWNER, nv_handle,
                      ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                      (uint16_t)size_to_read, offset, &nv_data);
    if (rc != TSS2_RC_SUCCESS) {
      return tss2_rc_to_errno(rc);
    }

    memcpy(buf + offset, nv_data->buffer, nv_data->size);
    offset += nv_data->size;
    Esys_Free(nv_data);
  }

  *out_size = data_size;
  return 0;
}
