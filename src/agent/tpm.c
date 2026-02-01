/* SPDX-License-Identifier: MIT */
/*
 * LOTA - TPM 2.0 Operations Module
 * Implementation using libtss2-esys
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>

#include <openssl/evp.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_tcti.h>
#include <tss2/tss2_tcti_device.h>

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

  if (!ctx)
    return -EINVAL;

  memset(ctx, 0, sizeof(*ctx));

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
  if (pcr_values && pcr_values->count > 0) {
    size_t copy_size = pcr_values->digests[0].size;
    if (copy_size > LOTA_HASH_SIZE)
      copy_size = LOTA_HASH_SIZE;
    memcpy(value, pcr_values->digests[0].buffer, copy_size);
  }

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

int tpm_quote(struct tpm_context *ctx, const uint8_t *nonce, uint32_t pcr_mask,
              struct tpm_quote_result *result) {
  TSS2_RC rc;
  ESYS_TR key_handle = ESYS_TR_NONE;
  TPM2B_DATA qualifying_data;
  TPMT_SIG_SCHEME in_scheme;
  TPML_PCR_SELECTION pcr_selection;
  TPM2B_ATTEST *quoted = NULL;
  TPMT_SIGNATURE *signature = NULL;
  uint32_t i;

  if (!ctx || !ctx->initialized || !nonce || !result)
    return -EINVAL;

  memset(result, 0, sizeof(*result));

  /*
   * Load the AIK (Attestation Identity Key) handle.
   * In production, this key would be provisioned and stored
   * in TPM NV or as a persistent handle.
   */
  rc = Esys_TR_FromTPMPublic(ctx->esys_ctx, TPM_AIK_HANDLE, ESYS_TR_NONE,
                             ESYS_TR_NONE, ESYS_TR_NONE, &key_handle);
  if (rc != TSS2_RC_SUCCESS) {
    return tss2_rc_to_errno(rc);
  }

  qualifying_data.size = LOTA_NONCE_SIZE;
  memcpy(qualifying_data.buffer, nonce, LOTA_NONCE_SIZE);

  /* default signing scheme (RSASSA for RSA keys) */
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
   * TPM signs: PCR digest + qualifying data + clock info
   */
  rc = Esys_Quote(ctx->esys_ctx, key_handle, ESYS_TR_PASSWORD, ESYS_TR_NONE,
                  ESYS_TR_NONE, &qualifying_data, &in_scheme, &pcr_selection,
                  &quoted, &signature);

  if (rc != TSS2_RC_SUCCESS)
    return tss2_rc_to_errno(rc);

  /* copy results */
  memcpy(result->nonce, nonce, LOTA_NONCE_SIZE);

  /*
   * Extract signature based on algorithm.
   * LOTA support RSA signatures (RSASSA).
   */
  if (signature->sigAlg == TPM2_ALG_RSASSA) {
    size_t sig_size = signature->signature.rsassa.sig.size;
    if (sig_size > LOTA_MAX_SIG_SIZE)
      sig_size = LOTA_MAX_SIG_SIZE;
    memcpy(result->signature, signature->signature.rsassa.sig.buffer, sig_size);
    result->signature_size = (uint16_t)sig_size;
  } else if (signature->sigAlg == TPM2_ALG_RSAPSS) {
    size_t sig_size = signature->signature.rsapss.sig.size;
    if (sig_size > LOTA_MAX_SIG_SIZE)
      sig_size = LOTA_MAX_SIG_SIZE;
    memcpy(result->signature, signature->signature.rsapss.sig.buffer, sig_size);
    result->signature_size = (uint16_t)sig_size;
  }

  Esys_Free(quoted);
  Esys_Free(signature);

  return 0;
}

int tpm_hash_file(const char *path, uint8_t *hash) {
  int fd;
  ssize_t n;
  EVP_MD_CTX *md_ctx;
  uint8_t *buf;
  unsigned int hash_len;
  int ret = 0;

  if (!path || !hash)
    return -EINVAL;

  fd = open(path, O_RDONLY);
  if (fd < 0)
    return -errno;

  buf = malloc(HASH_READ_BUF_SIZE);
  if (!buf) {
    close(fd);
    return -ENOMEM;
  }

  md_ctx = EVP_MD_CTX_new();
  if (!md_ctx) {
    free(buf);
    close(fd);
    return -ENOMEM;
  }

  if (EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) != 1) {
    ret = -EIO;
    goto cleanup;
  }

  while ((n = read(fd, buf, HASH_READ_BUF_SIZE)) > 0) {
    if (EVP_DigestUpdate(md_ctx, buf, (size_t)n) != 1) {
      ret = -EIO;
      goto cleanup;
    }
  }

  if (n < 0) {
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
