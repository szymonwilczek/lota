/* SPDX-License-Identifier: MIT */
/*
 * LOTA Server SDK - Integration Test
 *
 * Tests the full pipeline:
 *  - Serialize a token (gaming SDK)
 *  - Parse without verification (server SDK)
 *  - Full RSA signature verification (server SDK)
 *  - Bad signature rejection
 *  - Tampered token rejection
 *  - Expired token detection
 *  - Nonce mismatch rejection
 *  - Malformed input handling
 */

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "lota_gaming.h"
#include "lota_server.h"

#define GREEN "\033[32m"
#define RED "\033[31m"
#define YELLOW "\033[33m"
#define RESET "\033[0m"
#define BOLD "\033[1m"

static int tests_run = 0;
static int tests_pass = 0;
static int tests_fail = 0;

#define TEST(name)                                                             \
  do {                                                                         \
    tests_run++;                                                               \
    printf("  [%2d] %-50s ", tests_run, name);                                 \
  } while (0)

#define PASS()                                                                 \
  do {                                                                         \
    tests_pass++;                                                              \
    printf(GREEN "PASS" RESET "\n");                                           \
  } while (0)

#define FAIL(reason)                                                           \
  do {                                                                         \
    tests_fail++;                                                              \
    printf(RED "FAIL" RESET " — %s\n", reason);                                \
  } while (0)

#define TPM_GENERATED_VALUE 0xff544347
#define TPM_ST_ATTEST_QUOTE 0x8018

static void write_be16(uint8_t *p, uint16_t v) {
  p[0] = (uint8_t)(v >> 8);
  p[1] = (uint8_t)(v);
}

static void write_be32(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v >> 24);
  p[1] = (uint8_t)(v >> 16);
  p[2] = (uint8_t)(v >> 8);
  p[3] = (uint8_t)(v);
}

/*
 * Build a fake TPMS_ATTEST blob with given extraData (nonce) and pcr digest.
 * Returns allocated buffer, caller must free.
 */
static uint8_t *build_fake_tpms_attest(const uint8_t *extra_data,
                                       size_t extra_len,
                                       const uint8_t *pcr_digest,
                                       size_t pcr_digest_len, size_t *out_len) {
  /* generous buffer */
  uint8_t *buf = calloc(1, 512);
  size_t off = 0;

  /* magic */
  write_be32(buf + off, TPM_GENERATED_VALUE);
  off += 4;

  /* type = QUOTE */
  write_be16(buf + off, TPM_ST_ATTEST_QUOTE);
  off += 2;

  /* qualifiedSigner: TPM2B_NAME (size=4, dummy data) */
  write_be16(buf + off, 4);
  off += 2;
  buf[off++] = 0x00;
  buf[off++] = 0x0B;
  buf[off++] = 0xAA;
  buf[off++] = 0xBB;

  /* extraData: TPM2B_DATA */
  write_be16(buf + off, (uint16_t)extra_len);
  off += 2;
  memcpy(buf + off, extra_data, extra_len);
  off += extra_len;

  /* clockInfo: 17 bytes zeros */
  off += 17;

  /* firmwareVersion: 8 bytes */
  off += 8;

  /* TPMS_QUOTE_INFO */
  /* TPML_PCR_SELECTION: count=1 */
  write_be32(buf + off, 1);
  off += 4;
  /* TPMS_PCR_SELECTION: hash=SHA-256(0x000B), sizeOfSelect=3, select=PCR0+14 */
  write_be16(buf + off, 0x000B);
  off += 2;
  buf[off++] = 3;
  buf[off++] = 0x01; /* PCR 0 */
  buf[off++] = 0x00;
  buf[off++] = 0x40; /* PCR 14 */

  /* pcrDigest: TPM2B_DIGEST */
  write_be16(buf + off, (uint16_t)pcr_digest_len);
  off += 2;
  if (pcr_digest_len > 0) {
    memcpy(buf + off, pcr_digest, pcr_digest_len);
    off += pcr_digest_len;
  }

  *out_len = off;
  return buf;
}

/*
 * Compute SHA256(issued_at || valid_until || flags || nonce)
 * with integers in little-endian (matching wire format).
 */
static void compute_expected_nonce(uint64_t issued_at, uint64_t valid_until,
                                   uint32_t flags, const uint8_t nonce[32],
                                   uint8_t out[32]) {
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
  EVP_DigestUpdate(ctx, &issued_at, 8);
  EVP_DigestUpdate(ctx, &valid_until, 8);
  EVP_DigestUpdate(ctx, &flags, 4);
  EVP_DigestUpdate(ctx, nonce, 32);
  unsigned int len = 32;
  EVP_DigestFinal_ex(ctx, out, &len);
  EVP_MD_CTX_free(ctx);
}

/*
 * Generate RSA-2048 key pair, return EVP_PKEY (caller frees)
 */
static EVP_PKEY *generate_rsa_key(void) {
  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
  EVP_PKEY *pkey = NULL;

  EVP_PKEY_keygen_init(ctx);
  EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
  EVP_PKEY_keygen(ctx, &pkey);
  EVP_PKEY_CTX_free(ctx);

  return pkey;
}

/*
 * Sign data with RSASSA-PKCS1v15(SHA-256), return allocated sig
 */
static uint8_t *rsa_sign(EVP_PKEY *pkey, const uint8_t *data, size_t data_len,
                         size_t *sig_len) {
  EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();

  EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, pkey);
  EVP_DigestSignUpdate(md_ctx, data, data_len);

  /* get required size */
  EVP_DigestSignFinal(md_ctx, NULL, sig_len);
  uint8_t *sig = malloc(*sig_len);
  EVP_DigestSignFinal(md_ctx, sig, sig_len);

  EVP_MD_CTX_free(md_ctx);
  return sig;
}

/*
 * Export AIK public key as DER (PKIX/SPKI format)
 */
static uint8_t *export_pubkey_der(EVP_PKEY *pkey, size_t *out_len) {
  int len = i2d_PUBKEY(pkey, NULL);
  if (len <= 0)
    return NULL;

  uint8_t *der = malloc((size_t)len);
  uint8_t *p = der;
  i2d_PUBKEY(pkey, &p);
  *out_len = (size_t)len;
  return der;
}

/*
 * Build a complete test token: metadata -> expected nonce -> TPMS_ATTEST ->
 * sign -> serialize
 */
static int build_full_token(EVP_PKEY *key, uint64_t issued_at,
                            uint64_t valid_until, uint32_t flags,
                            const uint8_t nonce[32], uint8_t *tokbuf,
                            size_t tokbuf_size, size_t *tok_written) {
  /* compute expected nonce */
  uint8_t exp_nonce[32];
  compute_expected_nonce(issued_at, valid_until, flags, nonce, exp_nonce);

  /* build TPMS_ATTEST with expected_nonce as extraData */
  uint8_t pcr_digest[32] = {0xDD};
  size_t attest_len = 0;
  uint8_t *attest =
      build_fake_tpms_attest(exp_nonce, 32, pcr_digest, 32, &attest_len);

  /* sign attest_data */
  size_t sig_len = 0;
  uint8_t *sig = rsa_sign(key, attest, attest_len, &sig_len);

  struct lota_token token;
  memset(&token, 0, sizeof(token));
  token.issued_at = issued_at;
  token.valid_until = valid_until;
  token.flags = flags;
  memcpy(token.nonce, nonce, 32);
  token.sig_alg = 0x0014;  /* RSASSA */
  token.hash_alg = 0x000B; /* SHA-256 */
  token.pcr_mask = 0x4001; /* PCR 0 + 14 */
  token.attest_data = attest;
  token.attest_size = attest_len;
  token.signature = sig;
  token.signature_len = sig_len;

  /* serialize */
  int ret = lota_token_serialize(&token, tokbuf, tokbuf_size, tok_written);

  free(attest);
  free(sig);

  return ret;
}

static void test_serialize_basic(void) {
  TEST("lota_token_serialize - basic roundtrip");

  struct lota_token token;
  memset(&token, 0, sizeof(token));
  token.issued_at = 1700000000;
  token.valid_until = 1700003600;
  token.flags = 0x07;
  token.sig_alg = 0x0014;
  token.hash_alg = 0x000B;
  token.pcr_mask = 0x4001;

  uint8_t fake_attest[64] = {0xAA};
  uint8_t fake_sig[32] = {0xBB};
  token.attest_data = fake_attest;
  token.attest_size = sizeof(fake_attest);
  token.signature = fake_sig;
  token.signature_len = sizeof(fake_sig);

  size_t expected = lota_token_serialized_size(&token);
  if (expected != 72 + 64 + 32) {
    char msg[64];
    snprintf(msg, sizeof(msg), "size=%zu, expected=%d", expected, 72 + 64 + 32);
    FAIL(msg);
    return;
  }

  uint8_t buf[256];
  size_t written = 0;
  int ret = lota_token_serialize(&token, buf, sizeof(buf), &written);
  if (ret != LOTA_OK || written != expected) {
    FAIL("serialize failed or wrong size");
    return;
  }

  uint32_t magic;
  memcpy(&magic, buf, 4);
  if (magic != 0x4B544F4C) {
    FAIL("bad magic");
    return;
  }

  PASS();
}

static void test_serialize_buffer_too_small(void) {
  TEST("lota_token_serialize - buffer too small");

  struct lota_token token;
  memset(&token, 0, sizeof(token));
  uint8_t fake[16] = {0};
  token.attest_data = fake;
  token.attest_size = 16;
  token.signature = fake;
  token.signature_len = 16;

  uint8_t tiny[10];
  int ret = lota_token_serialize(&token, tiny, sizeof(tiny), NULL);
  if (ret == LOTA_ERR_BUFFER_TOO_SMALL) {
    PASS();
  } else {
    FAIL("expected LOTA_ERR_BUFFER_TOO_SMALL");
  }
}

static void test_parse_untrusted(void) {
  TEST("lota_server_parse_token - untrusted parse");

  struct lota_token token;
  memset(&token, 0, sizeof(token));
  token.issued_at = 1700000000;
  token.valid_until = 1700003600;
  token.flags = 0x1F;
  memset(token.nonce, 0x42, 32);
  token.sig_alg = 0x0014;
  token.hash_alg = 0x000B;
  token.pcr_mask = 0x4001;

  uint8_t fake_attest[32] = {0};
  token.attest_data = fake_attest;
  token.attest_size = sizeof(fake_attest);
  uint8_t fake_sig[32] = {0};
  token.signature = fake_sig;
  token.signature_len = sizeof(fake_sig);

  uint8_t buf[256];
  size_t written;
  lota_token_serialize(&token, buf, sizeof(buf), &written);

  struct lota_server_claims claims;
  int ret = lota_server_parse_token(buf, written, &claims);
  if (ret != LOTA_SERVER_OK) {
    char msg[64];
    snprintf(msg, sizeof(msg), "parse returned %d: %s", ret,
             lota_server_strerror(ret));
    FAIL(msg);
    return;
  }

  if (claims.issued_at != 1700000000 || claims.valid_until != 1700003600 ||
      claims.flags != 0x1F || claims.pcr_mask != 0x4001) {
    FAIL("claims mismatch");
    return;
  }

  if (claims.nonce[0] != 0x42) {
    FAIL("nonce not echoed");
    return;
  }

  PASS();
}

static void test_verify_full_success(EVP_PKEY *key, const uint8_t *aik_der,
                                     size_t aik_len) {
  TEST("lota_server_verify_token - full success");

  uint64_t now = (uint64_t)time(NULL);
  uint8_t nonce[32] = {0xDE, 0xAD, 0xBE, 0xEF};

  uint8_t tokbuf[2048];
  size_t tok_written;
  int ret = build_full_token(key, now, now + 3600, 0x07, nonce, tokbuf,
                             sizeof(tokbuf), &tok_written);
  if (ret != LOTA_OK) {
    FAIL("build_full_token failed");
    return;
  }

  struct lota_server_claims claims;
  ret = lota_server_verify_token(tokbuf, tok_written, aik_der, aik_len, NULL,
                                 &claims);
  if (ret != LOTA_SERVER_OK) {
    char msg[128];
    snprintf(msg, sizeof(msg), "verify returned %d: %s", ret,
             lota_server_strerror(ret));
    FAIL(msg);
    return;
  }

  if (claims.expired) {
    FAIL("should not be expired");
    return;
  }
  if (claims.too_old) {
    FAIL("fresh token should not be too_old");
    return;
  }
  if (claims.issued_in_future) {
    FAIL("should not be issued_in_future");
    return;
  }
  if (claims.flags != 0x07) {
    FAIL("flags mismatch");
    return;
  }
  if (claims.pcr_digest_len != 32) {
    char msg[64];
    snprintf(msg, sizeof(msg), "pcr_digest_len=%zu, want 32",
             claims.pcr_digest_len);
    FAIL(msg);
    return;
  }

  PASS();
}

static void test_verify_with_expected_nonce(EVP_PKEY *key,
                                            const uint8_t *aik_der,
                                            size_t aik_len) {
  TEST("lota_server_verify_token — correct expected_nonce");

  uint64_t now = (uint64_t)time(NULL);
  uint8_t nonce[32] = {0x01, 0x02, 0x03};

  uint8_t tokbuf[2048];
  size_t tok_written;
  build_full_token(key, now, now + 3600, 0, nonce, tokbuf, sizeof(tokbuf),
                   &tok_written);

  struct lota_server_claims claims;
  int ret = lota_server_verify_token(tokbuf, tok_written, aik_der, aik_len,
                                     nonce, &claims);
  if (ret != LOTA_SERVER_OK) {
    FAIL("should pass with correct nonce");
    return;
  }

  PASS();
}

static void test_verify_wrong_nonce(EVP_PKEY *key, const uint8_t *aik_der,
                                    size_t aik_len) {
  TEST("lota_server_verify_token — wrong expected_nonce → NONCE_FAIL");

  uint64_t now = (uint64_t)time(NULL);
  uint8_t nonce[32] = {0x01, 0x02, 0x03};

  uint8_t tokbuf[2048];
  size_t tok_written;
  build_full_token(key, now, now + 3600, 0, nonce, tokbuf, sizeof(tokbuf),
                   &tok_written);

  uint8_t wrong_nonce[32] = {0xFF, 0xFF, 0xFF};
  struct lota_server_claims claims;
  int ret = lota_server_verify_token(tokbuf, tok_written, aik_der, aik_len,
                                     wrong_nonce, &claims);
  if (ret == LOTA_SERVER_ERR_NONCE_FAIL) {
    PASS();
  } else {
    char msg[64];
    snprintf(msg, sizeof(msg), "expected NONCE_FAIL, got %d", ret);
    FAIL(msg);
  }
}

static void test_verify_bad_signature(EVP_PKEY *key, const uint8_t *aik_der,
                                      size_t aik_len) {
  TEST("lota_server_verify_token — wrong AIK key → SIG_FAIL");
  (void)key; /* original key, not used directly */

  /* DIFFERENT key to sign with */
  EVP_PKEY *wrong_key = generate_rsa_key();

  uint64_t now = (uint64_t)time(NULL);
  uint8_t nonce[32] = {0};

  uint8_t tokbuf[2048];
  size_t tok_written;
  /* sign with wrong_key, but verify with original aik_der */
  build_full_token(wrong_key, now, now + 3600, 0, nonce, tokbuf, sizeof(tokbuf),
                   &tok_written);

  struct lota_server_claims claims;
  int ret = lota_server_verify_token(tokbuf, tok_written, aik_der, aik_len,
                                     NULL, &claims);
  EVP_PKEY_free(wrong_key);

  if (ret == LOTA_SERVER_ERR_SIG_FAIL) {
    PASS();
  } else {
    char msg[64];
    snprintf(msg, sizeof(msg), "expected SIG_FAIL, got %d", ret);
    FAIL(msg);
  }
}

static void test_verify_tampered_flags(EVP_PKEY *key, const uint8_t *aik_der,
                                       size_t aik_len) {
  TEST("lota_server_verify_token - tampered flags → NONCE_FAIL");

  uint64_t now = (uint64_t)time(NULL);
  uint8_t nonce[32] = {0};

  uint8_t tokbuf[2048];
  size_t tok_written;
  build_full_token(key, now, now + 3600, 0x07, nonce, tokbuf, sizeof(tokbuf),
                   &tok_written);

  /* tamper: change flags from 0x07 to 0xFF in wire (offset 24) */
  tokbuf[24] = 0xFF;

  struct lota_server_claims claims;
  int ret = lota_server_verify_token(tokbuf, tok_written, aik_der, aik_len,
                                     NULL, &claims);
  if (ret == LOTA_SERVER_ERR_NONCE_FAIL) {
    PASS();
  } else {
    char msg[64];
    snprintf(msg, sizeof(msg), "expected NONCE_FAIL, got %d", ret);
    FAIL(msg);
  }
}

static void test_verify_expired(EVP_PKEY *key, const uint8_t *aik_der,
                                size_t aik_len) {
  TEST("lota_server_verify_token - expired token → claims.expired=1");

  uint64_t now = (uint64_t)time(NULL);
  uint8_t nonce[32] = {0};

  uint8_t tokbuf[2048];
  size_t tok_written;
  /* valid_until 1 hour AGO */
  build_full_token(key, now - 7200, now - 3600, 0, nonce, tokbuf,
                   sizeof(tokbuf), &tok_written);

  struct lota_server_claims claims;
  int ret = lota_server_verify_token(tokbuf, tok_written, aik_der, aik_len,
                                     NULL, &claims);
  if (ret != LOTA_SERVER_OK) {
    char msg[64];
    snprintf(msg, sizeof(msg), "verify returned %d (expected OK)", ret);
    FAIL(msg);
    return;
  }
  if (claims.expired) {
    PASS();
  } else {
    FAIL("claims.expired should be 1");
  }
}

static void test_verify_stale_token(EVP_PKEY *key, const uint8_t *aik_der,
                                    size_t aik_len) {
  TEST("lota_server_verify_token - stale token → claims.too_old=1");

  uint64_t now = (uint64_t)time(NULL);
  uint8_t nonce[32] = {0xAA};

  uint8_t tokbuf[2048];
  size_t tok_written;
  /* issued 1 hour ago, valid_until still in the future */
  build_full_token(key, now - 3600, now + 3600, 0x07, nonce, tokbuf,
                   sizeof(tokbuf), &tok_written);

  struct lota_server_claims claims;
  int ret = lota_server_verify_token(tokbuf, tok_written, aik_der, aik_len,
                                     NULL, &claims);
  if (ret != LOTA_SERVER_OK) {
    char msg[64];
    snprintf(msg, sizeof(msg), "verify returned %d (expected OK)", ret);
    FAIL(msg);
    return;
  }
  if (!claims.too_old) {
    char msg[128];
    snprintf(msg, sizeof(msg), "too_old should be 1 (age=%ld)",
             (long)claims.age_seconds);
    FAIL(msg);
    return;
  }
  if (claims.expired) {
    FAIL("should not be expired (valid_until is future)");
    return;
  }
  if (claims.age_seconds < 3500) {
    char msg[64];
    snprintf(msg, sizeof(msg), "age_seconds=%ld, expected ~3600",
             (long)claims.age_seconds);
    FAIL(msg);
    return;
  }
  PASS();
}

static void test_verify_future_token(EVP_PKEY *key, const uint8_t *aik_der,
                                     size_t aik_len) {
  TEST("lota_server_verify_token - future token → issued_in_future=1");

  uint64_t now = (uint64_t)time(NULL);
  uint8_t nonce[32] = {0xBB};

  uint8_t tokbuf[2048];
  size_t tok_written;
  /* issued 10 minutes in the future (far beyond clock skew tolerance) */
  build_full_token(key, now + 600, now + 7200, 0, nonce, tokbuf, sizeof(tokbuf),
                   &tok_written);

  struct lota_server_claims claims;
  int ret = lota_server_verify_token(tokbuf, tok_written, aik_der, aik_len,
                                     NULL, &claims);
  if (ret != LOTA_SERVER_OK) {
    char msg[64];
    snprintf(msg, sizeof(msg), "verify returned %d (expected OK)", ret);
    FAIL(msg);
    return;
  }
  if (!claims.issued_in_future) {
    char msg[128];
    snprintf(msg, sizeof(msg), "issued_in_future should be 1 (age=%ld)",
             (long)claims.age_seconds);
    FAIL(msg);
    return;
  }
  if (claims.age_seconds >= 0) {
    char msg[64];
    snprintf(msg, sizeof(msg), "age should be negative, got %ld",
             (long)claims.age_seconds);
    FAIL(msg);
    return;
  }
  PASS();
}

static void test_verify_fresh_token_not_stale(EVP_PKEY *key,
                                              const uint8_t *aik_der,
                                              size_t aik_len) {
  TEST("lota_server_verify_token - fresh token → too_old=0");

  uint64_t now = (uint64_t)time(NULL);
  uint8_t nonce[32] = {0xCC};

  uint8_t tokbuf[2048];
  size_t tok_written;
  /* issued 10 seconds ago - well within max age */
  build_full_token(key, now - 10, now + 3600, 0x07, nonce, tokbuf,
                   sizeof(tokbuf), &tok_written);

  struct lota_server_claims claims;
  int ret = lota_server_verify_token(tokbuf, tok_written, aik_der, aik_len,
                                     NULL, &claims);
  if (ret != LOTA_SERVER_OK) {
    char msg[64];
    snprintf(msg, sizeof(msg), "verify returned %d (expected OK)", ret);
    FAIL(msg);
    return;
  }
  if (claims.too_old || claims.issued_in_future || claims.expired) {
    char msg[128];
    snprintf(msg, sizeof(msg),
             "too_old=%d issued_in_future=%d expired=%d (all should be 0)",
             claims.too_old, claims.issued_in_future, claims.expired);
    FAIL(msg);
    return;
  }
  if (claims.age_seconds < 0 || claims.age_seconds > 60) {
    char msg[64];
    snprintf(msg, sizeof(msg), "age_seconds=%ld, expected ~10",
             (long)claims.age_seconds);
    FAIL(msg);
    return;
  }
  PASS();
}

static void test_malformed_inputs(void) {
  TEST("lota_server_verify_token - NULL inputs");
  struct lota_server_claims claims;
  int ret = lota_server_verify_token(NULL, 0, NULL, 0, NULL, &claims);
  if (ret == LOTA_SERVER_ERR_INVALID_ARG) {
    PASS();
  } else {
    FAIL("expected INVALID_ARG");
  }

  TEST("lota_server_verify_token - too short token");
  uint8_t tiny[10] = {0};
  uint8_t fake_key[16] = {0};
  ret = lota_server_verify_token(tiny, sizeof(tiny), fake_key, sizeof(fake_key),
                                 NULL, &claims);
  if (ret == LOTA_SERVER_ERR_BAD_TOKEN) {
    PASS();
  } else {
    char msg[64];
    snprintf(msg, sizeof(msg), "expected BAD_TOKEN, got %d", ret);
    FAIL(msg);
  }

  TEST("lota_server_verify_token - bad magic");
  uint8_t bad_magic[128] = {0};
  bad_magic[0] = 0xDE;
  bad_magic[1] = 0xAD;
  ret = lota_server_verify_token(bad_magic, sizeof(bad_magic), fake_key,
                                 sizeof(fake_key), NULL, &claims);
  if (ret == LOTA_SERVER_ERR_BAD_TOKEN) {
    PASS();
  } else {
    FAIL("expected BAD_TOKEN for bad magic");
  }
}

static void test_strerror(void) {
  TEST("lota_server_strerror - all error codes");

  const char *s;
  int all_ok = 1;

  s = lota_server_strerror(LOTA_SERVER_OK);
  if (!s || strlen(s) == 0)
    all_ok = 0;

  s = lota_server_strerror(LOTA_SERVER_ERR_SIG_FAIL);
  if (!s || strlen(s) == 0)
    all_ok = 0;

  s = lota_server_strerror(LOTA_SERVER_ERR_NONCE_FAIL);
  if (!s || strlen(s) == 0)
    all_ok = 0;

  s = lota_server_strerror(LOTA_SERVER_ERR_ATTEST_PARSE);
  if (!s || strlen(s) == 0)
    all_ok = 0;

  s = lota_server_strerror(-999);
  if (!s || strlen(s) == 0)
    all_ok = 0;

  if (all_ok) {
    PASS();
  } else {
    FAIL("some strerror returned NULL or empty");
  }
}

static void test_sdk_version(void) {
  TEST("lota_server_sdk_version - returns version string");

  const char *v = lota_server_sdk_version();
  if (v && strcmp(v, "1.0.0") == 0) {
    PASS();
  } else {
    FAIL(v ? v : "NULL");
  }
}

int main(void) {
  printf(BOLD "\n=== LOTA Server SDK - Test Suite ===\n\n" RESET);

  /* test RSA-2048 key pair */
  printf(YELLOW "Generating RSA-2048 test key pair..." RESET "\n");
  EVP_PKEY *key = generate_rsa_key();
  if (!key) {
    fprintf(stderr, "Failed to generate RSA key\n");
    return 1;
  }

  /* public key as DER */
  size_t aik_len = 0;
  uint8_t *aik_der = export_pubkey_der(key, &aik_len);
  if (!aik_der) {
    fprintf(stderr, "Failed to export public key\n");
    return 1;
  }
  printf(YELLOW "AIK public key: %zu bytes (DER/PKIX)\n\n" RESET, aik_len);

  printf(BOLD "Serialization (Gaming SDK):\n" RESET);
  test_serialize_basic();
  test_serialize_buffer_too_small();

  printf(BOLD "\nParsing (Server SDK - untrusted):\n" RESET);
  test_parse_untrusted();

  printf(BOLD
         "\nFull Verification (Server SDK - RSA + nonce binding):\n" RESET);
  test_verify_full_success(key, aik_der, aik_len);
  test_verify_with_expected_nonce(key, aik_der, aik_len);

  printf(BOLD "\nRejection Scenarios:\n" RESET);
  test_verify_wrong_nonce(key, aik_der, aik_len);
  test_verify_bad_signature(key, aik_der, aik_len);
  test_verify_tampered_flags(key, aik_der, aik_len);
  test_verify_expired(key, aik_der, aik_len);

  printf(BOLD "\nFreshness Checks:\n" RESET);
  test_verify_stale_token(key, aik_der, aik_len);
  test_verify_future_token(key, aik_der, aik_len);
  test_verify_fresh_token_not_stale(key, aik_der, aik_len);

  printf(BOLD "\nEdge Cases & Error Handling:\n" RESET);
  test_malformed_inputs();
  test_strerror();
  test_sdk_version();

  printf(BOLD "\n=== Results: %d/%d passed" RESET, tests_pass, tests_run);
  if (tests_fail > 0) {
    printf(RED " (%d FAILED)" RESET, tests_fail);
  }
  printf("\n\n");

  free(aik_der);
  EVP_PKEY_free(key);

  return tests_fail > 0 ? 1 : 0;
}
