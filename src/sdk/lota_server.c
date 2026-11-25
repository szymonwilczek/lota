/* SPDX-License-Identifier: MIT */
/*
 * LOTA Server-Side Token Verification SDK
 *
 * Verifies attestation tokens using OpenSSL for RSA signature
 * verification and TPMS_ATTEST parsing.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

#include "../../include/lota.h"
#include "../../include/lota_runtime_image_measure.h"
#include "../../include/lota_ipc.h"
#include "../../include/lota_registry_digest.h"
#include "../../include/lota_runtime_protect_digest.h"
#include "../../include/lota_server.h"
#include "../../include/lota_token_quote_nonce.h"
#include "lota_token.h"

/*
 * Injected from the VERSION file by the Makefile. A library that cannot name
 * its build is useless to an advisory or a support ticket.
 */
#ifndef LOTA_BUILD_VERSION_STRING
#error "LOTA_BUILD_VERSION_STRING must be defined at build time"
#endif

#define TPM_GENERATED_VALUE 0xff544347
#define TPM_ST_ATTEST_QUOTE 0x8018
#define TPM_ALG_RSASSA 0x0014
#define TPM_ALG_RSAPSS 0x0016

#define TPM_ALG_SHA256 0x000B
#define TPM_ALG_SHA384 0x000C
#define TPM_ALG_SHA512 0x000D

static const EVP_MD *select_hash_md(uint16_t hash_alg)
{
	switch (hash_alg) {
	case TPM_ALG_SHA256:
		return EVP_sha256();
	case TPM_ALG_SHA384:
		return EVP_sha384();
	case TPM_ALG_SHA512:
		return EVP_sha512();
	default:
		return NULL;
	}
}

static size_t hash_alg_digest_len(uint16_t hash_alg)
{
	switch (hash_alg) {
	case TPM_ALG_SHA256:
		return SHA256_DIGEST_LENGTH;
	case TPM_ALG_SHA384:
		return SHA384_DIGEST_LENGTH;
	case TPM_ALG_SHA512:
		return SHA512_DIGEST_LENGTH;
	default:
		return 0;
	}
}

#define LOTA_MAX_AIK_PUB_DER_SIZE 512

static uint16_t read_be16(const uint8_t *p)
{
	return (uint16_t)((uint16_t)p[0] << 8 | (uint16_t)p[1]);
}

static uint32_t read_be32(const uint8_t *p)
{
	return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
	       (uint32_t)p[2] << 8 | (uint32_t)p[3];
}

static uint16_t read_le16(const uint8_t *p)
{
	return (uint16_t)((uint16_t)p[1] << 8 | (uint16_t)p[0]);
}

static uint32_t read_le32(const uint8_t *p)
{
	return (uint32_t)p[3] << 24 | (uint32_t)p[2] << 16 |
	       (uint32_t)p[1] << 8 | (uint32_t)p[0];
}

static uint64_t read_le64(const uint8_t *p)
{
	return (uint64_t)read_le32(p) | ((uint64_t)read_le32(p + 4) << 32);
}

/*
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
 * Return: 0, or -1 on parse error.
 */
static int parse_tpms_attest(const uint8_t *data, size_t len,
			     const uint8_t **extra_data, size_t *extra_data_len,
			     const uint8_t **pcr_digest, size_t *pcr_digest_len,
			     uint32_t *pcr_mask_out)
{
	size_t off = 0;

	/* minimum: magic(4) + type(2) + signer_size(2) + extra_size(2) */
	if (len < 10)
		return -1;

	uint32_t magic = read_be32(data + off);
	off += 4;
	if (magic != TPM_GENERATED_VALUE)
		return -1;

	uint16_t type = read_be16(data + off);
	off += 2;

	if (off + 2 > len)
		return -1;
	uint16_t signer_size = read_be16(data + off);
	off += 2;
	if (off + signer_size > len)
		return -1;
	off += signer_size;

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

	/* clockInfo: clock(8) + resetCount(4) + restartCount(4) + safe(1) */
	if (off + 17 > len)
		return -1;
	off += 17;

	if (off + 8 > len)
		return -1;
	off += 8;

	if (type == TPM_ST_ATTEST_QUOTE) {
		uint32_t parsed_pcr_mask = 0;
		uint16_t pcr_bank_alg = 0;
		if (off + 4 > len)
			return -1;
		uint32_t pcr_sel_count = read_be32(data + off);
		off += 4;

		/* TPM2_NUM_PCR_BANKS in the TSS headers */
		if (pcr_sel_count > 16)
			return -1;

		/* TPMS_PCR_SELECTION: hash(2) + sizeOfSelect(1) + select[] */
		for (uint32_t i = 0; i < pcr_sel_count; i++) {
			uint16_t hash_alg;
			if (off + 3 > len)
				return -1;
			hash_alg = read_be16(data + off);
			off += 2;

			/* the token has one PCR mask, for the SHA-256 bank */
			if (i == 0) {
				pcr_bank_alg = hash_alg;
			} else if (hash_alg != pcr_bank_alg) {
				return -1;
			}

			if (hash_alg != TPM_ALG_SHA256) {
				return -1;
			}

			uint8_t select_size = data[off];
			off += 1;
			if (off + select_size > len)
				return -1;

			for (uint8_t j = 0; j < select_size; j++) {
				uint8_t sel = data[off + j];

				if (j < 3) {
					parsed_pcr_mask |= ((uint32_t)sel)
							   << (8U * j);
				} else if (sel != 0) {
					/* the mask covers PCR 0-23 */
					return -1;
				}
			}
			off += select_size;
		}

		if (off + 2 > len)
			return -1;
		uint16_t digest_size = read_be16(data + off);
		off += 2;
		if (off + digest_size > len)
			return -1;

		if (digest_size == 0 ||
		    digest_size > LOTA_SERVER_MAX_PCR_DIGEST_SIZE)
			return -1;

		if (pcr_digest)
			*pcr_digest = data + off;
		if (pcr_digest_len)
			*pcr_digest_len = digest_size;
		if (pcr_mask_out)
			*pcr_mask_out = parsed_pcr_mask;
	} else {
		if (pcr_digest)
			*pcr_digest = NULL;
		if (pcr_digest_len)
			*pcr_digest_len = 0;
		if (pcr_mask_out)
			*pcr_mask_out = 0;
	}

	return 0;
}

static int verify_rsa_signature(const uint8_t *attest_data, size_t attest_len,
				const uint8_t *signature, size_t sig_len,
				uint16_t sig_alg, uint16_t hash_alg,
				const uint8_t *aik_pub_der, size_t aik_pub_len)
{
	EVP_PKEY *pkey = NULL;
	EVP_MD_CTX *md_ctx = NULL;
	EVP_PKEY_CTX *pkey_ctx = NULL;
	const uint8_t *der_ptr;
	int ret = LOTA_SERVER_ERR_SIG_FAIL;

	if (!aik_pub_der || aik_pub_len == 0)
		return LOTA_SERVER_ERR_INVALID_ARG;
	if (aik_pub_len > (size_t)LONG_MAX)
		return LOTA_SERVER_ERR_INVALID_ARG;
	if (aik_pub_len > LOTA_MAX_AIK_PUB_DER_SIZE)
		return LOTA_SERVER_ERR_INVALID_ARG;

	der_ptr = aik_pub_der;
	pkey = d2i_PUBKEY(NULL, &der_ptr, (long)aik_pub_len);
	if (!pkey)
		return LOTA_SERVER_ERR_CRYPTO;

	if (EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA) {
		ret = LOTA_SERVER_ERR_CRYPTO;
		goto out;
	}

	if (EVP_PKEY_get_bits(pkey) < 2048) {
		ret = LOTA_SERVER_ERR_CRYPTO;
		goto out;
	}

	md_ctx = EVP_MD_CTX_new();
	if (!md_ctx) {
		ret = LOTA_SERVER_ERR_CRYPTO;
		goto out;
	}

	const EVP_MD *md = select_hash_md(hash_alg);
	if (!md) {
		ret = LOTA_SERVER_ERR_SIG_FAIL;
		goto out;
	}

	if (sig_alg == TPM_ALG_RSAPSS) {
		if (EVP_DigestVerifyInit(md_ctx, &pkey_ctx, md, NULL, pkey) !=
		    1)
			goto out;

		if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx,
						 RSA_PKCS1_PSS_PADDING) != 1)
			goto out;

		if (EVP_PKEY_CTX_set_rsa_pss_saltlen(
			    pkey_ctx, RSA_PSS_SALTLEN_DIGEST) != 1)
			goto out;
	} else if (sig_alg == TPM_ALG_RSASSA) {
		if (EVP_DigestVerifyInit(md_ctx, NULL, md, NULL, pkey) != 1)
			goto out;
	} else {
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

static int parse_wire_header(const uint8_t *data, size_t len,
			     struct lota_token_wire *hdr)
{
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

	hdr->valid_until = read_le64(data + 8);
	hdr->flags = read_le32(data + 16);
	memcpy(hdr->nonce, data + 20, 32);
	hdr->sig_alg = read_le16(data + 52);
	hdr->hash_alg = read_le16(data + 54);
	hdr->pcr_mask = read_le32(data + 56);
	memcpy(hdr->policy_digest, data + 60, 32);
	memcpy(hdr->runtime_protect_digest, data + 92, 32);
	hdr->protect_pid_count = read_le32(data + 124);
	hdr->runtime_protect_epoch = read_le64(data + 128);
	hdr->pid_list_size = read_le16(data + 136);
	hdr->attest_size = read_le16(data + 138);
	hdr->sig_size = read_le16(data + 140);
	hdr->runtime_protect_version = read_le16(data + 142);
	hdr->stopped_ms = read_le64(data + 144);

	if (hash_alg_digest_len(hdr->hash_alg) == 0)
		return LOTA_SERVER_ERR_BAD_TOKEN;
	if (hdr->runtime_protect_version != LOTA_RUNTIME_PROTECT_V1)
		return LOTA_SERVER_ERR_BAD_TOKEN;
	if (hdr->protect_pid_count > LOTA_TOKEN_MAX_PROTECT_PIDS)
		return LOTA_SERVER_ERR_BAD_TOKEN;
	if (hdr->pid_list_size > LOTA_TOKEN_MAX_PID_LIST_SIZE)
		return LOTA_SERVER_ERR_BAD_TOKEN;
	if (hdr->pid_list_size !=
	    (uint16_t)(hdr->protect_pid_count * sizeof(uint32_t)))
		return LOTA_SERVER_ERR_BAD_TOKEN;

	/* the registry-digest block follows the PID list */
	size_t registry_list_size = (size_t)hdr->protect_pid_count *
				    LOTA_TOKEN_REGISTRY_DIGEST_SIZE;

	size_t expected = (size_t)LOTA_TOKEN_HEADER_SIZE + hdr->pid_list_size +
			  registry_list_size + hdr->attest_size + hdr->sig_size;
	if (expected > (size_t)hdr->total_size)
		return LOTA_SERVER_ERR_BAD_TOKEN;
	if (hdr->attest_size > 1024 || hdr->sig_size > 512)
		return LOTA_SERVER_ERR_BAD_TOKEN;

	return LOTA_SERVER_OK;
}

int lota_server_verify_token(const uint8_t *token_data, size_t token_len,
			     const uint8_t *aik_pub_der, size_t aik_pub_len,
			     const uint8_t *expected_nonce,
			     struct lota_server_claims *claims)
{
	struct lota_token_wire hdr;
	int ret;

	if (!token_data || !aik_pub_der || !expected_nonce || !claims)
		return LOTA_SERVER_ERR_INVALID_ARG;
	if (token_len == 0 || aik_pub_len == 0)
		return LOTA_SERVER_ERR_INVALID_ARG;

	memset(claims, 0, sizeof(*claims));

	ret = parse_wire_header(token_data, token_len, &hdr);
	if (ret != LOTA_SERVER_OK)
		return ret;

	const uint8_t *pid_list_bytes = token_data + LOTA_TOKEN_HEADER_SIZE;
	size_t registry_list_size =
		(size_t)hdr.protect_pid_count * LOTA_TOKEN_REGISTRY_DIGEST_SIZE;
	const uint8_t (*registry_digests)[32] =
		(const uint8_t (*)[32])(pid_list_bytes + hdr.pid_list_size);
	const uint8_t *attest_data =
		pid_list_bytes + hdr.pid_list_size + registry_list_size;
	const uint8_t *signature = attest_data + hdr.attest_size;
	uint8_t runtime_protect_digest[32];
	uint32_t *pid_list = NULL;

	if (hdr.attest_size == 0 || hdr.sig_size == 0)
		return LOTA_SERVER_ERR_BAD_TOKEN;

	/* parse_wire_header checked this; repeated for the allocation below */
	uint32_t pid_count = hdr.protect_pid_count;
	if (pid_count > LOTA_TOKEN_MAX_PROTECT_PIDS)
		return LOTA_SERVER_ERR_BAD_TOKEN;

	if (pid_count > 0) {
		pid_list = calloc(pid_count, sizeof(uint32_t));
		if (!pid_list)
			return LOTA_SERVER_ERR_CRYPTO;

		for (uint32_t i = 0; i < pid_count; i++)
			pid_list[i] = read_le32(pid_list_bytes +
						((size_t)i * sizeof(uint32_t)));

		if (lota_validate_canonical_protect_pid_list(pid_list,
							     pid_count) != 0) {
			OPENSSL_cleanse(pid_list, pid_count * sizeof(uint32_t));
			free(pid_list);
			return LOTA_SERVER_ERR_BAD_TOKEN;
		}
	}

	ret = lota_compute_runtime_protect_digest(
		pid_list, pid_count ? registry_digests : NULL, pid_count,
		runtime_protect_digest);
	if (ret != 0) {
		if (pid_list) {
			OPENSSL_cleanse(pid_list, pid_count * sizeof(uint32_t));
			free(pid_list);
		}
		return LOTA_SERVER_ERR_BAD_TOKEN;
	}
	if (CRYPTO_memcmp(runtime_protect_digest, hdr.runtime_protect_digest,
			  32) != 0)
		ret = LOTA_SERVER_ERR_RUNTIME_IMAGE;
	else
		ret = LOTA_SERVER_OK;

	if (pid_list) {
		OPENSSL_cleanse(pid_list, pid_count * sizeof(uint32_t));
		free(pid_list);
	}
	if (ret != LOTA_SERVER_OK)
		return ret;

	ret = verify_rsa_signature(attest_data, hdr.attest_size, signature,
				   hdr.sig_size, hdr.sig_alg, hdr.hash_alg,
				   aik_pub_der, aik_pub_len);
	if (ret != LOTA_SERVER_OK)
		return ret;

	const uint8_t *extra_data = NULL;
	size_t extra_data_len = 0;
	const uint8_t *pcr_digest = NULL;
	size_t pcr_digest_len = 0;
	uint32_t quoted_pcr_mask = 0;
	size_t expected_pcr_digest_len = hash_alg_digest_len(hdr.hash_alg);

	if (parse_tpms_attest(attest_data, hdr.attest_size, &extra_data,
			      &extra_data_len, &pcr_digest, &pcr_digest_len,
			      &quoted_pcr_mask) != 0) {
		return LOTA_SERVER_ERR_ATTEST_PARSE;
	}

	if (quoted_pcr_mask != hdr.pcr_mask)
		return LOTA_SERVER_ERR_NONCE_FAIL;

	/* verify nonce binding: extraData ==
	 * SHA256(valid_until||flags||pcr_mask||nonce||policy_digest||
	 * runtime_protect_digest||runtime_protect_epoch||stopped_ms) */
	uint8_t computed_nonce[32];
	if (lota_compute_token_quote_nonce(
		    hdr.valid_until, hdr.flags, hdr.pcr_mask, hdr.nonce,
		    hdr.policy_digest, hdr.runtime_protect_digest,
		    hdr.runtime_protect_epoch, hdr.stopped_ms,
		    computed_nonce) != 0) {
		return LOTA_SERVER_ERR_NONCE_FAIL;
	}

	if (extra_data_len != 32 ||
	    CRYPTO_memcmp(extra_data, computed_nonce, 32) != 0) {
		return LOTA_SERVER_ERR_NONCE_FAIL;
	}

	if (CRYPTO_memcmp(hdr.nonce, expected_nonce, 32) != 0)
		return LOTA_SERVER_ERR_NONCE_FAIL;

	if (expected_pcr_digest_len == 0)
		return LOTA_SERVER_ERR_SIG_FAIL;

	claims->valid_until = hdr.valid_until;
	claims->flags = hdr.flags;
	memcpy(claims->nonce, hdr.nonce, 32);
	claims->pcr_mask = hdr.pcr_mask;
	memcpy(claims->policy_digest, hdr.policy_digest, 32);
	memcpy(claims->runtime_protect_digest, hdr.runtime_protect_digest, 32);
	claims->runtime_protect_epoch = hdr.runtime_protect_epoch;
	claims->protect_pid_count = hdr.protect_pid_count;
	claims->stopped_ms = hdr.stopped_ms;

	if (!pcr_digest || pcr_digest_len != expected_pcr_digest_len)
		return LOTA_SERVER_ERR_ATTEST_PARSE;

	if (pcr_digest_len > sizeof(claims->pcr_digest))
		return LOTA_SERVER_ERR_ATTEST_PARSE;

	memcpy(claims->pcr_digest, pcr_digest, pcr_digest_len);
	claims->pcr_digest_len = pcr_digest_len;

	uint64_t now = (uint64_t)time(NULL);

	/*
	 * The token has no issue time, so valid_until is the only temporal
	 * anchor. sdk/server computes this bound from the same two values.
	 */
	{
		const uint64_t window =
			(uint64_t)LOTA_SERVER_MAX_TOKEN_AGE_SEC +
			(uint64_t)LOTA_SERVER_MAX_CLOCK_SKEW_SEC;
		uint64_t future_cutoff;

		if (now <= UINT64_MAX - window)
			future_cutoff = now + window;
		else
			future_cutoff = UINT64_MAX;

		if (hdr.valid_until > future_cutoff)
			return LOTA_SERVER_ERR_FUTURE;
	}

	claims->expired = (hdr.valid_until > 0 && now > hdr.valid_until) ? 1 :
									   0;

	if (claims->expired)
		return LOTA_SERVER_ERR_EXPIRED;

	return LOTA_SERVER_OK;
}

int lota_server_parse_token(const uint8_t *token_data, size_t token_len,
			    struct lota_server_claims *claims)
{
	struct lota_token_wire hdr;
	int ret;

	if (!token_data || !claims)
		return LOTA_SERVER_ERR_INVALID_ARG;

	memset(claims, 0, sizeof(*claims));

	ret = parse_wire_header(token_data, token_len, &hdr);
	if (ret != LOTA_SERVER_OK)
		return ret;

	claims->valid_until = hdr.valid_until;
	claims->flags = hdr.flags;
	memcpy(claims->nonce, hdr.nonce, 32);
	claims->pcr_mask = hdr.pcr_mask;
	memcpy(claims->policy_digest, hdr.policy_digest, 32);
	memcpy(claims->runtime_protect_digest, hdr.runtime_protect_digest, 32);
	claims->runtime_protect_epoch = hdr.runtime_protect_epoch;
	claims->protect_pid_count = hdr.protect_pid_count;
	claims->stopped_ms = hdr.stopped_ms;

	if (hdr.attest_size > 0) {
		size_t registry_list_size = (size_t)hdr.protect_pid_count *
					    LOTA_TOKEN_REGISTRY_DIGEST_SIZE;
		const uint8_t *attest_data =
			token_data + LOTA_TOKEN_HEADER_SIZE +
			hdr.pid_list_size + registry_list_size;
		const uint8_t *pcr_digest = NULL;
		size_t pcr_digest_len = 0;
		size_t expected_pcr_digest_len =
			hash_alg_digest_len(hdr.hash_alg);

		if (parse_tpms_attest(attest_data, hdr.attest_size, NULL, NULL,
				      &pcr_digest, &pcr_digest_len,
				      NULL) == 0) {
			if (pcr_digest &&
			    pcr_digest_len <= sizeof(claims->pcr_digest) &&
			    pcr_digest_len == expected_pcr_digest_len) {
				memcpy(claims->pcr_digest, pcr_digest,
				       pcr_digest_len);
				claims->pcr_digest_len = pcr_digest_len;
			}
		}
	}

	uint64_t now = (uint64_t)time(NULL);
	claims->expired = (hdr.valid_until > 0 && now > hdr.valid_until) ? 1 :
									   0;

	return LOTA_SERVER_OK;
}

const char *lota_server_strerror(int error)
{
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
	case LOTA_SERVER_ERR_FUTURE:
		return "Token valid_until too far in the future";
	case LOTA_SERVER_ERR_RUNTIME_IMAGE:
		return "Runtime image measurement does not match the quote";
	case LOTA_SERVER_ERR_BAD_EVIDENCE:
		return "Boot evidence does not match the token";

	default:
		return "Unknown error";
	}
}

const char *lota_server_sdk_version(void)
{
	return LOTA_BUILD_VERSION_STRING;
}

/* the agent's bounds, terminator included; lota_gaming.h repeats them */
#define REGISTRY_SONAME_MAX LOTA_RUNTIME_IMAGE_SONAME_MAX
#define REGISTRY_PATH_MAX (LOTA_RUNTIME_IMAGE_SONAME_MAX + 64)
#define REGISTRY_FLAGS                                                 \
	(LOTA_IPC_REGISTRY_MEASURED | LOTA_IPC_REGISTRY_HISTORY_LOST | \
	 LOTA_IPC_REGISTRY_ACTORS_LOST | LOTA_IPC_REGISTRY_FROM_EXEC | \
	 LOTA_IPC_REGISTRY_TRUNCATED)

_Static_assert(LOTA_SERVER_REGISTRY_MAX_OBJECTS ==
		       LOTA_IPC_REGISTRY_MAX_OBJECTS,
	       "lota_server.h copies the agent's registry bound");
_Static_assert(LOTA_SERVER_REGISTRY_MAX_ACTORS == LOTA_IPC_REGISTRY_MAX_ACTORS,
	       "lota_server.h copies the agent's actor bound");
_Static_assert(
	sizeof(((struct lota_server_registry_actor *)0)->comm) ==
			sizeof(((struct lota_ipc_registry_actor *)0)->comm) &&
		sizeof(((struct lota_server_registry_actor *)0)->owner_comm) ==
			sizeof(((struct lota_ipc_registry_actor *)0)
				       ->owner_comm),
	"lota_server.h copies the agent's name width");

/* @m as the agent put it on the wire; 0 or LOTA_SERVER_ERR_INVALID_ARG */
static int registry_wire_entry(const struct lota_server_registry_module *m,
			       struct lota_ipc_registry_entry *e)
{
	const char *path = m->path ? m->path : "";
	size_t slen;
	size_t plen;

	if (!m->soname)
		return LOTA_SERVER_ERR_INVALID_ARG;
	slen = strnlen(m->soname, REGISTRY_SONAME_MAX);
	plen = strnlen(path, REGISTRY_PATH_MAX);
	if (slen == 0 || slen >= REGISTRY_SONAME_MAX ||
	    plen >= REGISTRY_PATH_MAX)
		return LOTA_SERVER_ERR_INVALID_ARG;
	if (m->flags & ~(uint32_t)LOTA_IPC_REGISTRY_ENTRY_KNOWN)
		return LOTA_SERVER_ERR_INVALID_ARG;

	switch (m->road) {
	case LOTA_IPC_REGISTRY_ROAD_NONE:
		if (m->digest_len != 0)
			return LOTA_SERVER_ERR_INVALID_ARG;
		break;
	case LOTA_IPC_REGISTRY_ROAD_VERITY:
	case LOTA_IPC_REGISTRY_ROAD_CONTENT:
		if (!m->digest ||
		    !LOTA_VERITY_DIGEST_LEN_SUPPORTED(m->digest_len))
			return LOTA_SERVER_ERR_INVALID_ARG;
		break;
	default:
		return LOTA_SERVER_ERR_INVALID_ARG;
	}

	memset(e, 0, sizeof(*e));
	e->size = m->size;
	e->dev = m->dev;
	e->ino = m->ino;
	e->road = (uint8_t)m->road;
	e->digest_len = (uint8_t)m->digest_len;
	e->soname_len = (uint16_t)slen;
	e->path_len = (uint16_t)plen;
	e->flags = (uint16_t)m->flags;
	if (m->digest_len)
		memcpy(e->digest, m->digest, m->digest_len);
	return 0;
}

/* @p as the agent put it on the wire; 0 or LOTA_SERVER_ERR_INVALID_ARG */
static int registry_wire_actor(const struct lota_server_registry_actor *p,
			       struct lota_ipc_registry_actor *w)
{
	if (p->kind < LOTA_IPC_REGISTRY_ACTOR_CONNECT ||
	    p->kind > LOTA_IPC_REGISTRY_ACTOR_KIND_MAX)
		return LOTA_SERVER_ERR_INVALID_ARG;
	if (memchr(p->comm, '\0', sizeof(p->comm)) == NULL ||
	    memchr(p->owner_comm, '\0', sizeof(p->owner_comm)) == NULL)
		return LOTA_SERVER_ERR_INVALID_ARG;

	memset(w, 0, sizeof(*w));
	w->count = p->count;
	w->start_ticks = p->start_ticks;
	w->exe_dev = p->exe_dev;
	w->exe_ino = p->exe_ino;
	w->tgid = p->tgid;
	w->uid = p->uid;
	w->owner_tgid = p->owner_tgid;
	w->kind = p->kind;
	memcpy(w->comm, p->comm, sizeof(w->comm));
	memcpy(w->owner_comm, p->owner_comm, sizeof(w->owner_comm));
	return 0;
}

int lota_server_registry_digest(uint32_t flags,
				const struct lota_server_registry_module *mods,
				size_t count,
				const struct lota_server_registry_actor *actors,
				size_t actor_count, uint8_t out[32])
{
	EVP_MD_CTX *md;
	int ret = LOTA_SERVER_OK;

	if (!out || (count > 0 && !mods) || (actor_count > 0 && !actors))
		return LOTA_SERVER_ERR_INVALID_ARG;
	if (count > LOTA_SERVER_REGISTRY_MAX_OBJECTS ||
	    actor_count > LOTA_SERVER_REGISTRY_MAX_ACTORS ||
	    (flags & ~REGISTRY_FLAGS))
		return LOTA_SERVER_ERR_INVALID_ARG;

	md = EVP_MD_CTX_new();
	if (!md)
		return LOTA_SERVER_ERR_CRYPTO;
	if (lota_registry_digest_begin(md, (uint16_t)flags, (uint32_t)count,
				       (uint32_t)actor_count))
		ret = LOTA_SERVER_ERR_CRYPTO;

	for (size_t i = 0; ret == LOTA_SERVER_OK && i < count; i++) {
		const struct lota_server_registry_module *m = &mods[i];
		struct lota_ipc_registry_entry e;

		ret = registry_wire_entry(m, &e);
		if (ret != LOTA_SERVER_OK)
			break;
		if (lota_registry_digest_entry(md, &e, m->soname,
					       m->path ? m->path : ""))
			ret = LOTA_SERVER_ERR_CRYPTO;
	}

	for (size_t i = 0; ret == LOTA_SERVER_OK && i < actor_count; i++) {
		struct lota_ipc_registry_actor w;

		ret = registry_wire_actor(&actors[i], &w);
		if (ret != LOTA_SERVER_OK)
			break;
		if (lota_registry_digest_actor(md, &w))
			ret = LOTA_SERVER_ERR_CRYPTO;
	}

	if (ret == LOTA_SERVER_OK && lota_registry_digest_final(md, out))
		ret = LOTA_SERVER_ERR_CRYPTO;
	EVP_MD_CTX_free(md);
	return ret;
}

/* EFI global variable namespace 8be4df61-93ca-11d2-aa0d-00e098032b8c */
static const uint8_t efi_global_guid[16] = {
	0x61, 0xdf, 0xe4, 0x8b, 0xca, 0x93, 0xd2, 0x11,
	0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c,
};

/* "SecureBoot" in UTF-16LE */
static const uint8_t secure_boot_name[20] = {
	'S', 0, 'e', 0, 'c', 0, 'u', 0, 'r', 0,
	'e', 0, 'B', 0, 'o', 0, 'o', 0, 't', 0,
};

#define EVIDENCE_PCR_SECURE_BOOT 7u
#define EFI_VARIABLE_DATA_HEADER (16 + 8 + 8)

static int sha256_once(const void *data, size_t len, uint8_t out[32])
{
	return EVP_Digest(data, len, out, NULL, EVP_sha256(), NULL) == 1 ? 0 :
									   -1;
}

/*
 * The SecureBoot value an event measures: 1 for on, 0 for any other value,
 * -1 when the event measures some other variable.
 */
static int secure_boot_vote(const uint8_t *data, size_t size)
{
	uint64_t name_len, value_len;
	const uint8_t *value;

	if (size < EFI_VARIABLE_DATA_HEADER + sizeof(secure_boot_name))
		return -1;
	if (memcmp(data, efi_global_guid, sizeof(efi_global_guid)) != 0)
		return -1;
	name_len = read_le64(data + 16);
	value_len = read_le64(data + 24);
	if (name_len != sizeof(secure_boot_name) / 2 ||
	    memcmp(data + EFI_VARIABLE_DATA_HEADER, secure_boot_name,
		   sizeof(secure_boot_name)) != 0)
		return -1;

	value = data + EFI_VARIABLE_DATA_HEADER + sizeof(secure_boot_name);
	if (value_len != size - (size_t)(value - data))
		return 0;
	return value_len == 1 && value[0] == 1;
}

int lota_server_verify_boot_evidence(const struct lota_server_claims *claims,
				     const uint8_t *evidence, size_t len,
				     int *secure_boot)
{
	static const uint8_t zero4[4];
	uint8_t separator[32], digest[32], pcr7[32] = { 0 };
	uint8_t chain[64];
	const uint8_t *p, *end;
	uint32_t mask;
	uint16_t count;
	size_t npcr = 0;
	int votes_on = 0, votes_off = 0, before_separator = 1;
	EVP_MD_CTX *md;

	if (!claims || !evidence || !secure_boot)
		return LOTA_SERVER_ERR_INVALID_ARG;
	*secure_boot = 0;

	if (len < LOTA_BOOT_EVIDENCE_HEADER_SIZE ||
	    read_le16(evidence) != LOTA_BOOT_EVIDENCE_VERSION)
		return LOTA_SERVER_ERR_BAD_EVIDENCE;
	count = read_le16(evidence + 2);
	mask = read_le32(evidence + 4);
	if (mask != claims->pcr_mask || claims->pcr_digest_len != 32 ||
	    !(mask & (1u << EVIDENCE_PCR_SECURE_BOOT)) ||
	    mask >> LOTA_PCR_COUNT)
		return LOTA_SERVER_ERR_BAD_EVIDENCE;

	p = evidence + LOTA_BOOT_EVIDENCE_HEADER_SIZE;
	end = evidence + len;

	/* the PCR values, checked against the digest the TPM signed */
	md = EVP_MD_CTX_new();
	if (!md || EVP_DigestInit_ex(md, EVP_sha256(), NULL) != 1) {
		EVP_MD_CTX_free(md);
		return LOTA_SERVER_ERR_CRYPTO;
	}
	for (uint32_t i = 0; i < LOTA_PCR_COUNT; i++) {
		if (!(mask & (1u << i)))
			continue;
		if ((size_t)(end - p) < 32) {
			EVP_MD_CTX_free(md);
			return LOTA_SERVER_ERR_BAD_EVIDENCE;
		}
		if (EVP_DigestUpdate(md, p, 32) != 1) {
			EVP_MD_CTX_free(md);
			return LOTA_SERVER_ERR_CRYPTO;
		}
		if (i == EVIDENCE_PCR_SECURE_BOOT)
			memcpy(pcr7, p, 32);
		p += 32;
		npcr++;
	}
	if (EVP_DigestFinal_ex(md, digest, NULL) != 1) {
		EVP_MD_CTX_free(md);
		return LOTA_SERVER_ERR_CRYPTO;
	}
	EVP_MD_CTX_free(md);
	if (npcr == 0 || CRYPTO_memcmp(digest, claims->pcr_digest, 32) != 0)
		return LOTA_SERVER_ERR_BAD_EVIDENCE;

	/*
	 * The events, replayed to the PCR 7 value. Event types are labels
	 * the log carries outside the digest, so only digests and data count:
	 * the separator is the first event that extends SHA-256 of four zero
	 * bytes, and only a SecureBoot measurement before it is the firmware's.
	 */
	if (sha256_once(zero4, sizeof(zero4), separator))
		return LOTA_SERVER_ERR_CRYPTO;
	memset(chain, 0, 32);
	for (uint32_t i = 0; i < count; i++) {
		uint16_t data_size;
		const uint8_t *ev = p;

		if ((size_t)(end - p) < LOTA_BOOT_EVIDENCE_EVENT_SIZE)
			return LOTA_SERVER_ERR_BAD_EVIDENCE;
		data_size = read_le16(p + 32);
		p += LOTA_BOOT_EVIDENCE_EVENT_SIZE;
		if ((size_t)(end - p) < data_size)
			return LOTA_SERVER_ERR_BAD_EVIDENCE;

		if (data_size > 0) {
			int vote;

			if (sha256_once(p, data_size, digest))
				return LOTA_SERVER_ERR_CRYPTO;
			if (CRYPTO_memcmp(digest, ev, 32) != 0)
				return LOTA_SERVER_ERR_BAD_EVIDENCE;
			vote = secure_boot_vote(p, data_size);
			if (before_separator && vote == 1)
				votes_on++;
			else if (before_separator && vote == 0)
				votes_off++;
		}
		if (memcmp(ev, separator, 32) == 0)
			before_separator = 0;

		memcpy(chain + 32, ev, 32);
		if (sha256_once(chain, sizeof(chain), chain))
			return LOTA_SERVER_ERR_CRYPTO;
		p += data_size;
	}
	if (p != end || CRYPTO_memcmp(chain, pcr7, 32) != 0)
		return LOTA_SERVER_ERR_BAD_EVIDENCE;

	*secure_boot = !before_separator && votes_on > 0 && votes_off == 0;
	return LOTA_SERVER_OK;
}
