/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * LOTA server-side token verification, for game servers checking the bytes
 * lota_token_serialize() produced on a client.
 *
 * The AIK public key must come from a trusted source.
 */

#ifndef LOTA_SERVER_H
#define LOTA_SERVER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "lota_token.h"

/* SHA-256, SHA-384 or SHA-512 */
#define LOTA_SERVER_MAX_PCR_DIGEST_SIZE 64

/*
 * Freshness window. A token has an expiry and no issue time, so verification
 * refuses one whose expiry lies further ahead than the age plus the skew
 * between the agent's clock and the relying party's. sdk/server computes the
 * same bound.
 * The agent's attest_interval must stay at or below the age.
 */
#define LOTA_SERVER_MAX_TOKEN_AGE_SEC 300U
#define LOTA_SERVER_MAX_CLOCK_SKEW_SEC 60U

enum lota_server_error {
	LOTA_SERVER_OK = 0,
	LOTA_SERVER_ERR_INVALID_ARG = -1, /* NULL pointer or bad parameter */
	LOTA_SERVER_ERR_BAD_TOKEN = -2, /* Token parse error (bad magic/size) */
	LOTA_SERVER_ERR_BAD_VERSION = -3, /* Unsupported token version */
	LOTA_SERVER_ERR_SIG_FAIL = -4, /* RSA signature verification failed */
	LOTA_SERVER_ERR_NONCE_FAIL = -5, /* TPMS_ATTEST or nonce do not match */
	LOTA_SERVER_ERR_EXPIRED = -6, /* Token has expired */
	LOTA_SERVER_ERR_ATTEST_PARSE = -7, /* Failed to parse TPMS_ATTEST */
	LOTA_SERVER_ERR_CRYPTO = -8, /* OpenSSL internal error */
	LOTA_SERVER_ERR_BUFFER = -9, /* Buffer too small */
	LOTA_SERVER_ERR_FUTURE = -10, /* valid_until too far in the future */
	LOTA_SERVER_ERR_RUNTIME_IMAGE =
		-11, /* the runtime image measurement does not
			reconcile with the one the TPM signed */
	LOTA_SERVER_ERR_BAD_EVIDENCE = -12, /* boot evidence malformed, or not
						the boot the token quotes */
};

/*
 * Claims of a token. A successful verification proves that the AIK signed these
 * fields. pcr_mask and pcr_digest come from the TPM; the rest is what the
 * signer stated, and a local root can sign its own: see
 * Documentation/security/threat-model.rst.
 */
struct lota_server_claims {
	uint64_t valid_until; /* Token expiry time (Unix timestamp) */
	uint32_t flags; /* LOTA_FLAG_* bitmask at issue time */
	uint8_t nonce[32]; /* Client nonce echoed from token */
	uint32_t pcr_mask; /* PCRs included in TPM quote */
	uint8_t policy_digest[32]; /* SHA-256 over startup enforcement policy */
	uint8_t runtime_protect_digest[32];
	uint64_t runtime_protect_epoch; /* Monotonic PID-set mutation id */
	uint32_t protect_pid_count;
	uint8_t pcr_digest[LOTA_SERVER_MAX_PCR_DIGEST_SIZE];
	size_t pcr_digest_len; /* Actual length of pcr_digest (0 if absent) */
	int expired; /* 1 if token has expired, 0 otherwise */
	/* ms any thread of the instance stood stopped, suspend aside */
	uint64_t stopped_ms;
};

/**
 * lota_server_verify_token() - Verify a serialized attestation token.
 * @token_data: token from lota_token_serialize().
 * @token_len: size of @token_data.
 * @aik_pub_der: AIK public key in DER (PKIX/SPKI) format.
 * @aik_pub_len: size of @aik_pub_der.
 * @expected_nonce: 32-byte nonce the server issued for this attempt.
 * @claims: zeroed unless an argument is invalid, filled once the signature,
 *          extraData and nonce check out, so LOTA_SERVER_ERR_FUTURE and
 *          LOTA_SERVER_ERR_EXPIRED still report valid_until.
 *
 * Recomputes the runtime digest from the PID list and registry digests, then
 * checks the TPM signature over attest_data, the quoted PCR mask against the
 * header, and extraData against lota_compute_token_quote_nonce() over the
 * header, so every field the caller acts on is inside the signature. Then the
 * token nonce and the expiry.
 *
 * A relying party that wants a tighter freshness window applies it to
 * claims.valid_until itself.
 *
 * Return: LOTA_SERVER_OK on success,
 * LOTA_SERVER_ERR_EXPIRED if a nonzero valid_until has passed,
 * LOTA_SERVER_ERR_FUTURE if valid_until is too far ahead,
 * LOTA_SERVER_ERR_NONCE_FAIL if the mask, extraData or nonce differ,
 * LOTA_SERVER_ERR_RUNTIME_IMAGE if the digest recomputed from the PID list and
 * registry digests differs from the signed one,
 * another negative code otherwise.
 */
int lota_server_verify_token(const uint8_t *token_data, size_t token_len,
			     const uint8_t *aik_pub_der, size_t aik_pub_len,
			     const uint8_t *expected_nonce,
			     struct lota_server_claims *claims);

/**
 * lota_server_parse_token() - Extract claims without verifying the signature.
 * @token_data: token from lota_token_serialize().
 * @token_len: size of @token_data.
 * @claims: receives the claims.
 *
 * Claims from this function are untrusted.
 *
 * Return: LOTA_SERVER_OK on success, a negative code on a parse failure.
 */
int lota_server_parse_token(const uint8_t *token_data, size_t token_len,
			    struct lota_server_claims *claims);

/**
 * lota_server_strerror() - Word an error code.
 * @error: LOTA_SERVER_* code.
 *
 * Return: a static string.
 */
const char *lota_server_strerror(int error);

/**
 * lota_server_sdk_version() - Identify the build this library came from.
 *
 * Opaque: match it, do not parse it. Binary compatibility is the soname and the
 * ABI version pkg-config reports, see
 * Documentation/contributor/development/api-stability.rst.
 *
 * Return: the static string lota_sdk_version() reports for the same release.
 */
const char *lota_server_sdk_version(void);

/*
 * One code object of a protected process's registry, with every field of the
 * lota_registry_object lota_get_registry() reported.
 */
struct lota_server_registry_module {
	const char *soname;
	const char *path; /* NULL or "" for none */
	uint64_t size;
	uint64_t dev;
	uint64_t ino;
	uint32_t road; /* LOTA_REGISTRY_ROAD_* */
	uint32_t flags; /* LOTA_REGISTRY_OBJECT_* */
	uint32_t digest_len; /* 0, 32 or 64 */
	const uint8_t *digest;
};

/* Most objects the agent lists for one process */
#define LOTA_SERVER_REGISTRY_MAX_OBJECTS 1024

/*
 * One actor of the instance, with every field of the lota_registry_actor
 * lota_get_registry() reported.
 */
struct lota_server_registry_actor {
	uint64_t count;
	uint64_t start_ticks;
	uint64_t exe_dev;
	uint64_t exe_ino;
	uint32_t tgid;
	uint32_t uid;
	uint32_t owner_tgid;
	uint32_t kind; /* LOTA_REGISTRY_ACTOR_* */
	char comm[16];
	char owner_comm[16];
};

/* Most actors the agent lists for one process */
#define LOTA_SERVER_REGISTRY_MAX_ACTORS 256

/**
 * lota_server_registry_digest() - Hash a registry the way the agent does.
 * @flags: the registry's LOTA_REGISTRY_* flags.
 * @mods: objects of one process, in the order listed.
 * @count: entries in @mods.
 * @actors: actors of the process, in the order listed.
 * @actor_count: entries in @actors.
 * @out: receives the digest.
 *
 * @out equals the token's protected_registry_digests entry for the process when
 * the registry is the one that round measured. Anything else, reordered, short
 * of an entry or with one rewritten, is not the list behind the token.
 *
 * Return: LOTA_SERVER_OK, LOTA_SERVER_ERR_INVALID_ARG for a malformed entry, an
 * unknown flag or too many entries, or LOTA_SERVER_ERR_CRYPTO.
 */
int lota_server_registry_digest(uint32_t flags,
				const struct lota_server_registry_module *mods,
				size_t count,
				const struct lota_server_registry_actor *actors,
				size_t actor_count, uint8_t out[32]);

/**
 * lota_server_verify_boot_evidence() - Read Secure Boot from a token's PCRs.
 * @claims: from lota_server_verify_token(); lota_server_parse_token() claims
 *          prove nothing.
 * @evidence: bytes lota_get_boot_evidence() returned with the token.
 * @len: size of @evidence.
 * @secure_boot: 1 when the firmware measured Secure Boot on before it handed
 *               over to the boot loader, 0 otherwise.
 *
 * Accepts the evidence only when its PCR values hash to the signed PCR digest
 * and its PCR 7 events replay to the PCR 7 value. A SecureBoot measurement that
 * is absent, carries any value but 1 or follows the firmware's separator leaves
 * @secure_boot at 0, as does evidence with no separator.
 *
 * Return: LOTA_SERVER_OK, LOTA_SERVER_ERR_INVALID_ARG,
 * LOTA_SERVER_ERR_BAD_EVIDENCE or LOTA_SERVER_ERR_CRYPTO.
 */
int lota_server_verify_boot_evidence(const struct lota_server_claims *claims,
				     const uint8_t *evidence, size_t len,
				     int *secure_boot);

#ifdef __cplusplus
}
#endif

#endif /* LOTA_SERVER_H */
