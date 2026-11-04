/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * LOTA Server-Side Token Verification SDK
 *
 * Library for game servers to verify attestation tokens received
 * from game clients running the LOTA Gaming SDK.
 *
 * Verification flow:
 *  1. Game server generates a random 32-byte nonce
 *  2. Game server sends nonce to game client
 *  3. Game client calls lota_get_token()
 *  4. Game client serializes: lota_token_serialize()
 *  5. Game client sends serialized bytes to game server
 *  6. Game server calls lota_server_verify_token()
 *
 * The AIK public key must be obtained from a trusted source - typically the
 * LOTA verifier's /api/v1/clients endpoint or a pre-enrollment database.
 *
 * Example:
 *
 *   struct lota_server_claims claims;
 *   int ret = lota_server_verify_token(
 *       token_bytes, token_len,
 *       aik_pub_der, aik_pub_len,
 *       server_nonce,
 *       60,          max 60 seconds old
 *       &claims
 *   );
 *
 *   if (ret == LOTA_SERVER_OK) {
 *       Client is attested and token is fresh.
 *   }
 */

#ifndef LOTA_SERVER_H
#define LOTA_SERVER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "lota_token.h"

/* TPM2 PCR composite digest can be SHA-256, SHA-384, or SHA-512. */
#define LOTA_SERVER_MAX_PCR_DIGEST_SIZE 64

/*
 * Freshness window.
 * Token carries an expiry and no issue time, so valid_until is the only temporal
 * anchor: agent on the default attestation interval mints one expiring that
 * interval from now, and token claiming to live much longer is either from
 * misconfigured agent or replayed from elsewhere.
 * Verification refuses one whose expiry is beyond the interval plus allowance
 * for clock skew between the agent and the relying party.
 *
 * sdk/server computes the same bound from the same two values,
 * so the C and Go verifiers accept exactly the same set of tokens.
 * Keep the agent's attest_interval at or below LOTA_SERVER_MAX_TOKEN_AGE_SEC.
 */
#define LOTA_SERVER_MAX_TOKEN_AGE_SEC 300U
#define LOTA_SERVER_MAX_CLOCK_SKEW_SEC 60U

/*
 * Server-side error codes
 */
enum lota_server_error {
	LOTA_SERVER_OK = 0,
	LOTA_SERVER_ERR_INVALID_ARG = -1, /* NULL pointer or bad parameter */
	LOTA_SERVER_ERR_BAD_TOKEN = -2, /* Token parse error (bad magic/size) */
	LOTA_SERVER_ERR_BAD_VERSION = -3, /* Unsupported token version */
	LOTA_SERVER_ERR_SIG_FAIL = -4, /* RSA signature verification failed */
	LOTA_SERVER_ERR_NONCE_FAIL = -5, /* Nonce mismatch in TPMS_ATTEST */
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
 * Verified claims extracted from a token
 *
 * A successful verification proves that the AIK signed these fields. pcr_mask
 * and pcr_digest come from the TPM. The rest is what the signer stated, and a
 * local root can sign its own: see Documentation/security/threat-model.rst.
 */
struct lota_server_claims {
	uint64_t valid_until; /* Token expiry time (Unix timestamp) */
	uint32_t flags; /* LOTA_FLAG_* bitmask at issue time */
	uint8_t nonce[32]; /* Client nonce echoed from token */
	uint32_t pcr_mask; /* PCRs included in TPM quote */
	uint8_t policy_digest[32]; /* SHA-256 over startup enforcement policy */
	uint8_t runtime_protect_digest[32];
	uint64_t runtime_protect_epoch; /* Monotonic runtime PID-set mutation id */
	uint32_t protect_pid_count;
	uint8_t pcr_digest[LOTA_SERVER_MAX_PCR_DIGEST_SIZE];
	size_t pcr_digest_len; /* Actual length of pcr_digest (0 if absent) */
	int expired; /* 1 if token has expired, 0 otherwise */
	/* milliseconds any thread of the instance stood stopped, suspend aside */
	uint64_t stopped_ms;
};

/*
 * lota_server_verify_token - Verify a serialized attestation token
 *
 * @token_data:     Serialized token bytes (from lota_token_serialize)
 * @token_len:      Length of token_data
 * @aik_pub_der:    AIK public key in DER (PKIX/SPKI) format
 * @aik_pub_len:    Length of aik_pub_der
 * @expected_nonce: Required 32-byte nonce expected by the server for this
 *                  verification attempt
 * @claims:         Output claims structure, populated whenever the token
 *                  parses far enough to fill it -- including on EXPIRED,
 *                  so the caller can report valid_until
 *
 * Verification steps:
 *  1. Parse token wire format
 *  2. Verify the TPM signature over attest_data with the AIK public key
 *  3. Parse TPMS_ATTEST, extract extraData and the quoted PCR mask
 *  4. Quoted PCR mask == the mask the token header claims
 *  5. extraData == SHA256(valid_until || flags || pcr_mask || nonce ||
 *     policy_digest || runtime_protect_digest || runtime_protect_epoch),
 *     so every field the caller acts on is inside the TPM signature
 *  6. Token nonce == expected_nonce
 *  7. valid_until has not passed and is not further ahead than
 *     LOTA_SERVER_MAX_TOKEN_AGE_SEC + LOTA_SERVER_MAX_CLOCK_SKEW_SEC
 *  8. Extract the PCR digest from the TPMS_ATTEST QuoteInfo
 *
 * There is no token-age parameter:
 * Token carries an expiry and no issue time, so the freshness window is expressed
 * as a bound on `valid_until` and applied here rather than passed in.
 * Relying party that wants a tighter one applies it to `claims.valid_until` itself.
 *
 * Returns: LOTA_SERVER_OK on success.
 *          LOTA_SERVER_ERR_EXPIRED if now > valid_until.
 *          LOTA_SERVER_ERR_FUTURE if valid_until is too far ahead.
 *          LOTA_SERVER_ERR_NONCE_FAIL if either nonce check fails.
 *          LOTA_SERVER_ERR_RUNTIME_IMAGE if the runtime-protect digest
 *          recomputed from the token's pid list and image digests differs
 *          from the one inside the TPM signature.
 *          Other negative error codes on verification failure.
 */
int lota_server_verify_token(const uint8_t *token_data, size_t token_len,
			     const uint8_t *aik_pub_der, size_t aik_pub_len,
			     const uint8_t *expected_nonce,
			     struct lota_server_claims *claims);

/*
 * Parse token without cryptographic verification.
 *
 * Extracts claims from a serialized token WITHOUT verifying the
 * TPM signature. Useful for logging, debugging, or when the caller
 * handles verification separately.
 *
 * WARNING: Claims from this function are UNTRUSTED.
 *
 * Returns LOTA_SERVER_OK on success, negative error on parse failure.
 */
int lota_server_parse_token(const uint8_t *token_data, size_t token_len,
			    struct lota_server_claims *claims);

const char *lota_server_strerror(int error);

/*
 * Identify the build this library came from.
 *
 * Returns static string naming the LOTA release the library was compiled from,
 * the same one lota_sdk_version() reports, so relying party and the client it
 * verifies name their builds the same way.
 * Treat it as opaque: the format carries no promise, so match it, do not parse it.
 *
 * It is NOT the answer to "what may I link against".
 * Binary compatibility is the soname the loader resolves and the ABI version
 * the pkg-config module reports;
 * see Documentation/contributor/development/api-stability.rst.
 */
const char *lota_server_sdk_version(void);

/*
 * One code object of a protected process's registry, as the relying party
 * received it: every field of the lota_registry_object lota_get_registry()
 * reported, unchanged. digest_len is 0 for an object without a digest.
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
#define LOTA_SERVER_REGISTRY_MAX_OBJECTS 512

/*
 * One actor of the instance, as the relying party received it: every field of the lota_registry_actor lota_get_registry()
 * reported, unchanged.
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

/*
 * lota_server_registry_digest - Hash a registry into its image digest
 * @flags:      The registry's LOTA_REGISTRY_* flags
 * @mods:       The objects of one process, in the order they were listed
 * @count:      Number of objects
 * @actors:      The actors of the process, in the order they were listed
 * @actor_count: Number of actors
 * @out:        Receives the 32-byte image digest
 *
 * Hashes the flags, every object and every actor the way the agent does,
 * objects without a digest included, so @out equals the token's
 * protected_image_digests entry for the process when the registry is the
 * one that round measured. A registry that hashes to anything else,
 * reordered, short of an entry or with one rewritten, is not the list
 * behind the token.
 *
 * Returns: LOTA_SERVER_OK, LOTA_SERVER_ERR_INVALID_ARG for a malformed
 *          object or actor, an unknown flag or more entries than a process
 *          is listed with, or LOTA_SERVER_ERR_CRYPTO.
 */
int lota_server_registry_digest(uint32_t flags,
				const struct lota_server_registry_module *mods,
				size_t count,
				const struct lota_server_registry_actor *actors,
				size_t actor_count, uint8_t out[32]);

/*
 * lota_server_verify_boot_evidence - Read Secure Boot from a token's PCRs
 * @claims:      Claims lota_server_verify_token() returned for the token;
 *               lota_server_parse_token() claims prove nothing
 * @evidence:    Bytes lota_get_boot_evidence() returned next to it
 * @len:         Length of @evidence
 * @secure_boot: Output: 1 when the firmware measured Secure Boot on before
 *               it handed over to the boot loader, 0 otherwise
 *
 * Accepts the evidence only when its PCR values hash to the signed PCR
 * digest and its PCR 7 events replay to the PCR 7 value, so a host cannot
 * rewrite it. A SecureBoot measurement that is absent, carries any value but
 * 1 or comes after the firmware's separator leaves @secure_boot at 0, as
 * does evidence with no separator.
 *
 * Returns: LOTA_SERVER_OK, LOTA_SERVER_ERR_INVALID_ARG,
 *          LOTA_SERVER_ERR_BAD_EVIDENCE or LOTA_SERVER_ERR_CRYPTO.
 */
int lota_server_verify_boot_evidence(const struct lota_server_claims *claims,
				     const uint8_t *evidence, size_t len,
				     int *secure_boot);

#ifdef __cplusplus
}
#endif

#endif /* LOTA_SERVER_H */
