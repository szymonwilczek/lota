/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - Policy File Ed25519 Signing
 *
 * Provides Ed25519 key generation, signing, and verification for
 * YAML policy files. Detached signatures are stored alongside the
 * policy as <policy>.sig (raw 64-byte Ed25519 signature).
 *
 * Key format: raw 32-byte seed (private) / 32-byte public key.
 * On disk, keys are stored as PEM-encoded PKCS#8 (private) and
 * SubjectPublicKeyInfo (public) via OpenSSL.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_POLICY_SIGN_H
#define LOTA_POLICY_SIGN_H

#include <stddef.h>
#include <stdint.h>

#define POLICY_SIG_SIZE 64     /* Ed25519 signature size */
#define POLICY_PUBKEY_SIZE 32  /* Ed25519 public key size */
#define POLICY_PRIVKEY_SIZE 32 /* Ed25519 private key seed size */

/*
 * policy_sign_generate_keypair - Generate an Ed25519 keypair
 *
 * @privkey_pem_path: Output path for PEM-encoded private key (PKCS#8)
 * @pubkey_pem_path:  Output path for PEM-encoded public key (SPKI)
 *
 * Generates a cryptographically random Ed25519 keypair and writes
 * both keys to disk in PEM format.
 *
 * Returns: 0 on success, negative errno on failure
 */
int policy_sign_generate_keypair(const char *privkey_pem_path,
                                 const char *pubkey_pem_path);

/*
 * policy_sign_file - Sign a file with Ed25519
 *
 * @file_path:        Path to the file to sign (e.g: policy.yaml)
 * @privkey_pem_path: Path to PEM-encoded Ed25519 private key
 * @sig_path:         Output path for the 64-byte raw signature
 *
 * Reads the entire file, signs with Ed25519, and writes the detached
 * signature to sig_path.
 *
 * Returns: 0 on success, negative errno on failure
 */
int policy_sign_file(const char *file_path, const char *privkey_pem_path,
                     const char *sig_path);

/*
 * policy_verify_file - Verify an Ed25519 signature on a file
 *
 * @file_path:       Path to the file that was signed
 * @pubkey_pem_path: Path to PEM-encoded Ed25519 public key
 * @sig_path:        Path to the 64-byte raw signature file
 *
 * Returns: 0 if signature is valid, -EAUTH if invalid, negative errno otherwise
 */
int policy_verify_file(const char *file_path, const char *pubkey_pem_path,
                       const char *sig_path);

/*
 * policy_sign_buffer - Sign a buffer with Ed25519 (for testing!)
 *
 * @data:             Data to sign
 * @data_len:         Length of data
 * @privkey_pem_path: Path to PEM-encoded Ed25519 private key
 * @sig_out:          Output buffer (POLICY_SIG_SIZE bytes)
 *
 * Returns: 0 on success, negative errno on failure
 */
int policy_sign_buffer(const uint8_t *data, size_t data_len,
                       const char *privkey_pem_path, uint8_t *sig_out);

/*
 * policy_verify_buffer - Verify Ed25519 signature on buffer (for testing!)
 *
 * @data:             Data that was signed
 * @data_len:         Length of data
 * @pubkey_pem_path:  Path to PEM-encoded Ed25519 public key
 * @sig:              Signature to verify (POLICY_SIG_SIZE bytes)
 *
 * Returns: 0 if valid, -EAUTH if invalid, negative errno otherwise
 */
int policy_verify_buffer(const uint8_t *data, size_t data_len,
                         const char *pubkey_pem_path, const uint8_t *sig);

#endif /* LOTA_POLICY_SIGN_H */
