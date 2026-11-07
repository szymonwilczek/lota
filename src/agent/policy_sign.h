/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - Policy File Ed25519 Signing
 *
 * A signature is the raw POLICY_SIG_SIZE bytes in a file of its own. Keys are
 * PEM: PKCS#8 for the private key, SubjectPublicKeyInfo for the public one.
 * EAUTH is 80 where the C library does not define it.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_POLICY_SIGN_H
#define LOTA_POLICY_SIGN_H

#include <stddef.h>
#include <stdint.h>

#define POLICY_SIG_SIZE 64

/* Largest file the functions below and the BPF loader read. */
#define LOTA_MAX_SIGNED_OBJECT_SIZE (4 * 1024 * 1024)

/**
 * policy_sign_generate_keypair() - Write a new Ed25519 keypair.
 * @privkey_pem_path: Receives the private key, created with mode 0600.
 * @pubkey_pem_path: Receives the public key, created with mode 0644.
 *
 * The umask applies to both modes. A file that exists is truncated and keeps
 * its mode.
 *
 * Return: 0, -EINVAL for a NULL path, or another negative errno.
 */
int policy_sign_generate_keypair(const char *privkey_pem_path,
				 const char *pubkey_pem_path);

/**
 * policy_sign_file() - Write a detached signature of a file.
 * @file_path: File to sign.
 * @privkey_pem_path: The private key.
 * @sig_path: Receives the signature, created with mode 0644 under the umask.
 *
 * Return: 0; -ENOENT when the key cannot be read or is not Ed25519; -EFBIG
 * when the file exceeds LOTA_MAX_SIGNED_OBJECT_SIZE; -EAGAIN when its size
 * changes while it is read; or another negative errno.
 */
int policy_sign_file(const char *file_path, const char *privkey_pem_path,
		     const char *sig_path);

/**
 * policy_verify_file() - Check a detached signature of a file.
 * @file_path: The signed file.
 * @pubkey_pem_path: The public key.
 * @sig_path: The signature; bytes past POLICY_SIG_SIZE are ignored.
 *
 * Return: 0 for a valid signature; -EAUTH for an invalid one or a signature
 * shorter than POLICY_SIG_SIZE; otherwise as policy_sign_file().
 */
int policy_verify_file(const char *file_path, const char *pubkey_pem_path,
		       const char *sig_path);

/**
 * policy_sign_buffer() - Sign a buffer.
 * @data: Data to sign.
 * @data_len: Its length.
 * @privkey_pem_path: The private key.
 * @sig_out: Receives POLICY_SIG_SIZE bytes.
 *
 * Return: 0, -EINVAL for a NULL argument, -ENOENT when the key cannot be read
 * or is not Ed25519, -ENOMEM, or -EIO.
 */
int policy_sign_buffer(const uint8_t *data, size_t data_len,
		       const char *privkey_pem_path, uint8_t *sig_out);

/**
 * policy_verify_buffer() - Check a signature of a buffer.
 * @data: The signed data.
 * @data_len: Its length.
 * @pubkey_pem_path: The public key.
 * @sig: POLICY_SIG_SIZE bytes.
 *
 * Return: 0 for a valid signature, -EAUTH for an invalid one, -EINVAL for
 * a NULL argument, -ENOENT when the key cannot be read or is not Ed25519,
 * -ENOMEM, or -EIO.
 */
int policy_verify_buffer(const uint8_t *data, size_t data_len,
			 const char *pubkey_pem_path, const uint8_t *sig);

#endif /* LOTA_POLICY_SIGN_H */
