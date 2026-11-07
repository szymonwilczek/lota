/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/* Lifetime and key checks on a stored AIK certificate */

#ifndef LOTA_AGENT_AIK_CERT_H
#define LOTA_AGENT_AIK_CERT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * aik_cert_lifetime_path() - Validity of a stored AIK certificate.
 * @path: The DER certificate.
 * @remaining_sec: Set on success: seconds until notAfter, <= 0 once expired.
 * @total_sec: Set on success: the notBefore..notAfter span.
 *
 * Return: 0, -ENOENT if no certificate is present, or another negative errno
 * if it cannot be read or parsed.
 */
int aik_cert_lifetime_path(const char *path, int64_t *remaining_sec,
			   int64_t *total_sec);

/**
 * aik_cert_matches_key() - Is this the key a certificate was issued over?
 * @path: The DER certificate.
 * @spki_der: DER SubjectPublicKeyInfo, the form tpm_get_aik_public() exports.
 * @spki_len: Length of @spki_der.
 *
 * Compares byte for byte with the certificate's own SPKI; verifies no
 * signature.
 *
 * Return: 0 when they are the same key, -EKEYREJECTED when they are not,
 * -ENOENT when no certificate is stored, or another negative errno if the
 * certificate cannot be read or parsed.
 */
int aik_cert_matches_key(const char *path, const uint8_t *spki_der,
			 size_t spki_len);

/**
 * aik_cert_renew_due() - Has the certificate entered its final third?
 * @remaining_sec: Validity left.
 * @total_sec: Whole span; a non-positive one counts as due.
 *
 * Return: true when renewal is due.
 */
bool aik_cert_renew_due(int64_t remaining_sec, int64_t total_sec);

#endif /* LOTA_AGENT_AIK_CERT_H */
