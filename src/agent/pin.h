/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/* The SHA-256 fingerprint of the certificate a connection may present. */

#ifndef LOTA_AGENT_PIN_H
#define LOTA_AGENT_PIN_H

#include <stdint.h>

#define LOTA_PIN_SHA256_LEN 32

/**
 * lota_pin_sha256_parse() - Parse a hex SHA-256 fingerprint.
 * @hex: 32 bytes as hex pairs; colons and spaces around a pair are skipped.
 * @out: At least LOTA_PIN_SHA256_LEN bytes.
 *
 * Return: 0, or -EINVAL for anything else.
 */
int lota_pin_sha256_parse(const char *hex, uint8_t *out);

#endif /* LOTA_AGENT_PIN_H */
