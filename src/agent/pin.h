/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Certificate pin: the SHA-256 fingerprint of the certificate a connection is
 * allowed to present.
 *
 * Kept apart from the TLS layer because the pin arrives long before any
 * connection does -- on the command line, and from every publisher profile in
 * the configuration -- and both of those are parsed in translation units that
 * have no business linking OpenSSL.
 */

#ifndef LOTA_AGENT_PIN_H
#define LOTA_AGENT_PIN_H

#include <stdint.h>

/* SHA-256 digest length, which is what a pin is */
#define LOTA_PIN_SHA256_LEN 32

/*
 * Parse a hex-encoded SHA-256 fingerprint into binary.
 *
 * @hex: 64 hex characters; colons (':') and spaces are skipped, so the output
 *       of `openssl x509 -fingerprint -sha256` can be pasted as it is printed.
 * @out: at least LOTA_PIN_SHA256_LEN bytes.
 *
 * Anything shorter, longer or not hex is refused: a pin that parses to something
 * other than what the operator wrote pins the wrong certificate.
 *
 * Returns 0, or -EINVAL.
 */
int lota_pin_sha256_parse(const char *hex, uint8_t *out);

#endif /* LOTA_AGENT_PIN_H */
