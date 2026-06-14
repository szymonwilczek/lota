/* SPDX-License-Identifier: MIT */
/*
 * AIK certificate lifetime inspection.
 *
 * Reads the CA-issued AIK certificate the daemon stores on disk and answers
 * two questions the continuous attestation loop needs to renew it before it
 * lapses: how much validity is left, and whether renewal is due yet.
 */

#ifndef LOTA_AGENT_AIK_CERT_H
#define LOTA_AGENT_AIK_CERT_H

#include <stdbool.h>
#include <stdint.h>

/*
 * Validity of the stored AIK certificate, via OpenSSL.
 * On success both *remaining_sec (until notAfter; <= 0 once expired) and
 * *total_sec (the notBefore..notAfter span) are set.
 * Returns 0, -ENOENT if no certificate is present, or another negative errno
 * if it cannot be read or parsed.
 */
int aik_cert_lifetime(int64_t *remaining_sec, int64_t *total_sec);

/* Path-parameterized variant behind the fixed-path wrapper above (tests). */
int aik_cert_lifetime_path(const char *path, int64_t *remaining_sec,
			   int64_t *total_sec);

/*
 * Renewal is due once the certificate has entered its final third
 * (remaining < total / 3).
 * Non-positive total_sec is treated as due so an unreadable span errs toward
 * renewing.
 */
bool aik_cert_renew_due(int64_t remaining_sec, int64_t total_sec);

#endif /* LOTA_AGENT_AIK_CERT_H */
