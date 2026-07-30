/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * AIK certificate lifetime inspection.
 *
 * CA issues short-lived AIK certificates (24h by default), so the daemon must
 * renew before notAfter.
 *
 * These helpers read the stored DER certificate and report its remaining and
 * total validity so the attestation loop can decide when to re-enroll.
 */

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/types.h>

#include "aik_cert.h"
#include "io_utils.h"
#include "../../include/lota_enroll.h"

bool aik_cert_renew_due(int64_t remaining_sec, int64_t total_sec)
{
	if (total_sec <= 0)
		return true;
	return remaining_sec < total_sec / 3;
}

/* Seconds spanned by an ASN1_TIME interval, or a negative errno on failure. */
static int asn1_interval_seconds(const ASN1_TIME *from, const ASN1_TIME *to,
				 int64_t *out)
{
	int days = 0, secs = 0;

	/* from == NULL means "now"
	 * (ASN1_TIME_diff convention) */
	if (!to)
		return -EINVAL;
	if (ASN1_TIME_diff(&days, &secs, from, to) != 1)
		return -EINVAL;
	*out = (int64_t)days * 86400 + (int64_t)secs;
	return 0;
}

int aik_cert_lifetime_path(const char *path, int64_t *remaining_sec,
			   int64_t *total_sec)
{
	uint8_t der[LOTA_ENROLL_MAX_AIK_CERT];
	size_t der_len = 0;
	const uint8_t *p;
	X509 *cert;
	const ASN1_TIME *not_before, *not_after;
	int64_t remaining, total;
	int ret;

	if (!path || !remaining_sec || !total_sec)
		return -EINVAL;

	ret = lota_read_file_bounded(path, der, sizeof(der), &der_len);
	if (ret < 0)
		return ret;
	if (der_len == 0)
		return -ENOENT;

	p = der;
	cert = d2i_X509(NULL, &p, (long)der_len);
	if (!cert)
		return -EINVAL;

	not_before = X509_get0_notBefore(cert);
	not_after = X509_get0_notAfter(cert);

	ret = asn1_interval_seconds(not_before, not_after, &total);
	if (ret < 0)
		goto out;
	ret = asn1_interval_seconds(NULL, not_after, &remaining);
out:
	X509_free(cert);
	if (ret < 0)
		return ret;
	*total_sec = total;
	*remaining_sec = remaining;
	return 0;
}
