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
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/types.h>

#include "aik_cert.h"
#include "io_utils.h"
#include "../../include/lota.h"
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

int aik_cert_matches_key(const char *path, const uint8_t *spki_der,
			 size_t spki_len)
{
	uint8_t der[LOTA_ENROLL_MAX_AIK_CERT];
	uint8_t cert_spki[LOTA_MAX_AIK_PUB_SIZE];
	unsigned char *p_out = cert_spki;
	size_t der_len = 0;
	const uint8_t *p;
	X509 *cert;
	EVP_PKEY *pkey = NULL;
	int cert_spki_len;
	int ret;

	if (!path || !spki_der || spki_len == 0)
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

	pkey = X509_get_pubkey(cert);
	if (!pkey) {
		ret = -EINVAL;
		goto out;
	}

	/*
	 * i2d_PUBKEY is what produced the caller's bytes too, so both sides
	 * are the same DER encoding of the same question and a plain memcmp
	 * is the comparison.
	 * Re-encoding the certificate's stored bytes keeps it independent of
	 * how the CA chose to serialise them.
	 */
	cert_spki_len = i2d_PUBKEY(pkey, NULL);
	if (cert_spki_len <= 0 || (size_t)cert_spki_len > sizeof(cert_spki)) {
		ret = -EINVAL;
		goto out;
	}

	cert_spki_len = i2d_PUBKEY(pkey, &p_out);
	if (cert_spki_len <= 0) {
		ret = -EINVAL;
		goto out;
	}

	if ((size_t)cert_spki_len != spki_len ||
	    memcmp(cert_spki, spki_der, spki_len) != 0) {
		ret = -EKEYREJECTED;
		goto out;
	}

	ret = 0;
out:
	if (pkey)
		EVP_PKEY_free(pkey);
	X509_free(cert);
	return ret;
}
