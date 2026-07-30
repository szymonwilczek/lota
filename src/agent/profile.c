/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Publisher profile identity: hash CA trust anchor into the directory the host
 * keeps that publisher's enrollment under.
 * See profile.h for why the anchor and not the endpoint names a publisher.
 *
 * Self-contained file I/O and OpenSSL so it stays unit-testable apart from
 * the TPM and network stack the enrollment ceremony pulls in.
 */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "profile.h"

/*
 * Read the first certificate of PEM or DER file.
 *
 * Second attempt reopens the file rather than rewinding it:
 * BIO_reset() reports success as 0 on a file BIO and 1 elsewhere,
 * so shared rewind is trap for the next reader of this code.
 */
static X509 *anchor_read(const char *path)
{
	X509 *cert = NULL;
	BIO *bio;

	bio = BIO_new_file(path, "r");
	if (!bio) {
		ERR_clear_error();
		return NULL;
	}
	cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
	BIO_free(bio);
	if (cert)
		return cert;

	/* not PEM:
	 * try DER, keeping the error queue clean so later TLS failure is not
	 * reported against this file */
	ERR_clear_error();

	bio = BIO_new_file(path, "r");
	if (!bio) {
		ERR_clear_error();
		return NULL;
	}
	cert = d2i_X509_bio(bio, NULL);
	BIO_free(bio);
	if (!cert)
		ERR_clear_error();

	return cert;
}

/*
 * SHA-256 over the anchor's SubjectPublicKeyInfo, taken from the parsed X509_PUBKEY
 * rather than the public key itself:
 * the SPKI carries the algorithm identifier, so two keys of different types cannot
 * hash alike.
 */
static int anchor_spki_sha256(const char *path, uint8_t out[32])
{
	unsigned char *der = NULL;
	X509_PUBKEY *pubkey;
	unsigned int md_len = 0;
	X509 *cert;
	int der_len;
	int ret = 0;

	cert = anchor_read(path);
	if (!cert)
		return -EINVAL;

	pubkey = X509_get_X509_PUBKEY(cert); /* internal, not owned */
	if (!pubkey) {
		X509_free(cert);
		return -EINVAL;
	}

	der_len = i2d_X509_PUBKEY(pubkey, &der);
	if (der_len <= 0) {
		ERR_clear_error();
		X509_free(cert);
		return -EINVAL;
	}

	if (EVP_Digest(der, (size_t)der_len, out, &md_len, EVP_sha256(),
		       NULL) != 1 ||
	    md_len != 32) {
		ERR_clear_error();
		ret = -EINVAL;
	}

	OPENSSL_free(der);
	X509_free(cert);
	return ret;
}

int profile_id_from_anchor(const char *ca_cert_path, char *out, size_t out_len)
{
	uint8_t digest[32];
	int ret;

	if (!ca_cert_path || !out || out_len < LOTA_PROFILE_ID_LEN)
		return -EINVAL;

	if (access(ca_cert_path, R_OK) != 0)
		return -ENOENT;

	ret = anchor_spki_sha256(ca_cert_path, digest);
	if (ret < 0)
		return ret;

	for (size_t i = 0; i < sizeof(digest); i++)
		snprintf(out + i * 2, 3, "%02x", digest[i]);

	return 0;
}

int profile_paths_from_anchor_base(const char *base_dir,
				   const char *ca_cert_path,
				   struct profile_paths *out)
{
	struct profile_paths p;
	int ret;

	if (!base_dir || !out)
		return -EINVAL;

	memset(&p, 0, sizeof(p));

	ret = profile_id_from_anchor(ca_cert_path, p.id, sizeof(p.id));
	if (ret < 0)
		return ret;

	if (snprintf(p.dir, sizeof(p.dir), "%s/%s", base_dir, p.id) >=
	    (int)sizeof(p.dir))
		return -ENAMETOOLONG;
	if (snprintf(p.enroll_state, sizeof(p.enroll_state), "%s/%s", p.dir,
		     LOTA_PROFILE_ENROLL_STATE_FILE) >=
	    (int)sizeof(p.enroll_state))
		return -ENAMETOOLONG;
	if (snprintf(p.aik_cert, sizeof(p.aik_cert), "%s/%s", p.dir,
		     LOTA_PROFILE_AIK_CERT_FILE) >= (int)sizeof(p.aik_cert))
		return -ENAMETOOLONG;

	*out = p;
	return 0;
}

int profile_paths_from_anchor(const char *ca_cert_path,
			      struct profile_paths *out)
{
	return profile_paths_from_anchor_base(LOTA_PROFILE_BASE_DIR,
					      ca_cert_path, out);
}

int profile_dir_ensure(const struct profile_paths *paths)
{
	char parent[PATH_MAX];
	char *slash;

	if (!paths || paths->dir[0] == '\0')
		return -EINVAL;

	if (snprintf(parent, sizeof(parent), "%s", paths->dir) >=
	    (int)sizeof(parent))
		return -ENAMETOOLONG;

	slash = strrchr(parent, '/');
	if (slash && slash != parent) {
		*slash = '\0';
		if (mkdir(parent, 0700) != 0 && errno != EEXIST)
			return -errno;
	}

	if (mkdir(paths->dir, 0700) != 0 && errno != EEXIST)
		return -errno;

	return 0;
}
