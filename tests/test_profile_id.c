/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for publisher profile identity (profile.c).
 *
 * The identity is what keeps two publishers' enrollments apart on one host,
 * so the properties pinned here are the ones the layout depends on:
 * it follows the CA's key rather than the certificate carrying it, it does not
 * depend on how the anchor was encoded, and it refuses anything it cannot
 * derive from.
 *
 * No TPM and no CA: certificates are minted locally with OpenSSL.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/types.h>
#include <openssl/x509.h>

#include "../src/agent/profile.h"

static int g_failures;

#define CHECK(cond, msg)                                    \
	do {                                                \
		if (!(cond)) {                              \
			fprintf(stderr, "FAIL: %s\n", msg); \
			g_failures++;                       \
		} else {                                    \
			printf("PASS: %s\n", msg);          \
		}                                           \
	} while (0)

/* Caller-owned: several anchors are live at once in one test */
static void tmp_path(char *out, size_t out_len, const char *suffix)
{
	snprintf(out, out_len, "/tmp/lota-profile-test.%d.%s", getpid(),
		 suffix);
}

static int write_all(const char *path, const uint8_t *data, size_t len)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	ssize_t w;

	if (fd < 0)
		return -1;
	w = write(fd, data, len);
	close(fd);
	return (w == (ssize_t)len) ? 0 : -1;
}

/* Self-signed certificate over pkey, with cn and serial as given */
static X509 *mint_cert(EVP_PKEY *pkey, const char *cn, long serial)
{
	X509_NAME *name;
	X509 *x;

	x = X509_new();
	if (!x)
		return NULL;

	X509_set_version(x, 2);
	ASN1_INTEGER_set(X509_get_serialNumber(x), serial);
	X509_gmtime_adj(X509_getm_notBefore(x), 0);
	X509_gmtime_adj(X509_getm_notAfter(x), 3600);
	X509_set_pubkey(x, pkey);

	name = X509_get_subject_name(x);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
				   (const unsigned char *)cn, -1, -1, 0);
	X509_set_issuer_name(x, name);

	if (!X509_sign(x, pkey, EVP_sha256())) {
		X509_free(x);
		return NULL;
	}
	return x;
}

static int write_cert_der(const char *path, X509 *x)
{
	uint8_t *der = NULL;
	int len, ret;

	len = i2d_X509(x, &der);
	if (len <= 0)
		return -1;
	ret = write_all(path, der, (size_t)len);
	OPENSSL_free(der);
	return ret;
}

static int write_cert_pem(const char *path, X509 *x)
{
	FILE *f = fopen(path, "wb");
	int ok;

	if (!f)
		return -1;
	ok = PEM_write_X509(f, x);
	fclose(f);
	return ok == 1 ? 0 : -1;
}

/*
 * Identity the implementation must produce, derived through different OpenSSL path:
 * i2d_PUBKEY over the key itself rather than i2d_X509_PUBKEY over the certificate's
 * parsed SPKI.
 * Same bytes for the same key, so this pins "SHA-256 of the SubjectPublicKeyInfo"
 * and not merely "some digest"
 */
static int expected_id(EVP_PKEY *pkey, char *out, size_t out_len)
{
	uint8_t digest[32];
	unsigned char *der = NULL;
	unsigned int md_len = 0;
	int len;

	if (out_len < LOTA_PROFILE_ID_LEN)
		return -1;

	len = i2d_PUBKEY(pkey, &der);
	if (len <= 0)
		return -1;
	if (EVP_Digest(der, (size_t)len, digest, &md_len, EVP_sha256(), NULL) !=
		    1 ||
	    md_len != sizeof(digest)) {
		OPENSSL_free(der);
		return -1;
	}
	OPENSSL_free(der);

	for (size_t i = 0; i < sizeof(digest); i++)
		snprintf(out + i * 2, 3, "%02x", digest[i]);
	return 0;
}

/*
 * CA that reissues its own certificate -- new serial, new subject, new validity,
 * same key -- must land on the same profile.
 * Otherwise every CA certificate renewal would silently orphan the host's enrollment.
 */
static void test_identity_follows_the_key(void)
{
	char der_path[256], pem_path[256], other_path[256], reissued_path[256];
	char id_der[LOTA_PROFILE_ID_LEN] = { 0 };
	char id_pem[LOTA_PROFILE_ID_LEN] = { 0 };
	char id_reissued[LOTA_PROFILE_ID_LEN] = { 0 };
	char id_other[LOTA_PROFILE_ID_LEN] = { 0 };
	char id_expected[LOTA_PROFILE_ID_LEN] = { 0 };
	EVP_PKEY *key = EVP_EC_gen("P-256");
	EVP_PKEY *other_key = EVP_EC_gen("P-256");
	X509 *cert = NULL, *reissued = NULL, *other = NULL;

	tmp_path(der_path, sizeof(der_path), "a.der");
	tmp_path(pem_path, sizeof(pem_path), "a.pem");
	tmp_path(other_path, sizeof(other_path), "b.der");
	tmp_path(reissued_path, sizeof(reissued_path), "a2.der");

	if (!key || !other_key) {
		CHECK(0, "key generation");
		goto out;
	}

	cert = mint_cert(key, "publisher-a", 1);
	reissued = mint_cert(key, "publisher-a-renewed", 2);
	other = mint_cert(other_key, "publisher-b", 1);
	if (!cert || !reissued || !other) {
		CHECK(0, "certificate minting");
		goto out;
	}

	if (write_cert_der(der_path, cert) != 0 ||
	    write_cert_pem(pem_path, cert) != 0 ||
	    write_cert_der(reissued_path, reissued) != 0 ||
	    write_cert_der(other_path, other) != 0) {
		CHECK(0, "writing anchors");
		goto out;
	}

	CHECK(profile_id_from_anchor(der_path, id_der, sizeof(id_der)) == 0,
	      "DER anchor derives an identity");
	CHECK(profile_id_from_anchor(pem_path, id_pem, sizeof(id_pem)) == 0,
	      "PEM anchor derives an identity");
	CHECK(profile_id_from_anchor(reissued_path, id_reissued,
				     sizeof(id_reissued)) == 0,
	      "reissued anchor derives an identity");
	CHECK(profile_id_from_anchor(other_path, id_other, sizeof(id_other)) ==
		      0,
	      "second publisher's anchor derives an identity");

	CHECK(strlen(id_der) == LOTA_PROFILE_ID_LEN - 1,
	      "identity is 64 hex characters");
	CHECK(strspn(id_der, "0123456789abcdef") == strlen(id_der),
	      "identity is lowercase hex");

	CHECK(strcmp(id_der, id_pem) == 0,
	      "PEM and DER of one anchor are one profile");
	CHECK(strcmp(id_der, id_reissued) == 0,
	      "reissuing the CA certificate keeps the profile");
	CHECK(strcmp(id_der, id_other) != 0,
	      "a second publisher gets a second profile");

	CHECK(expected_id(key, id_expected, sizeof(id_expected)) == 0 &&
		      strcmp(id_der, id_expected) == 0,
	      "identity is the SHA-256 of the anchor's SPKI");

out:
	unlink(der_path);
	unlink(pem_path);
	unlink(reissued_path);
	unlink(other_path);
	X509_free(cert);
	X509_free(reissued);
	X509_free(other);
	EVP_PKEY_free(key);
	EVP_PKEY_free(other_key);
}

/* Nothing may be guessed: anchor that cannot be read has no identity */
static void test_unusable_anchor_is_refused(void)
{
	char garbage_path[256];
	char id[LOTA_PROFILE_ID_LEN] = { 0 };
	const uint8_t garbage[] = { 0x00, 0x01, 0x02, 0x03 };
	struct profile_paths paths;

	tmp_path(garbage_path, sizeof(garbage_path), "garbage.der");

	CHECK(profile_id_from_anchor(NULL, id, sizeof(id)) == -EINVAL,
	      "no anchor is refused");
	CHECK(profile_id_from_anchor("/tmp/lota-profile-absent.XXXXXX", id,
				     sizeof(id)) == -ENOENT,
	      "missing anchor reports ENOENT");

	CHECK(write_all(garbage_path, garbage, sizeof(garbage)) == 0,
	      "write a non-certificate anchor");
	CHECK(profile_id_from_anchor(garbage_path, id, sizeof(id)) == -EINVAL,
	      "a file that is not a certificate is refused");
	CHECK(profile_paths_from_anchor(garbage_path, &paths) == -EINVAL,
	      "paths are refused with the identity");

	CHECK(profile_id_from_anchor(garbage_path, id,
				     LOTA_PROFILE_ID_LEN - 1) == -EINVAL,
	      "a buffer too small for the identity is refused");

	unlink(garbage_path);
}

static void test_paths_and_directory(void)
{
	char der_path[256];
	char base[256];
	char expect[PATH_MAX + 128];
	struct profile_paths paths;
	EVP_PKEY *key = EVP_EC_gen("P-256");
	X509 *cert = NULL;
	struct stat st;

	tmp_path(der_path, sizeof(der_path), "paths.der");

	if (!key) {
		CHECK(0, "key generation");
		goto out;
	}
	cert = mint_cert(key, "publisher-a", 1);
	if (!cert || write_cert_der(der_path, cert) != 0) {
		CHECK(0, "writing the anchor");
		goto out;
	}

	snprintf(base, sizeof(base), "/tmp/lota-profile-base.%d", getpid());

	CHECK(profile_paths_from_anchor_base(base, der_path, &paths) == 0,
	      "paths derive from an anchor");

	snprintf(expect, sizeof(expect), "%s/%s", base, paths.id);
	CHECK(strcmp(paths.dir, expect) == 0, "profile directory is base/id");
	snprintf(expect, sizeof(expect), "%s/%s", paths.dir,
		 LOTA_PROFILE_ENROLL_STATE_FILE);
	CHECK(strcmp(paths.enroll_state, expect) == 0,
	      "enrollment record sits in the profile");
	snprintf(expect, sizeof(expect), "%s/%s", paths.dir,
		 LOTA_PROFILE_AIK_CERT_FILE);
	CHECK(strcmp(paths.aik_cert, expect) == 0,
	      "AIK certificate sits in the profile");

	CHECK(profile_dir_ensure(&paths) == 0, "profile directory is created");
	CHECK(stat(paths.dir, &st) == 0 && S_ISDIR(st.st_mode),
	      "profile directory exists");
	CHECK((st.st_mode & 0777) == 0700,
	      "profile directory is root-only: the record carries the "
	      "enrollment token");
	CHECK(profile_dir_ensure(&paths) == 0,
	      "creating an existing profile directory is a no-op");

	rmdir(paths.dir);
	rmdir(base);

out:
	unlink(der_path);
	X509_free(cert);
	EVP_PKEY_free(key);
}

int main(void)
{
	printf("=== Publisher profile identity tests ===\n\n");

	test_identity_follows_the_key();
	test_unusable_anchor_is_refused();
	test_paths_and_directory();

	printf("\n%s\n", g_failures ? "FAILURES" : "All tests passed");
	return g_failures ? 1 : 0;
}
