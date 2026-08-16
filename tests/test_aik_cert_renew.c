/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for AIK certificate lifetime inspection (aik_cert.c).
 *
 * Daemon renews the short-lived CA-issued AIK certificate before it expires,
 * so the expiry probe and the "renewal due" decision that gate that renewal are
 * pinned here.
 *
 * No TPM or CA is involved: certificates are minted locally with OpenSSL.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/types.h>

#include "../src/agent/aik_cert.h"

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

static const char *tmp_path(void)
{
	static char path[256];
	snprintf(path, sizeof(path), "/tmp/lota-aik-cert-test.%d.der",
		 getpid());
	return path;
}

/*
 * Mint a self-signed P-256 certificate whose validity runs from now+before to
 * now+after (seconds), store it as DER at path.
 *
 * When spki_out is given, the DER SubjectPublicKeyInfo of the key the certificate
 * was issued over is written there too -- the form tpm_get_aik_public() hands
 * back, so a test can ask whether a certificate names a given key without a TPM.
 *
 * Returns 0 on success.
 */
static int write_test_cert_ex(const char *path, long before, long after,
			      uint8_t *spki_out, size_t spki_cap,
			      size_t *spki_len)
{
	EVP_PKEY *pkey = NULL;
	X509 *x = NULL;
	X509_NAME *name;
	uint8_t *der = NULL;
	int len, fd, ret = -1;
	FILE *f;

	pkey = EVP_EC_gen("P-256");
	if (!pkey)
		goto out;

	if (spki_out) {
		unsigned char *p = spki_out;
		int spki_der_len = i2d_PUBKEY(pkey, NULL);

		if (spki_der_len <= 0 || (size_t)spki_der_len > spki_cap)
			goto out;
		spki_der_len = i2d_PUBKEY(pkey, &p);
		if (spki_der_len <= 0)
			goto out;
		*spki_len = (size_t)spki_der_len;
	}
	x = X509_new();
	if (!x)
		goto out;

	X509_set_version(x, 2);
	ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
	X509_gmtime_adj(X509_getm_notBefore(x), before);
	X509_gmtime_adj(X509_getm_notAfter(x), after);
	X509_set_pubkey(x, pkey);

	name = X509_get_subject_name(x);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
				   (const unsigned char *)"lota-test", -1, -1,
				   0);
	X509_set_issuer_name(x, name);

	if (!X509_sign(x, pkey, EVP_sha256()))
		goto out;

	len = i2d_X509(x, &der);
	if (len <= 0)
		goto out;

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0)
		goto out;
	f = fdopen(fd, "wb");
	if (!f) {
		close(fd);
		goto out;
	}
	if (fwrite(der, 1, (size_t)len, f) == (size_t)len)
		ret = 0;
	fclose(f);

out:
	OPENSSL_free(der);
	X509_free(x);
	EVP_PKEY_free(pkey);
	return ret;
}

static int write_test_cert(const char *path, long before, long after)
{
	return write_test_cert_ex(path, before, after, NULL, 0, NULL);
}

static void test_renew_due_decision(void)
{
	/* final third: remaining < total/3 */
	CHECK(aik_cert_renew_due(100, 3000), "deep in final third is due");
	CHECK(!aik_cert_renew_due(2000, 3000), "first two thirds not due");
	CHECK(!aik_cert_renew_due(1000, 3000), "exact third boundary not due");
	CHECK(aik_cert_renew_due(999, 3000), "just inside final third is due");
	CHECK(aik_cert_renew_due(-10, 3000), "expired cert is due");
	CHECK(aik_cert_renew_due(5, 0), "unreadable span errs toward due");
	CHECK(aik_cert_renew_due(5, -1), "negative span errs toward due");
}

static void test_lifetime_valid_cert(void)
{
	const char *path = tmp_path();
	int64_t remaining = 0, total = 0;

	CHECK(write_test_cert(path, -60, 3600) == 0, "mint valid cert");
	CHECK(aik_cert_lifetime_path(path, &remaining, &total) == 0,
	      "lifetime parses valid cert");
	/* total span ~3660s; remaining ~3600s
	 * allow a few seconds of slack */
	CHECK(total >= 3655 && total <= 3665, "total span as minted");
	CHECK(remaining >= 3590 && remaining <= 3600,
	      "remaining near notAfter");
	unlink(path);
}

static void test_lifetime_expired_cert(void)
{
	const char *path = tmp_path();
	int64_t remaining = 0, total = 0;

	CHECK(write_test_cert(path, -7200, -3600) == 0, "mint expired cert");
	CHECK(aik_cert_lifetime_path(path, &remaining, &total) == 0,
	      "lifetime parses expired cert");
	CHECK(remaining < 0, "expired cert reports negative remaining");
	CHECK(aik_cert_renew_due(remaining, total),
	      "expired cert is renewal-due");
	unlink(path);
}

static void test_missing_is_enoent(void)
{
	int64_t remaining = 0, total = 0;
	CHECK(aik_cert_lifetime_path("/tmp/lota-aik-cert-absent.XXXXXX",
				     &remaining, &total) == -ENOENT,
	      "absent cert returns -ENOENT");
}

static void test_garbage_is_einval(void)
{
	const char *path = tmp_path();
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	FILE *f = fd < 0 ? NULL : fdopen(fd, "wb");
	int64_t remaining = 0, total = 0;

	if (fd >= 0 && !f)
		close(fd);
	CHECK(f != NULL, "open garbage file");
	if (f) {
		fwrite("not a certificate", 1, 17, f);
		fclose(f);
	}
	CHECK(aik_cert_lifetime_path(path, &remaining, &total) == -EINVAL,
	      "unparseable cert rejected");
	unlink(path);
}

static void test_null_args(void)
{
	int64_t remaining = 0, total = 0;
	CHECK(aik_cert_lifetime_path(NULL, &remaining, &total) == -EINVAL,
	      "NULL path rejected");
	CHECK(aik_cert_lifetime_path("/tmp/x", NULL, &total) == -EINVAL,
	      "NULL remaining rejected");
}

/*
 * A profile's handle, its AIK auth and its certificate must agree.
 * When the key at the handle has been replaced, the only thing that noticed
 * was the TPM refusing to sign -- which costs a dictionary-attack attempt to
 * learn, every round, forever.
 * This is the free question that answers it instead.
 */
static void test_certificate_names_the_key(void)
{
	const char *path = tmp_path();
	uint8_t spki[512];
	size_t spki_len = 0;

	CHECK(write_test_cert_ex(path, -60, 3600, spki, sizeof(spki),
				 &spki_len) == 0,
	      "mint a cert and keep the key it was issued over");
	CHECK(spki_len > 0, "the minted key exported an SPKI");
	CHECK(aik_cert_matches_key(path, spki, spki_len) == 0,
	      "a certificate matches the key it was issued over");
	unlink(path);
}

static void test_a_replaced_key_is_rejected(void)
{
	const char *path = tmp_path();
	uint8_t spki_a[512], spki_b[512];
	size_t len_a = 0, len_b = 0;

	/* two certificates, two keys: B's key against A's certificate */
	CHECK(write_test_cert_ex(path, -60, 3600, spki_a, sizeof(spki_a),
				 &len_a) == 0,
	      "mint publisher A's certificate");
	CHECK(write_test_cert_ex(path, -60, 3600, spki_b, sizeof(spki_b),
				 &len_b) == 0,
	      "mint a second certificate over a different key");

	/* path now holds B's certificate, so A's key is the stranger */
	CHECK(aik_cert_matches_key(path, spki_b, len_b) == 0,
	      "the second certificate matches its own key");
	CHECK(aik_cert_matches_key(path, spki_a, len_a) == -EKEYREJECTED,
	      "a key the certificate does not name is refused");

	/* a truncated key is not a match either, and must not read past it */
	CHECK(aik_cert_matches_key(path, spki_b, len_b - 1) == -EKEYREJECTED,
	      "a truncated key is refused rather than matched short");
	unlink(path);
}

static void test_match_arguments_and_missing_cert(void)
{
	const char *path = tmp_path();
	uint8_t spki[512];
	size_t spki_len = 0;

	CHECK(write_test_cert_ex(path, -60, 3600, spki, sizeof(spki),
				 &spki_len) == 0,
	      "mint a cert for the argument checks");

	CHECK(aik_cert_matches_key(NULL, spki, spki_len) == -EINVAL,
	      "NULL certificate path rejected");
	CHECK(aik_cert_matches_key(path, NULL, spki_len) == -EINVAL,
	      "NULL key rejected");
	CHECK(aik_cert_matches_key(path, spki, 0) == -EINVAL,
	      "empty key rejected");
	unlink(path);

	CHECK(aik_cert_matches_key(path, spki, spki_len) == -ENOENT,
	      "a profile with no certificate stored is -ENOENT, not a match");
}

int main(void)
{
	test_renew_due_decision();
	test_lifetime_valid_cert();
	test_lifetime_expired_cert();
	test_missing_is_enoent();
	test_garbage_is_einval();
	test_null_args();
	test_certificate_names_the_key();
	test_a_replaced_key_is_rejected();
	test_match_arguments_and_missing_cert();

	if (g_failures) {
		fprintf(stderr, "\n%d test(s) FAILED\n", g_failures);
		return 1;
	}
	printf("\nAll AIK cert renewal tests passed\n");
	return 0;
}
