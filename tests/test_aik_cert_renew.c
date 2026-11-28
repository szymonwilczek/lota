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

#include "test.h"

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
	TEST("deep in final third is due");
	if (!aik_cert_renew_due(100, 3000))
		FAIL("expected: aik_cert_renew_due(100, 3000)");
	TEST("first two thirds not due");
	if (aik_cert_renew_due(2000, 3000))
		FAIL("expected: !aik_cert_renew_due(2000, 3000)");
	TEST("exact third boundary not due");
	if (aik_cert_renew_due(1000, 3000))
		FAIL("expected: !aik_cert_renew_due(1000, 3000)");
	TEST("just inside final third is due");
	if (!aik_cert_renew_due(999, 3000))
		FAIL("expected: aik_cert_renew_due(999, 3000)");
	TEST("expired cert is due");
	if (!aik_cert_renew_due(-10, 3000))
		FAIL("expected: aik_cert_renew_due(-10, 3000)");
	TEST("unreadable span errs toward due");
	if (!aik_cert_renew_due(5, 0))
		FAIL("expected: aik_cert_renew_due(5, 0)");
	TEST("negative span errs toward due");
	if (!aik_cert_renew_due(5, -1))
		FAIL("expected: aik_cert_renew_due(5, -1)");
}

static void test_lifetime_valid_cert(void)
{
	const char *path = tmp_path();
	int64_t remaining = 0, total = 0;

	TEST("mint valid cert");
	if (write_test_cert(path, -60, 3600) != 0)
		FAIL("expected: write_test_cert(path, -60, 3600) == 0");
	TEST("lifetime parses valid cert");
	if (aik_cert_lifetime_path(path, &remaining, &total) != 0)
		FAIL("expected: aik_cert_lifetime_path(path, &remaining, "
		     "&total) == 0");
	/* total span ~3660s; remaining ~3600s
	 * allow a few seconds of slack */
	TEST("total span as minted");
	if (!(total >= 3655 && total <= 3665))
		FAIL("expected: total >= 3655 && total <= 3665");
	TEST("remaining near notAfter");
	if (!(remaining >= 3590 && remaining <= 3600))
		FAIL("expected: remaining >= 3590 && remaining <= 3600");
	unlink(path);
}

static void test_lifetime_expired_cert(void)
{
	const char *path = tmp_path();
	int64_t remaining = 0, total = 0;

	TEST("mint expired cert");
	if (write_test_cert(path, -7200, -3600) != 0)
		FAIL("expected: write_test_cert(path, -7200, -3600) == 0");
	TEST("lifetime parses expired cert");
	if (aik_cert_lifetime_path(path, &remaining, &total) != 0)
		FAIL("expected: aik_cert_lifetime_path(path, &remaining, "
		     "&total) == 0");
	TEST("expired cert reports negative remaining");
	if (remaining >= 0)
		FAIL("expected: remaining < 0");
	TEST("expired cert is renewal-due");
	if (!aik_cert_renew_due(remaining, total))
		FAIL("expected: aik_cert_renew_due(remaining, total)");
	unlink(path);
}

static void test_missing_is_enoent(void)
{
	int64_t remaining = 0, total = 0;
	TEST("absent cert returns -ENOENT");
	if (aik_cert_lifetime_path("/tmp/lota-aik-cert-absent.XXXXXX",
				   &remaining, &total) != -ENOENT)
		FAIL("expected: aik_cert_lifetime_path(\"/tmp/lota-aik-cert-absent.XXXXXX\", "
		     "&remaining, &total) == -ENOENT");
}

static void test_garbage_is_einval(void)
{
	const char *path = tmp_path();
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	FILE *f = fd < 0 ? NULL : fdopen(fd, "wb");
	int64_t remaining = 0, total = 0;

	if (fd >= 0 && !f)
		close(fd);
	TEST("open garbage file");
	if (f == NULL)
		FAIL("expected: f != NULL");
	if (f) {
		fwrite("not a certificate", 1, 17, f);
		fclose(f);
	}
	TEST("unparseable cert rejected");
	if (aik_cert_lifetime_path(path, &remaining, &total) != -EINVAL)
		FAIL("expected: aik_cert_lifetime_path(path, &remaining, "
		     "&total) == -EINVAL");
	unlink(path);
}

static void test_null_args(void)
{
	int64_t remaining = 0, total = 0;
	TEST("NULL path rejected");
	if (aik_cert_lifetime_path(NULL, &remaining, &total) != -EINVAL)
		FAIL("expected: aik_cert_lifetime_path(NULL, &remaining, "
		     "&total) == -EINVAL");
	TEST("NULL remaining rejected");
	if (aik_cert_lifetime_path("/tmp/x", NULL, &total) != -EINVAL)
		FAIL("expected: aik_cert_lifetime_path(\"/tmp/x\", NULL, "
		     "&total) == -EINVAL");
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

	TEST("mint a cert and keep the key it was issued over");
	if (write_test_cert_ex(path, -60, 3600, spki, sizeof(spki),
			       &spki_len) != 0)
		FAIL("expected: write_test_cert_ex(path, -60, 3600, spki, "
		     "sizeof(spki), &spki_len) == 0");
	TEST("the minted key exported an SPKI");
	if (spki_len <= 0)
		FAIL("expected: spki_len > 0");
	TEST("a certificate matches the key it was issued over");
	if (aik_cert_matches_key(path, spki, spki_len) != 0)
		FAIL("expected: aik_cert_matches_key(path, spki, spki_len) == "
		     "0");
	unlink(path);
}

static void test_a_replaced_key_is_rejected(void)
{
	const char *path = tmp_path();
	uint8_t spki_a[512], spki_b[512];
	size_t len_a = 0, len_b = 0;

	/* two certificates, two keys: B's key against A's certificate */
	TEST("mint publisher A's certificate");
	if (write_test_cert_ex(path, -60, 3600, spki_a, sizeof(spki_a),
			       &len_a) != 0)
		FAIL("expected: write_test_cert_ex(path, -60, 3600, spki_a, "
		     "sizeof(spki_a), &len_a) == 0");
	TEST("mint a second certificate over a different key");
	if (write_test_cert_ex(path, -60, 3600, spki_b, sizeof(spki_b),
			       &len_b) != 0)
		FAIL("expected: write_test_cert_ex(path, -60, 3600, spki_b, "
		     "sizeof(spki_b), &len_b) == 0");

	/* path now holds B's certificate, so A's key is the stranger */
	TEST("the second certificate matches its own key");
	if (aik_cert_matches_key(path, spki_b, len_b) != 0)
		FAIL("expected: aik_cert_matches_key(path, spki_b, len_b) == 0");
	TEST("a key the certificate does not name is refused");
	if (aik_cert_matches_key(path, spki_a, len_a) != -EKEYREJECTED)
		FAIL("expected: aik_cert_matches_key(path, spki_a, len_a) == "
		     "-EKEYREJECTED");

	/* a truncated key is not a match either, and must not read past it */
	TEST("a truncated key is refused rather than matched short");
	if (aik_cert_matches_key(path, spki_b, len_b - 1) != -EKEYREJECTED)
		FAIL("expected: aik_cert_matches_key(path, spki_b, len_b - 1) "
		     "== -EKEYREJECTED");
	unlink(path);
}

static void test_match_arguments_and_missing_cert(void)
{
	const char *path = tmp_path();
	uint8_t spki[512];
	size_t spki_len = 0;

	TEST("mint a cert for the argument checks");
	if (write_test_cert_ex(path, -60, 3600, spki, sizeof(spki),
			       &spki_len) != 0)
		FAIL("expected: write_test_cert_ex(path, -60, 3600, spki, "
		     "sizeof(spki), &spki_len) == 0");

	TEST("NULL certificate path rejected");
	if (aik_cert_matches_key(NULL, spki, spki_len) != -EINVAL)
		FAIL("expected: aik_cert_matches_key(NULL, spki, spki_len) == "
		     "-EINVAL");
	TEST("NULL key rejected");
	if (aik_cert_matches_key(path, NULL, spki_len) != -EINVAL)
		FAIL("expected: aik_cert_matches_key(path, NULL, spki_len) == "
		     "-EINVAL");
	TEST("empty key rejected");
	if (aik_cert_matches_key(path, spki, 0) != -EINVAL)
		FAIL("expected: aik_cert_matches_key(path, spki, 0) == -EINVAL");
	unlink(path);

	TEST("a profile with no certificate stored is -ENOENT, not a match");
	if (aik_cert_matches_key(path, spki, spki_len) != -ENOENT)
		FAIL("expected: aik_cert_matches_key(path, spki, spki_len) == "
		     "-ENOENT");
}

int main(void)
{
	test_begin("aik cert renew");
	test_renew_due_decision();
	test_lifetime_valid_cert();
	test_lifetime_expired_cert();
	test_missing_is_enoent();
	test_garbage_is_einval();
	test_null_args();
	test_certificate_names_the_key();
	test_a_replaced_key_is_rejected();
	test_match_arguments_and_missing_cert();

	return test_end();
}
