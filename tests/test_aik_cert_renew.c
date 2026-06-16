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
 * Returns 0 on success.
 */
static int write_test_cert(const char *path, long before, long after)
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

int main(void)
{
	test_renew_due_decision();
	test_lifetime_valid_cert();
	test_lifetime_expired_cert();
	test_missing_is_enoent();
	test_garbage_is_einval();
	test_null_args();

	if (g_failures) {
		fprintf(stderr, "\n%d test(s) FAILED\n", g_failures);
		return 1;
	}
	printf("\nAll AIK cert renewal tests passed\n");
	return 0;
}
