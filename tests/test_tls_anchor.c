/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * --ca-cert as a pinned anchor: a CA, a listener certificate that CA issued,
 * or a self-signed listener certificate. A CA-issued leaf in the store needs
 * X509_V_FLAG_PARTIAL_CHAIN, or OpenSSL looks for its unreachable issuer.
 */

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "../src/agent/net.h"

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

static long g_serial = 1;

/* One certificate, signed by @issuer_key or by its own key when that is NULL */
static X509 *make_cert(EVP_PKEY *key, const char *cn, X509 *issuer,
		       EVP_PKEY *issuer_key, int is_ca)
{
	X509 *x = X509_new();
	X509_NAME *subject;
	X509V3_CTX v3;
	X509_EXTENSION *ext;

	if (!x)
		return NULL;

	X509_set_version(x, 2);
	ASN1_INTEGER_set(X509_get_serialNumber(x), g_serial++);
	X509_gmtime_adj(X509_getm_notBefore(x), 0);
	X509_gmtime_adj(X509_getm_notAfter(x), 3600);
	X509_set_pubkey(x, key);

	subject = X509_get_subject_name(x);
	X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
				   (const unsigned char *)cn, -1, -1, 0);
	X509_set_issuer_name(x,
			     issuer ? X509_get_subject_name(issuer) : subject);

	X509V3_set_ctx(&v3, issuer ? issuer : x, x, NULL, NULL, 0);
	X509V3_set_ctx_nodb(&v3);
	ext = X509V3_EXT_conf_nid(NULL, &v3, NID_basic_constraints,
				  is_ca ? "critical,CA:TRUE" :
					  "critical,CA:FALSE");
	if (ext) {
		X509_add_ext(x, ext, -1);
		X509_EXTENSION_free(ext);
	}

	if (X509_sign(x, issuer_key ? issuer_key : key, EVP_sha256()) == 0) {
		X509_free(x);
		return NULL;
	}
	return x;
}

static int write_pem(const char *path, X509 *cert)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	FILE *f;
	int ok;

	if (fd < 0)
		return -1;
	f = fdopen(fd, "w");
	if (!f) {
		close(fd);
		return -1;
	}
	ok = PEM_write_X509(f, cert);
	fclose(f);
	return ok == 1 ? 0 : -1;
}

/* verify @leaf against the store and params a context on @anchor_path built */
static int anchor_accepts(const char *anchor_path, X509 *leaf, int *err_out)
{
	struct net_context ctx;
	X509_STORE_CTX *sc;
	int rc;

	memset(&ctx, 0, sizeof(ctx));
	if (net_context_init(&ctx, "127.0.0.1", 8443, anchor_path, 0, NULL) <
	    0) {
		fprintf(stderr, "net_context_init(%s) failed\n", anchor_path);
		return -1;
	}

	sc = X509_STORE_CTX_new();
	if (!sc || X509_STORE_CTX_init(sc, SSL_CTX_get_cert_store(ctx.ssl_ctx),
				       leaf, NULL) != 1) {
		X509_STORE_CTX_free(sc);
		net_context_cleanup(&ctx);
		return -1;
	}
	X509_VERIFY_PARAM_inherit(X509_STORE_CTX_get0_param(sc),
				  SSL_CTX_get0_param(ctx.ssl_ctx));

	rc = X509_verify_cert(sc);
	if (err_out)
		*err_out = X509_STORE_CTX_get_error(sc);

	X509_STORE_CTX_free(sc);
	net_context_cleanup(&ctx);
	return rc == 1;
}

int main(void)
{
	EVP_PKEY *ca_key = EVP_EC_gen("P-256");
	EVP_PKEY *leaf_key = EVP_EC_gen("P-256");
	EVP_PKEY *self_key = EVP_EC_gen("P-256");
	X509 *ca = NULL, *leaf = NULL, *self = NULL;
	char dir[] = "/tmp/lota-tls-anchor-XXXXXX";
	char ca_pem[128], leaf_pem[128], self_pem[128];
	int err = 0;

	printf("=== pinned anchor tests ===\n");

	if (!ca_key || !leaf_key || !self_key || !mkdtemp(dir)) {
		fprintf(stderr, "setup failed\n");
		return 1;
	}

	ca = make_cert(ca_key, "LOTA test CA", NULL, NULL, 1);
	leaf = make_cert(leaf_key, "verifier.test", ca, ca_key, 0);
	self = make_cert(self_key, "verifier.test", NULL, NULL, 0);
	if (!ca || !leaf || !self) {
		fprintf(stderr, "certificate generation failed\n");
		return 1;
	}

	snprintf(ca_pem, sizeof(ca_pem), "%s/ca.pem", dir);
	snprintf(leaf_pem, sizeof(leaf_pem), "%s/leaf.pem", dir);
	snprintf(self_pem, sizeof(self_pem), "%s/self.pem", dir);
	if (write_pem(ca_pem, ca) < 0 || write_pem(leaf_pem, leaf) < 0 ||
	    write_pem(self_pem, self) < 0) {
		fprintf(stderr, "writing the certificates failed\n");
		return 1;
	}

	CHECK(anchor_accepts(ca_pem, leaf, &err) == 1,
	      "a CA anchor accepts the certificate it issued");

	/* its issuer is not in the store; the pin ends the chain */
	CHECK(anchor_accepts(leaf_pem, leaf, &err) == 1,
	      "a pinned CA-issued listener certificate is its own anchor");

	CHECK(anchor_accepts(self_pem, self, &err) == 1,
	      "a pinned self-signed listener certificate still verifies");

	CHECK(anchor_accepts(self_pem, leaf, &err) == 0,
	      "a pinned certificate does not vouch for a different one");

	X509_free(ca);
	X509_free(leaf);
	X509_free(self);
	EVP_PKEY_free(ca_key);
	EVP_PKEY_free(leaf_key);
	EVP_PKEY_free(self_key);
	unlink(ca_pem);
	unlink(leaf_pem);
	unlink(self_pem);
	rmdir(dir);

	if (g_failures) {
		fprintf(stderr, "\n%d test(s) failed\n", g_failures);
		return 1;
	}
	printf("\nAll pinned anchor tests passed\n");
	return 0;
}
