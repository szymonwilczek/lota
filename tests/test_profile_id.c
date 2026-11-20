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
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/types.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "../src/agent/enroll.h"
#include "../src/agent/profile.h"
#include "../src/agent/publishers.h"

#include "test.h"

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

/* Self-signed certificate carrying basicConstraints CA:TRUE,
 * which is what a publisher's trust anchor is and a listener certificate is not */
static X509 *mint_ca_cert(EVP_PKEY *pkey, const char *cn, long serial)
{
	X509_EXTENSION *ext;
	X509 *x = mint_cert(pkey, cn, serial);

	if (!x)
		return NULL;

	ext = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints,
				  "critical,CA:TRUE");
	if (!ext || !X509_add_ext(x, ext, -1)) {
		X509_EXTENSION_free(ext);
		X509_free(x);
		return NULL;
	}
	X509_EXTENSION_free(ext);

	/* the signature covers the extensions, so re-sign after adding one */
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

static FILE *fopen_priv(const char *path, const char *mode)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	FILE *f;

	if (fd < 0)
		return NULL;
	f = fdopen(fd, mode);
	if (!f)
		close(fd);
	return f;
}

static int write_cert_pem(const char *path, X509 *x)
{
	FILE *f = fopen_priv(path, "wb");
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
		TEST("key generation");
		if (!0)
			FAIL("expected: 0");
		goto out;
	}

	cert = mint_cert(key, "publisher-a", 1);
	reissued = mint_cert(key, "publisher-a-renewed", 2);
	other = mint_cert(other_key, "publisher-b", 1);
	if (!cert || !reissued || !other) {
		TEST("certificate minting");
		if (!0)
			FAIL("expected: 0");
		goto out;
	}

	if (write_cert_der(der_path, cert) != 0 ||
	    write_cert_pem(pem_path, cert) != 0 ||
	    write_cert_der(reissued_path, reissued) != 0 ||
	    write_cert_der(other_path, other) != 0) {
		TEST("writing anchors");
		if (!0)
			FAIL("expected: 0");
		goto out;
	}

	TEST("DER anchor derives an identity");
	if (profile_id_from_anchor(der_path, id_der, sizeof(id_der)) != 0)
		FAIL("expected: profile_id_from_anchor(der_path, id_der, "
		     "sizeof(id_der)) == 0");
	TEST("PEM anchor derives an identity");
	if (profile_id_from_anchor(pem_path, id_pem, sizeof(id_pem)) != 0)
		FAIL("expected: profile_id_from_anchor(pem_path, id_pem, "
		     "sizeof(id_pem)) == 0");
	TEST("reissued anchor derives an identity");
	if (profile_id_from_anchor(reissued_path, id_reissued,
				   sizeof(id_reissued)) != 0)
		FAIL("expected: profile_id_from_anchor(reissued_path, "
		     "id_reissued, sizeof(id_reissued)) == 0");
	TEST("second publisher's anchor derives an identity");
	if (profile_id_from_anchor(other_path, id_other, sizeof(id_other)) != 0)
		FAIL("expected: profile_id_from_anchor(other_path, id_other, "
		     "sizeof(id_other)) == 0");

	TEST("identity is 64 hex characters");
	if (!(strlen(id_der) == LOTA_PROFILE_ID_LEN - 1))
		FAIL("expected: strlen(id_der) == LOTA_PROFILE_ID_LEN - 1");
	TEST("identity is lowercase hex");
	if (strspn(id_der, "0123456789abcdef") != strlen(id_der))
		FAIL("expected: strspn(id_der, \"0123456789abcdef\") == "
		     "strlen(id_der)");

	TEST("PEM and DER of one anchor are one profile");
	if (strcmp(id_der, id_pem) != 0)
		FAIL("expected: strcmp(id_der, id_pem) == 0");
	TEST("reissuing the CA certificate keeps the profile");
	if (strcmp(id_der, id_reissued) != 0)
		FAIL("expected: strcmp(id_der, id_reissued) == 0");
	TEST("a second publisher gets a second profile");
	if (strcmp(id_der, id_other) == 0)
		FAIL("expected: strcmp(id_der, id_other) != 0");

	TEST("identity is the SHA-256 of the anchor's SPKI");
	if (!(expected_id(key, id_expected, sizeof(id_expected)) == 0 &&
	      strcmp(id_der, id_expected) == 0))
		FAIL("expected: expected_id(key, id_expected, "
		     "sizeof(id_expected)) == 0 && strcmp(id_der, "
		     "id_expected) == 0");

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

	TEST("no anchor is refused");
	if (profile_id_from_anchor(NULL, id, sizeof(id)) != -EINVAL)
		FAIL("expected: profile_id_from_anchor(NULL, id, sizeof(id)) "
		     "== -EINVAL");
	TEST("missing anchor reports ENOENT");
	if (profile_id_from_anchor("/tmp/lota-profile-absent.XXXXXX", id,
				   sizeof(id)) != -ENOENT)
		FAIL("expected: profile_id_from_anchor(\"/tmp/lota-profile-absent.XXXXXX\", "
		     "id, sizeof(id)) == -ENOENT");

	/* root reads a 0000 file; the refusal is only there for a user */
	if (geteuid() != 0 &&
	    write_all(garbage_path, garbage, sizeof(garbage)) == 0 &&
	    chmod(garbage_path, 0) == 0) {
		TEST("an anchor that cannot be read is not reported missing");
		if (profile_id_from_anchor(garbage_path, id, sizeof(id)) !=
		    -EACCES)
			FAIL("expected: profile_id_from_anchor(garbage_path, id, "
			     "sizeof(id)) == -EACCES");
		unlink(garbage_path);
	}

	TEST("write a non-certificate anchor");
	if (write_all(garbage_path, garbage, sizeof(garbage)) != 0)
		FAIL("expected: write_all(garbage_path, garbage, "
		     "sizeof(garbage)) == 0");
	TEST("a file that is not a certificate is refused");
	if (profile_id_from_anchor(garbage_path, id, sizeof(id)) != -EINVAL)
		FAIL("expected: profile_id_from_anchor(garbage_path, id, "
		     "sizeof(id)) == -EINVAL");
	TEST("paths are refused with the identity");
	if (profile_paths_from_anchor(garbage_path, &paths) != -EINVAL)
		FAIL("expected: profile_paths_from_anchor(garbage_path, "
		     "&paths) == -EINVAL");

	TEST("a buffer too small for the identity is refused");
	if (profile_id_from_anchor(garbage_path, id, LOTA_PROFILE_ID_LEN - 1) !=
	    -EINVAL)
		FAIL("expected: profile_id_from_anchor(garbage_path, id, "
		     "LOTA_PROFILE_ID_LEN - 1) == -EINVAL");

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
		TEST("key generation");
		if (!0)
			FAIL("expected: 0");
		goto out;
	}
	cert = mint_cert(key, "publisher-a", 1);
	if (!cert || write_cert_der(der_path, cert) != 0) {
		TEST("writing the anchor");
		if (!0)
			FAIL("expected: 0");
		goto out;
	}

	snprintf(base, sizeof(base), "/tmp/lota-profile-base.%d", getpid());

	TEST("paths derive from an anchor");
	if (profile_paths_from_anchor_base(base, der_path, &paths) != 0)
		FAIL("expected: profile_paths_from_anchor_base(base, "
		     "der_path, &paths) == 0");

	snprintf(expect, sizeof(expect), "%s/%s", base, paths.id);
	TEST("profile directory is base/id");
	if (strcmp(paths.dir, expect) != 0)
		FAIL("expected: strcmp(paths.dir, expect) == 0");
	snprintf(expect, sizeof(expect), "%s/%s", paths.dir,
		 LOTA_PROFILE_ENROLL_STATE_FILE);
	TEST("enrollment record sits in the profile");
	if (strcmp(paths.enroll_state, expect) != 0)
		FAIL("expected: strcmp(paths.enroll_state, expect) == 0");
	snprintf(expect, sizeof(expect), "%s/%s", paths.dir,
		 LOTA_PROFILE_AIK_CERT_FILE);
	TEST("AIK certificate sits in the profile");
	if (strcmp(paths.aik_cert, expect) != 0)
		FAIL("expected: strcmp(paths.aik_cert, expect) == 0");

	TEST("profile directory is created");
	if (profile_dir_ensure(&paths) != 0)
		FAIL("expected: profile_dir_ensure(&paths) == 0");
	TEST("profile directory exists");
	if (!(stat(paths.dir, &st) == 0 && S_ISDIR(st.st_mode)))
		FAIL("expected: stat(paths.dir, &st) == 0 && "
		     "S_ISDIR(st.st_mode)");
	TEST("profile directory is root-only: the record carries the "
	     "enrollment token");
	if ((st.st_mode & 0777) != 0700)
		FAIL("expected: (st.st_mode & 0777) == 0700");
	TEST("creating an existing profile directory is a no-op");
	if (profile_dir_ensure(&paths) != 0)
		FAIL("expected: profile_dir_ensure(&paths) == 0");

	rmdir(paths.dir);
	rmdir(base);

out:
	unlink(der_path);
	X509_free(cert);
	EVP_PKEY_free(key);
}

/*
 * Publisher named in lota.conf exists before anything enrolls with it,
 * and the first thing written under it is the handle its AIK will live at
 * -- the daemon binds the profile at startup, and enrollment is what happens later.
 * Recording that handle therefore has to create the layout it writes into rather
 * than assume an enrollment already did: without this, configured publisher
 * that has never enrolled fails the bind with ENOENT and takes the host's
 * enforcement down with it.
 */
static void test_handle_record_first_use(void)
{
	char der_path[256];
	char base[256];
	struct profile_paths paths;
	uint32_t handle = 0;
	EVP_PKEY *key = EVP_EC_gen("P-256");
	X509 *cert = NULL;
	struct stat st;

	tmp_path(der_path, sizeof(der_path), "firstuse.der");
	snprintf(base, sizeof(base), "/tmp/lota-profile-fbase.%d", getpid());

	if (!key) {
		TEST("key generation");
		if (!0)
			FAIL("expected: 0");
		goto out;
	}
	cert = mint_cert(key, "publisher-first-use", 1);
	if (!cert || write_cert_der(der_path, cert) != 0 ||
	    profile_paths_from_anchor_base(base, der_path, &paths) != 0) {
		TEST("profile setup");
		if (!0)
			FAIL("expected: 0");
		goto out;
	}

	TEST("a handle is recorded for a publisher that has never enrolled");
	if (profile_aik_handle_save(&paths, 0x81010012) != 0)
		FAIL("expected: profile_aik_handle_save(&paths, 0x81010012) "
		     "== 0");
	TEST("recording the handle creates the profile directory root-only");
	if (!(stat(paths.dir, &st) == 0 && S_ISDIR(st.st_mode) &&
	      (st.st_mode & 0777) == 0700))
		FAIL("expected: stat(paths.dir, &st) == 0 && "
		     "S_ISDIR(st.st_mode) && (st.st_mode & 0777) == 0700");
	TEST("the recorded handle reads back");
	if (!(profile_aik_handle_load(&paths, &handle) == 0 &&
	      handle == 0x81010012))
		FAIL("expected: profile_aik_handle_load(&paths, &handle) == 0 "
		     "&& handle == 0x81010012");

	unlink(paths.aik_handle);
	rmdir(paths.dir);
	rmdir(base);

out:
	unlink(der_path);
	X509_free(cert);
	EVP_PKEY_free(key);
}

/*
 * Handle allocation.
 * Record is what keeps a publisher on its own key across config edit,
 * so what is pinned here is that a recorded handle is never handed out again
 * and that the order does not depend on the order profiles were created in.
 */
static void write_handle_record(const char *base, const char *profile_id,
				const char *contents)
{
	char dir[PATH_MAX];
	char path[PATH_MAX + 64];
	FILE *f;

	snprintf(dir, sizeof(dir), "%s/%s", base, profile_id);
	mkdir(base, 0700);
	mkdir(dir, 0700);
	snprintf(path, sizeof(path), "%s/%s", dir,
		 LOTA_PROFILE_AIK_HANDLE_FILE);
	f = fopen_priv(path, "w");
	if (!f) {
		TEST("write a sibling handle record");
		if (!0)
			FAIL("expected: 0");
		return;
	}
	fputs(contents, f);
	fclose(f);
}

static void remove_profile_dir(const char *base, const char *profile_id)
{
	char path[PATH_MAX + 64];

	snprintf(path, sizeof(path), "%s/%s/%s", base, profile_id,
		 LOTA_PROFILE_AIK_HANDLE_FILE);
	unlink(path);
	snprintf(path, sizeof(path), "%s/%s", base, profile_id);
	rmdir(path);
}

static void test_handle_record_round_trip(void)
{
	char der_path[256];
	char base[256];
	struct profile_paths paths;
	uint32_t handle = 0;
	EVP_PKEY *key = EVP_EC_gen("P-256");
	X509 *cert = NULL;

	tmp_path(der_path, sizeof(der_path), "handle.der");
	snprintf(base, sizeof(base), "/tmp/lota-profile-hbase.%d", getpid());

	if (!key) {
		TEST("key generation");
		if (!0)
			FAIL("expected: 0");
		goto out;
	}
	cert = mint_cert(key, "publisher-a", 1);
	if (!cert || write_cert_der(der_path, cert) != 0 ||
	    profile_paths_from_anchor_base(base, der_path, &paths) != 0) {
		TEST("profile setup");
		if (!0)
			FAIL("expected: 0");
		goto out;
	}

	TEST("a profile that has not provisioned records no handle");
	if (profile_aik_handle_load(&paths, &handle) != -ENOENT)
		FAIL("expected: profile_aik_handle_load(&paths, &handle) == "
		     "-ENOENT");

	TEST("profile directory");
	if (profile_dir_ensure(&paths) != 0)
		FAIL("expected: profile_dir_ensure(&paths) == 0");
	TEST("handle is recorded");
	if (profile_aik_handle_save(&paths, 0x81010011) != 0)
		FAIL("expected: profile_aik_handle_save(&paths, 0x81010011) "
		     "== 0");
	TEST("recorded handle reads back");
	if (!(profile_aik_handle_load(&paths, &handle) == 0 &&
	      handle == 0x81010011))
		FAIL("expected: profile_aik_handle_load(&paths, &handle) == 0 "
		     "&& handle == 0x81010011");
	TEST("handle 0 is not a handle");
	if (profile_aik_handle_save(&paths, 0) != -EINVAL)
		FAIL("expected: profile_aik_handle_save(&paths, 0) == -EINVAL");

	unlink(paths.aik_handle);
	rmdir(paths.dir);
	rmdir(base);

out:
	unlink(der_path);
	X509_free(cert);
	EVP_PKEY_free(key);
}

static void test_handle_candidates(void)
{
	const uint32_t base_handle = 0x81010010;
	uint32_t out[LOTA_PROFILE_MAX_AIK_HANDLES];
	char base[256];
	size_t n = 0;

	snprintf(base, sizeof(base), "/tmp/lota-profile-cbase.%d", getpid());

	TEST("with no profiles the whole range is free");
	if (!(profile_aik_handle_candidates(base, base_handle, 4, out,
					    LOTA_PROFILE_MAX_AIK_HANDLES,
					    &n) == 0 &&
	      n == 4 && out[0] == base_handle && out[3] == base_handle + 3))
		FAIL("expected: profile_aik_handle_candidates(base, "
		     "base_handle, 4, out, LOTA_PROFILE_MAX_AIK_HANDLES, &n) "
		     "== 0 && n == 4 && out[0] == base_handle && out[3] == "
		     "base_handle + 3");

	/* two publishers hold the first and the third slot */
	write_handle_record(base, "aaaa", "0x81010010\n");
	write_handle_record(base, "cccc", "0x81010012\n");

	/* profile that exists but has not provisioned records nothing */
	{
		char dir[PATH_MAX];

		snprintf(dir, sizeof(dir), "%s/%s", base, "bbbb");
		mkdir(dir, 0700);
	}

	TEST("recorded handles are skipped, the rest stays in order");
	if (!(profile_aik_handle_candidates(base, base_handle, 4, out,
					    LOTA_PROFILE_MAX_AIK_HANDLES,
					    &n) == 0 &&
	      n == 2 && out[0] == base_handle + 1 && out[1] == base_handle + 3))
		FAIL("expected: profile_aik_handle_candidates(base, "
		     "base_handle, 4, out, LOTA_PROFILE_MAX_AIK_HANDLES, &n) "
		     "== 0 && n == 2 && out[0] == base_handle + 1 && out[1] "
		     "== base_handle + 3");

	write_handle_record(base, "dddd", "0x81010011\n");
	write_handle_record(base, "eeee", "0x81010013\n");
	TEST("a full range offers nothing rather than reusing a handle");
	if (!(profile_aik_handle_candidates(base, base_handle, 4, out,
					    LOTA_PROFILE_MAX_AIK_HANDLES,
					    &n) == 0 &&
	      n == 0))
		FAIL("expected: profile_aik_handle_candidates(base, "
		     "base_handle, 4, out, LOTA_PROFILE_MAX_AIK_HANDLES, &n) "
		     "== 0 && n == 0");

	/* unreadable record must not silently free the slot it names */
	write_handle_record(base, "cccc", "not-a-handle\n");
	TEST("a corrupt record frees its slot for reallocation");
	if (!(profile_aik_handle_candidates(base, base_handle, 4, out,
					    LOTA_PROFILE_MAX_AIK_HANDLES,
					    &n) == 0 &&
	      n == 1 && out[0] == base_handle + 2))
		FAIL("expected: profile_aik_handle_candidates(base, "
		     "base_handle, 4, out, LOTA_PROFILE_MAX_AIK_HANDLES, &n) "
		     "== 0 && n == 1 && out[0] == base_handle + 2");

	remove_profile_dir(base, "aaaa");
	remove_profile_dir(base, "bbbb");
	remove_profile_dir(base, "cccc");
	remove_profile_dir(base, "dddd");
	remove_profile_dir(base, "eeee");
	rmdir(base);
}

/*
 * Consent is what stands between a title asking and this machine holding key
 * that publisher can recognise it by, so what matters is that its absence is
 * unambiguous and that recording it does not depend on enrollment that has not
 * happened yet.
 */
static void test_consent_record(void)
{
	char der_path[256];
	char base[256];
	struct profile_paths paths;
	time_t agreed = 0;
	EVP_PKEY *key = EVP_EC_gen("P-256");
	X509 *cert = NULL;
	struct stat st;

	tmp_path(der_path, sizeof(der_path), "consent.der");
	snprintf(base, sizeof(base), "/tmp/lota-profile-consent.%d", getpid());

	if (!key) {
		TEST("key generation");
		if (!0)
			FAIL("expected: 0");
		goto out;
	}
	cert = mint_cert(key, "publisher-a", 1);
	if (!cert || write_cert_der(der_path, cert) != 0 ||
	    profile_paths_from_anchor_base(base, der_path, &paths) != 0) {
		TEST("profile setup");
		if (!0)
			FAIL("expected: 0");
		goto out;
	}

	TEST("a publisher nobody agreed to has no consent");
	if (profile_consent_time(&paths, &agreed) != -ENOENT)
		FAIL("expected: profile_consent_time(&paths, &agreed) == "
		     "-ENOENT");

	TEST("consent is recorded before anything enrolled");
	if (profile_consent_record(&paths, 0) != 0)
		FAIL("expected: profile_consent_record(&paths, 0) == 0");
	TEST("recording consent creates the profile directory");
	if (stat(paths.dir, &st) != 0)
		FAIL("expected: stat(paths.dir, &st) == 0");
	TEST("the record says when the decision was made");
	if (!(profile_consent_time(&paths, &agreed) == 0 && agreed > 0 &&
	      agreed <= time(NULL)))
		FAIL("expected: profile_consent_time(&paths, &agreed) == 0 && "
		     "agreed > 0 && agreed <= time(NULL)");

	/* record that is not one must not read as consent */
	{
		FILE *f = fopen_priv(paths.consent, "w");

		if (f) {
			fputs("yes please\n", f);
			fclose(f);
		}
		TEST("a file that is not a consent record is refused");
		if (profile_consent_time(&paths, &agreed) != -EINVAL)
			FAIL("expected: profile_consent_time(&paths, &agreed) == "
			     "-EINVAL");
	}

	unlink(paths.consent);
	unlink(paths.aik_handle);
	rmdir(paths.dir);
	rmdir(base);

out:
	unlink(der_path);
	X509_free(cert);
	EVP_PKEY_free(key);
}

/*
 * A publisher's identity may not be pinned to a certificate that is meant to
 * rotate.
 *
 * The agent takes one --ca-cert and uses it for two things: verifying the CA
 * server's TLS chain, and naming the publisher. A CA anchor serves both.
 * A TLS listener certificate serves the first and is rotated on a schedule
 * -- so naming it moves every host of that publisher onto a new profile,
 * a new AIK and a fresh consent prompt on the day the certificate is re-keyed,
 * with nothing reporting it.
 *
 * The anchor cannot be refused outright: a self-signed leaf is a legitimate pin
 * for a deployment that wants one. What the agent can do is know the difference,
 * which is what this pins.
 */
static void test_anchor_is_ca(void)
{
	EVP_PKEY *key = EVP_EC_gen("P-256");
	X509 *ca = NULL;
	X509 *leaf = NULL;
	char ca_path[256];
	char leaf_path[256];

	snprintf(ca_path, sizeof(ca_path), "/tmp/lota-anchor-ca.%d.pem",
		 (int)getpid());
	snprintf(leaf_path, sizeof(leaf_path), "/tmp/lota-anchor-leaf.%d.pem",
		 (int)getpid());

	if (!key) {
		TEST("key generation");
		if (!0)
			FAIL("expected: 0");
		return;
	}
	ca = mint_ca_cert(key, "publisher anchor", 1);
	leaf = mint_cert(key, "lota-attest-ca listener", 2);
	if (!ca || !leaf || write_cert_pem(ca_path, ca) != 0 ||
	    write_cert_pem(leaf_path, leaf) != 0) {
		TEST("certificate fixtures");
		if (!0)
			FAIL("expected: 0");
		goto out;
	}

	TEST("a CA anchor is recognised as one");
	if (profile_anchor_is_ca(ca_path) != 1)
		FAIL("expected: profile_anchor_is_ca(ca_path) == 1");
	TEST("a listener certificate is not a CA anchor");
	if (profile_anchor_is_ca(leaf_path) != 0)
		FAIL("expected: profile_anchor_is_ca(leaf_path) == 0");
	TEST("an anchor that cannot be read is an error, not an answer");
	if (profile_anchor_is_ca("/nonexistent/anchor.pem") >= 0)
		FAIL("expected: profile_anchor_is_ca(\"/nonexistent/anchor.pem\") "
		     "< 0");

out:
	unlink(ca_path);
	unlink(leaf_path);
	X509_free(ca);
	X509_free(leaf);
	EVP_PKEY_free(key);
}

static void test_aik_slot_tally(void)
{
	const uint32_t base = 0x81010010;
	struct profile_aik_slots slots;

	/* nothing recorded, nothing on the chip: the whole range is free */
	TEST("an untouched range is entirely free");
	if (!(profile_aik_slot_tally(base, 8, NULL, 0, NULL, 0, &slots) == 0 &&
	      slots.total == 8 && slots.free_slots == 8 &&
	      slots.recorded == 0 && slots.unrecorded == 0))
		FAIL("expected: profile_aik_slot_tally(base, 8, NULL, 0, "
		     "NULL, 0, &slots) == 0 && slots.total == 8 && "
		     "slots.free_slots == 8 && slots.recorded == 0 && "
		     "slots.unrecorded == 0");

	{
		const uint32_t recorded[] = { base, base + 1 };
		const uint32_t in_use[] = { base, base + 1 };

		TEST("a slot a profile records is not an orphan");
		if (!(profile_aik_slot_tally(base, 8, recorded, 2, in_use, 2,
					     &slots) == 0 &&
		      slots.recorded == 2 && slots.unrecorded == 0 &&
		      slots.free_slots == 6))
			FAIL("expected: profile_aik_slot_tally(base, 8, recorded, 2, "
			     "in_use, 2, &slots) == 0 && slots.recorded == 2 && "
			     "slots.unrecorded == 0 && slots.free_slots == 6");
	}

	{
		/* 3 unrecorded objects, 2 recorded keys gone from the chip */
		const uint32_t recorded[] = { base, base + 1, base + 5,
					      base + 6, base + 7 };
		const uint32_t in_use[] = { base,     base + 1, base + 2,
					    base + 3, base + 4, base + 6 };

		TEST("objects nothing records fill the rest of the range");
		if (!(profile_aik_slot_tally(base, 8, recorded, 5, in_use, 6,
					     &slots) == 0 &&
		      slots.recorded == 5 && slots.unrecorded == 3 &&
		      slots.free_slots == 0))
			FAIL("expected: profile_aik_slot_tally(base, 8, recorded, 5, "
			     "in_use, 6, &slots) == 0 && slots.recorded == 5 && "
			     "slots.unrecorded == 3 && slots.free_slots == 0");
		TEST("the orphaned handles are named, lowest first");
		if (!(slots.unrecorded_handles[0] == base + 2 &&
		      slots.unrecorded_handles[1] == base + 3 &&
		      slots.unrecorded_handles[2] == base + 4))
			FAIL("expected: slots.unrecorded_handles[0] == base + 2 && "
			     "slots.unrecorded_handles[1] == base + 3 && "
			     "slots.unrecorded_handles[2] == base + 4");
	}

	{
		/* an object outside the range costs this build nothing */
		const uint32_t in_use[] = { 0x81010002, base + 9 };

		TEST("handles outside the range are not this build's");
		if (!(profile_aik_slot_tally(base, 8, NULL, 0, in_use, 2,
					     &slots) == 0 &&
		      slots.unrecorded == 0 && slots.free_slots == 8))
			FAIL("expected: profile_aik_slot_tally(base, 8, NULL, 0, "
			     "in_use, 2, &slots) == 0 && slots.unrecorded == 0 && "
			     "slots.free_slots == 8");
	}

	TEST("the tally rejects a missing result and an empty range");
	if (!(profile_aik_slot_tally(base, 8, NULL, 0, NULL, 0, NULL) ==
		      -EINVAL &&
	      profile_aik_slot_tally(base, 0, NULL, 0, NULL, 0, &slots) ==
		      -EINVAL))
		FAIL("expected: profile_aik_slot_tally(base, 8, NULL, 0, "
		     "NULL, 0, NULL) == -EINVAL && "
		     "profile_aik_slot_tally(base, 0, NULL, 0, NULL, 0, "
		     "&slots) == -EINVAL");
}

/*
 * The inventory is what a player checks and what revocation acts on,
 * so what matters is that a half-finished profile is still listed
 * -- "agreed to, not enrolled" is the state between accepting and title running,
 * and hiding it would hide the answer to "why is this not working yet"
 * -- and that forgetting leaves nothing behind.
 */
static void test_publisher_inventory(void)
{
	struct publisher_entry entries[LOTA_PROFILE_MAX_AIK_HANDLES];
	const char *id_a =
		"1111111111111111111111111111111111111111111111111111111111111111";
	const char *id_b =
		"2222222222222222222222222222222222222222222222222222222222222222";
	struct profile_paths paths;
	char base[256];
	size_t count = 0;
	struct stat st;

	snprintf(base, sizeof(base), "/tmp/lota-profile-inv.%d", getpid());

	TEST("a host that answered to nobody lists nobody");
	if (!(publishers_list(base, entries, LOTA_PROFILE_MAX_AIK_HANDLES,
			      &count) == 0 &&
	      count == 0))
		FAIL("expected: publishers_list(base, entries, "
		     "LOTA_PROFILE_MAX_AIK_HANDLES, &count) == 0 && count == 0");

	TEST("paths derive from an identity");
	if (profile_paths_from_id(base, id_a, &paths) != 0)
		FAIL("expected: profile_paths_from_id(base, id_a, &paths) == 0");
	TEST("publisher A agreed to");
	if (profile_consent_record(&paths, 0) != 0)
		FAIL("expected: profile_consent_record(&paths, 0) == 0");
	TEST("publisher A holds a key");
	if (profile_aik_handle_save(&paths, 0x81010010) != 0)
		FAIL("expected: profile_aik_handle_save(&paths, 0x81010010) "
		     "== 0");

	/* directory whose name is not an identity is not a publisher */
	{
		char junk[PATH_MAX];

		snprintf(junk, sizeof(junk), "%s/%s", base, "not-a-profile");
		mkdir(junk, 0700);
	}

	TEST("only directories named by an identity are publishers");
	if (!(publishers_list(base, entries, LOTA_PROFILE_MAX_AIK_HANDLES,
			      &count) == 0 &&
	      count == 1))
		FAIL("expected: publishers_list(base, entries, "
		     "LOTA_PROFILE_MAX_AIK_HANDLES, &count) == 0 && count == 1");
	TEST("the entry says what is stored for that publisher");
	if (!(strcmp(entries[0].id, id_a) == 0 && entries[0].consented &&
	      entries[0].has_aik_handle && entries[0].aik_handle == 0x81010010))
		FAIL("expected: strcmp(entries[0].id, id_a) == 0 && "
		     "entries[0].consented && entries[0].has_aik_handle && "
		     "entries[0].aik_handle == 0x81010010");
	TEST("agreed to but not enrolled is a state, not an omission");
	if (!(!entries[0].enrolled && !entries[0].has_cert))
		FAIL("expected: !entries[0].enrolled && !entries[0].has_cert");
	TEST("no record on disk is not an unreadable one");
	if (entries[0].enroll_unreadable)
		FAIL("expected: !entries[0].enroll_unreadable");

	/* an unreadable record is held, not "never enrolled" */
	{
		struct enroll_state old_rec;
		int fd;

		memset(&old_rec, 0, sizeof(old_rec));
		old_rec.magic = LOTA_ENROLL_STATE_MAGIC;
		old_rec.version = LOTA_ENROLL_STATE_VERSION + 1;
		fd = open(paths.enroll_state, O_WRONLY | O_CREAT | O_TRUNC,
			  0600);
		TEST("an enrollment record can be planted");
		if (fd < 0)
			FAIL("expected: fd >= 0");
		if (fd >= 0) {
			TEST("the planted record is a whole record");
			if (write(fd, &old_rec, sizeof(old_rec)) !=
			    (ssize_t)sizeof(old_rec))
				FAIL("expected: write(fd, &old_rec, sizeof(old_rec)) == "
				     "(ssize_t)sizeof(old_rec)");
			close(fd);
		}

		TEST("the profile is still one publisher");
		if (!(publishers_list(base, entries,
				      LOTA_PROFILE_MAX_AIK_HANDLES,
				      &count) == 0 &&
		      count == 1))
			FAIL("expected: publishers_list(base, entries, "
			     "LOTA_PROFILE_MAX_AIK_HANDLES, &count) == 0 && count == 1");
		TEST("a record this build cannot read is held, not absent");
		if (!(!entries[0].enrolled && entries[0].enroll_unreadable &&
		      entries[0].enroll_rc == -ENOTSUP))
			FAIL("expected: !entries[0].enrolled && "
			     "entries[0].enroll_unreadable && entries[0].enroll_rc == "
			     "-ENOTSUP");

		TEST("the planted record is removed again");
		if (unlink(paths.enroll_state) != 0)
			FAIL("expected: unlink(paths.enroll_state) == 0");
		TEST("removing it makes the profile unenrolled again");
		if (!(publishers_list(base, entries,
				      LOTA_PROFILE_MAX_AIK_HANDLES,
				      &count) == 0 &&
		      !entries[0].enroll_unreadable))
			FAIL("expected: publishers_list(base, entries, "
			     "LOTA_PROFILE_MAX_AIK_HANDLES, &count) == 0 && "
			     "!entries[0].enroll_unreadable");
	}

	/*
	 * One key is one TPM persistent slot, and running out of them is what
	 * reported "Input/output error" to a player whose machine was merely
	 * full. The count is what the ceiling is stated against, so a publisher
	 * that holds no key must not be counted as using a slot.
	 */
	TEST("a publisher holding a key counts against the TPM's slots");
	if (publishers_keys_held(entries, count) != 1)
		FAIL("expected: publishers_keys_held(entries, count) == 1");

	TEST("publisher B agreed to, with no key yet");
	if (!(profile_paths_from_id(base, id_b, &paths) == 0 &&
	      profile_consent_record(&paths, 0) == 0))
		FAIL("expected: profile_paths_from_id(base, id_b, &paths) == "
		     "0 && profile_consent_record(&paths, 0) == 0");
	TEST("a publisher with no key holds no slot");
	if (!(publishers_list(base, entries, LOTA_PROFILE_MAX_AIK_HANDLES,
			      &count) == 0 &&
	      count == 2 && publishers_keys_held(entries, count) == 1))
		FAIL("expected: publishers_list(base, entries, "
		     "LOTA_PROFILE_MAX_AIK_HANDLES, &count) == 0 && count == "
		     "2 && publishers_keys_held(entries, count) == 1");
	TEST("publisher B forgotten");
	if (publishers_forget(&paths) != 0)
		FAIL("expected: publishers_forget(&paths) == 0");
	TEST("the inventory is back to one publisher");
	if (!(publishers_list(base, entries, LOTA_PROFILE_MAX_AIK_HANDLES,
			      &count) == 0 &&
	      count == 1))
		FAIL("expected: publishers_list(base, entries, "
		     "LOTA_PROFILE_MAX_AIK_HANDLES, &count) == 0 && count == 1");
	TEST("paths derive from publisher A again");
	if (profile_paths_from_id(base, id_a, &paths) != 0)
		FAIL("expected: profile_paths_from_id(base, id_a, &paths) == 0");

	/*
	 * A handle is recorded before its key exists, so it can be given back
	 * without the key ever having been made. Giving back a handle that is
	 * already gone succeeds, and the profile stays listed with its consent
	 * but holds no key.
	 */
	{
		uint32_t handle = 0;

		TEST("a reserved handle can be given back");
		if (!(profile_aik_handle_forget(&paths) == 0 &&
		      profile_aik_handle_load(&paths, &handle) == -ENOENT))
			FAIL("expected: profile_aik_handle_forget(&paths) == 0 && "
			     "profile_aik_handle_load(&paths, &handle) == -ENOENT");
		TEST("giving back a handle twice is not a failure");
		if (profile_aik_handle_forget(&paths) != 0)
			FAIL("expected: profile_aik_handle_forget(&paths) == 0");
		TEST("a profile that gave its handle back holds no key");
		if (!(publishers_list(base, entries,
				      LOTA_PROFILE_MAX_AIK_HANDLES,
				      &count) == 0 &&
		      count == 1 && publishers_keys_held(entries, count) == 0))
			FAIL("expected: publishers_list(base, entries, "
			     "LOTA_PROFILE_MAX_AIK_HANDLES, &count) == 0 && count == "
			     "1 && publishers_keys_held(entries, count) == 0");
		TEST("and is still listed, with the consent it was given");
		if (!entries[0].consented)
			FAIL("expected: entries[0].consented");
		TEST("publisher A holds a key again");
		if (profile_aik_handle_save(&paths, 0x81010010) != 0)
			FAIL("expected: profile_aik_handle_save(&paths, 0x81010010) "
			     "== 0");
	}

	TEST("a publisher can be forgotten");
	if (publishers_forget(&paths) != 0)
		FAIL("expected: publishers_forget(&paths) == 0");
	TEST("forgetting leaves no directory behind");
	if (stat(paths.dir, &st) == 0)
		FAIL("expected: stat(paths.dir, &st) != 0");
	TEST("a forgotten publisher is gone from the inventory");
	if (!(publishers_list(base, entries, LOTA_PROFILE_MAX_AIK_HANDLES,
			      &count) == 0 &&
	      count == 0))
		FAIL("expected: publishers_list(base, entries, "
		     "LOTA_PROFILE_MAX_AIK_HANDLES, &count) == 0 && count == 0");

	TEST("an identity that is not one cannot become a path");
	if (!(profile_paths_from_id(base, "not-hex", &paths) == -EINVAL &&
	      profile_paths_from_id(base, id_b + 1, &paths) == -EINVAL))
		FAIL("expected: profile_paths_from_id(base, \"not-hex\", "
		     "&paths) == -EINVAL && profile_paths_from_id(base, id_b "
		     "+ 1, &paths) == -EINVAL");

	{
		char junk[PATH_MAX];

		snprintf(junk, sizeof(junk), "%s/%s", base, "not-a-profile");
		rmdir(junk);
	}
	rmdir(base);
}

/*
 * How many attestation keys a host-wide verb has to act on.
 *
 * --seal-aik-auth and --reprovision-aik act on one key per publisher, each with
 * its own authorization, and on the pre-profile default only when the host has
 * no publishers.
 *
 * Three publishers, two of them holding a key: the expected count of two
 * differs from the publisher count (three) and from acting on a single key
 * (one), so a count that stands for either fails here.
 */
static void test_host_wide_verbs_count_every_key(void)
{
	struct publisher_entry entries[LOTA_PROFILE_MAX_AIK_HANDLES];
	const char *ids[3] = {
		"3333333333333333333333333333333333333333333333333333333333333333",
		"4444444444444444444444444444444444444444444444444444444444444444",
		"5555555555555555555555555555555555555555555555555555555555555555",
	};
	struct profile_paths paths[3];
	char base[256];
	size_t count = 0;

	snprintf(base, sizeof(base), "/tmp/lota-profile-seal.%d", getpid());

	TEST("a host with no publishers offers no per-publisher key");
	if (!(publishers_list(base, entries, LOTA_PROFILE_MAX_AIK_HANDLES,
			      &count) == 0 &&
	      count == 0))
		FAIL("expected: publishers_list(base, entries, "
		     "LOTA_PROFILE_MAX_AIK_HANDLES, &count) == 0 && count == 0");

	for (int i = 0; i < 3; i++) {
		TEST("three publishers agreed to");
		if (!(profile_paths_from_id(base, ids[i], &paths[i]) == 0 &&
		      profile_consent_record(&paths[i], 0) == 0))
			FAIL("expected: profile_paths_from_id(base, ids[i], "
			     "&paths[i]) == 0 && profile_consent_record(&paths[i], 0) "
			     "== 0");
	}

	/* two of the three hold a key; the third consented and stopped there */
	TEST("two of the three hold an attestation key");
	if (!(profile_aik_handle_save(&paths[0], 0x81010010) == 0 &&
	      profile_aik_handle_save(&paths[1], 0x81010011) == 0))
		FAIL("expected: profile_aik_handle_save(&paths[0], "
		     "0x81010010) == 0 && profile_aik_handle_save(&paths[1], "
		     "0x81010011) == 0");

	TEST("all three publishers are listed");
	if (!(publishers_list(base, entries, LOTA_PROFILE_MAX_AIK_HANDLES,
			      &count) == 0 &&
	      count == 3))
		FAIL("expected: publishers_list(base, entries, "
		     "LOTA_PROFILE_MAX_AIK_HANDLES, &count) == 0 && count == 3");
	TEST("a host-wide verb has two keys to act on, not one and not three");
	if (publishers_keys_held(entries, count) != 2)
		FAIL("expected: publishers_keys_held(entries, count) == 2");

	/* the default key is in use only on a host with no publishers */
	TEST("a host with publishers does not attest with the default key");
	if (publishers_default_key_in_use(count))
		FAIL("expected: !publishers_default_key_in_use(count)");
	TEST("a host with no publisher does attest with the default key");
	if (!publishers_default_key_in_use(0))
		FAIL("expected: publishers_default_key_in_use(0)");

	for (int i = 0; i < 3; i++)
		publishers_forget(&paths[i]);
	rmdir(base);
}

/*
 * How the AIK authorization is kept at rest: none, plaintext, sealed, or both.
 *
 * It decides whether a captured disk yields the key's authorization.
 * SEALED and BOTH both hold a sealed copy, but only SEALED has no plaintext
 * beside it, so only SEALED counts as protected.
 */
static void test_aik_auth_at_rest_state(void)
{
	const char *id =
		"6666666666666666666666666666666666666666666666666666666666666666";
	struct profile_paths paths;
	char base[256];
	/* room for dir + '/' + the longest of the two names */
	char plain[PATH_MAX + 32], sealed[PATH_MAX + 32];

	snprintf(base, sizeof(base), "/tmp/lota-profile-auth.%d", getpid());

	TEST("a publisher to hold an authorization");
	if (!(profile_paths_from_id(base, id, &paths) == 0 &&
	      profile_consent_record(&paths, 0) == 0))
		FAIL("expected: profile_paths_from_id(base, id, &paths) == 0 "
		     "&& profile_consent_record(&paths, 0) == 0");

	snprintf(plain, sizeof(plain), "%s/%s", paths.dir,
		 LOTA_PROFILE_AIK_AUTH_FILE);
	snprintf(sealed, sizeof(sealed), "%s/%s", paths.dir,
		 LOTA_PROFILE_AIK_AUTH_SEALED_FILE);

	TEST("a publisher holding no authorization reports none");
	if (profile_aik_auth_state(&paths) != PROFILE_AIK_AUTH_NONE)
		FAIL("expected: profile_aik_auth_state(&paths) == "
		     "PROFILE_AIK_AUTH_NONE");
	TEST("no authorization is not an exposed one");
	if (profile_aik_auth_exposed(PROFILE_AIK_AUTH_NONE))
		FAIL("expected: !profile_aik_auth_exposed(PROFILE_AIK_AUTH_NONE)");

	TEST("sidecar written");
	if (write_all(plain, (const uint8_t *)"auth", 4) != 0)
		FAIL("expected: write_all(plain, (const uint8_t *)\"auth\", "
		     "4) == 0");
	TEST("the shipped default reports plaintext on disk");
	if (profile_aik_auth_state(&paths) != PROFILE_AIK_AUTH_PLAINTEXT)
		FAIL("expected: profile_aik_auth_state(&paths) == "
		     "PROFILE_AIK_AUTH_PLAINTEXT");
	TEST("plaintext is readable from a captured disk");
	if (!profile_aik_auth_exposed(PROFILE_AIK_AUTH_PLAINTEXT))
		FAIL("expected: profile_aik_auth_exposed(PROFILE_AIK_AUTH_PLAINTEXT)");

	TEST("sealed written");
	if (write_all(sealed, (const uint8_t *)"blob", 4) != 0)
		FAIL("expected: write_all(sealed, (const uint8_t *)\"blob\", "
		     "4) == 0");
	TEST("adopting sealing without strict reports both copies");
	if (profile_aik_auth_state(&paths) != PROFILE_AIK_AUTH_BOTH)
		FAIL("expected: profile_aik_auth_state(&paths) == "
		     "PROFILE_AIK_AUTH_BOTH");
	TEST("sealing a second copy protects nothing while the first remains");
	if (!profile_aik_auth_exposed(PROFILE_AIK_AUTH_BOTH))
		FAIL("expected: profile_aik_auth_exposed(PROFILE_AIK_AUTH_BOTH)");

	unlink(plain);
	TEST("strict reports sealed with no plaintext copy");
	if (profile_aik_auth_state(&paths) != PROFILE_AIK_AUTH_SEALED)
		FAIL("expected: profile_aik_auth_state(&paths) == "
		     "PROFILE_AIK_AUTH_SEALED");
	TEST("sealed alone is the state that is not exposed");
	if (profile_aik_auth_exposed(PROFILE_AIK_AUTH_SEALED))
		FAIL("expected: !profile_aik_auth_exposed(PROFILE_AIK_AUTH_SEALED)");

	/* empty file is not a copy of anything */
	TEST("empty sidecar");
	if (write_all(plain, (const uint8_t *)"", 0) != 0)
		FAIL("expected: write_all(plain, (const uint8_t *)\"\", 0) == "
		     "0");
	TEST("an interrupted write is not counted as a stored authorization");
	if (profile_aik_auth_state(&paths) != PROFILE_AIK_AUTH_SEALED)
		FAIL("expected: profile_aik_auth_state(&paths) == "
		     "PROFILE_AIK_AUTH_SEALED");

	TEST("no profile reports no authorization");
	if (profile_aik_auth_state(NULL) != PROFILE_AIK_AUTH_NONE)
		FAIL("expected: profile_aik_auth_state(NULL) == "
		     "PROFILE_AIK_AUTH_NONE");
	TEST("every state names itself");
	if (!(profile_aik_auth_state_str(PROFILE_AIK_AUTH_SEALED) != NULL &&
	      profile_aik_auth_state_str(PROFILE_AIK_AUTH_NONE) != NULL))
		FAIL("expected: profile_aik_auth_state_str(PROFILE_AIK_AUTH_SEALED) "
		     "!= NULL && profile_aik_auth_state_str(PROFILE_AIK_AUTH_NONE) "
		     "!= NULL");

	unlink(plain);
	unlink(sealed);
	publishers_forget(&paths);
	rmdir(base);
}

/*
 * profile_consent_record() creates a directory before enrollment and nothing
 * prunes, so a host can hold more profiles than the array a caller sizes.
 * publishers_list() must then return -ENOBUFS and the real count,
 * not a silent readdir-order prefix that may drop the active profile.
 */
static void test_a_listing_that_does_not_fit_is_refused(void)
{
	const size_t bound = LOTA_PROFILE_MAX_AIK_HANDLES;
	const size_t extra = 2;
	struct publisher_entry entries[LOTA_PROFILE_MAX_AIK_HANDLES];
	struct profile_paths paths;
	char base[256];
	char id[LOTA_PROFILE_ID_LEN];
	size_t count = 0;

	snprintf(base, sizeof(base), "/tmp/lota-profile-full.%d", getpid());

	for (size_t i = 0; i < bound + extra; i++) {
		memset(id, (int)('0' + (i % 10)), sizeof(id) - 1);
		id[sizeof(id) - 1] = '\0';
		TEST("a publisher is agreed to");
		if (!(profile_paths_from_id(base, id, &paths) == 0 &&
		      profile_consent_record(&paths, 0) == 0))
			FAIL("expected: profile_paths_from_id(base, id, &paths) == 0 "
			     "&& profile_consent_record(&paths, 0) == 0");
	}

	TEST("a listing that cannot hold every profile is refused, not cut short");
	if (publishers_list(base, entries, bound, &count) != -ENOBUFS)
		FAIL("expected: publishers_list(base, entries, bound, &count) "
		     "== -ENOBUFS");
	TEST("and the refusal says how many profiles there are");
	if (!(count == bound + extra))
		FAIL("expected: count == bound + extra");

	{
		struct publisher_entry *all = NULL;
		size_t seen = 0;

		TEST("the allocating listing holds every profile there is");
		if (!(publishers_list_alloc(base, &all, &seen) == 0 &&
		      seen == bound + extra && all != NULL))
			FAIL("expected: publishers_list_alloc(base, &all, &seen) == 0 "
			     "&& seen == bound + extra && all != NULL");
		free(all);
	}

	{
		struct publisher_entry *none = (void *)-1;
		size_t seen = 1;
		char empty[256];

		snprintf(empty, sizeof(empty), "/tmp/lota-profile-none.%d",
			 getpid());
		TEST("a host that answered to nobody allocates nothing");
		if (!(publishers_list_alloc(empty, &none, &seen) == 0 &&
		      none == NULL && seen == 0))
			FAIL("expected: publishers_list_alloc(empty, &none, &seen) == "
			     "0 && none == NULL && seen == 0");
	}

	for (size_t i = 0; i < bound + extra; i++) {
		memset(id, (int)('0' + (i % 10)), sizeof(id) - 1);
		id[sizeof(id) - 1] = '\0';
		if (profile_paths_from_id(base, id, &paths) == 0)
			publishers_forget(&paths);
	}
	rmdir(base);
}

/*
 * A listener certificate re-issued over a new key is a second profile here
 * while the CA, keyed on the EK, sees one device; both queries must spot it.
 */
static void test_a_rotated_pin_is_visible(void)
{
	EVP_PKEY *gen1 = EVP_RSA_gen(2048);
	EVP_PKEY *gen2 = EVP_RSA_gen(2048);
	X509 *cert1 = NULL, *cert2 = NULL;
	char anchor_path[256];
	char base[256];
	char id1[LOTA_PROFILE_ID_LEN] = { 0 };
	char id2[LOTA_PROFILE_ID_LEN] = { 0 };
	char named[LOTA_PROFILE_ID_LEN] = { 0 };
	struct profile_paths paths;
	struct enroll_state rec;

	snprintf(base, sizeof(base), "/tmp/lota-profile-rot.%d", getpid());
	tmp_path(anchor_path, sizeof(anchor_path), "listener.pem");

	if (!gen1 || !gen2) {
		TEST("two listener keys are generated");
		if (!0)
			FAIL("expected: 0");
		goto out;
	}
	cert1 = mint_cert(gen1, "verifier.example", 41);
	cert2 = mint_cert(gen2, "verifier.example", 42);
	if (!cert1 || !cert2 || write_cert_pem(anchor_path, cert1) != 0) {
		TEST("the first listener certificate is written");
		if (!0)
			FAIL("expected: 0");
		goto out;
	}

	TEST("the first generation names a publisher");
	if (profile_id_from_anchor(anchor_path, id1, sizeof(id1)) != 0)
		FAIL("expected: profile_id_from_anchor(anchor_path, id1, "
		     "sizeof(id1)) == 0");
	TEST("the first generation gets a profile");
	if (!(profile_paths_from_id(base, id1, &paths) == 0 &&
	      profile_dir_ensure(&paths) == 0))
		FAIL("expected: profile_paths_from_id(base, id1, &paths) == 0 "
		     "&& profile_dir_ensure(&paths) == 0");

	memset(&rec, 0, sizeof(rec));
	rec.magic = LOTA_ENROLL_STATE_MAGIC;
	rec.version = LOTA_ENROLL_STATE_VERSION;
	rec.ca_port = 18703;
	snprintf(rec.ca_server, sizeof(rec.ca_server), "%s", "127.0.0.1");
	snprintf(rec.ca_cert, sizeof(rec.ca_cert), "%s", anchor_path);
	TEST("the first generation records where it enrolled");
	if (enroll_state_save_path(paths.enroll_state, &rec) != 0)
		FAIL("expected: enroll_state_save_path(paths.enroll_state, "
		     "&rec) == 0");

	TEST("before the rotation the anchor still names its own profile");
	if (publisher_anchor_names_another(base, id1, named, sizeof(named)) !=
	    0)
		FAIL("expected: publisher_anchor_names_another(base, id1, "
		     "named, sizeof(named)) == 0");

	/* the publisher re-issues the listener certificate over a new key */
	TEST("the listener certificate is re-issued in place");
	if (write_cert_pem(anchor_path, cert2) != 0)
		FAIL("expected: write_cert_pem(anchor_path, cert2) == 0");
	TEST("the re-issued certificate is a different publisher here");
	if (!(profile_id_from_anchor(anchor_path, id2, sizeof(id2)) == 0 &&
	      strcmp(id1, id2) != 0))
		FAIL("expected: profile_id_from_anchor(anchor_path, id2, "
		     "sizeof(id2)) == 0 && strcmp(id1, id2) != 0");

	TEST("the first profile is named as one its own anchor left behind");
	if (!(publisher_anchor_names_another(base, id1, named, sizeof(named)) ==
		      1 &&
	      strcmp(named, id2) == 0))
		FAIL("expected: publisher_anchor_names_another(base, id1, "
		     "named, sizeof(named)) == 1 && strcmp(named, id2) == 0");

	/* the second enrollment, at the same endpoint */
	TEST("the second generation gets a profile of its own");
	if (!(profile_paths_from_id(base, id2, &paths) == 0 &&
	      profile_dir_ensure(&paths) == 0))
		FAIL("expected: profile_paths_from_id(base, id2, &paths) == 0 "
		     "&& profile_dir_ensure(&paths) == 0");
	snprintf(rec.ca_cert, sizeof(rec.ca_cert), "%s", anchor_path);
	TEST("the second generation records the same endpoint");
	if (enroll_state_save_path(paths.enroll_state, &rec) != 0)
		FAIL("expected: enroll_state_save_path(paths.enroll_state, "
		     "&rec) == 0");

	TEST("the second enrollment finds the first at the same endpoint");
	if (!(publishers_endpoint_shared(base, id2, "127.0.0.1", 18703, named,
					 sizeof(named)) == 1 &&
	      strcmp(named, id1) == 0))
		FAIL("expected: publishers_endpoint_shared(base, id2, "
		     "\"127.0.0.1\", 18703, named, sizeof(named)) == 1 && "
		     "strcmp(named, id1) == 0");
	TEST("the profile the anchor names now is not left behind");
	if (publisher_anchor_names_another(base, id2, named, sizeof(named)) !=
	    0)
		FAIL("expected: publisher_anchor_names_another(base, id2, "
		     "named, sizeof(named)) == 0");
	TEST("a different port at the same host is a different endpoint");
	if (publishers_endpoint_shared(base, id2, "127.0.0.1", 18704, named,
				       sizeof(named)) != 0)
		FAIL("expected: publishers_endpoint_shared(base, id2, "
		     "\"127.0.0.1\", 18704, named, sizeof(named)) == 0");

	/* a publisher that never enrolled has no anchor to compare */
	{
		char never[LOTA_PROFILE_ID_LEN];

		memset(never, '7', sizeof(never) - 1);
		never[sizeof(never) - 1] = '\0';
		TEST("a profile with no record is not called left behind");
		if (publisher_anchor_names_another(base, never, named,
						   sizeof(named)) >= 0)
			FAIL("expected: publisher_anchor_names_another(base, never, "
			     "named, sizeof(named)) < 0");
	}

	remove_profile_dir(base, id1);
	remove_profile_dir(base, id2);
	{
		char path[PATH_MAX + 64];

		snprintf(path, sizeof(path), "%s/%s/%s", base, id1,
			 LOTA_PROFILE_ENROLL_STATE_FILE);
		unlink(path);
		snprintf(path, sizeof(path), "%s/%s/%s", base, id2,
			 LOTA_PROFILE_ENROLL_STATE_FILE);
		unlink(path);
		snprintf(path, sizeof(path), "%s/%s", base, id1);
		rmdir(path);
		snprintf(path, sizeof(path), "%s/%s", base, id2);
		rmdir(path);
	}
	rmdir(base);
	unlink(anchor_path);

out:
	X509_free(cert1);
	X509_free(cert2);
	EVP_PKEY_free(gen1);
	EVP_PKEY_free(gen2);
}

int main(void)
{
	test_begin("profile id");

	test_identity_follows_the_key();
	test_unusable_anchor_is_refused();
	test_paths_and_directory();
	test_handle_record_round_trip();
	test_handle_record_first_use();
	test_handle_candidates();
	test_consent_record();
	test_anchor_is_ca();
	test_aik_slot_tally();
	test_publisher_inventory();
	test_host_wide_verbs_count_every_key();
	test_a_listing_that_does_not_fit_is_refused();
	test_aik_auth_at_rest_state();
	test_a_rotated_pin_is_visible();

	return test_end();
}
