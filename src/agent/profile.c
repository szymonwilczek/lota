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

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
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
	if (snprintf(p.aik_meta, sizeof(p.aik_meta), "%s/%s", p.dir,
		     LOTA_PROFILE_AIK_META_FILE) >= (int)sizeof(p.aik_meta))
		return -ENAMETOOLONG;
	if (snprintf(p.aik_handle, sizeof(p.aik_handle), "%s/%s", p.dir,
		     LOTA_PROFILE_AIK_HANDLE_FILE) >= (int)sizeof(p.aik_handle))
		return -ENAMETOOLONG;
	if (snprintf(p.consent, sizeof(p.consent), "%s/%s", p.dir,
		     LOTA_PROFILE_CONSENT_FILE) >= (int)sizeof(p.consent))
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

/* Read recorded handle out of one profile directory's aik_handle file */
static int handle_read(const char *path, uint32_t *out)
{
	char buf[32];
	unsigned long v;
	char *end;
	ssize_t n;
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno; /* -ENOENT: nothing allocated yet */

	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n < 0)
		return -errno;
	buf[n] = '\0';

	errno = 0;
	v = strtoul(buf, &end, 0);
	if (errno != 0 || end == buf || v == 0 || v > UINT32_MAX)
		return -EINVAL;
	/* only whitespace may follow the number */
	for (; *end; end++) {
		if (*end != '\n' && *end != '\r' && *end != ' ' && *end != '\t')
			return -EINVAL;
	}

	*out = (uint32_t)v;
	return 0;
}

int profile_aik_handle_load(const struct profile_paths *paths, uint32_t *out)
{
	if (!paths || !out || paths->aik_handle[0] == '\0')
		return -EINVAL;
	return handle_read(paths->aik_handle, out);
}

int profile_aik_handle_save(const struct profile_paths *paths, uint32_t handle)
{
	char tmp[PATH_MAX];
	char line[32];
	int len, fd, ret;

	if (!paths || paths->aik_handle[0] == '\0' || handle == 0)
		return -EINVAL;

	if (snprintf(tmp, sizeof(tmp), "%s.tmp", paths->aik_handle) >=
	    (int)sizeof(tmp))
		return -ENAMETOOLONG;

	len = snprintf(line, sizeof(line), "0x%08X\n", handle);
	if (len <= 0 || len >= (int)sizeof(line))
		return -EINVAL;

	fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0)
		return -errno;
	if (write(fd, line, (size_t)len) != len) {
		ret = -errno;
		close(fd);
		unlink(tmp);
		return ret;
	}
	if (fsync(fd) < 0) {
		ret = -errno;
		close(fd);
		unlink(tmp);
		return ret;
	}
	if (close(fd) < 0) {
		ret = -errno;
		unlink(tmp);
		return ret;
	}
	if (rename(tmp, paths->aik_handle) < 0) {
		ret = -errno;
		unlink(tmp);
		return ret;
	}
	return 0;
}

int profile_aik_handle_candidates(const char *base_dir, uint32_t base,
				  uint32_t count, uint32_t *out, size_t out_max,
				  size_t *out_count)
{
	uint32_t taken[LOTA_PROFILE_MAX_AIK_HANDLES];
	size_t taken_count = 0;
	struct dirent *ent;
	size_t written = 0;
	DIR *dir;

	if (!base_dir || !out || !out_count || count == 0 ||
	    count > LOTA_PROFILE_MAX_AIK_HANDLES)
		return -EINVAL;

	*out_count = 0;

	dir = opendir(base_dir);
	if (!dir) {
		/* no profile has ever been created, so nothing is taken */
		if (errno == ENOENT)
			goto emit;
		return -errno;
	}

	while ((ent = readdir(dir)) != NULL) {
		char path[PATH_MAX];
		uint32_t handle = 0;

		if (ent->d_name[0] == '.')
			continue;
		if (snprintf(path, sizeof(path), "%s/%s/%s", base_dir,
			     ent->d_name,
			     LOTA_PROFILE_AIK_HANDLE_FILE) >= (int)sizeof(path))
			continue;
		/* profile that has not provisioned records nothing */
		if (handle_read(path, &handle) < 0)
			continue;
		if (taken_count < LOTA_PROFILE_MAX_AIK_HANDLES)
			taken[taken_count++] = handle;
	}
	closedir(dir);

emit:
	for (uint32_t i = 0; i < count && written < out_max; i++) {
		uint32_t handle = base + i;
		bool used = false;

		for (size_t j = 0; j < taken_count; j++) {
			if (taken[j] == handle) {
				used = true;
				break;
			}
		}
		if (!used)
			out[written++] = handle;
	}

	*out_count = written;
	return 0;
}

int profile_consent_record(const struct profile_paths *paths, uid_t by)
{
	char line[160];
	int len, fd, ret;

	if (!paths || paths->consent[0] == '\0')
		return -EINVAL;

	ret = profile_dir_ensure(paths);
	if (ret < 0)
		return ret;

	len = snprintf(line, sizeof(line),
		       "lota-consent 1\nprofile %s\nrecorded %lld\nby-uid %u\n",
		       paths->id, (long long)time(NULL), (unsigned int)by);
	if (len <= 0 || len >= (int)sizeof(line))
		return -EINVAL;

	fd = open(paths->consent, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
		  0600);
	if (fd < 0)
		return -errno;
	if (write(fd, line, (size_t)len) != len) {
		ret = -errno;
		close(fd);
		return ret;
	}
	if (fsync(fd) < 0) {
		ret = -errno;
		close(fd);
		return ret;
	}
	return close(fd) < 0 ? -errno : 0;
}

int profile_consent_time(const struct profile_paths *paths, time_t *out)
{
	char buf[160];
	const char *p;
	ssize_t n;
	int fd;

	if (!paths || !out || paths->consent[0] == '\0')
		return -EINVAL;

	fd = open(paths->consent, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno; /* -ENOENT: nobody agreed to this publisher */

	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n < 0)
		return -errno;
	buf[n] = '\0';

	if (strncmp(buf, "lota-consent 1\n", strlen("lota-consent 1\n")) != 0)
		return -EINVAL;

	p = strstr(buf, "\nrecorded ");
	if (!p)
		return -EINVAL;
	p += strlen("\nrecorded ");

	errno = 0;
	*out = (time_t)strtoll(p, NULL, 10);
	return errno == 0 ? 0 : -EINVAL;
}

int profile_consent_forget(const struct profile_paths *paths)
{
	if (!paths || paths->consent[0] == '\0')
		return -EINVAL;
	if (unlink(paths->consent) != 0 && errno != ENOENT)
		return -errno;
	return 0;
}
