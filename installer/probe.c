/* SPDX-License-Identifier: MIT
 * Copyright (C) 2026 Szymon Wilczek
 *
 * lota-install - system state probes
 */

#include "probe.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <openssl/asn1.h>
#include <openssl/types.h>

#include <linux/fsverity.h>

#include <openssl/evp.h>
#include <openssl/x509.h>

int probe_read_text(const char *path, char *buf, size_t cap)
{
	ssize_t got;
	int fd;

	if (!path || !buf || cap < 2)
		return -EINVAL;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;

	got = read(fd, buf, cap - 1);
	close(fd);
	if (got < 0)
		return -errno;

	buf[got] = '\0';
	if (got > 0 && buf[got - 1] == '\n') {
		buf[--got] = '\0';
	}
	return (int)got;
}

int probe_fsverity_state(const char *path)
{
	struct fsverity_digest *d;
	char dbuf[sizeof(*d) + 64];
	int fd;
	int ret;

	if (!path)
		return -EINVAL;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;

	d = (struct fsverity_digest *)dbuf;
	memset(dbuf, 0, sizeof(dbuf));
	d->digest_size = 64;

	ret = ioctl(fd, FS_IOC_MEASURE_VERITY, d);
	close(fd);
	if (ret == 0)
		return PROBE_VERITY_ENABLED;
	if (errno == ENODATA)
		return PROBE_VERITY_DISABLED;
	if (errno == ENOTTY || errno == EOPNOTSUPP)
		return PROBE_VERITY_UNSUPPORTED;
	return -errno;
}

int probe_fsverity_enable(const char *path)
{
	struct fsverity_enable_arg arg;
	int fd;
	int ret;

	if (!path)
		return -EINVAL;

	/* O_RDONLY: FS_IOC_ENABLE_VERITY rejects writable fds */
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;

	memset(&arg, 0, sizeof(arg));
	arg.version = 1;
	arg.hash_algorithm = FS_VERITY_HASH_ALG_SHA256;
	arg.block_size = 4096;

	ret = ioctl(fd, FS_IOC_ENABLE_VERITY, &arg);
	close(fd);
	if (ret == 0)
		return 0;
	return -errno;
}

/*
 * EFI global variable GUID
 * 4-byte attribute header precedes the payload in efivarfs
 */
#define SECUREBOOT_EFIVAR            \
	"/sys/firmware/efi/efivars/" \
	"SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"

int probe_secureboot(void)
{
	uint8_t raw[5];
	ssize_t got;
	int fd;

	fd = open(SECUREBOOT_EFIVAR, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;

	got = read(fd, raw, sizeof(raw));
	close(fd);
	if (got < 0)
		return -errno;
	if (got != 5)
		return -EBADMSG;
	return raw[4] == 1 ? 1 : 0;
}

int probe_cmdline_ima_ok(const char *cmdline)
{
	char buf[4096];
	char *save = NULL;
	char *tok;
	size_t len;

	if (!cmdline)
		return -EINVAL;
	len = strlen(cmdline);
	if (len >= sizeof(buf))
		return -E2BIG;
	memcpy(buf, cmdline, len + 1);

	for (tok = strtok_r(buf, " \t", &save); tok;
	     tok = strtok_r(NULL, " \t", &save)) {
		const char *val;

		if (strncmp(tok, "ima_appraise=", 13) != 0)
			continue;
		val = tok + 13;
		if (strcmp(val, "enforce") == 0 || strcmp(val, "fix") == 0)
			return 0;
		return -EPERM;
	}
	return -EPERM;
}

int probe_cmdline_has_token(const char *cmdline, const char *token)
{
	char buf[4096];
	char *save = NULL;
	char *tok;
	size_t len;

	if (!cmdline || !token)
		return 0;
	len = strlen(cmdline);
	if (len >= sizeof(buf))
		return 0;
	memcpy(buf, cmdline, len + 1);

	for (tok = strtok_r(buf, " \t", &save); tok;
	     tok = strtok_r(NULL, " \t", &save)) {
		if (strcmp(tok, token) == 0)
			return 1;
	}
	return 0;
}

int probe_booted_ima_ok(void)
{
	char buf[4096];
	int ret = probe_read_text("/proc/cmdline", buf, sizeof(buf));

	if (ret < 0)
		return ret;
	return probe_cmdline_ima_ok(buf);
}

int probe_module_sig_enforced(void)
{
	char buf[16] = { 0 };
	int ret = probe_read_text("/sys/module/module/parameters/sig_enforce",
				  buf, sizeof(buf));

	if (ret < 0)
		return ret;
	if (ret == 0)
		return -EIO;
	if (buf[0] == 'Y' || buf[0] == '1')
		return 0;
	return -EPERM;
}

int probe_lockdown_restrictive(void)
{
	char buf[256];
	char *lb;
	char *rb;
	int ret = probe_read_text("/sys/kernel/security/lockdown", buf,
				  sizeof(buf));

	if (ret < 0)
		return ret;
	if (ret == 0)
		return -EIO;

	lb = strchr(buf, '[');
	rb = lb ? strchr(lb + 1, ']') : NULL;
	if (!lb || !rb || rb <= lb + 1)
		return -EPERM;

	*rb = '\0';
	if (strcmp(lb + 1, "integrity") == 0 ||
	    strcmp(lb + 1, "confidentiality") == 0)
		return 0;
	return -EPERM;
}

/*
 * Must match LOTA-PCR14-INITRAMFS-LOCK-v1 in
 * src/initramfs/lota-pcr14-lock.c and the verifier's
 * DeriveInitramfsLockPCR14 (src/verifier/verify/baseline.go)
 */
#define INITRAMFS_LOCK_TAG "LOTA-PCR14-INITRAMFS-LOCK-v1"

void probe_pcr14_lock_value(uint8_t out[PROBE_HASH_SIZE])
{
	uint8_t commit[PROBE_HASH_SIZE];
	uint8_t zero[PROBE_HASH_SIZE] = { 0 };
	unsigned int len = 0;
	EVP_MD_CTX *md = EVP_MD_CTX_new();

	/* SHA-256 over a static tag cannot fail with a live libcrypto;
	 * NULL ctx would mean allocation failure, where aborting via
	 * the zeroed output (never equal to a real PCR chain) is the
	 * fail-closed choice */
	memset(out, 0, PROBE_HASH_SIZE);
	if (!md)
		return;

	if (EVP_DigestInit_ex(md, EVP_sha256(), NULL) == 1 &&
	    EVP_DigestUpdate(md, INITRAMFS_LOCK_TAG,
			     strlen(INITRAMFS_LOCK_TAG)) == 1 &&
	    EVP_DigestFinal_ex(md, commit, &len) == 1 && len == sizeof(commit))
		if (EVP_DigestInit_ex(md, EVP_sha256(), NULL) == 1 &&
		    EVP_DigestUpdate(md, zero, sizeof(zero)) == 1 &&
		    EVP_DigestUpdate(md, commit, sizeof(commit)) == 1)
			EVP_DigestFinal_ex(md, out, &len);

	EVP_MD_CTX_free(md);
}

static int hex_nibble(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

int probe_hex_to_bytes(const char *hex, uint8_t *out, size_t n)
{
	size_t i;

	if (!hex || !out)
		return -EINVAL;
	if (strlen(hex) != 2 * n)
		return -EINVAL;

	for (i = 0; i < n; i++) {
		int hi = hex_nibble(hex[2 * i]);
		int lo = hex_nibble(hex[2 * i + 1]);

		if (hi < 0 || lo < 0)
			return -EINVAL;
		out[i] = (uint8_t)((hi << 4) | lo);
	}
	return 0;
}

int probe_pcr14_state(void)
{
	uint8_t live[PROBE_HASH_SIZE];
	uint8_t lock[PROBE_HASH_SIZE];
	uint8_t zero[PROBE_HASH_SIZE] = { 0 };
	char buf[2 * PROBE_HASH_SIZE + 8] = { 0 };
	int ret = probe_read_text("/sys/class/tpm/tpm0/pcr-sha256/14", buf,
				  sizeof(buf));

	if (ret < 0)
		return ret;
	if (probe_hex_to_bytes(buf, live, sizeof(live)) < 0)
		return -EBADMSG;

	if (memcmp(live, zero, sizeof(zero)) == 0)
		return PROBE_PCR14_ZERO;

	probe_pcr14_lock_value(lock);
	if (memcmp(live, lock, sizeof(lock)) == 0)
		return PROBE_PCR14_LOCK_ONLY;
	return PROBE_PCR14_OTHER;
}

int probe_selinux_tpm_label(void)
{
	static const char *const tpm_paths[] = { "/dev/tpmrm0", "/dev/tpm0" };
	const char *expected = "lota_tpm_device_t";
	int any_present = 0;
	size_t i;

	for (i = 0; i < sizeof(tpm_paths) / sizeof(tpm_paths[0]); i++) {
		char ctx[256];
		ssize_t got = getxattr(tpm_paths[i], "security.selinux", ctx,
				       sizeof(ctx) - 1);

		if (got < 0) {
			if (errno == ENOENT)
				continue;
			/* No SELinux xattr support:
			 * udev fence is not the active defence on this host,
			 * same call the agent's gate makes */
			if (errno == ENOTSUP)
				return 0;
			return -errno;
		}
		any_present = 1;
		ctx[got] = '\0';
		if (!strstr(ctx, expected))
			return -EPERM;
	}

	if (!any_present)
		return -ENOENT;
	return 0;
}

int probe_cert_days_left(const char *der_path, int *days_left)
{
	uint8_t der[8192];
	const unsigned char *p = der;
	X509 *cert;
	int sec_diff = 0;
	int day_diff = 0;
	ssize_t got;
	int fd;

	if (!der_path || !days_left)
		return -EINVAL;

	fd = open(der_path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	got = read(fd, der, sizeof(der));
	close(fd);
	if (got <= 0)
		return got == 0 ? -EBADMSG : -errno;

	cert = d2i_X509(NULL, &p, got);
	if (!cert)
		return -EBADMSG;

	/*
	 * days/seconds from now until notAfter
	 * negative = expired
	 */
	if (ASN1_TIME_diff(&day_diff, &sec_diff, NULL,
			   X509_get0_notAfter(cert)) != 1) {
		X509_free(cert);
		return -EBADMSG;
	}
	X509_free(cert);

	if (day_diff == 0 && sec_diff < 0)
		day_diff = -1;
	*days_left = day_diff;
	return 0;
}

int probe_conf_buf_has_key(const char *buf, const char *key)
{
	size_t klen;
	const char *line;

	if (!buf || !key)
		return 0;
	klen = strlen(key);

	for (line = buf; line && *line;) {
		const char *p = line;
		const char *eol = strchr(line, '\n');

		while (*p == ' ' || *p == '\t')
			p++;
		if (*p != '#' && strncmp(p, key, klen) == 0) {
			p += klen;
			while (*p == ' ' || *p == '\t')
				p++;
			if (*p == '=')
				return 1;
		}
		line = eol ? eol + 1 : NULL;
	}
	return 0;
}

int probe_conf_has_key(const char *conf_path, const char *key)
{
	char buf[16384] = { 0 };
	int ret = probe_read_text(conf_path, buf, sizeof(buf));

	if (ret < 0)
		return ret;
	return probe_conf_buf_has_key(buf, key);
}

/* 1 when an ESRT System Firmware entry (fw_type == 1) exists, else 0. */
int probe_esrt_system_firmware_present_at(const char *base)
{
	DIR *d;
	struct dirent *de;
	int present = 0;

	if (!base)
		return 0;
	d = opendir(base);
	if (!d)
		return 0;

	while (!present && (de = readdir(d)) != NULL) {
		char path[512];
		char buf[32];

		if (de->d_name[0] == '.')
			continue;
		if (snprintf(path, sizeof(path), "%s/%s/fw_type", base,
			     de->d_name) >= (int)sizeof(path))
			continue;
		/* probe_read_text returns the byte count read (>= 0) or a
		 * negative errno; only a negative value is a failure */
		if (probe_read_text(path, buf, sizeof(buf)) < 0)
			continue;
		if (atoi(buf) == 1) /* ESRT_FW_TYPE_SYSTEM */
			present = 1;
	}

	closedir(d);
	return present;
}

int probe_esrt_system_firmware_present(void)
{
	return probe_esrt_system_firmware_present_at(
		"/sys/firmware/efi/esrt/entries");
}
