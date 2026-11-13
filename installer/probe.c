/* SPDX-License-Identifier: MIT
 * Copyright (C) 2026 Szymon Wilczek
 *
 * lota-install - system state probes
 */

#include "probe.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <openssl/asn1.h>
#include <openssl/types.h>

#include <linux/fsverity.h>

#include "../include/lota_ima_appraise.h"
#include "../include/lota_ima_policy_scope.h"
#include "../include/lota_ima_xattr.h"
#include "../include/lota_secure_boot.h"

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

#define PROBE_MAGIC_EXT 0xEF53L
#define PROBE_MAGIC_XFS 0x58465342L
#define PROBE_MAGIC_BTRFS 0x9123683EL
#define PROBE_MAGIC_F2FS 0xF2F52010L
#define PROBE_MAGIC_ZFS 0x2FC12FC1L

int probe_manifest_line(const char *line, char *out, size_t cap)
{
	const char *start;
	const char *comp;
	size_t len;

	if (!line || !out || cap == 0)
		return -EINVAL;

	out[0] = '\0';

	start = line;
	while (*start == ' ' || *start == '\t')
		start++;

	len = strcspn(start, "\r\n");
	while (len > 0 && (start[len - 1] == ' ' || start[len - 1] == '\t'))
		len--;

	if (len == 0 || start[0] == '#')
		return 0;

	if (start[0] != '/')
		return -EINVAL;
	if (len >= cap)
		return -EINVAL;

	for (comp = start; comp < start + len; comp++) {
		if (comp != start && comp[-1] != '/')
			continue;
		if (comp[0] != '.' || comp[1] != '.')
			continue;
		if (comp + 2 == start + len || comp[2] == '/')
			return -EINVAL;
	}

	memcpy(out, start, len);
	out[len] = '\0';
	return 1;
}

int probe_file_ima_signed(const char *path)
{
	uint8_t xattr[4096];
	ssize_t n;

	if (!path)
		return -EINVAL;
	n = getxattr(path, "security.ima", xattr, sizeof(xattr));
	if (n < 0)
		return errno == ENODATA ? 0 : -errno;
	return lota_ima_xattr_is_signature(xattr, (size_t)n) ? 1 : 0;
}

#define EFI_GLOBAL_GUID "8be4df61-93ca-11d2-aa0d-00e098032b8c"
#define EFI_FIRMWARE_DIR "/sys/firmware/efi"
#define EFIVARS_DIR "/sys/firmware/efi/efivars/"
#define SETUPMODE_EFIVAR EFIVARS_DIR "SetupMode-" EFI_GLOBAL_GUID
#define OSINDICATIONS_SUPPORTED_EFIVAR \
	EFIVARS_DIR "OsIndicationsSupported-" EFI_GLOBAL_GUID

#define EFIVAR_ATTR_LEN 4

/* never returns 0, which a caller would read as a clear flag */
static int read_efivar_payload(const char *path, uint8_t *out, size_t cap)
{
	uint8_t raw[EFIVAR_ATTR_LEN + 8];
	ssize_t got;
	int err;
	int fd;

	if (!path || !out || cap == 0 || cap > sizeof(raw) - EFIVAR_ATTR_LEN)
		return -EINVAL;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		err = errno;
		return err > 0 ? -err : -EIO;
	}

	got = read(fd, raw, EFIVAR_ATTR_LEN + cap);
	err = got < 0 ? errno : 0;
	close(fd);
	if (got < 0)
		return err > 0 ? -err : -EIO;
	if (got <= EFIVAR_ATTR_LEN)
		return -EBADMSG;

	got -= EFIVAR_ATTR_LEN;
	memcpy(out, raw + EFIVAR_ATTR_LEN, (size_t)got);
	return (int)got;
}

int probe_efivar_flag_at(const char *path)
{
	uint8_t val;
	int ret = read_efivar_payload(path, &val, sizeof(val));

	if (ret < 0)
		return ret;
	return val == 1 ? 1 : 0;
}

/* little-endian: bit 0 is in the first payload byte */
int probe_efivar_bit0_at(const char *path)
{
	uint8_t val;
	int ret = read_efivar_payload(path, &val, sizeof(val));

	if (ret < 0)
		return ret;
	return val & 1U ? 1 : 0;
}

int probe_firmware_is_uefi_at(const char *dir)
{
	struct stat st;

	if (!dir)
		return 0;

	return stat(dir, &st) == 0 && S_ISDIR(st.st_mode) ? 1 : 0;
}

int probe_firmware_is_uefi(void)
{
	return probe_firmware_is_uefi_at(EFI_FIRMWARE_DIR);
}

int probe_secureboot(void)
{
	return lota_secure_boot_read(LOTA_EFIVARS_DIR);
}

int probe_secureboot_setup_mode(void)
{
	return probe_efivar_flag_at(SETUPMODE_EFIVAR);
}

int probe_firmware_setup_supported(void)
{
	return probe_efivar_bit0_at(OSINDICATIONS_SUPPORTED_EFIVAR);
}

static int str_starts_with_ci(const char *s, const char *prefix)
{
	size_t i;

	if (!s || !prefix)
		return 0;
	for (i = 0; prefix[i]; i++) {
		if (tolower((unsigned char)s[i]) !=
		    tolower((unsigned char)prefix[i]))
			return 0;
	}
	return 1;
}

#define DMI_ID_DIR "/sys/class/dmi/id"

static void read_dmi_field(const char *dmi_dir, const char *field, char *out,
			   size_t cap)
{
	char path[512];

	out[0] = '\0';
	if (!dmi_dir)
		return;
	snprintf(path, sizeof(path), "%s/%s", dmi_dir, field);
	if (probe_read_text(path, out, cap) < 0)
		out[0] = '\0';
}

static int dmi_is_placeholder(const char *s)
{
	static const char *const junk[] = {
		"To Be Filled",
		"System Product Name",
		"System manufacturer",
		"Default string",
		"Not Applicable",
		"Not Specified",
		"INVALID",
		"None",
		"OEM",
		"Unknown",
	};
	size_t i;

	if (!s || !*s)
		return 1;
	for (i = 0; i < sizeof(junk) / sizeof(junk[0]); i++) {
		if (str_starts_with_ci(s, junk[i]))
			return 1;
	}
	return 0;
}

void probe_machine_description_at(const char *dmi_dir, char *out, size_t cap)
{
	char vendor[128];
	char product[128];
	int have_vendor;
	int have_product;

	if (!out || cap == 0)
		return;
	out[0] = '\0';

	read_dmi_field(dmi_dir, "sys_vendor", vendor, sizeof(vendor));
	read_dmi_field(dmi_dir, "product_name", product, sizeof(product));
	have_vendor = !dmi_is_placeholder(vendor);
	have_product = !dmi_is_placeholder(product);

	if (have_vendor && have_product)
		snprintf(out, cap, "%s %s", vendor, product);
	else if (have_vendor)
		snprintf(out, cap, "%s", vendor);
	else if (have_product)
		snprintf(out, cap, "%s", product);
}

void probe_machine_description(char *out, size_t cap)
{
	probe_machine_description_at(DMI_ID_DIR, out, cap);
}

void probe_secureboot_remediation(const char *machine, int is_virtual,
				  int setup_mode, int firmware_setup_supported,
				  char *out, size_t cap)
{
	size_t used;

	if (!out || cap == 0)
		return;

	used = (size_t)snprintf(
		out, cap,
		"Secure Boot is off. It is a firmware setting, so LOTA cannot "
		"turn it on for you -- and it cannot be worked around either: "
		"Secure Boot is the machine-independent anchor a verifier uses "
		"to conclude the kernel it is talking to is the one the "
		"distribution signed. ");
	if (used >= cap)
		return;

	if (is_virtual == 1) {
		snprintf(out + used, cap - used,
			 "This is a virtual machine: give it an OVMF/EDK II "
			 "image with Secure Boot enabled (libvirt: a q35 "
			 "machine with SMM and <loader secure='yes'>), boot "
			 "it once, then re-run lota-install.");
		return;
	}

	if (machine && *machine) {
		used += (size_t)snprintf(out + used, cap - used,
					 "The firmware to change is the one on "
					 "this %s. ",
					 machine);
		if (used >= cap)
			return;
	}

	if (firmware_setup_supported == 1) {
		used += (size_t)snprintf(
			out + used, cap - used,
			"Run 'systemctl reboot --firmware-setup' to reboot "
			"straight into firmware setup; this firmware accepts "
			"that request. If it is refused ('Cannot allocate "
			"memory' means the EFI variable store is full), reboot "
			"and enter setup with the key the startup screen "
			"names (commonly Del, F2, F10 or Esc, held while the "
			"vendor logo is up). ");
	} else {
		used += (size_t)snprintf(
			out + used, cap - used,
			"This firmware does not take a reboot-into-setup "
			"request, so enter setup the way its startup screen "
			"says (commonly Del, F2, F10 or Esc, held while the "
			"vendor logo is up). ");
	}
	if (used >= cap)
		return;

	used += (size_t)snprintf(
		out + used, cap - used,
		"The setting is called Secure Boot and usually sits under a "
		"Security or Boot heading; set it to Enabled, save, and re-run "
		"lota-install. ");
	if (used >= cap)
		return;

	if (setup_mode == 1) {
		used += (size_t)snprintf(
			out + used, cap - used,
			"This firmware currently holds no platform keys (setup "
			"mode), so restore the default or factory keys in the "
			"same menu first -- the switch does nothing without "
			"them. ");
		if (used >= cap)
			return;
	}

	snprintf(out + used, cap - used,
		 "Turning it on keeps distribution kernels bootable; only "
		 "modules built locally (DKMS, akmods) need their key enrolled "
		 "once with 'mokutil --import'.");
}

void probe_secureboot_guidance(int is_virtual, char *out, size_t cap)
{
	char machine[192];

	probe_machine_description(machine, sizeof(machine));
	probe_secureboot_remediation(machine, is_virtual,
				     probe_secureboot_setup_mode(),
				     probe_firmware_setup_supported(), out,
				     cap);
}

int probe_cmdline_ima_ok(const char *cmdline)
{
	if (!cmdline)
		return -EINVAL;
	return lota_ima_cmdline_enforce(cmdline) ? 0 : -EPERM;
}

static int rule_demands_signed_policy(const char *rule)
{
	char buf[LOTA_IMA_POLICY_RULE_MAX];
	char *save = NULL;
	char *tok;
	int policy_check = 0;
	int imasig = 0;
	size_t len;

	if (!rule)
		return 0;
	len = strlen(rule);
	if (len >= sizeof(buf))
		return 0;
	memcpy(buf, rule, len + 1);

	tok = strtok_r(buf, " \t\n", &save);
	if (!tok || strcmp(tok, "appraise") != 0)
		return 0;

	while ((tok = strtok_r(NULL, " \t\n", &save))) {
		if (strcmp(tok, "func=POLICY_CHECK") == 0)
			policy_check = 1;
		else if (strcmp(tok, "appraise_type=imasig") == 0)
			imasig = 1;
	}
	return policy_check && imasig;
}

int probe_ima_policy_scope(const char *policy_path, int *policy_signed)
{
	char line[LOTA_IMA_POLICY_RULE_MAX];
	FILE *fp;
	int found = 0;

	if (policy_signed)
		*policy_signed = 0;
	if (!policy_path)
		return -EINVAL;

	fp = fopen(policy_path, "re");
	if (!fp)
		return -errno;

	while (fgets(line, sizeof(line), fp)) {
		if (lota_ima_policy_rule_appraises_exec(line))
			found = 1;
		if (policy_signed && rule_demands_signed_policy(line))
			*policy_signed = 1;
	}

	fclose(fp);
	return found ? PROBE_IMA_SCOPE_EXEC : PROBE_IMA_SCOPE_NONE;
}

int probe_ima_policy_appraises(const char *policy_path)
{
	char line[LOTA_IMA_POLICY_RULE_MAX];
	FILE *fp;
	int found = 0;

	if (!policy_path)
		return -EINVAL;
	fp = fopen(policy_path, "re");
	if (!fp)
		return -errno;
	while (!found && fgets(line, sizeof(line), fp))
		found = strncmp(line, "appraise", 8) == 0 &&
			(line[8] == ' ' || line[8] == '\t' || line[8] == '\n');
	fclose(fp);
	return found;
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

int probe_ima_appraise_built(void)
{
	return lota_ima_appraise_built(LOTA_VMLINUX_BTF_PATH);
}

int probe_ima_mode_blocking(int secureboot, const char *cmdline)
{
	if (secureboot)
		return 1;
	return probe_cmdline_ima_ok(cmdline) == 0;
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

/* must match lota-pcr14-lock.c and DeriveInitramfsLockPCR14 */
#define INITRAMFS_LOCK_TAG "LOTA-PCR14-INITRAMFS-LOCK-v1"

/* must match BASELINE_PATH in src/initramfs/lota-pcr14-lock.c */
#define PCR14_BASELINE_PATH "/run/lota/pcr14_baseline"

static void read_pcr14_baseline_at(const char *path,
				   uint8_t out[PROBE_HASH_SIZE])
{
	uint8_t buf[PROBE_HASH_SIZE + 1];
	int fd;

	memset(out, 0, PROBE_HASH_SIZE);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return;
	if (read(fd, buf, sizeof(buf)) == PROBE_HASH_SIZE)
		memcpy(out, buf, PROBE_HASH_SIZE);
	close(fd);
}

void probe_pcr14_lock_value_at(const char *baseline_path,
			       uint8_t out[PROBE_HASH_SIZE])
{
	uint8_t baseline[PROBE_HASH_SIZE];
	uint8_t commit[PROBE_HASH_SIZE];
	unsigned int len = 0;
	EVP_MD_CTX *md = EVP_MD_CTX_new();

	read_pcr14_baseline_at(baseline_path, baseline);

	/* left zeroed on failure */
	memset(out, 0, PROBE_HASH_SIZE);
	if (!md)
		return;

	if (EVP_DigestInit_ex(md, EVP_sha256(), NULL) == 1 &&
	    EVP_DigestUpdate(md, INITRAMFS_LOCK_TAG,
			     strlen(INITRAMFS_LOCK_TAG)) == 1 &&
	    EVP_DigestFinal_ex(md, commit, &len) == 1 && len == sizeof(commit))
		if (EVP_DigestInit_ex(md, EVP_sha256(), NULL) == 1 &&
		    EVP_DigestUpdate(md, baseline, sizeof(baseline)) == 1 &&
		    EVP_DigestUpdate(md, commit, sizeof(commit)) == 1)
			EVP_DigestFinal_ex(md, out, &len);

	EVP_MD_CTX_free(md);
}

const char *probe_pcr14_baseline_path(void)
{
	return PCR14_BASELINE_PATH;
}

void probe_pcr14_lock_value(uint8_t out[PROBE_HASH_SIZE])
{
	probe_pcr14_lock_value_at(probe_pcr14_baseline_path(), out);
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

static int read_live_pcr14(uint8_t live[PROBE_HASH_SIZE])
{
	char buf[2 * PROBE_HASH_SIZE + 8] = { 0 };
	int ret = probe_read_text("/sys/class/tpm/tpm0/pcr-sha256/14", buf,
				  sizeof(buf));

	if (ret < 0)
		return ret;
	if (probe_hex_to_bytes(buf, live, PROBE_HASH_SIZE) < 0)
		return -EBADMSG;
	return 0;
}

int probe_pcr14_state(void)
{
	uint8_t live[PROBE_HASH_SIZE];
	uint8_t lock[PROBE_HASH_SIZE];
	uint8_t zero[PROBE_HASH_SIZE] = { 0 };
	int ret = read_live_pcr14(live);

	if (ret < 0)
		return ret;

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

int probe_auto_bringup_at(const char *path)
{
	const char *env = getenv("LOTA_AUTO_BRINGUP");

	if (env && env[0] == '1' && env[1] == '\0')
		return 1;
	if (!path)
		return 0;
	return access(path, F_OK) == 0;
}

int probe_conf_buf_value(const char *buf, const char *key, char *out,
			 size_t cap)
{
	size_t klen;
	const char *line;

	if (!out || cap == 0)
		return 0;
	out[0] = '\0';
	if (!buf || !key)
		return 0;
	klen = strlen(key);

	for (line = buf; line && *line;) {
		const char *p = line;
		const char *eol = strchr(line, '\n');

		while (*p == ' ' || *p == '\t')
			p++;
		if (*p != '#' && strncmp(p, key, klen) == 0) {
			const char *end;
			size_t len;

			p += klen;
			while (*p == ' ' || *p == '\t')
				p++;
			if (*p != '=')
				goto next;
			p++;
			while (*p == ' ' || *p == '\t')
				p++;
			end = eol ? eol : p + strlen(p);
			while (end > p && (end[-1] == ' ' || end[-1] == '\t' ||
					   end[-1] == '\r'))
				end--;
			len = (size_t)(end - p);
			if (len == 0 || len >= cap)
				return 0;
			memcpy(out, p, len);
			out[len] = '\0';
			return 1;
		}
next:
		line = eol ? eol + 1 : NULL;
	}
	return 0;
}

int probe_conf_value(const char *conf_path, const char *key, char *out,
		     size_t cap)
{
	char buf[16384] = { 0 };

	if (out && cap)
		out[0] = '\0';
	if (probe_read_text(conf_path, buf, sizeof(buf)) < 0)
		return 0;
	return probe_conf_buf_value(buf, key, out, cap);
}

int probe_conf_has_key(const char *conf_path, const char *key)
{
	char buf[16384] = { 0 };
	int ret = probe_read_text(conf_path, buf, sizeof(buf));

	if (ret < 0)
		return ret;
	return probe_conf_buf_has_key(buf, key);
}

int probe_conf_buf_profile_count(const char *buf)
{
	const char *line;
	int count = 0;

	if (!buf)
		return 0;

	for (line = buf; line && *line;) {
		const char *p = line;
		const char *eol = strchr(line, '\n');

		while (*p == ' ' || *p == '\t')
			p++;
		if (*p != '#' && strncmp(p, "[profile", 8) == 0) {
			p += 8;
			while (*p == ' ' || *p == '\t')
				p++;
			if (*p == '"')
				count++;
		}
		line = eol ? eol + 1 : NULL;
	}
	return count;
}

int probe_conf_profile_count(const char *conf_path)
{
	char buf[16384] = { 0 };
	int ret = probe_read_text(conf_path, buf, sizeof(buf));

	if (ret < 0)
		return ret;
	return probe_conf_buf_profile_count(buf);
}

/* 1 and the value in @out when @line sets @key; '-' reads as '_' */
static int conf_line_value(const char *line, const char *eol, const char *key,
			   char *out, size_t cap)
{
	const char *p = line;
	const char *end;
	size_t len;

	while (*p == ' ' || *p == '\t')
		p++;
	for (; *key; key++, p++) {
		char c = *p == '-' ? '_' : *p;

		if (p >= eol || c != *key)
			return 0;
	}
	while (*p == ' ' || *p == '\t')
		p++;
	if (*p != '=')
		return 0;
	p++;
	while (*p == ' ' || *p == '\t')
		p++;
	end = eol;
	while (end > p &&
	       (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r'))
		end--;
	len = (size_t)(end - p);
	if (len == 0 || len >= cap)
		return 0;
	memcpy(out, p, len);
	out[len] = '\0';
	return 1;
}

static bool conf_line_opens_profile(const char *line)
{
	const char *p = line;

	while (*p == ' ' || *p == '\t')
		p++;
	if (strncmp(p, "[profile", 8) != 0)
		return false;
	p += 8;
	while (*p == ' ' || *p == '\t')
		p++;
	return *p == '"';
}

/* @fn sees only lines under a [profile] header, sections from 0 */
typedef void (*conf_profile_line_fn)(int section, const char *line,
				     const char *eol, void *arg);

static int conf_walk_profiles(const char *buf, conf_profile_line_fn fn,
			      void *arg)
{
	const char *line;
	int section = -1;

	for (line = buf; line && *line;) {
		const char *nl = strchr(line, '\n');
		const char *eol = nl ? nl : line + strlen(line);

		if (conf_line_opens_profile(line))
			section++;
		else if (section >= 0)
			fn(section, line, eol, arg);
		line = nl ? nl + 1 : NULL;
	}
	return section + 1;
}

struct anchor_lookup {
	int index;
	char *out;
	size_t cap;
	int found;
};

static void anchor_line(int section, const char *line, const char *eol,
			void *arg)
{
	struct anchor_lookup *l = arg;

	if (section == l->index && !l->found)
		l->found =
			conf_line_value(line, eol, "ca_cert", l->out, l->cap);
}

int probe_conf_buf_profile_anchor(const char *buf, int index, char *out,
				  size_t cap)
{
	struct anchor_lookup l = { index, out, cap, 0 };

	if (!out || cap == 0)
		return 0;
	out[0] = '\0';
	if (!buf || index < 0)
		return 0;
	conf_walk_profiles(buf, anchor_line, &l);
	return l.found;
}

#define CONF_MAX_PROFILES 64

struct continuous_scan {
	bool continuous[CONF_MAX_PROFILES];
	bool reports[CONF_MAX_PROFILES];
};

static void continuous_line(int section, const char *line, const char *eol,
			    void *arg)
{
	struct continuous_scan *c = arg;
	char v[256];

	if (section >= CONF_MAX_PROFILES)
		return;
	if (conf_line_value(line, eol, "reporting", v, sizeof(v)))
		c->continuous[section] = strcmp(v, "continuous") == 0;
	else if (conf_line_value(line, eol, "verifier", v, sizeof(v)))
		c->reports[section] = strcmp(v, "none") != 0;
}

int probe_conf_buf_continuous_count(const char *buf)
{
	struct continuous_scan c;
	int sections;
	int count = 0;

	if (!buf)
		return 0;
	memset(&c, 0, sizeof(c));
	sections = conf_walk_profiles(buf, continuous_line, &c);
	if (sections > CONF_MAX_PROFILES)
		sections = CONF_MAX_PROFILES;
	for (int i = 0; i < sections; i++)
		count += c.continuous[i] && c.reports[i];
	return count;
}

int probe_attest_status_covers(const char *status, const char *before,
			       int expected)
{
	static const char prefix[] = "Attested (";
	char *end;
	long n;

	if (!status || strncmp(status, prefix, sizeof(prefix) - 1) != 0)
		return 0;
	if (before && before[0] && strcmp(status, before) == 0)
		return 0;
	status += sizeof(prefix) - 1;
	if (*status < '0' || *status > '9')
		return 0;
	n = strtol(status, &end, 10);
	if (strncmp(end, " publisher", 10) != 0)
		return 0;
	return n >= expected;
}

enum probe_selfcheck_plan probe_selfcheck_plan(const char *verifier,
					       int profile_count,
					       bool fleet_profile)
{
	if (fleet_profile && verifier && verifier[0])
		return SELFCHECK_LOOP_REPORTS;
	if (profile_count > 0)
		return SELFCHECK_PUBLISHERS_REPORT;
	if (!verifier || !verifier[0])
		return SELFCHECK_SKIP_NO_VERIFIER;
	return SELFCHECK_ONE_ROUND;
}

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

enum stage_state probe_agent_service_stage(const struct probe_service_state *s,
					   char *note, size_t cap)
{
	if (!s) {
		snprintf(note, cap,
			 "The agent's unit state could not be read.");
		return STAGE_ERROR;
	}

	if (!s->agent_active) {
		snprintf(note, cap, "lota-agent.service is NOT RUNNING.");
		return STAGE_PENDING;
	}

	if (!s->agent_enabled || !s->socket_enabled || !s->attest_enabled) {
		char units[160];
		size_t used = 0;

		units[0] = '\0';
		if (!s->agent_enabled)
			used += (size_t)snprintf(units + used,
						 sizeof(units) - used,
						 "lota-agent.service");
		if (!s->socket_enabled)
			used += (size_t)snprintf(units + used,
						 sizeof(units) - used,
						 "%slota-agent.socket",
						 used ? ", " : "");
		if (!s->attest_enabled)
			snprintf(units + used, sizeof(units) - used,
				 "%slota-attest.service", used ? ", " : "");

		snprintf(note, cap,
			 "lota-agent.service is running, but these units are "
			 "not enabled and will not start after a reboot: %s.",
			 units);
		return STAGE_PENDING;
	}

	snprintf(note, cap, "lota-agent.service is ACTIVE and enabled.");
	return STAGE_DONE;
}

enum stage_state probe_cmdline_next_boot_stage(const struct probe_floor *st,
					       const char *args, char *note,
					       size_t cap)
{
	if (!st || !note)
		return STAGE_ERROR;
	if (args) {
		int ima_cfg = !st->ima_built || probe_cmdline_ima_ok(args) == 0;
		int sig_cfg =
			st->sig_ok ||
			probe_cmdline_has_token(args, "module.sig_enforce=1");
		int lock_cfg =
			st->lockdown_ok ||
			probe_cmdline_has_token(args, "lockdown=integrity");

		if (ima_cfg && !st->ima_ok && st->appraises) {
			snprintf(
				note, cap,
				"The default kernel cmdline puts IMA appraisal "
				"in enforce, and the loaded IMA policy has "
				"appraise rules, or cannot be read: the next "
				"boot would refuse each file they reach "
				"without a valid signature or hash. Keep the "
				"booted ima_appraise= mode on it until they "
				"carry one.%s%s%s%s",
				sig_cfg && lock_cfg ?
					"" :
					" Once it is kept, rerunning the "
					"installer adds:",
				sig_cfg ? "" : " module.sig_enforce=1",
				lock_cfg ? "" : " lockdown=integrity",
				sig_cfg && lock_cfg ? "" : ".");
			return STAGE_BLOCKED;
		}
		if (ima_cfg && sig_cfg && lock_cfg) {
			snprintf(note, cap,
				 "kernel cmdline is configured. "
				 "The floor takes effect on the "
				 "next boot");
			return STAGE_REBOOT;
		}
	}

	if (!st->ima_ok && st->appraises && st->sig_ok && st->lockdown_ok) {
		snprintf(note, cap,
			 "The loaded IMA policy has appraise rules, or cannot "
			 "be read, and the booted mode refuses nothing they "
			 "reach. ima_appraise=enforce would refuse, from the "
			 "next boot, each of those files without a valid "
			 "signature or hash, so it is not added. Add it once "
			 "they carry one.");
		return STAGE_BLOCKED;
	}

	snprintf(note, cap, "Booted kernel lacks:%s%s%s%s",
		 st->ima_ok ? "" : " ima_appraise",
		 st->sig_ok ? "" : " module.sig_enforce",
		 st->lockdown_ok ? "" : " lockdown",
		 !st->ima_ok && st->appraises ?
			 " (ima_appraise=enforce is not added: the loaded "
			 "IMA policy has appraise rules, or cannot be read)" :
			 "");
	return STAGE_PENDING;
}

enum stage_state probe_ima_scope_stage(const struct probe_ima_scope *s,
				       char *note, size_t cap)
{
	if (!s) {
		snprintf(note, cap, "The loaded IMA policy could not be read.");
		return STAGE_ERROR;
	}

	if (s->no_appraisal) {
		snprintf(note, cap,
			 "The booted kernel has no IMA appraisal (its BTF has "
			 "no ima_appraise_measurement()), so every token says "
			 "KERNEL_APPRAISAL is clear.");
		return STAGE_DONE;
	}

	if (s->scope == PROBE_IMA_SCOPE_EXEC) {
		snprintf(note, cap,
			 "The loaded IMA policy appraises executables, so "
			 "tokens can say KERNEL_APPRAISAL.");
		return STAGE_DONE;
	}

	if (s->scope != PROBE_IMA_SCOPE_NONE) {
		if (!s->is_root && s->scope == -EACCES) {
			snprintf(note, cap,
				 "Cannot read %s (%s). Run as root to check "
				 "the appraisal scope.",
				 PROBE_IMA_POLICY_PATH, strerror(-s->scope));
			return STAGE_ERROR;
		}
		snprintf(note, cap,
			 "This kernel does not publish its loaded IMA policy "
			 "(%s: %s), so the scope cannot be checked and every "
			 "token says KERNEL_APPRAISAL is clear.",
			 PROBE_IMA_POLICY_PATH, strerror(-s->scope));
		return STAGE_DONE;
	}

	snprintf(note, cap,
		 "The loaded IMA policy has no appraise rule on BPRM_CHECK or "
		 "without func=, so every token says KERNEL_APPRAISAL is "
		 "clear. The installer does not widen the scope: an IMA rule "
		 "cannot name a path, so a rule reaching the agent reaches "
		 "every executable it matches%s, and this host's %s The "
		 "scope arrives with the signatures -- IMA-signed "
		 "distribution packages, or an image pipeline that signs "
		 "executables and enrols its certificate (production "
		 "bring-up guide, \"IMA appraisal policy\").%s",
		 s->secureboot ? ", in enforce, since Secure Boot makes the "
				 "kernel discard ima_appraise=" :
				 "",
		 s->agent_signed ?
			 "executables are signed, so a rule set covering them "
			 "is the remaining step." :
			 "executables carry no signature (its agent binary "
			 "carries none), so the next boot would refuse them.",
		 s->policy_signed ?
			 " Policy writes are appraised here (appraise "
			 "func=POLICY_CHECK appraise_type=imasig), so any rule "
			 "set has to be signed by a key on the .ima keyring." :
			 "");
	return STAGE_DONE;
}

int probe_installed_kernels_at(const char *modules_dir, const char *boot_dir,
			       struct probe_kernel_image *out, size_t max,
			       size_t *count)
{
	DIR *d;
	struct dirent *de;
	size_t n = 0;

	if (!modules_dir || !boot_dir || !out || !count)
		return -EINVAL;

	*count = 0;

	d = opendir(modules_dir);
	if (!d)
		return 0;

	while (n < max && (de = readdir(d)) != NULL) {
		char image[PROBE_KERNEL_IMAGE_MAX];

		if (de->d_name[0] == '.')
			continue;
		if (strlen(de->d_name) >= PROBE_KERNEL_RELEASE_MAX)
			continue;

		if (snprintf(image, sizeof(image), "%s/initramfs-%s.img",
			     boot_dir, de->d_name) >= (int)sizeof(image))
			continue;
		if (access(image, F_OK) != 0)
			continue;

		snprintf(out[n].release, sizeof(out[n].release), "%s",
			 de->d_name);
		snprintf(out[n].image, sizeof(out[n].image), "%s", image);
		n++;
	}

	closedir(d);
	*count = n;
	return 0;
}

int probe_installed_kernels(struct probe_kernel_image *out, size_t max,
			    size_t *count)
{
	return probe_installed_kernels_at("/lib/modules", "/boot", out, max,
					  count);
}

int probe_pcr14_lock_ran_at(const char *baseline_path)
{
	if (!baseline_path)
		return 0;
	return access(baseline_path, F_OK) == 0;
}

int probe_pcr14_lock_ran(void)
{
	return probe_pcr14_lock_ran_at(probe_pcr14_baseline_path());
}

/* struct lota_clock_state (src/agent/tpm.h) */
#define CLOCK_STATE_PATH "/var/lib/lota/clock_state.dat"
#define CLOCK_STATE_MAGIC 0x4C434C4BU /* "LCLK" */
#define CLOCK_STATE_VERSION 1U
#define CLOCK_STATE_SIZE 120
#define CLOCK_STATE_PCR14_OFF 16
#define CLOCK_STATE_FLAGS_OFF 88
#define CLOCK_STATE_FLAG_SHUTDOWN_POISON 0x02U

static uint32_t le32_at(const uint8_t *p)
{
	return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 |
	       (uint32_t)p[3] << 24;
}

int probe_agent_paused_at(const char *snapshot_path,
			  const uint8_t live[PROBE_HASH_SIZE])
{
	uint8_t snap[CLOCK_STATE_SIZE];
	ssize_t n;
	int fd;

	if (!snapshot_path || !live)
		return 0;
	fd = open(snapshot_path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 0;
	n = read(fd, snap, sizeof(snap));
	close(fd);

	if (n != (ssize_t)sizeof(snap) || le32_at(snap) != CLOCK_STATE_MAGIC ||
	    le32_at(snap + 4) != CLOCK_STATE_VERSION)
		return 0;
	if (!(snap[CLOCK_STATE_FLAGS_OFF] & CLOCK_STATE_FLAG_SHUTDOWN_POISON))
		return 0;
	return memcmp(snap + CLOCK_STATE_PCR14_OFF, live, PROBE_HASH_SIZE) == 0;
}

int probe_agent_paused(void)
{
	uint8_t live[PROBE_HASH_SIZE];

	if (read_live_pcr14(live) < 0)
		return 0;
	return probe_agent_paused_at(CLOCK_STATE_PATH, live);
}

enum stage_state probe_pcr14_barrier_stage(int pcr_state, int lock_ran,
					   int agent_active, int agent_failed,
					   int agent_paused, char *note,
					   size_t cap)
{
	if (agent_paused && !agent_active) {
		snprintf(note, cap,
			 "lota-agent was paused this boot (lota-install "
			 "--pause or lota-agent --shutdown), which spends its "
			 "PCR14 commitment until the next boot, so it refuses "
			 "to start again until then. A reboot resumes it; "
			 "'lota-install --resume' offers one.");
		return STAGE_REBOOT;
	}

	if (agent_failed && !agent_active) {
		snprintf(note, cap,
			 "lota-agent has already run and refused to start this "
			 "boot, so rebooting does not clear the refusal. What "
			 "it refused is in its own log "
			 "('journalctl -u lota-agent -b'); fix that and run "
			 "the installer again.");
		return STAGE_BLOCKED;
	}

	switch (pcr_state) {
	case PROBE_PCR14_LOCK_ONLY:
		snprintf(note, cap,
			 "PCR14 carries the initramfs lock from this boot.");
		return STAGE_DONE;
	case PROBE_PCR14_OTHER:
		if (agent_active) {
			snprintf(note, cap,
				 "PCR14 carries this boot's agent commitment.");
			return STAGE_DONE;
		}
		if (!lock_ran) {
			snprintf(note, cap,
				 "PCR14 was extended by the platform before "
				 "LOTA ran (on a Secure Boot host, shim's MOK "
				 "measurement) and the initramfs lock has not "
				 "run this boot. A reboot puts the lock in "
				 "place; nothing here is left over from an "
				 "earlier install.");
			return STAGE_REBOOT;
		}
		snprintf(note, cap,
			 "PCR14 holds a stale value from an earlier agent run. "
			 "PCR14 only resets on a hardware reset.");
		return STAGE_REBOOT;
	default:
		snprintf(note, cap,
			 "The initramfs PCR14 lock has not run during this "
			 "boot.");
		return STAGE_REBOOT;
	}
}

/* 0 when @row does not list @want, 1 in a range, 2 as a single entry */
static int port_row_lists(const char *row, unsigned long want, char *type,
			  size_t type_cap)
{
	char fmt[32];
	char proto[8];
	const char *p;
	int off = 0;
	int found = 0;

	snprintf(fmt, sizeof(fmt), "%%%zus %%7s %%n", type_cap - 1);
	if (sscanf(row, fmt, type, proto, &off) != 2 || off == 0 ||
	    strcmp(proto, "tcp") != 0)
		return 0;

	for (p = row + off; *p;) {
		char *end;
		unsigned long lo = strtoul(p, &end, 10);
		unsigned long hi = lo;

		if (end == p)
			break;
		if (*end == '-')
			hi = strtoul(end + 1, &end, 10);
		if (want >= lo && want <= hi)
			found = lo == hi ? 2 : (found ? found : 1);
		for (p = end; *p == ',' || *p == ' ';)
			p++;
	}
	return found;
}

int probe_port_needs_label(const char *listing, const char *port)
{
	unsigned long want;
	const char *line = listing;
	char *end;
	int taken = 0;

	want = strtoul(port, &end, 10);
	if (!isdigit((unsigned char)port[0]) || *end || want == 0 ||
	    want > 65535)
		return -EINVAL;

	while (line && *line) {
		const char *next = strchr(line, '\n');
		size_t len = next ? (size_t)(next - line) : strlen(line);
		char row[1024];
		char type[64];
		int listed;

		snprintf(row, sizeof(row), "%.*s", (int)len, line);
		listed = port_row_lists(row, want, type, sizeof(type));
		if (listed && (strcmp(type, "lota_port_t") == 0 ||
			       strcmp(type, "http_port_t") == 0))
			return 0;
		if (listed == 2)
			taken = 1;
		line = next ? next + 1 : NULL;
	}
	return !taken;
}

int probe_named_files(const struct probe_named_file *files, size_t count,
		      char *note, size_t cap)
{
	size_t i;

	for (i = 0; i < count; i++) {
		int err;

		if (!files[i].path)
			continue;
		if (access(files[i].path, R_OK) == 0)
			continue;

		err = errno;
		if (err == EACCES && geteuid() != 0)
			snprintf(note, cap,
				 "Cannot read %s %s (%s). Run as root, or "
				 "name a file this user can read.",
				 files[i].flag, files[i].path, strerror(err));
		else
			snprintf(note, cap, "Cannot read %s %s (%s)",
				 files[i].flag, files[i].path, strerror(err));

		return -err;
	}

	return 0;
}
