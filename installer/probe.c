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
#include <sys/vfs.h>
#include <sys/xattr.h>
#include <unistd.h>
#include <openssl/asn1.h>
#include <openssl/types.h>

#include <linux/fsverity.h>

#include "../include/lota_ima_xattr.h"

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

/* statfs f_type magics, mirroring <linux/magic.h> */
#define PROBE_MAGIC_EXT 0xEF53L
#define PROBE_MAGIC_XFS 0x58465342L
#define PROBE_MAGIC_BTRFS 0x9123683EL
#define PROBE_MAGIC_F2FS 0xF2F52010L
#define PROBE_MAGIC_ZFS 0x2FC12FC1L

enum probe_fstype probe_fstype_from_magic(long magic)
{
	switch (magic) {
	case PROBE_MAGIC_EXT:
		return PROBE_FS_EXT4;
	case PROBE_MAGIC_XFS:
		return PROBE_FS_XFS;
	case PROBE_MAGIC_BTRFS:
		return PROBE_FS_BTRFS;
	case PROBE_MAGIC_F2FS:
		return PROBE_FS_F2FS;
	case PROBE_MAGIC_ZFS:
		return PROBE_FS_ZFS;
	default:
		return PROBE_FS_UNKNOWN;
	}
}

int probe_fs_supports_fsverity(enum probe_fstype fs)
{
	switch (fs) {
	case PROBE_FS_EXT4:
	case PROBE_FS_BTRFS:
	case PROBE_FS_F2FS:
		return 1;
	default:
		return 0;
	}
}

void probe_verity_remediation(enum probe_fstype fs, const char *path, char *out,
			      size_t cap)
{
	if (!out || cap == 0)
		return;
	if (!path)
		path = "the agent binary";

	if (probe_fs_supports_fsverity(fs)) {
		/* verity-capable filesystem,
		 * feature just not enabled here */
		snprintf(out, cap,
			 "Filesystem holding %s supports fs-verity but it "
			 "is not enabled. ext4: 'tune2fs -O verity' on the "
			 "unmounted device; btrfs and f2fs ship the feature by "
			 "default. Then re-run lota-install.",
			 path);
		return;
	}

	/* XFS / ZFS: no native fs-verity
	 * IMA appraisal of a signed security.ima xattr gives the same offline-swap
	 * guarantee on any filesystem, and the agent accepts it as equivalent */
	snprintf(out, cap,
		 "Filesystem holding %s has no fs-verity. Establish "
		 "kernel-enforced immutability with IMA instead: sign the "
		 "binary into a security.ima xattr (evmctl ima_sign --key "
		 "<ima.key>), load the matching certificate into the .ima "
		 "keyring, and boot with ima_appraise=enforce. Then re-run "
		 "lota-install.",
		 path);
}

enum probe_fstype probe_path_fstype(const char *path)
{
	struct statfs sfs;

	if (!path || statfs(path, &sfs) != 0)
		return PROBE_FS_UNKNOWN;
	return probe_fstype_from_magic((long)sfs.f_type);
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

/*
 * EFI global variable GUID
 * 4-byte attribute header precedes the payload in efivarfs
 */
#define EFI_GLOBAL_GUID "8be4df61-93ca-11d2-aa0d-00e098032b8c"
#define EFI_FIRMWARE_DIR "/sys/firmware/efi"
#define EFIVARS_DIR "/sys/firmware/efi/efivars/"
#define SECUREBOOT_EFIVAR EFIVARS_DIR "SecureBoot-" EFI_GLOBAL_GUID
#define SETUPMODE_EFIVAR EFIVARS_DIR "SetupMode-" EFI_GLOBAL_GUID
#define OSINDICATIONS_SUPPORTED_EFIVAR \
	EFIVARS_DIR "OsIndicationsSupported-" EFI_GLOBAL_GUID

#define EFIVAR_ATTR_LEN 4

/* Reads the payload of an efivarfs variable, dropping the attribute header.
 * Byte count (>= 1) or -errno;
 * -EBADMSG when the file is shorter than the header plus one payload byte.
 * A failure never encodes as 0, which the callers would read as a clear flag */
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

/* UEFI bitmask variables are little-endian UINT64,
 * so the flag this cares about lives in the first payload byte whatever
 * the firmware wrote above it */
int probe_efivar_bit0_at(const char *path)
{
	uint8_t val;
	int ret = read_efivar_payload(path, &val, sizeof(val));

	if (ret < 0)
		return ret;
	return val & 1U ? 1 : 0;
}

/* Whether the machine booted through UEFI at all.
 *
 * Asked apart from Secure Boot because missing SecureBoot variable does not say
 * which of two machines this is: legacy BIOS boot, or UEFI firmware built without
 * Secure Boot support.
 * Firmware directory exists in the second case and not in the first,
 * and the two need opposite instructions.
 */
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
	return probe_efivar_flag_at(SECUREBOOT_EFIVAR);
}

int probe_secureboot_setup_mode(void)
{
	return probe_efivar_flag_at(SETUPMODE_EFIVAR);
}

/* EFI_OS_INDICATIONS_BOOT_TO_FW_UI is bit 0 of OsIndicationsSupported */
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

/* Reads one DMI field, leaving out an empty string on any failure */
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

/*
 * Placeholders a board ships when nobody filled the DMI field in.
 * Reading one back describes no machine anybody owns.
 */
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
			 "This is a virtual machine, where Secure Boot belongs "
			 "to the VM definition rather than to a menu inside "
			 "the guest. Give it an OVMF/EDK II image with Secure "
			 "Boot enabled (libvirt: a q35 machine with SMM and "
			 "<loader secure='yes'>), boot it once, then re-run "
			 "lota-install.");
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

	/*
	 * reboot-to-setup request is the only route this can state with certainty,
	 * and the firmware itself says whether it honours it.
	 * Where it does not, the firmware's own splash screen names its key
	 * -- which is a better source than a table here could be, since the menu
	 * layout and the key differ between revisions of a single model.
	 */
	if (firmware_setup_supported == 1) {
		used += (size_t)snprintf(
			out + used, cap - used,
			"Run 'systemctl reboot --firmware-setup' to reboot "
			"straight into firmware setup -- this firmware accepts "
			"that request, so no key has to be caught at the right "
			"moment. ");
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
		/*
		 * With no platform key installed there is nothing for Secure Boot
		 * to enforce against, and firmware commonly leaves the switch
		 * unselectable until the factory keys are restored.
		 */
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

/*
 * lota-pcr14-lock records the pre-extend PCR14 content here on the /run
 * tmpfs (the shim MOK measurement, or 0^32 on a UEFI host whose boot chain
 * never measured PCR14).
 * Must match BASELINE_PATH in src/initramfs/lota-pcr14-lock.c.
 */
#define PCR14_BASELINE_PATH "/run/lota/pcr14_baseline"

/*
 * read_pcr14_baseline_at - load the baseline the lock helper persisted this
 * boot.
 * Missing or short file yields a zero baseline, matching the agent's own fallback:
 * that is the correct anchor where no shim measured PCR14, and elsewhere it
 * simply fails to match the live register.
 */
static void read_pcr14_baseline_at(const char *path,
				   uint8_t out[PROBE_HASH_SIZE])
{
	int fd;

	memset(out, 0, PROBE_HASH_SIZE);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return;
	if (read(fd, out, PROBE_HASH_SIZE) != PROBE_HASH_SIZE)
		memset(out, 0, PROBE_HASH_SIZE);
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
		    EVP_DigestUpdate(md, baseline, sizeof(baseline)) == 1 &&
		    EVP_DigestUpdate(md, commit, sizeof(commit)) == 1)
			EVP_DigestFinal_ex(md, out, &len);

	EVP_MD_CTX_free(md);
}

void probe_pcr14_lock_value(uint8_t out[PROBE_HASH_SIZE])
{
	probe_pcr14_lock_value_at(PCR14_BASELINE_PATH, out);
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

int probe_auto_bringup_at(const char *path)
{
	const char *env = getenv("LOTA_AUTO_BRINGUP");

	if (env && env[0] == '1' && env[1] == '\0')
		return 1;
	if (!path)
		return 0;
	return access(path, F_OK) == 0;
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
