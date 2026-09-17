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

#include "../include/lota_ima_policy_scope.h"
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

	/*
	 * '..' component takes the walk out of the directory the line names,
	 * so manifest a title ships could aim the root-only ioctl at any file
	 * on the box -- an fs-verity digest is permanent and makes the file
	 * read-only for good.
	 * Only paths that mean what they read are taken.
	 */
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

/*
 * Return 1 if @rule requires a signed IMA policy (func=POLICY_CHECK with
 * appraise_type=imasig). Such a host refuses any unsigned policy write,
 * the shipped developer baseline included, so the installer reports that
 * instead of suggesting a file the kernel will reject.
 */
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

	/*
	 * Read to the end whatever the first rule says: the scope answer and
	 * the signed-policy answer are two different rules, and the second is
	 * what turns a remedy into a route the host would refuse.
	 */
	while (fgets(line, sizeof(line), fp)) {
		if (lota_ima_policy_rule_appraises_exec(line))
			found = 1;
		if (policy_signed && rule_demands_signed_policy(line))
			*policy_signed = 1;
	}

	fclose(fp);
	return found ? PROBE_IMA_SCOPE_EXEC : PROBE_IMA_SCOPE_NONE;
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
			/* a value is what is left after the trailing blanks;
			 * a key with nothing after it is not a value */
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
			/* the section name is quoted and follows the keyword */
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

enum probe_selfcheck_plan probe_selfcheck_plan(const char *verifier,
					       int profile_count)
{
	/*
	 * Publishers first: they are the agent's target list, so they decide
	 * where this host reports whether or not a verifier was named.
	 * A round that named one as well is the combination the agent refuses.
	 */
	if (profile_count > 0)
		return SELFCHECK_PUBLISHERS_REPORT;
	if (!verifier || !verifier[0])
		return SELFCHECK_SKIP_NO_VERIFIER;
	return SELFCHECK_ONE_ROUND;
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

	/*
	 * Running is not installed.
	 * A unit that is not enabled does not come back after a reboot,
	 * and a host that stops enforcing at its next boot must not be
	 * reported as satisfied.
	 */
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

/*
 * Stage verdict for the IMA appraisal scope.
 *
 * The previous stage checks the cmdline mode; this one checks the loaded
 * rules. If no rule appraises executables, nothing is appraised and the
 * agent refuses to start.
 *
 * The installer never widens the scope. IMA rules cannot match by path,
 * so a wider rule appraises every matching executable, and Secure Boot
 * kernels ignore ima_appraise= and always enforce.
 * On an unsigned rootfs that stops the next boot. The missing piece is
 * signatures, which come from the distribution or the operator's image
 * pipeline.
 */
enum stage_state probe_ima_scope_stage(const struct probe_ima_scope *s,
				       char *note, size_t cap)
{
	if (!s) {
		snprintf(note, cap, "The loaded IMA policy could not be read.");
		return STAGE_ERROR;
	}

	if (s->scope == PROBE_IMA_SCOPE_EXEC) {
		snprintf(note, cap,
			 "The loaded IMA policy appraises executables, which "
			 "is the scope the agent's startup gate requires.");
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
		/*
		 * A kernel built without CONFIG_IMA_READ_POLICY publishes no
		 * policy, and the agent's gate lets the mode decide alone on
		 * exactly that host.
		 * Refusing here would block a machine the agent starts on,
		 * so the stage reports what it could not see.
		 */
		snprintf(note, cap,
			 "This kernel does not publish its loaded IMA policy "
			 "(%s: %s), so the scope cannot be checked. The agent "
			 "starts on the appraisal mode alone and records that "
			 "the scope is unverified.",
			 PROBE_IMA_POLICY_PATH, strerror(-s->scope));
		return STAGE_DONE;
	}

	/*
	 * Four sentences at most, because STAGE_NOTE_CAP is the whole budget
	 * and a report that runs past it loses its last clause
	 */
	snprintf(note, cap,
		 "The loaded IMA policy carries no appraise rule that reaches "
		 "an executable, so the kernel appraises nothing here%s. The "
		 "installer does not widen the scope: an IMA rule cannot name "
		 "a path, so a rule reaching the agent reaches every "
		 "executable it matches%s, and this host's %s The scope "
		 "arrives with the signatures -- IMA-signed distribution "
		 "packages, or an image pipeline that signs executables and "
		 "enrols its certificate (production bring-up guide, \"IMA "
		 "appraisal policy\").%s",
		 s->agent_verity ?
			 ", which the agent reports: "
			 "fs-verity holds its own binary and the token says "
			 "KERNEL_APPRAISAL is clear" :
			 " -- and the agent refuses to start, because without "
			 "fs-verity on its binary an unappraised signature is "
			 "the only thing holding it",
		 s->secureboot ? ", in enforce, since Secure Boot makes the "
				 "kernel discard ima_appraise=" :
				 "",
		 s->agent_signed ?
			 "executables are signed, so a rule set covering them "
			 "is the remaining step." :
			 "executables carry no signature (its agent binary "
			 "carries none), so the next boot would refuse them.",
		 s->policy_signed ?
			 " Policy writes are appraised here too (appraise "
			 "func=POLICY_CHECK appraise_type=imasig), so any rule "
			 "set has to be signed by a key on the .ima keyring." :
			 "");
	return lota_ima_scope_is_advisory(s->agent_verity) ? STAGE_DONE :
							     STAGE_BLOCKED;
}

/*
 * Kernels installed on this host.
 *
 * /lib/modules is the register of what is installed -- the package manager
 * creates a tree per kernel and removes it with the kernel -- and /boot holds
 * the image each one boots with.
 * A tree with no image cannot be locked (a half-removed kernel), and an image
 * with no tree is the rescue entry, which dracut does not regenerate,
 * so neither is a kernel this stage can act on.
 */
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
		return 0; /* no modules tree: nothing installed to lock */

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

/*
 * Layout of struct lota_clock_state (src/agent/tpm.h), spelled out because the
 * installer does not link the TPM stack. The probe tests write it through the
 * agent's struct.
 */
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

/*
 * Verdict for the reboot barrier.
 *
 * A register the installer cannot derive means one of three things, and they
 * do not need the same sentence -- or, in one case, the same reboot: an agent
 * ran earlier this boot and left its commitment, an agent ran this boot
 * and refused to start, or the platform extended PCR 14 before LOTA was ever
 * installed, which every Secure Boot host does because shim measures the MOK
 * variables there.
 * Whether the lock ran this boot separates the last from the others,
 * and whether the unit has failed separates the first two.
 * A pause is the one refusal the next boot clears.
 */
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

	/*
	 * A reboot is what this stage asks for, and it is the one thing that
	 * cannot help here: the agent refused a gate that will refuse it again
	 * on the next boot, and the register carries the extend of the attempt.
	 * Say that instead, whatever the register holds.
	 */
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
