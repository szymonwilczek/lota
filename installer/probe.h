/* SPDX-License-Identifier: MIT
 * Copyright (C) 2026 Szymon Wilczek
 *
 * lota-install - System State Probes
 */

#ifndef LOTA_INSTALL_PROBE_H
#define LOTA_INSTALL_PROBE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "install.h"

#define PROBE_HASH_SIZE 32

struct probe_service_state {
	int agent_active;
	int agent_enabled;
	int socket_enabled;
	int attest_enabled;
};

/**
 * probe_agent_service_stage() - Verdict for the agent-service stage.
 * @s:    service state the caller read.
 * @note: filled with the reason for the verdict.
 * @cap:  size of @note.
 *
 * Return: STAGE_DONE when the agent is active and the agent, socket
 * and attest units are enabled, STAGE_PENDING when one of those is
 * not, STAGE_ERROR when @s is NULL.
 */
enum stage_state probe_agent_service_stage(const struct probe_service_state *s,
					   char *note, size_t cap);

#define PROBE_IMA_POLICY_PATH "/sys/kernel/security/ima/policy"

struct probe_floor {
	int ima_ok;
	int sig_ok;
	int lockdown_ok;
	/* ima_built, and a scope not PROBE_IMA_SCOPE_NONE, unreadable too */
	int appraised;
	int secureboot;
	int ima_built; /* probe_ima_appraise_built() is not 0 */
	int appraises; /* probe_ima_policy_appraises() is not 0 */
};

/**
 * probe_cmdline_next_boot_stage() - Cmdline stage verdict for the next boot.
 * @st:   booted floor with at least one of ima_ok, sig_ok and lockdown_ok
 *        clear.
 * @args: default kernel cmdline from grubby, or NULL when unread.
 * @note: filled with the reason for the verdict.
 * @cap:  size of @note.
 *
 * Return: STAGE_ERROR when @st or @note is NULL. With @st->appraises set and
 * @st->ima_ok clear, STAGE_BLOCKED when @args puts IMA appraisal in enforce
 * or ima_ok is the only one clear. Otherwise STAGE_REBOOT when @args carries
 * the floor, else STAGE_PENDING.
 */
enum stage_state probe_cmdline_next_boot_stage(const struct probe_floor *st,
					       const char *args, char *note,
					       size_t cap);

struct probe_ima_scope {
	int scope; /* enum probe_ima_scope_state, or -errno from the read */
	int policy_signed; /* policy writes are appraised against a signature */
	int secureboot;
	int agent_signed; /* agent binary carries a signed security.ima */
	int is_root;
	int no_appraisal; /* probe_ima_appraise_built() returned 0 */
};

/**
 * probe_ima_scope_stage() - Verdict for the IMA appraisal-scope stage.
 * @s:    policy state the caller read.
 * @note: filled with the reason for the verdict.
 * @cap:  size of @note.
 *
 * Return: STAGE_ERROR when @s is NULL or the read failed with -EACCES
 * without root, otherwise STAGE_DONE.
 */
enum stage_state probe_ima_scope_stage(const struct probe_ima_scope *s,
				       char *note, size_t cap);

enum probe_ima_scope_state {
	PROBE_IMA_SCOPE_EXEC = 0, /* a rule reaches an executable */
	PROBE_IMA_SCOPE_NONE = 1, /* readable, and appraises no executable */
};

/**
 * probe_ima_policy_scope() - Read the loaded IMA policy.
 * @policy_path:   policy file.
 * @policy_signed: set when an appraise rule for func=POLICY_CHECK requires
 *                 appraise_type=imasig.
 *
 * Return: enum probe_ima_scope_state, or -errno when the file cannot be read.
 */
int probe_ima_policy_scope(const char *policy_path, int *policy_signed);

/**
 * probe_ima_policy_appraises() - Does the loaded IMA policy appraise anything?
 * @policy_path: policy file.
 *
 * Return: 1 when a rule has the appraise action, whatever its func=,
 * 0 when none has, -errno when the file cannot be read.
 */
int probe_ima_policy_appraises(const char *policy_path);

enum probe_verity {
	PROBE_VERITY_ENABLED = 0,
	PROBE_VERITY_DISABLED,
	PROBE_VERITY_UNSUPPORTED,
};

enum probe_pcr14 {
	PROBE_PCR14_LOCK_ONLY = 0, /* holds the initramfs lock value */
	PROBE_PCR14_ZERO,
	PROBE_PCR14_OTHER,
};

/**
 * probe_read_text() - Read a small text file.
 * @path: file to read.
 * @buf:  NUL-terminated output, one trailing newline stripped.
 * @cap:  size of @buf; at least 2.
 *
 * Return: bytes in @buf, or -errno.
 */
int probe_read_text(const char *path, char *buf, size_t cap);

/**
 * probe_fsverity_state() - fs-verity state of a file.
 * @path: file to query.
 *
 * Return: enum probe_verity, or -errno.
 */
int probe_fsverity_state(const char *path);

/**
 * probe_fsverity_enable() - Enable fs-verity (SHA-256, 4096-byte blocks).
 * @path: file to seal.
 *
 * Return: 0 or -errno.
 */
int probe_fsverity_enable(const char *path);

/**
 * probe_manifest_line() - Parse one line of a runtime manifest.
 * @line: the line.
 * @out:  receives the path.
 * @cap:  size of @out.
 *
 * Surrounding spaces, tabs and line endings are trimmed.
 *
 * Return: 1 when @line names a path, 0 for a blank or '#' line, -EINVAL for
 * a relative path, a path with a '..' component, or one @out cannot hold.
 */
int probe_manifest_line(const char *line, char *out, size_t cap);

/**
 * probe_port_needs_label() - Whether a tcp port needs an SELinux label.
 * @listing: output of `semanage port -l`.
 * @port:    decimal port.
 *
 * Return: 0 when a tcp row of lota_port_t or http_port_t covers @port,
 * or a tcp row of any other type lists @port as a single entry, otherwise 1.
 * -EINVAL when @port is not a port number.
 */
int probe_port_needs_label(const char *listing, const char *port);

/**
 * probe_file_ima_signed() - Whether a file carries a signed security.ima.
 * @path: file to check.
 *
 * Return: 1 for a signature, 0 for none or a bare digest, -errno on read
 * failure.
 */
int probe_file_ima_signed(const char *path);

/**
 * probe_firmware_is_uefi() - Whether the machine booted through UEFI.
 *
 * Return: 1 or 0.
 */
int probe_firmware_is_uefi(void);
/* probe_firmware_is_uefi() against firmware directory @dir */
int probe_firmware_is_uefi_at(const char *dir);

/**
 * probe_secureboot() - Read the SecureBoot variable.
 *
 * Return: 1 when enabled, 0 when not, -errno on read failure (-ENOENT when
 * the variable is absent).
 */
int probe_secureboot(void);

/**
 * probe_secureboot_setup_mode() - Read the SetupMode variable.
 *
 * Return: 1 in setup mode, 0 in user mode, -errno on read failure.
 */
int probe_secureboot_setup_mode(void);

/**
 * probe_firmware_setup_supported() - Whether firmware accepts a boot into
 * its setup UI.
 *
 * Return: bit 0 of OsIndicationsSupported, or -errno on read failure.
 */
int probe_firmware_setup_supported(void);

/* efivarfs readers behind the wrappers above; 4-byte attribute header first */
int probe_efivar_flag_at(const char *path);
int probe_efivar_bit0_at(const char *path);

/**
 * probe_secureboot_remediation() - Secure Boot instructions for the person
 * at the machine.
 * @machine:                  DMI description, or NULL.
 * @is_virtual:               1 for a guest.
 * @setup_mode:               probe_secureboot_setup_mode() result.
 * @firmware_setup_supported: probe_firmware_setup_supported() result.
 * @out:                      output buffer.
 * @cap:                      size of @out.
 *
 * Only a @firmware_setup_supported of 1 offers the reboot into setup,
 * and only a @setup_mode of 1 adds the step that restores the keys.
 */
void probe_secureboot_remediation(const char *machine, int is_virtual,
				  int setup_mode, int firmware_setup_supported,
				  char *out, size_t cap);

/**
 * probe_secureboot_guidance() - probe_secureboot_remediation() on live DMI
 * and EFI variables.
 * @is_virtual: 1 for a guest.
 * @out:        output buffer.
 * @cap:        size of @out.
 */
void probe_secureboot_guidance(int is_virtual, char *out, size_t cap);

/**
 * probe_machine_description() - DMI vendor and product of this machine.
 * @out: output buffer; empty when DMI holds only placeholders.
 * @cap: size of @out.
 */
void probe_machine_description(char *out, size_t cap);
/* probe_machine_description() against DMI directory @dmi_dir */
void probe_machine_description_at(const char *dmi_dir, char *out, size_t cap);

/**
 * probe_esrt_system_firmware_present() - Whether ESRT has a system firmware
 * entry.
 *
 * Return: 1 when an entry has fw_type 1, otherwise 0.
 */
int probe_esrt_system_firmware_present(void);
/* probe_esrt_system_firmware_present() against ESRT entries directory @base */
int probe_esrt_system_firmware_present_at(const char *base);

/**
 * probe_cmdline_ima_ok() - Whether a cmdline leaves ima_appraise=enforce.
 * @cmdline: kernel command line.
 *
 * Return: 0 when lota_ima_cmdline_enforce() returns 1, -EPERM otherwise,
 * -EINVAL for NULL.
 */
int probe_cmdline_ima_ok(const char *cmdline);

/**
 * probe_cmdline_has_token() - Whether a cmdline holds an exact token.
 * @cmdline: whitespace-separated kernel command line.
 * @token:   token to find.
 *
 * Return: 1 or 0.
 */
int probe_cmdline_has_token(const char *cmdline, const char *token);

/**
 * probe_ima_appraise_built() - lota_ima_appraise_built() on the booted kernel.
 *
 * Return: as for lota_ima_appraise_built().
 */
int probe_ima_appraise_built(void);

/**
 * probe_ima_mode_blocking() - Nonzero @secureboot, or a cmdline that passes
 * probe_cmdline_ima_ok().
 * @secureboot: probe_secureboot() result.
 * @cmdline:    kernel command line.
 *
 * Return: 1 when @secureboot is nonzero or @cmdline passes
 * probe_cmdline_ima_ok(), otherwise 0.
 */
int probe_ima_mode_blocking(int secureboot, const char *cmdline);

/**
 * probe_module_sig_enforced() - Whether module signatures are enforced.
 *
 * Return: 0 when enforced, -EPERM when not, -EIO for an empty parameter,
 * -errno on read failure.
 */
int probe_module_sig_enforced(void);

/**
 * probe_lockdown_restrictive() - Whether lockdown is integrity or stricter.
 *
 * Return: 0 for [integrity] or [confidentiality], -EPERM otherwise, -EIO for
 * an empty file, -errno on read failure.
 */
int probe_lockdown_restrictive(void);

/**
 * probe_pcr14_baseline_path() - File lota-pcr14-lock records the pre-extend
 * PCR 14 in.
 *
 * Return: the path.
 */
const char *probe_pcr14_baseline_path(void);

/**
 * probe_pcr14_lock_value() - PCR 14 after the initramfs lock.
 * @out: SHA256(baseline || SHA256("LOTA-PCR14-INITRAMFS-LOCK-v1")).
 *
 * A missing or short baseline counts as zero.
 */
void probe_pcr14_lock_value(uint8_t out[PROBE_HASH_SIZE]);
/* probe_pcr14_lock_value() with the baseline read from @baseline_path */
void probe_pcr14_lock_value_at(const char *baseline_path,
			       uint8_t out[PROBE_HASH_SIZE]);

/**
 * probe_hex_to_bytes() - Decode hex.
 * @hex: exactly 2 * @n hex digits, either case.
 * @out: receives @n bytes.
 * @n:   number of bytes.
 *
 * Return: 0 or -EINVAL.
 */
int probe_hex_to_bytes(const char *hex, uint8_t *out, size_t n);

/**
 * probe_pcr14_state() - Classify the live PCR 14.
 *
 * Return: enum probe_pcr14, -EBADMSG for an unparseable value, or -errno
 * (-ENOENT without the TPM sysfs PCR interface).
 */
int probe_pcr14_state(void);

/**
 * probe_selinux_tpm_label() - Whether the TPM nodes carry lota_tpm_device_t.
 *
 * Return: 0 when each present /dev/tpmrm0 and /dev/tpm0 carries the label,
 * or the filesystem has no SELinux xattrs; -ENOENT when neither node exists;
 * -EPERM on another label; -errno on read failure.
 */
int probe_selinux_tpm_label(void);

/**
 * probe_cert_days_left() - Whole days until a DER certificate expires.
 * @der_path:  certificate file.
 * @days_left: receives the days; negative once expired.
 *
 * Return: 0, -EBADMSG for an unparseable file, or -errno.
 */
int probe_cert_days_left(const char *der_path, int *days_left);

/**
 * probe_conf_buf_has_key() - Whether a configuration sets a key.
 * @buf: configuration text.
 * @key: exact key.
 *
 * Return: 1 when a "key = value" line exists, otherwise 0.
 */
int probe_conf_buf_has_key(const char *buf, const char *key);

/**
 * probe_conf_buf_value() - Value of a configuration key.
 * @buf: configuration text.
 * @key: exact key.
 * @out: receives the value.
 * @cap: size of @out.
 *
 * Return: 1, or 0 with @out empty when the key is absent, empty or its
 * value does not fit.
 */
int probe_conf_buf_value(const char *buf, const char *key, char *out,
			 size_t cap);

/**
 * probe_conf_value() - probe_conf_buf_value() on a file.
 * @conf_path: configuration file.
 * @key:       exact key.
 * @out:       receives the value.
 * @cap:       size of @out.
 *
 * Return: as probe_conf_buf_value(); 0 when the file cannot be read.
 */
int probe_conf_value(const char *conf_path, const char *key, char *out,
		     size_t cap);

/**
 * probe_conf_has_key() - probe_conf_buf_has_key() on a file.
 * @conf_path: configuration file.
 * @key:       exact key.
 *
 * Return: 1, 0, or -errno.
 */
int probe_conf_has_key(const char *conf_path, const char *key);

/**
 * probe_conf_buf_profile_count() - Number of [profile "name"] sections.
 * @buf: configuration text.
 *
 * Return: the count.
 */
int probe_conf_buf_profile_count(const char *buf);

/**
 * probe_conf_profile_count() - probe_conf_buf_profile_count() on a file.
 * @conf_path: configuration file.
 *
 * Return: the count, or -errno.
 */
int probe_conf_profile_count(const char *conf_path);

/**
 * probe_conf_buf_profile_anchor() - ca_cert of a profile section.
 * @buf:   configuration text.
 * @index: 0-based profile section.
 * @out:   receives the path.
 * @cap:   size of @out.
 *
 * Return: 1, or 0 when the section or its ca_cert is absent.
 */
int probe_conf_buf_profile_anchor(const char *buf, int index, char *out,
				  size_t cap);

/**
 * probe_conf_buf_continuous_count() - Profiles that report continuously.
 * @buf: configuration text.
 *
 * Return: profile sections with reporting = continuous and a verifier
 * other than none.
 */
int probe_conf_buf_continuous_count(const char *buf);

/**
 * probe_attest_status_covers() - Whether the loop reported a new round.
 * @status:   current loop status.
 * @before:   status read before a reload; NULL or empty for none.
 * @expected: publishers the round must cover.
 *
 * Return: 1 when @status reads "Attested (N publisher..." with N at least
 * @expected and differs from a non-empty @before, otherwise 0.
 */
int probe_attest_status_covers(const char *status, const char *before,
			       int expected);

enum probe_selfcheck_plan {
	SELFCHECK_SKIP_NO_VERIFIER,
	SELFCHECK_ONE_ROUND, /* one round against the named verifier */
	SELFCHECK_PUBLISHERS_REPORT,
	SELFCHECK_LOOP_REPORTS, /* wait on the loop's status */
};

/**
 * probe_selfcheck_plan() - How the self-check proves this host attests.
 * @verifier:      verifier named on the command line, or NULL.
 * @profile_count: profile sections in the configuration.
 * @fleet_profile: the CA this install enrolled with is recorded as a profile.
 *
 * Return: SELFCHECK_LOOP_REPORTS for @fleet_profile with a verifier, else
 * SELFCHECK_PUBLISHERS_REPORT when profiles exist, else
 * SELFCHECK_SKIP_NO_VERIFIER without a verifier, else SELFCHECK_ONE_ROUND.
 */
enum probe_selfcheck_plan probe_selfcheck_plan(const char *verifier,
					       int profile_count,
					       bool fleet_profile);

/**
 * probe_auto_bringup_at() - Whether unattended boot-path bring-up is allowed.
 * @path: marker file, or NULL.
 *
 * Return: 1 when $LOTA_AUTO_BRINGUP is exactly "1" or @path exists,
 * otherwise 0.
 */
int probe_auto_bringup_at(const char *path);

#define PROBE_MAX_KERNELS 8
#define PROBE_KERNEL_RELEASE_MAX 96
#define PROBE_KERNEL_IMAGE_MAX 320

struct probe_kernel_image {
	char release[PROBE_KERNEL_RELEASE_MAX];
	char image[PROBE_KERNEL_IMAGE_MAX]; /* its initramfs */
};

/**
 * probe_installed_kernels_at() - Kernels that have an initramfs.
 * @modules_dir: modules tree, one directory per release.
 * @boot_dir:    holds initramfs-<release>.img.
 * @out:         receives the kernels.
 * @max:         capacity of @out; enumeration stops there.
 * @count:       receives the number found.
 *
 * Return: 0, with @count 0 when @modules_dir cannot be opened; -EINVAL for
 * a NULL argument.
 */
int probe_installed_kernels_at(const char *modules_dir, const char *boot_dir,
			       struct probe_kernel_image *out, size_t max,
			       size_t *count);

/* probe_installed_kernels_at() on /lib/modules and /boot */
int probe_installed_kernels(struct probe_kernel_image *out, size_t max,
			    size_t *count);

/**
 * probe_pcr14_lock_ran() - Whether lota-pcr14-lock ran this boot.
 *
 * Return: 1 when its baseline file exists, otherwise 0.
 */
int probe_pcr14_lock_ran(void);
/* probe_pcr14_lock_ran() for baseline file @baseline_path */
int probe_pcr14_lock_ran_at(const char *baseline_path);

/**
 * probe_agent_paused_at() - Whether PCR 14 was spent on a requested shutdown.
 * @snapshot_path: the agent's clock-state snapshot.
 * @live:          live PCR 14.
 *
 * Return: 1 when the snapshot records a pause and @live holds the PCR 14 it
 * recorded, otherwise 0.
 */
int probe_agent_paused_at(const char *snapshot_path,
			  const uint8_t live[PROBE_HASH_SIZE]);

/* probe_agent_paused_at() on the agent's snapshot and the live PCR 14 */
int probe_agent_paused(void);

/**
 * probe_pcr14_barrier_stage() - Verdict for the reboot barrier.
 * @pcr_state:    enum probe_pcr14.
 * @lock_ran:     probe_pcr14_lock_ran() result.
 * @agent_active: the agent unit is active.
 * @agent_failed: the agent unit failed.
 * @agent_paused: probe_agent_paused() result.
 * @note:         filled with the reason for the verdict.
 * @cap:          size of @note.
 *
 * Return: STAGE_BLOCKED when the agent failed and is not active (after the
 * paused case), STAGE_DONE for PROBE_PCR14_LOCK_ONLY or for
 * PROBE_PCR14_OTHER with the agent active, otherwise STAGE_REBOOT.
 */
enum stage_state probe_pcr14_barrier_stage(int pcr_state, int lock_ran,
					   int agent_active, int agent_failed,
					   int agent_paused, char *note,
					   size_t cap);

struct probe_named_file {
	const char *flag; /* e.g. "--ca-cert" */
	const char *path; /* NULL when the option was not given */
};

/**
 * probe_named_files() - Find the first named file that cannot be read.
 * @files: files named on the command line.
 * @count: entries in @files.
 * @note:  names the flag, path and reason of the failure.
 * @cap:   size of @note.
 *
 * Entries with a NULL path are skipped.
 *
 * Return: 0 when each file is readable, otherwise -errno for the first that
 * is not.
 */
int probe_named_files(const struct probe_named_file *files, size_t count,
		      char *note, size_t cap);

#endif /* LOTA_INSTALL_PROBE_H */
