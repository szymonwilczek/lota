/* SPDX-License-Identifier: MIT
 * Copyright (C) 2026 Szymon Wilczek
 *
 * lota-install - System State Probes
 *
 * Every stage of the guided installer decides "done vs pending"
 * by probing live system state instead of trusting a state file.
 * Probes mirror the agent's own startup gates (src/agent/bpf_loader.c)
 * so the installer never reports green for a host the agent would
 * refuse.
 */

#ifndef LOTA_INSTALL_PROBE_H
#define LOTA_INSTALL_PROBE_H

#include <stddef.h>
#include <stdint.h>

#define PROBE_HASH_SIZE 32

/* fs-verity state of one file */
enum probe_verity {
	PROBE_VERITY_ENABLED = 0,
	PROBE_VERITY_DISABLED,
	PROBE_VERITY_UNSUPPORTED, /* filesystem lacks the verity feature */
};

/* Filesystem class of the volume backing path, used to steer binary-immutability
 * remediation: verity-capable filesystems take the fs-verity path, the rest take
 * the filesystem-agnostic signed-IMA-xattr path */
enum probe_fstype {
	PROBE_FS_UNKNOWN = 0,
	PROBE_FS_EXT4, /* ext2/ext3/ext4 */
	PROBE_FS_XFS,
	PROBE_FS_BTRFS,
	PROBE_FS_F2FS,
	PROBE_FS_ZFS,
};

/* PCR14 state relative to the initramfs lock */
enum probe_pcr14 {
	PROBE_PCR14_LOCK_ONLY = 0, /* lock ran, agent not yet extended */
	PROBE_PCR14_ZERO, /* lock did not run this boot */
	PROBE_PCR14_OTHER, /* extended past the lock (agent or stale) */
};

/* Reads a small text file, NUL-terminates, strips one trailing
 * newline.
 * Returns byte count >= 0 or -errno. */
int probe_read_text(const char *path, char *buf, size_t cap);

/* 1 = verity enabled, else enum probe_verity, or -errno on hard
 * failure (file missing, permission) */
int probe_fsverity_state(const char *path);

/* Enables fs-verity (SHA-256, 4K blocks) on the file.
 * 0 or -errno; EOPNOTSUPP/-ENOTTY mean the filesystem lacks the feature. */
int probe_fsverity_enable(const char *path);

/* Pure: maps statfs f_type magic to probe_fstype */
enum probe_fstype probe_fstype_from_magic(long magic);

/* Pure:
 * 1 when the filesystem implements native fs-verity (ext4, btrfs, f2fs),
 * 0 otherwise.
 * Live ioctl in probe_fsverity_state() stays authoritative for capability;
 * this only steers remediation text */
int probe_fs_supports_fsverity(enum probe_fstype fs);

/* Pure:
 * Writes filesystem-specific guidance for establishing kernel-enforced
 * immutability of the binary at path.
 * Verity-capable filesystems get the fs-verity-enable path;
 * the rest get the filesystem-agnostic signed-IMA-xattr path */
void probe_verity_remediation(enum probe_fstype fs, const char *path, char *out,
			      size_t cap);

/* statfs the path and classify its filesystem.
 * enum probe_fstype, or PROBE_FS_UNKNOWN when statfs fails */
enum probe_fstype probe_path_fstype(const char *path);

/* Mirrors the agent's agent_self_ima_signed():
 * 1 when the file carries a signature-type security.ima xattr,
 * 0 when it has none or only a bare digest, errno on read failure. */
int probe_file_ima_signed(const char *path);

/* 1 when the machine booted through UEFI, 0 when it did not.
 *
 * Separate from probe_secureboot(): missing SecureBoot variable is either legacy
 * BIOS boot or UEFI firmware without Secure Boot support, and the two get
 * different instructions.
 * _at form takes the firmware directory so the decision is testable without reboot */
int probe_firmware_is_uefi(void);
int probe_firmware_is_uefi_at(const char *dir);

/* 1 = Secure Boot enabled, 0 = disabled/setup mode,
 * -ENOENT = no UEFI (BIOS/CSM host), other -errno on read failure. */
int probe_secureboot(void);

/* 1 = firmware holds no platform key (setup mode), so enabling Secure Boot also
 * needs the factory keys restored,
 * 0 = user mode,
 * -errno on read failure (-ENOENT on firmware that exposes no SetupMode variable) */
int probe_secureboot_setup_mode(void);

/* 1 = firmware accepts the OsIndications request to boot straight into its setup
 * UI, which is what makes 'systemctl reboot --firmware-setup' work,
 * 0 = unsupported,
 * -errno on read failure */
int probe_firmware_setup_supported(void);

/* Path-parameterized variants behind the fixed-path wrappers above.
 * Both read efivarfs file: 4-byte attribute header, then the payload */
int probe_efivar_flag_at(const char *path);
int probe_efivar_bit0_at(const char *path);

/* Pure:
 * Writes the Secure-Boot remediation a player can act on without a manual:
 * what the setting is called, how to reach firmware setup on this machine,
 * and what enabling it does not break.
 *
 * It deliberately carries no per-vendor menu path or setup key.
 * Those differ between firmware revisions of one model, nothing here can verify
 * them, and confidently wrong instruction costs more than general one.
 *
 * machine is the DMI description echoed back (may be NULL);
 * is_virtual says this is a guest (systemd-detect-virt, decided by the caller);
 * setup_mode and firmware_setup_supported take the probe results above,
 * where negative value reads as "could not tell" */
void probe_secureboot_remediation(const char *machine, int is_virtual,
				  int setup_mode, int firmware_setup_supported,
				  char *out, size_t cap);

/* Gathers the live inputs this file owns (DMI, SetupMode, OsIndicationsSupported)
 * and builds the remediation above.
 * Whether the host is a guest comes from the caller, since answering it means
 * running systemd-detect-virt and no probe here spawns a process */
void probe_secureboot_guidance(int is_virtual, char *out, size_t cap);

/* Describes this machine the way DMI does ("Dell Inc. Latitude 7420"),
 * for echoing back to whoever is at the keyboard.
 * Writes empty string when DMI says nothing usable;
 * placeholder strings a board ships unfilled ("System Product Name") count
 * as nothing */
void probe_machine_description(char *out, size_t cap);
void probe_machine_description_at(const char *dmi_dir, char *out, size_t cap);

/* 1 when the platform exposes an ESRT System Firmware entry (fw_type == 1),
 * 0 otherwise.
 * Informational only: it tells the player whether a future self-service
 * re-anchor takes the strong (firmware-version) path or the
 * Low-Firmware-Assurance path. Many DIY boards expose no ESRT. */
int probe_esrt_system_firmware_present(void);

/* Path-parameterized variant behind the fixed-path wrapper above; base is
 * the ESRT entries directory. Lets tests point at a fixture tree. */
int probe_esrt_system_firmware_present_at(const char *base);

/* Pure parser:
 * 0 when the cmdline buffer carries ima_appraise=enforce|fix,
 * -EPERM otherwise.
 * First token wins, mirroring the agent's kernel_ima_appraise_enforcing() */
int probe_cmdline_ima_ok(const char *cmdline);

/* Pure parser:
 * 1 when the whitespace-separated cmdline buffer contains the exact token,
 * 0 otherwise. */
int probe_cmdline_has_token(const char *cmdline, const char *token);

/* 0 when the BOOTED kernel satisfies the agent's IMA floor */
int probe_booted_ima_ok(void);

/* 0 when the running kernel enforces module signatures */
int probe_module_sig_enforced(void);

/* 0 when lockdown is [integrity] or [confidentiality] */
int probe_lockdown_restrictive(void);

/* Derives the post-lock PCR14 value installed by the initramfs lock:
 * SHA256(baseline || SHA256("LOTA-PCR14-INITRAMFS-LOCK-v1")), where baseline
 * is the pre-extend PCR14 lota-pcr14-lock persisted this boot (the shim MOK
 * measurement, or 0^32 on a UEFI host whose boot chain never measured
 * PCR14). */
void probe_pcr14_lock_value(uint8_t out[PROBE_HASH_SIZE]);

/* Path-parameterized variant behind the fixed-path wrapper above;
 * baseline_path is the file lota-pcr14-lock writes the pre-extend PCR14 to.
 * Lets tests pin the derivation against known baseline. */
void probe_pcr14_lock_value_at(const char *baseline_path,
			       uint8_t out[PROBE_HASH_SIZE]);

/* Pure parser:
 * Hex string (exactly 2*n chars, case-insensitive) to bytes.
 * 0 or -EINVAL. */
int probe_hex_to_bytes(const char *hex, uint8_t *out, size_t n);

/* Classifies the live PCR14 from sysfs (/sys/class/tpm/tpm0/pcr-sha256/14)
 * enum probe_pcr14 or -errno (-ENOENT: no TPM 2.0 sysfs PCR interface) */
int probe_pcr14_state(void);

/* Mirrors the agent's tpm_device_selinux_label_ok():
 * 0 when every present /dev/tpm{rm,}0 carries lota_tpm_device_t (or the host
 * has no SELinux xattrs), -ENOENT when no TPM device exists, -EPERM on a wrong
 * label, other -errno on read failure */
int probe_selinux_tpm_label(void);

/* Parses a DER certificate and reports whole days until notAfter
 * (negative = expired).
 * 0 or -errno (-ENOENT: not enrolled, EBADMSG: unparseable) */
int probe_cert_days_left(const char *der_path, int *days_left);

/* Pure parser:
 * 1 when a "key = value" line for the exact key exists
 * (comments and leading whitespace skipped), 0 otherwise */
int probe_conf_buf_has_key(const char *buf, const char *key);

/* File-backed wrapper for probe_conf_buf_has_key().
 * 1/0 or -errno */
int probe_conf_has_key(const char *conf_path, const char *key);

/* 1 when this host has opted into unattended boot-path bring-up,
 * either by the marker file at path or by LOTA_AUTO_BRINGUP=1 in the environment.
 *
 * Exactly "1": package hook runs with whatever environment the transaction had,
 * and reading "0" or "false" as consent is how a host ends up with boot path
 * nobody chose. */
int probe_auto_bringup_at(const char *path);

#endif /* LOTA_INSTALL_PROBE_H */
