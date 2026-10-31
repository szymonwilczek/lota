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

#include "install.h"

#define PROBE_HASH_SIZE 32

/*
 * What the installer learned about the agent's units.
 *
 * Running and enabled are separate questions and a host can answer them
 * differently: one that was started by hand, or through socket activation,
 * enforces now and not after the next reboot.
 */
struct probe_service_state {
	int agent_active;
	int agent_enabled;
	int socket_enabled;
	int attest_enabled;
};

/*
 * Verdict for the agent-service stage, and the sentence explaining it.
 *
 * Pure: the caller does the asking, this decides.
 * Satisfied only when the agent is active and all three units are enabled,
 * so enforcement survives the next boot.
 */
enum stage_state probe_agent_service_stage(const struct probe_service_state *s,
					   char *note, size_t cap);

/* Where the kernel publishes the policy it loaded */
#define PROBE_IMA_POLICY_PATH "/sys/kernel/security/ima/policy"

/* What the loaded IMA policy says about this host, as the scope stage reads it */
struct probe_ima_scope {
	/* PROBE_IMA_SCOPE_EXEC, PROBE_IMA_SCOPE_NONE, or -errno when the policy
	 * could not be read at all */
	int scope;
	/* the policy appraises policy writes against a signature,
	 * so an unsigned rule set cannot be loaded on this host at all */
	int policy_signed;
	/* Secure Boot is on, which is what decides the appraisal mode:
	 * the kernel discards ima_appraise= on such a host and appraises in
	 * enforce, so a rule set loaded here refuses whatever it cannot verify */
	int secureboot;
	/* the agent binary carries a signature the kernel can appraise,
	 * which is the evidence that this host has a signing route at all */
	int agent_signed;
	/* fs-verity holds the agent binary;
	 * decides if missing scope stops the install */
	int agent_verity;
	/* the probe ran privileged, which decides whether an unreadable policy
	 * is a kernel that publishes none or a caller that may not look */
	int is_root;
};

/*
 * Verdict for the IMA appraisal-scope stage, and the sentence explaining it.
 *
 * Pure: the caller does the reading, this decides. The gate this stage exists
 * to satisfy lives in the agent, and an unreadable policy is deliberately decided
 * the way the agent decides it -- unknown scope leaves the appraisal mode
 * deciding on both sides, so the installer never blocks a host the agent would
 * have started on.
 *
 * Where the scope is missing the stage reports it; it does not widen it. Every
 * rule that reaches an executable appraises every executable the rule matches,
 * appraisal on a Secure Boot host runs in enforce whatever the cmdline asked
 * for, and a host whose files carry no signature would refuse them all at the
 * next boot. What is missing is a signing route, and that is the
 * distribution's or the operator's to supply.
 *
 * Whether that stops the install is lota_ima_scope_is_advisory(), the rule
 * the agent starts on.
 */
enum stage_state probe_ima_scope_stage(const struct probe_ima_scope *s,
				       char *note, size_t cap);

/* What the loaded policy appraises.
 * Missing file is -ENOENT from the read */
enum probe_ima_scope_state {
	PROBE_IMA_SCOPE_EXEC = 0, /* a rule reaches an executable */
	PROBE_IMA_SCOPE_NONE = 1, /* readable, and appraises no executable */
};

/*
 * Reads the loaded IMA policy: PROBE_IMA_SCOPE_EXEC or PROBE_IMA_SCOPE_NONE,
 * or -errno when the file could not be read (a kernel built without
 * CONFIG_IMA_READ_POLICY publishes nothing).
 * Sets @policy_signed when the policy appraises policy writes against a signature.
 */
int probe_ima_policy_scope(const char *policy_path, int *policy_signed);

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

/* enum probe_verity (PROBE_VERITY_ENABLED is 0), or -errno on hard
 * failure (file missing, permission) */
int probe_fsverity_state(const char *path);

/* Enables fs-verity (SHA-256, 4K blocks) on the file.
 * 0 or -errno; EOPNOTSUPP/-ENOTTY mean the filesystem lacks the feature. */
int probe_fsverity_enable(const char *path);

/*
 * Pure: reads one line of a runtime manifest -- the object list a title captures
 * with `demo_anticheat --print-runtime-objects` or the equivalent for its own
 * binary set.
 *
 * Writes the path into out and returns 1 when the line names one,
 * 0 when the line is blank or a '#' comment,
 * and -EINVAL when it is neither
 * (relative path, a path carrying a '..' component, or one longer than out holds).
 *
 * Absolute paths that read as what they resolve to, only:
 * the manifest comes from whoever ships the title and is acted on with privilege,
 * so a path resolved against a working directory or walked back out of the directory
 * it names is refused rather than guessed at.
 */
int probe_manifest_line(const char *line, char *out, size_t cap);

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
 * Writes the Secure-Boot remediation somebody at the machine can act on
 * without a manual:
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
 * Informational only: it tells whoever is installing whether a future
 * self-service
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

/*
 * Pure: 1 when IMA appraisal blocks on an integrity failure, 0 when it does
 * not, mirroring the agent's bpf_loader_ima_appraisal_active() mode half.
 *
 * A Secure Boot kernel discards ima_appraise= and keeps its own blocking default,
 * so on such a host the parameter says nothing about the mode and appending it
 * changes nothing. Only where the kernel honours the parameter does the cmdline
 * decide.
 */
int probe_ima_mode_blocking(int secureboot, const char *cmdline);

/* 0 when the running kernel enforces module signatures */
int probe_module_sig_enforced(void);

/* 0 when lockdown is [integrity] or [confidentiality] */
int probe_lockdown_restrictive(void);

/* Where lota-pcr14-lock persists the pre-extend PCR14;
 * read by the fixed-path helpers below */
const char *probe_pcr14_baseline_path(void);

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

/* Pure parser: copy @key's value into @out and return 1;
 * 0 with @out empty when absent, empty or too long */
int probe_conf_buf_value(const char *buf, const char *key, char *out,
			 size_t cap);

/* File-backed wrapper for probe_conf_buf_value() */
int probe_conf_value(const char *conf_path, const char *key, char *out,
		     size_t cap);

/* File-backed wrapper for probe_conf_buf_has_key().
 * 1/0 or -errno */
int probe_conf_has_key(const char *conf_path, const char *key);

/* Pure parser:
 * How many [profile "name"] sections the configuration carries.
 * Publisher profiles are the agent's target list, so the count is what
 * decides where this host reports */
int probe_conf_buf_profile_count(const char *buf);

/* File-backed wrapper for probe_conf_buf_profile_count().
 * count or -errno */
int probe_conf_profile_count(const char *conf_path);

/* How the self-check proves this host attests. */
enum probe_selfcheck_plan {
	/* Nobody named a verifier: the first title launch performs the round */
	SELFCHECK_SKIP_NO_VERIFIER,
	/* One verifier named and no profiles: one round against it, then exit */
	SELFCHECK_ONE_ROUND,
	/* Publisher profiles are the target list, so no single verifier can be
	 * named -- the agent refuses that combination */
	SELFCHECK_PUBLISHERS_REPORT,
};

/* Pure decision from the two inputs the stage has */
enum probe_selfcheck_plan probe_selfcheck_plan(const char *verifier,
					       int profile_count);

/* 1 when this host has opted into unattended boot-path bring-up,
 * either by the marker file at path or by LOTA_AUTO_BRINGUP=1 in the environment.
 *
 * Exactly "1": package hook runs with whatever environment the transaction had,
 * and reading "0" or "false" as consent is how a host ends up with boot path
 * nobody chose. */
int probe_auto_bringup_at(const char *path);

/* Kernels installed on this host, one entry each.
 *
 * The boot-path work is only done when every one of them carries it:
 * the cmdline floor is armed with --update-kernel=ALL, and the PCR 14 lock
 * has to match that scope or selecting an older kernel from the GRUB menu
 * -- the reason more than one is kept -- boots a host with no commitment.
 *
 * Eight is above Fedora's installonly_limit of three with room for a fleet
 * that raised it; a host holding more is enumerated up to the cap. */
#define PROBE_MAX_KERNELS 8
#define PROBE_KERNEL_RELEASE_MAX 96
#define PROBE_KERNEL_IMAGE_MAX 320

struct probe_kernel_image {
	char release[PROBE_KERNEL_RELEASE_MAX]; /* uname -r of that kernel */
	char image[PROBE_KERNEL_IMAGE_MAX]; /* its initramfs */
};

/* A kernel counts when /lib/modules holds its tree and /boot holds its initramfs.
 * A modules tree with no image is what a half-removed kernel leaves
 * and has nothing to lock; a rescue image belongs to no tree of its own and is
 * not regenerated by dracut, so neither is enumerated here.
 *
 * Returns 0 with *count set (0 when the host has no modules directory at all,
 * which is not an error), or a negative errno. */
int probe_installed_kernels_at(const char *modules_dir, const char *boot_dir,
			       struct probe_kernel_image *out, size_t max,
			       size_t *count);

/* Fixed-path wrapper over /lib/modules and /boot */
int probe_installed_kernels(struct probe_kernel_image *out, size_t max,
			    size_t *count);

/* 1 when the initramfs lock helper ran this boot, 0 when it did not.
 *
 * The helper writes the pre-extend PCR 14 to the /run handoff as its first act,
 * so the file's presence is the evidence.
 * Without it, a PCR 14 the installer cannot derive is the platform's -- shim
 * measures the MOK variables into it on every Secure Boot host -- and not
 * residue from a LOTA install. */
int probe_pcr14_lock_ran(void);
int probe_pcr14_lock_ran_at(const char *baseline_path);

/*
 * 1 when the snapshot at @snapshot_path records a pause (PCR 14 spent on an
 * operator-requested shutdown) and @live still holds the value it left, else 0.
 * Mirrors tpm_classify_pcr14(); the result only picks the operator's sentence.
 */
int probe_agent_paused_at(const char *snapshot_path,
			  const uint8_t live[PROBE_HASH_SIZE]);

/* probe_agent_paused_at() on the agent's snapshot and the live PCR 14 */
int probe_agent_paused(void);

/*
 * Verdict for the reboot barrier, and the sentence explaining it.
 *
 * Pure: the caller reads PCR 14, the handoff and the service state; this decides.
 * @pcr_state is an enum probe_pcr14, @lock_ran, @agent_active, @agent_failed
 * and @agent_paused are 1/0.
 *
 * A first install on a Secure Boot host and a host carrying a commitment from
 * an earlier agent run look identical in the register and need the same reboot;
 * they are told apart by whether the lock ran, and only ever differ in what the
 * operator is told.
 */
enum stage_state probe_pcr14_barrier_stage(int pcr_state, int lock_ran,
					   int agent_active, int agent_failed,
					   int agent_paused, char *note,
					   size_t cap);

/*
 * One file the operator named on the command line.
 *
 * The flag travels with the path because the refusal has to name it: an operator
 * who typed one of several file-taking options needs to know which of them did
 * not resolve, and the path alone does not say.
 */
struct probe_named_file {
	const char *flag; /* the option as it is spelled, e.g. "--ca-cert" */
	const char *path; /* what the operator typed, or NULL if they did not */
};

/*
 * probe_named_files - the first named file that cannot be read
 * @files: what the operator named
 * @count: how many entries @files holds
 * @note: sentence for the operator
 * @cap: size of @note
 *
 * Returns 0 when every named file is readable, or -errno for the first that is not,
 * with @note naming the flag, the path and the reason.
 * A NULL path is skipped: an option the operator did not use has nothing to check,
 * and only a path somebody typed can be a typo. An option with a built-in default
 * is passed as NULL unless it was named, since a default that is absent is a fact
 * about the host and not a mistake.
 *
 * Pure in the sense the other probes are: it asks the filesystem and decides,
 * so the caller does nothing but print.
 */
int probe_named_files(const struct probe_named_file *files, size_t count,
		      char *note, size_t cap);

#endif /* LOTA_INSTALL_PROBE_H */
