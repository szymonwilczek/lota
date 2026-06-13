/* SPDX-License-Identifier: MIT
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

/* PCR14 state relative to the initramfs lock */
enum probe_pcr14 {
	PROBE_PCR14_LOCK_ONLY = 0, /* lock ran, agent not yet extended */
	PROBE_PCR14_ZERO,	   /* lock did not run this boot */
	PROBE_PCR14_OTHER,	   /* extended past the lock (agent or stale) */
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

/* 1 = Secure Boot enabled, 0 = disabled/setup mode,
 * -ENOENT = no UEFI (BIOS/CSM host), other -errno on read failure. */
int probe_secureboot(void);

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

/* Derives the constant PCR14 value installed by the initramfs lock:
 * SHA256(0^32 || SHA256("LOTA-PCR14-INITRAMFS-LOCK-v1")) */
void probe_pcr14_lock_value(uint8_t out[PROBE_HASH_SIZE]);

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

#endif /* LOTA_INSTALL_PROBE_H */
