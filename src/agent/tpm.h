/* SPDX-License-Identifier: MIT */
/*
 * LOTA - TPM 2.0 Operations Module
 * Handles TPM context, PCR reading, and Quote generation
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_TPM_H
#define LOTA_TPM_H

/* Umbrella test gate -- see src/agent/agent_internal.h. */
#if defined(LOTA_INTERNAL_TESTS) && !defined(LOTA_TPM_TESTING)
#define LOTA_TPM_TESTING 1
#endif

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_tcti.h>
#include <time.h>
#include <tss2/tss2_common.h>
#include <tss2/tss2_tpm2_types.h>

#include "../../include/lota.h"
#include "profile.h"
#include "quote.h"

struct tpm_quote_response;

#define TPM_DEVICE_PATH "/dev/tpmrm0"

/*
 * LOTA-private error codes, above MAX_ERRNO (4095).
 * Print them through tpm_strerror().
 *
 * TPM2_RC_LOCKOUT. Dispatch on tpm_is_locked_out(): this value is for the log.
 */
#define LOTA_ERR_TPM_LOCKED 4097

/*
 * TPM2_RC_AUTH_FAIL, TPM2_RC_BAD_AUTH, TPM2_RC_NV_AUTHORIZATION.
 * Only TPM2_RC_AUTH_FAIL can count toward the dictionary-attack counter.
 */
#define LOTA_ERR_TPM_AUTH_FAIL 4098

/*
 * TPM2_RC_POLICY_FAIL, TPM2_RC_PCR_CHANGED: the policy of a sealed object was
 * not satisfied.
 */
#define LOTA_ERR_TPM_POLICY_FAIL 4099

/**
 * tpm_unseal_boot_state_unknown() - Print the boot-state hint after an unseal?
 * @err: Return value of the failed unseal.
 *
 * -EBADMSG is a bad blob.
 *
 * Return: true for any other negative @err.
 */
static inline bool tpm_unseal_boot_state_unknown(int err)
{
	if (err >= 0)
		return false;
	return err != -EBADMSG;
}

/**
 * tpm_strerror() - Describe a tpm_*() return value.
 * @err: errno or LOTA-private code, either sign; 0 reads "success".
 *
 * Return: the private code's own string, or strerror() for the rest.
 */
const char *tpm_strerror(int err);

/*
 * EK Certificate handle (RSA 2048)
 */
#define TPM_EK_CERT_HANDLE 0x01c00002

/*
 * EK certificate chain index: the intermediates between the EK certificate
 * and a published root, one blob with the certificates end to end.
 * Optional: tpm_get_ek_cert_chain() reads an absent index as -ENOENT.
 */
#define TPM_EK_CERT_CHAIN_HANDLE 0x01c00100

/*
 * AIK handle on a host with no publisher profile; aik_handle in lota.conf
 * overrides it. 0x81010001 is the EK (TPM_EK_RSA_HANDLE in tpm.c).
 */
#define TPM_AIK_HANDLE 0x81010002

/*
 * Persistent handles for per-publisher AIKs.
 *
 * One AIK per publisher: a shared key would let publishers correlate the
 * host across titles.
 *
 * Slots are shared with everything else on the machine, so the range is bounded
 * and a slot holding an object this host did not record is skipped.
 *
 * The range starts above the EK (0x81010001), the profile-less AIK (0x81010002)
 * and the seal storage primary (0x81010003).
 * A profile's handle is recorded in the profile: a position in lota.conf would
 * shift every later profile onto another publisher's key when one is removed.
 */
#define TPM_AIK_PROFILE_HANDLE_BASE 0x81010010
#define TPM_AIK_PROFILE_HANDLE_COUNT LOTA_PROFILE_MAX_AIK_HANDLES

/*
 * Optional persistent handle for the seal storage primary.
 *
 * By default seal and unseal derive the primary per operation with
 * Esys_CreatePrimary, which costs one key derivation per call and no slot.
 * --seal-persist-primary with seal_persistent_primary in lota.conf reuses
 * the persisted object. Both are the same key (owner hierarchy, fixed template,
 * empty unique), so blobs sealed either way unseal the other way.
 */
#define TPM_SEAL_PRIMARY_HANDLE 0x81010003

/* Hash algorithm for PCR bank */
#define TPM_HASH_ALG TPM2_ALG_SHA256

/* AIK metadata file magic and version */
#define TPM_AIK_META_MAGIC 0x4D4B4941 /* "AIKM" */
#define TPM_AIK_META_VERSION 1

/* How the key this record describes was derived */
#define TPM_AIK_KEY_DERIVATION_SHARED 0
#define TPM_AIK_KEY_DERIVATION_PER_PUBLISHER 2

/* Default metadata path (install target creates /var/lib/lota/) */
#define TPM_AIK_META_PATH "/var/lib/lota/aik_meta.dat"

/*
 * PCR14 clock-state snapshot.
 *
 * The agent extends PCR14 with an empty password, so the register does not say
 * who extended it. A successful commitment records resetCount, the post-extend
 * PCR14 and self_hash; the next start compares them with the TPM and the
 * running binary to attribute a mismatch (enum tpm_pcr14_state).
 */
#define TPM_CLOCK_STATE_PATH "/var/lib/lota/clock_state.dat"
#define TPM_CLOCK_STATE_MAGIC 0x4C434C4B /* "LCLK" */
#define TPM_CLOCK_STATE_VERSION 1

/*
 * Bit flags on the snapshot.
 *
 * Set when tpm_extend_boot_commitment() saves its snapshot.
 */
#define LOTA_CLOCK_STATE_FLAG_INITRAMFS_LOCK (1U << 0)

/*
 * Set on the snapshot written when the agent poisons PCR14 before unloading
 * BPF, so the next start reports TPM_PCR14_SPENT_BY_SHUTDOWN.
 * Selects a refusal only: the accepting verdicts are decided before it is read.
 */
#define LOTA_CLOCK_STATE_FLAG_SHUTDOWN_POISON (1U << 1)

/*
 * PCR14 boot-commitment snapshot, fixed layout.
 * flags is the first byte of the reserved tail; 31 bytes stay reserved.
 * The loader answers -EINVAL for another version and the caller carries on
 * with no snapshot.
 */
struct lota_clock_state {
	uint32_t magic;
	uint32_t version;
	uint32_t reset_count; /* TPM clockInfo.resetCount at last extend */
	uint32_t restart_count; /* TPM clockInfo.restartCount at last extend */
	uint8_t pcr14[LOTA_HASH_SIZE]; /* PCR14 after the extend */
	uint8_t self_hash[LOTA_HASH_SIZE]; /* self_hash used for the extend */
	int64_t saved_at; /* time_t when the snapshot was written */
	uint8_t flags;
	uint8_t _reserved[31];
} __attribute__((packed));

#define TPM_AIK_AUTH_MAGIC 0x41545541 /* "AUTA" */
#define TPM_AIK_AUTH_VERSION 1
#define TPM_AIK_AUTH_SIZE 32

struct aik_auth_record {
	uint32_t magic;
	uint32_t version;
	uint16_t size;
	uint8_t auth[TPM_AIK_AUTH_SIZE];
	uint8_t _reserved[22];
} __attribute__((packed));

/* AIK metadata on disk, at TPM_AIK_META_PATH or in the publisher profile. */
struct aik_metadata {
	uint32_t magic;
	uint32_t version;
	uint8_t _unused[24]; /* zero, ignored on read */
	uint8_t key_derivation; /* TPM_AIK_KEY_DERIVATION_* */
	uint8_t _reserved[63];
} __attribute__((packed));

/*
 * What PCR14 at agent startup means. tpm_classify_pcr14() takes values
 * the caller read and performs no I/O, so the rules run without a TPM.
 */
enum tpm_pcr14_state {
	/* Register holds the initramfs lock value: extend */
	TPM_PCR14_AWAITING_EXTEND = 0,
	/* Register carries this binary's commitment: nothing to extend */
	TPM_PCR14_ALREADY_COMMITTED,
	/* Bare baseline, or no baseline handoff: the lock did not run */
	TPM_PCR14_LOCK_MISSING,
	/*
	 * Snapshot carries LOTA_CLOCK_STATE_FLAG_SHUTDOWN_POISON and
	 * the register matches it. Refused; the message asks for a reboot.
	 */
	TPM_PCR14_SPENT_BY_SHUTDOWN,
	/*
	 * Register matches the snapshot, another binary is running.
	 * Put the committed binary back, or install this build and reboot.
	 */
	TPM_PCR14_BINARY_CHANGED,
	/*
	 * resetCount above the snapshot's, and the register holds
	 * a commitment or an unexpected value
	 */
	TPM_PCR14_TAMPERED_BEFORE_START,
	/* resetCount unchanged, the register differs from the snapshot */
	TPM_PCR14_MUTATED_IN_SESSION,
	/*
	 * Register and binary match the snapshot, the derivation misses:
	 * the /run baseline handoff moved (or the snapshot was forged)
	 */
	TPM_PCR14_HANDOFF_CHANGED,
	/* Unexpected value and no snapshot, or a malformed observation */
	TPM_PCR14_UNATTRIBUTABLE,
	/* TPM reports a lower resetCount than the snapshot recorded */
	TPM_PCR14_STATE_ROLLBACK,
};

/* TPM context: ESYS context and session state. */
struct tpm_context {
	ESYS_CONTEXT *esys_ctx;
	TSS2_TCTI_CONTEXT *tcti_ctx;
	bool tcti_from_loader;
	bool initialized;

	/* Optional explicit kernel image path override */
	char kernel_path_override[PATH_MAX];

	/* AIK persistent handle (configurable, default TPM_AIK_HANDLE) */
	uint32_t aik_handle;

	/* AIK record */
	struct aik_metadata aik_meta;
	bool aik_meta_loaded;

	/*
	 * Publisher named by the last successful tpm_bind_profile();
	 * empty on a host with no publisher.
	 * Creation input, so publishers hold different keys.
	 */
	char aik_profile_id[LOTA_PROFILE_ID_LEN];

	/*
	 * Set by the enrollment path, which fetches a certificate for
	 * the replaced key.
	 */
	bool aik_allow_shared_key_replace;
	char aik_meta_path[256];

	/* LOTA_AIK_META_PATH chose the path; tpm_bind_profile() keeps it */
	bool aik_meta_path_from_env;

	/* Empty selects TPM_CLOCK_STATE_PATH. Tests override it. */
	char clock_state_path[256];

	/*
	 * Name last seen at aik_handle. Handle numbers are reused across
	 * publishers; the Name ties the cached auth to the key.
	 */
	uint8_t aik_object_name[sizeof(TPMU_NAME)];
	uint16_t aik_object_name_size;
	bool aik_object_replaced; /* Name changed since the last read */

	/* AIK userAuth */
	uint8_t aik_auth[TPM_AIK_AUTH_SIZE];
	bool aik_auth_loaded;
	/*
	 * SHA-256 of Name || userAuth for the last pairs the TPM refused.
	 * A publisher switch keeps them; only init and cleanup drop them.
	 */
	uint8_t aik_auth_refused[TPM_AIK_PROFILE_HANDLE_COUNT][32];
	unsigned int aik_auth_refused_next;

	/*
	 * Dictionary-attack lockout state.
	 *
	 * A TPM call returning TPM2_RC_LOCKOUT sets lockout_active and, when
	 * that was clear, lockout_first_seen, and counts in
	 * lockout_event_count.
	 * A successful tpm_call_with_backoff() or TPM_CALL_RETRY clears the
	 * first two when TPM_PT_PERMANENT then reads without inLockout;
	 * tpm_reset_lockout_state() clears them without asking the TPM.
	 * Neither touches the count. tpm_init() zeroes all three.
	 */
	bool lockout_active;
	time_t lockout_first_seen; /* time_t; 0 if not in lockout */
	uint32_t lockout_event_count;

	/*
	 * SHA-256 of the running agent binary, set by self_measure().
	 * The boot commitment and report.system.agent_hash both use it.
	 * tpm_get_self_hash() answers -ENODATA before self_hash_ready.
	 */
	uint8_t self_hash[LOTA_HASH_SIZE];
	bool self_hash_ready;

	/*
	 * Set by tpm_extend_boot_commitment() on TPM_PCR14_ALREADY_COMMITTED
	 * and after the extend on TPM_PCR14_AWAITING_EXTEND, clear after any
	 * other verdict or a failed extend.
	 * The report builder refuses without it and mirrors it into
	 * LOTA_REPORT_FLAG_INITRAMFS_LOCK_V1.
	 */
	bool boot_commitment_locked;

	/*
	 * Verdict from the last tpm_extend_boot_commitment() call: names
	 * the refusal behind -EBADMSG. Meaningless before the first call.
	 */
	enum tpm_pcr14_state boot_commitment_state;

	/*
	 * AIK userAuth at rest (default off). seal_aik_auth keeps a copy sealed
	 * to the PCR state next to the plaintext sidecar and prefers it on
	 * load; seal_aik_auth_strict drops the sidecar.
	 */
	bool seal_aik_auth;
	bool seal_aik_auth_strict;

	/*
	 * Reuse the primary at TPM_SEAL_PRIMARY_HANDLE in seal and unseal
	 * (default off). With no object there they derive it per operation.
	 */
	bool seal_persistent_primary;

	/*
	 * Honor LOTA_TCTI, LOTA_AIK_META_PATH and LOTA_UEFI_FIRMWARE_PATH
	 * (default off): they redirect the TPM endpoint, the AIK files and the
	 * firmware check. attest_env_overrides_allowed() leaves it off for
	 * continuous attestation.
	 */
	bool allow_env_tpm_overrides;
};

/**
 * tpm_init() - Initialize a TPM context.
 * @ctx: Context to initialize; pair with tpm_cleanup().
 *
 * Opens /dev/tpmrm0. With @ctx->allow_env_tpm_overrides, LOTA_TCTI goes to the
 * TSS2 TCTI loader instead and LOTA_AIK_META_PATH redirects the AIK files.
 *
 * Return: 0, -EINVAL on a LOTA_AIK_META_PATH that is relative, holds ".." or
 * a disallowed character, or another negative errno.
 */
int tpm_init(struct tpm_context *ctx);

/**
 * tpm_cleanup() - Release a TPM context.
 * @ctx: Context to clean up.
 */
void tpm_cleanup(struct tpm_context *ctx);

/**
 * tpm_read_pcr() - Read one PCR.
 * @ctx: Initialized TPM context.
 * @pcr_index: PCR index, 0-23.
 * @hash_alg: Bank to read.
 * @value: LOTA_HASH_SIZE bytes.
 *
 * Return: 0, -EINVAL on an index above 23, or a negative errno.
 */
int tpm_read_pcr(struct tpm_context *ctx, uint32_t pcr_index,
		 TPM2_ALG_ID hash_alg, uint8_t *value);

/**
 * tpm_read_pcrs_batch() - Read several PCRs from the SHA-256 bank.
 * @ctx: Initialized TPM context.
 * @pcr_mask: PCRs to read; bit 0 is PCR 0.
 * @values: Receives the values; PCRs outside @pcr_mask read zero.
 *
 * Return: 0, -ENODATA when the TPM returns none of the PCRs still to read, or
 * a negative errno.
 */
int tpm_read_pcrs_batch(struct tpm_context *ctx, uint32_t pcr_mask,
			uint8_t values[LOTA_PCR_COUNT][LOTA_HASH_SIZE]);

/**
 * tpm_quote() - Generate a TPM quote over a nonce.
 * @ctx: Initialized TPM context.
 * @nonce: LOTA_NONCE_SIZE bytes.
 * @pcr_mask: PCRs to include.
 * @response: Receives the attestation, signature and PCR values (see quote.h).
 *
 * Signs with the AIK at @ctx->aik_handle. An authorization the TPM refused is
 * not offered again until the stored one changes or the key is rebound.
 *
 * Return: 0, -ENOKEY with no AIK at the handle, -LOTA_ERR_TPM_AUTH_FAIL for
 * a refused authorization, or a negative errno.
 */
int tpm_quote(struct tpm_context *ctx, const uint8_t *nonce, uint32_t pcr_mask,
	      struct tpm_quote_response *response);

/**
 * tpm_provision_aik() - Make sure the AIK exists at @ctx->aik_handle.
 * @ctx: Initialized TPM context.
 *
 * The key is an RSA 2048 restricted signing key (RSASSA, SHA-256, fixedTPM),
 * a primary under the owner hierarchy, derived with an empty owner password.
 *
 * With a key at the handle:
 * - auth readable: nothing changes;
 * - auth readable, record says shared: -ENOTSUP unless
 *   tpm_aik_allow_shared_key_replace() was set, then the profile's own key;
 * - auth record present but unreadable: the load error, key left alone;
 * - no auth record: fresh auth, refused as above for a shared key.
 *
 * Return: 0 or a negative errno.
 */
int tpm_provision_aik(struct tpm_context *ctx);

/**
 * tpm_bind_profile() - Point the context at one publisher's AIK.
 * @ctx: Initialized TPM context with an ESYS connection.
 * @paths: The publisher profile, from profile_paths_from_anchor().
 *
 * Moves the metadata path, and with it the userAuth sidecars, into the profile
 * and selects the handle: the one recorded in the profile, or else the lowest
 * in the range no other profile recorded and this TPM holds no object at,
 * which it then records.
 *
 * Call after tpm_init() and before tpm_provision_aik().
 * A LOTA_AIK_META_PATH override wins over the profile's metadata path.
 *
 * A failure past the argument checks restores the publisher,
 * the handle and the metadata path and drops the cached key.
 *
 * Return: 0, -ENOSPC when the range is exhausted, or a negative errno.
 */
int tpm_bind_profile(struct tpm_context *ctx,
		     const struct profile_paths *paths);

/**
 * tpm_aik_object_replaced() - Did the key behind the AIK handle change?
 * @ctx: TPM context.
 *
 * Set when an open of the handle finds an object other than the Name recorded
 * by the last open. A failed bind or a bind to another publisher, handle or
 * metadata path forgets that Name, so a change across one goes unseen.
 * The cached auth is already dropped by then, so this is diagnostic.
 * Reading clears it.
 *
 * Return: true when set since the last read.
 */
bool tpm_aik_object_replaced(struct tpm_context *ctx);

/**
 * tpm_aik_profile_unique() - Creation input that separates publishers' keys.
 * @profile_id: SHA-256 of the profile's CA anchor SubjectPublicKeyInfo as hex,
 *              or NULL/"" for a host with no publisher.
 * @out: LOTA_HASH_SIZE bytes.
 * @out_len: Receives the meaningful length, 0 with no publisher.
 *
 * A primary key is derived from the hierarchy seed and the creation template:
 * the same template gives the same key at any handle.
 *
 * Return: 0, or -EINVAL on a wrong length or a character that is not a hex
 * digit.
 */
int tpm_aik_profile_unique(const char *profile_id, uint8_t out[LOTA_HASH_SIZE],
			   uint16_t *out_len);

/**
 * tpm_aik_key_is_shared() - Does the record describe a key with no publisher?
 * @ctx: Context bound to a publisher profile, with metadata loaded.
 *
 * No publisher identity in the template gives the same key at any handle,
 * so a relying party comparing certificates can link those profiles.
 * Enrollment creates the profile's own key.
 *
 * Return: true when key_derivation is anything but
 * TPM_AIK_KEY_DERIVATION_PER_PUBLISHER; false with no publisher or no metadata.
 */
bool tpm_aik_key_is_shared(const struct tpm_context *ctx);

/* Shared-key refusal; the attest loop appends the publisher. */
#define TPM_AIK_SHARED_KEY_ADVICE                                             \
	"This publisher's attestation key was created before each publisher " \
	"got a key of its own, so it is byte for byte the key every other "   \
	"publisher enrolled here holds. Run lota-agent --reenroll "           \
	"--publisher <their ID> to replace it; the CA certifies the new key " \
	"under the device ID this host already has."

/**
 * tpm_aik_key_present() - Does the TPM hold a key at this profile's handle?
 * @ctx: Initialized TPM context.
 *
 * Return: 1 when a key is there, 0 when not or with no TPM connection to ask,
 * negative errno when the TPM could not answer.
 */
int tpm_aik_key_present(struct tpm_context *ctx);

/**
 * tpm_aik_replacing_shared_key() - Would enrollment replace a shared key?
 * @ctx: Context with metadata loaded.
 * @key_present: What tpm_aik_key_present() answered.
 *
 * The record alone is not a key: it can outlive the key it describes.
 *
 * Return: true when tpm_aik_key_is_shared() and @key_present is 1.
 */
bool tpm_aik_replacing_shared_key(const struct tpm_context *ctx,
				  int key_present);

/**
 * tpm_aik_provisioning_orphans_cert() - Would provisioning orphan the cert?
 * @key_present: What tpm_aik_key_present() answered before provisioning.
 * @cert_stored: An enrollment certificate is on disk for this profile.
 * @cert_match: What aik_cert_matches_key() answered for the key at the handle
 *              now: 0 when the certificate names it, -EKEYREJECTED when it
 *              names another, another negative errno when not asked.
 *
 * TPM2_Clear removes the keys and leaves the profile directory, so provisioning
 * makes another key at the recorded handle, one the certificate does not name.
 *
 * The AIK is derived, so an evicted handle comes back holding the same key.
 * An absent key alone orphans nothing.
 *
 * Return: true when @key_present is 0, @cert_stored, and @cert_match is
 * -EKEYREJECTED.
 */
bool tpm_aik_provisioning_orphans_cert(int key_present, bool cert_stored,
				       int cert_match);

/**
 * tpm_aik_allow_shared_key_replace() - Let provisioning replace a shared key.
 * @ctx: Initialized context.
 * @allow: True on the enrollment path, false everywhere else.
 *
 * The replacement changes the key the CA certificate names; the enrollment
 * path fetches a certificate for it.
 */
void tpm_aik_allow_shared_key_replace(struct tpm_context *ctx, bool allow);

/**
 * tpm_hash_fd() - SHA-256 of an open regular file.
 * @fd: Open regular file, positioned at its start.
 * @hash: LOTA_HASH_SIZE bytes.
 *
 * Reads st_size bytes from the current position.
 *
 * Return: 0, -EINVAL on a non-regular file, -EIO when the read does not end
 * exactly at st_size, or a negative errno.
 */
int tpm_hash_fd(int fd, uint8_t *hash);

/**
 * tpm_hash_file() - SHA-256 of a regular file, with no TPM involved.
 * @path: File to hash; a symlink is refused with -ELOOP.
 * @hash: LOTA_HASH_SIZE bytes.
 *
 * Return: 0, or a negative errno; see tpm_hash_fd().
 */
int tpm_hash_file(const char *path, uint8_t *hash);

/**
 * tpm_set_kernel_path() - Name the kernel image explicitly.
 * @ctx: TPM context.
 * @path: Absolute path, or NULL/empty to clear.
 *
 * Return: 0, -EINVAL on a relative path, -ENAMETOOLONG.
 */
int tpm_set_kernel_path(struct tpm_context *ctx, const char *path);

/**
 * tpm_kernel_path_is_overridden() - Has a configuration named the kernel image?
 * @ctx: TPM context.
 *
 * The override selects nothing about a measured-boot PCR; a caller reporting
 * on one asks this in order to say so.
 *
 * Return: true when a path is set.
 */
bool tpm_kernel_path_is_overridden(const struct tpm_context *ctx);

/**
 * tpm_get_current_kernel_path() - Find the running kernel's image.
 * @ctx: TPM context with the optional override.
 * @buf: Receives the path.
 * @buf_len: Size of @buf.
 *
 * The override, or else /boot/vmlinuz-<uname release>.
 *
 * Return: 0, or a negative errno when the file is unreadable or @buf too small.
 */
int tpm_get_current_kernel_path(struct tpm_context *ctx, char *buf,
				size_t buf_len);

/**
 * tpm_self_test() - Run the TPM self-test.
 * @ctx: Initialized TPM context.
 *
 * Return: 0 or a negative errno.
 */
int tpm_self_test(struct tpm_context *ctx);

/**
 * tpm_pcr_extend() - Extend one PCR in the SHA-256 bank.
 * @ctx: Initialized TPM context.
 * @pcr_index: PCR index, 0-23.
 * @digest: LOTA_HASH_SIZE bytes.
 *
 * Return: 0, -EINVAL on an index above 23, or a negative errno.
 */
int tpm_pcr_extend(struct tpm_context *ctx, uint32_t pcr_index,
		   const uint8_t *digest);

/**
 * tpm_boot_commitment_digest() - Compute the boot commitment for PCR14.
 * @self_hash: SHA-256 of the running agent binary.
 * @out_digest: LOTA_HASH_SIZE bytes.
 *
 * A domain tag and the agent hash. A quote obfuscates resetCount and
 * restartCount per signing key, so a digest over them would differ between
 * keys.
 * Documentation/security/threat-model.rst has what the register binds.
 *
 * Return: 0 or a negative errno.
 */
int tpm_boot_commitment_digest(const uint8_t self_hash[], uint8_t out_digest[]);

/**
 * tpm_initramfs_lock_digest() - Digest the initramfs lock helper extends with.
 * @out_digest: LOTA_HASH_SIZE bytes.
 *
 * SHA256("LOTA-PCR14-INITRAMFS-LOCK-v1"). PCR14 ends up at
 * SHA256(baseline || digest), the baseline being what the platform already
 * measured there. A constant, so a verifier derives the register from
 * the event-log baseline alone.
 *
 * Four implementations stay in step, none taking a counter: this one,
 * the helper (src/initramfs/lota-pcr14-lock.c), probe_pcr14_lock_value_at()
 * (installer/probe.c) and DeriveInitramfsLockPCR14()
 * (src/verifier/verify/baseline.go).
 *
 * Return: 0 or a negative errno.
 */
int tpm_initramfs_lock_digest(uint8_t out_digest[]);

/**
 * tpm_derive_locked_pcr14() - PCR14 after the lock-then-extend chain.
 * @self_hash: SHA-256 of the agent binary that commits.
 * @baseline: PCR14 content the initramfs lock extended on.
 * @out: LOTA_HASH_SIZE bytes.
 *
 * SHA-256(SHA-256(baseline || lock_commit) || boot_commit), no TPM or file
 * access. No counter enters it, so every relying party derives the same value.
 * src/verifier/verify/baseline.go mirrors it.
 *
 * Return: 0 or a negative errno.
 */
int tpm_derive_locked_pcr14(const uint8_t self_hash[],
			    const uint8_t baseline[LOTA_HASH_SIZE],
			    uint8_t out[LOTA_HASH_SIZE]);

/*
 * Input to tpm_classify_pcr14(), all of it read by the caller.
 * Pointers are LOTA_HASH_SIZE buffers; @prev is NULL with no usable snapshot.
 */
struct tpm_pcr14_observation {
	const uint8_t *current; /* PCR14 as the TPM reports it now */
	const uint8_t *baseline; /* pre-LOTA platform value */
	const uint8_t *lock_value; /* baseline + initramfs lock extend */
	const uint8_t *expected_locked; /* lock value + boot commitment */
	const uint8_t *self_hash; /* hash of the running binary */
	/*
	 * TPM's counters for this run. reset_count against the snapshot tells
	 * a restart within this boot from a TPM reset.
	 */
	uint32_t reset_count;
	uint32_t restart_count;
	const struct lota_clock_state *prev;
	/*
	 * Whether the initramfs lock helper ran this boot: the baseline handoff
	 * it writes is present.
	 *
	 * On a shim host PCR 14 carries the MOK measurement and an absent
	 * handoff reads as 0^32, so the baseline comparison misses a boot
	 * with no lock.
	 *
	 * Selects a refusal only: the accepting verdicts are decided first.
	 */
	int lock_ran;
};

/*
 * What a boot-commitment call left behind: it extended PCR 14, or the register
 * already carried the commitment. Both are success. A start that finds
 * the commitment has not spent the boot, so it costs no reboot.
 */
enum tpm_boot_commitment_outcome {
	/* This call extended PCR14 with the commitment */
	TPM_BOOT_COMMITMENT_EXTENDED = 0,
	/* The register already carried it */
	TPM_BOOT_COMMITMENT_ALREADY_HELD,
};

/**
 * tpm_boot_commitment_outcome() - What a successful extend call did.
 * @state: Verdict tpm_extend_boot_commitment() left on the context.
 *
 * Return: TPM_BOOT_COMMITMENT_ALREADY_HELD for TPM_PCR14_ALREADY_COMMITTED,
 * TPM_BOOT_COMMITMENT_EXTENDED otherwise.
 */
enum tpm_boot_commitment_outcome
tpm_boot_commitment_outcome(enum tpm_pcr14_state state);

/**
 * tpm_classify_pcr14() - Decide what the observed PCR14 value means.
 * @obs: Fully populated observation.
 *
 * No TPM access, file access or logging; the caller prints the message and
 * extends. The accepting verdicts compare the register with derivations.
 *
 * A commitment already present is refused when the snapshot records a lower
 * resetCount: after a TPM reset the register should hold the lock value here.
 *
 * Return: the verdict; TPM_PCR14_UNATTRIBUTABLE for a malformed observation.
 */
enum tpm_pcr14_state
tpm_classify_pcr14(const struct tpm_pcr14_observation *obs);

/**
 * tpm_extend_boot_commitment() - Bind PCR14 to the agent binary.
 * @ctx: Initialized TPM context.
 * @self_hash: SHA-256 of the running agent binary.
 *
 * Classifies the register with tpm_classify_pcr14(), leaves the verdict in
 * @ctx->boot_commitment_state, extends with tpm_boot_commitment_digest() on
 * TPM_PCR14_AWAITING_EXTEND and skips on TPM_PCR14_ALREADY_COMMITTED.
 *
 * The TPM's counters come from TPM2_ReadClock and enter no digest, for
 * attribution only. A quote obfuscates resetCount and restartCount per signing
 * key, so a snapshot taken under one publisher's AIK would read as an attack
 * under the next.
 *
 * Return: 0, -ENOTSUP on a non-UEFI host, -EBADMSG on any other verdict, or
 * a negative errno.
 */
int tpm_extend_boot_commitment(struct tpm_context *ctx,
			       const uint8_t self_hash[]);

/**
 * tpm_get_self_hash() - Return the agent hash self_measure() captured.
 * @ctx: Initialized TPM context.
 * @out: LOTA_HASH_SIZE bytes.
 *
 * The hash tpm_extend_boot_commitment() folded into PCR14. Report builders read
 * it here, so report.system.agent_hash and the commitment use the same bytes.
 *
 * Return: 0, or -ENODATA before self_measure().
 */
int tpm_get_self_hash(const struct tpm_context *ctx, uint8_t out[]);

/**
 * tpm_clock_state_load() - Read the PCR14 snapshot.
 * @ctx: TPM context; @ctx->clock_state_path, or TPM_CLOCK_STATE_PATH if empty.
 * @out: Filled on success.
 *
 * Return: 0, -ENOENT with no snapshot, which is not an error, -EINVAL on
 * a truncated file, wrong magic or unsupported version, or a negative errno.
 */
int tpm_clock_state_load(const struct tpm_context *ctx,
			 struct lota_clock_state *out);

/**
 * tpm_clock_state_save() - Persist the snapshot for the next agent run.
 * @ctx: TPM context selecting the path, as tpm_clock_state_load().
 * @in: Record to write.
 *
 * Goes through a temporary file, fsync and rename, so a crash leaves no partial
 * record.
 *
 * Return: 0 or a negative errno.
 */
int tpm_clock_state_save(const struct tpm_context *ctx,
			 const struct lota_clock_state *in);

/**
 * tpm_get_aik_public() - Export the AIK public key as DER SubjectPublicKeyInfo.
 * @ctx: Initialized TPM context.
 * @buf: Output buffer; LOTA_MAX_AIK_PUB_SIZE is enough.
 * @buf_size: Size of @buf.
 * @out_size: Receives the exported size.
 *
 * Return: 0, -ENOKEY with no AIK, -ENOSPC on a small @buf, -EINVAL on
 * a non-RSA key, or a negative errno.
 */
int tpm_get_aik_public(struct tpm_context *ctx, uint8_t *buf, size_t buf_size,
		       size_t *out_size);

/**
 * tpm_get_aik_tpmt_public() - Marshal the AIK public area as TPMT_PUBLIC.
 * @ctx: Initialized TPM context.
 * @buf: Output buffer.
 * @buf_size: Size of @buf.
 * @out_size: Receives the marshaled size.
 *
 * The attestation CA computes the AIK name from these bytes
 * (src/attestca/credential/credential.go); signature checks use the SPKI form.
 *
 * Return: 0, -ENOKEY with no AIK, or a negative errno.
 */
int tpm_get_aik_tpmt_public(struct tpm_context *ctx, uint8_t *buf,
			    size_t buf_size, size_t *out_size);

/**
 * tpm_activate_credential() - Recover an attestation-CA credential.
 * @ctx: Initialized TPM context.
 * @cred_blob: TPM2B_ID_OBJECT from the CA (MakeCredential output).
 * @cred_blob_len: Length of @cred_blob.
 * @enc_secret: TPM2B_ENCRYPTED_SECRET from the CA.
 * @enc_secret_len: Length of @enc_secret.
 * @out_secret: Receives the activation secret.
 * @out_secret_max: Capacity of @out_secret.
 * @out_secret_len: Receives the secret's length.
 *
 * TPM2_ActivateCredential against the AIK and the EK. A credential made for
 * another AIK name or another EK fails, which is the binding the EK certificate
 * alone does not prove.
 *
 * Return: 0, -ENOKEY with no AIK, -EINVAL on malformed input, or a negative
 * errno.
 */
int tpm_activate_credential(struct tpm_context *ctx, const uint8_t *cred_blob,
			    size_t cred_blob_len, const uint8_t *enc_secret,
			    size_t enc_secret_len, uint8_t *out_secret,
			    size_t out_secret_max, size_t *out_secret_len);

/**
 * tpm_get_ek_cert() - Read the DER EK certificate from NV index 0x01c00002.
 * @ctx: Initialized TPM context.
 * @buf: Output buffer.
 * @buf_size: Size of @buf.
 * @out_size: Receives the certificate's size.
 *
 * Return: 0, -ENOENT when absent, -ENOSPC on a small @buf, or a negative errno.
 */
int tpm_get_ek_cert(struct tpm_context *ctx, uint8_t *buf, size_t buf_size,
		    size_t *out_size);

/**
 * tpm_get_ek_cert_chain() - Read the EK chain from NV index 0x01c00100.
 * @ctx: Initialized TPM context.
 * @buf: Receives the DER certificates end to end, with no framing.
 * @buf_size: Size of @buf.
 * @out_size: Receives the blob's size.
 *
 * Return: 0, -ENOENT when the platform stores no chain, -ENOSPC on a small
 * @buf, or a negative errno.
 */
int tpm_get_ek_cert_chain(struct tpm_context *ctx, uint8_t *buf,
			  size_t buf_size, size_t *out_size);

/**
 * tpm_aik_load_metadata() - Load the AIK metadata.
 * @ctx: Initialized TPM context; @ctx->aik_meta_path, or TPM_AIK_META_PATH.
 *
 * A missing file with no key at the handle yields defaults in memory
 * (a per-publisher key), with nothing written.
 *
 * Return: 0, -EKEYREVOKED on a missing file with a key at the handle, -EIO on
 * a short file, -EINVAL on wrong magic, -ENOTSUP on another version, or
 * a negative errno.
 */
int tpm_aik_load_metadata(struct tpm_context *ctx);

/**
 * tpm_aik_save_metadata() - Persist the AIK metadata.
 * @ctx: TPM context with metadata to save.
 *
 * Return: 0 or a negative errno.
 */
int tpm_aik_save_metadata(struct tpm_context *ctx);

/*
 * TPM Event Log path
 */
#define TPM_EVENTLOG_PATH_BIOS \
	"/sys/kernel/security/tpm0/binary_bios_measurements"

/* Maximum event log size (512 KB) */
#define TPM_MAX_EVENT_LOG_SIZE (512 * 1024)

/*
 * PCR14 baseline handoff: the value the initramfs lock helper saw before its
 * extend (the shim MOK measurement, or 0^32 on a UEFI host that measured
 * nothing there), raw 32 bytes on the /run tmpfs that outlives switch-root.
 * The agent's derivations anchor on it. An absent file leaves it zero.
 */
#define LOTA_PCR14_BASELINE_PATH "/run/lota/pcr14_baseline"

/**
 * tpm_read_event_log() - Read the TCG binary event log from securityfs.
 * @buf: Output buffer; TPM_MAX_EVENT_LOG_SIZE is the recommended size.
 * @buf_size: Size of @buf.
 * @out_size: Receives the bytes read, also on -ENOSPC.
 *
 * The report carries the log for the verifier to replay against the PCRs.
 *
 * Return: 0, -ENOSPC when the log was truncated, or a negative errno.
 */
int tpm_read_event_log(uint8_t *buf, size_t buf_size, size_t *out_size);

/**
 * tpm_is_locked_out() - Report @ctx->lockout_active.
 * @ctx: TPM context.
 *
 * Return: true after TPM2_RC_LOCKOUT until a successful
 * tpm_call_with_backoff() or TPM_CALL_RETRY finds inLockout clear,
 * or tpm_reset_lockout_state(); the TPM can still be locked out when
 * it reads false.
 */
bool tpm_is_locked_out(const struct tpm_context *ctx);

/**
 * tpm_reset_lockout_state() - Clear the lockout flag, no TPM contact.
 * @ctx: TPM context.
 *
 * Clears lockout_active and lockout_first_seen; the event count stays.
 * The IPC gate calls it after a completed attestation round.
 */
void tpm_reset_lockout_state(struct tpm_context *ctx);

/**
 * tpm_seal_secret() - Seal a secret to the current PCR state.
 * @ctx: Initialized TPM context.
 * @secret: Plaintext, 1..LOTA_SEAL_MAX_SECRET bytes.
 * @secret_len: Length of @secret.
 * @pcr_mask: PCRs to bind to; 0 selects LOTA_SEAL_DEFAULT_PCR_MASK.
 * @out: Receives the sealed blob (see include/lota_seal.h).
 * @out_cap: Capacity of @out.
 * @out_len: Receives the blob's length.
 *
 * Wraps the secret under a restricted storage primary in the owner hierarchy,
 * with a PolicyPCR authPolicy. The blob fails to load on another TPM and after
 * TPM2_Clear, and unseals when the selected PCRs reproduce their seal-time
 * values.
 *
 * Return: 0, -EINVAL on bad arguments or a PCR above 23, -ENOSPC on a small
 * @out, or a negative errno / LOTA_ERR_TPM_*.
 */
int tpm_seal_secret(struct tpm_context *ctx, const uint8_t *secret,
		    size_t secret_len, uint32_t pcr_mask, uint8_t *out,
		    size_t out_cap, size_t *out_len);

/**
 * tpm_unseal_secret() - Release a secret sealed by tpm_seal_secret().
 * @ctx: Initialized TPM context.
 * @blob: Sealed blob.
 * @blob_len: Length of @blob.
 * @out_secret: Receives the secret.
 * @out_cap: Capacity of @out_secret.
 * @out_len: Receives the secret's length.
 *
 * Runs over an encrypted PolicyPCR session.
 *
 * Return: 0, -EINVAL/-EMSGSIZE on a header lota_seal_parse_header() refuses,
 * -EBADMSG on a body that does not unmarshal or that the TPM refuses while the
 * PCRs still hash to the header's pcr_digest, -ENOSPC on a small @out_secret,
 * -LOTA_ERR_TPM_POLICY_FAIL or -EIO on any other refusal of the policy or the
 * object, or a negative errno / LOTA_ERR_TPM_*.
 */
int tpm_unseal_secret(struct tpm_context *ctx, const uint8_t *blob,
		      size_t blob_len, uint8_t *out_secret, size_t out_cap,
		      size_t *out_len);

/**
 * tpm_seal_secret_envelope() - Seal a large payload via a TPM-sealed KEK.
 * @ctx: Initialized TPM context.
 * @payload: Plaintext, 1..LOTA_ENVELOPE_MAX_PAYLOAD bytes.
 * @payload_len: Length of @payload.
 * @pcr_mask: PCRs to bind to; 0 selects LOTA_SEAL_DEFAULT_PCR_MASK.
 * @out: Receives the envelope blob (see include/lota_envelope.h).
 * @out_cap: Capacity of @out.
 * @out_len: Receives the blob's length.
 *
 * tpm_seal_secret() seals a random AES-256 KEK. The payload goes under the KEK
 * with AES-256-GCM, the header and sealed-KEK blob authenticated as AAD.
 *
 * Return: 0, -EINVAL on bad arguments, -ENOSPC on a small @out, or a negative
 * errno / LOTA_ERR_TPM_*.
 */
int tpm_seal_secret_envelope(struct tpm_context *ctx, const uint8_t *payload,
			     size_t payload_len, uint32_t pcr_mask,
			     uint8_t *out, size_t out_cap, size_t *out_len);

/**
 * tpm_unseal_secret_envelope() - Recover a payload sealed by
 * tpm_seal_secret_envelope().
 * @ctx: Initialized TPM context.
 * @blob: Envelope blob.
 * @blob_len: Length of @blob.
 * @out: Receives the plaintext.
 * @out_cap: Capacity of @out.
 * @out_len: Receives the plaintext's length.
 *
 * Return: 0, -EINVAL/-EMSGSIZE on a malformed blob or bad arguments, -ENOSPC on
 * a small @out, -EBADMSG when the tag fails over the header, the sealed KEK or
 * the payload, or tpm_unseal_secret() gives it for the KEK,
 * -LOTA_ERR_TPM_POLICY_FAIL or -EIO when it gives those, or a negative errno /
 * LOTA_ERR_TPM_*.
 */
int tpm_unseal_secret_envelope(struct tpm_context *ctx, const uint8_t *blob,
			       size_t blob_len, uint8_t *out, size_t out_cap,
			       size_t *out_len);

/**
 * tpm_seal_persist_primary() - Persist the seal storage primary.
 * @ctx: Initialized TPM context.
 * @already: If non-NULL, set when an object was already at the handle.
 *
 * Return: 0 in both cases, or a negative errno / LOTA_ERR_TPM_*.
 */
int tpm_seal_persist_primary(struct tpm_context *ctx, bool *already);

/**
 * tpm_seal_evict_primary() - Remove the persistent seal storage primary.
 * @ctx: Initialized TPM context.
 *
 * Sealed blobs still unseal: the derived primary is the same key.
 *
 * Return: 0, -ENOENT with nothing persisted, or a negative errno /
 * LOTA_ERR_TPM_*.
 */
int tpm_seal_evict_primary(struct tpm_context *ctx);

/**
 * tpm_handle_holds_object() - Does this TPM have an object at @handle?
 * @ctx: Initialized TPM context.
 * @handle: A persistent handle.
 *
 * A profile's recorded handle is a claim; the TPM answers for what is there.
 *
 * Return: 1 when it holds an object, 0 when free, negative errno when
 * the TPM could not be asked.
 */
int tpm_handle_holds_object(struct tpm_context *ctx, uint32_t handle);

/**
 * tpm_persistent_slots() - Persistent objects this TPM holds and can hold.
 * @ctx: Initialized TPM context.
 * @used: Receives the objects resident, LOTA's and everyone else's.
 * @total: Receives @used plus TPM2_PT_HR_PERSISTENT_AVAIL.
 *
 * Each publisher's AIK occupies one. The available figure is the TPM's
 * estimate; enrollment prints it and refuses nothing on it.
 *
 * Return: 0, -ENOTSUP when the TPM does not answer for these properties,
 * or a negative errno.
 */
int tpm_persistent_slots(struct tpm_context *ctx, uint32_t *used,
			 uint32_t *total);

/**
 * tpm_evict_profile_aik() - Free the slot of a publisher's AIK.
 * @ctx: Initialized TPM context.
 * @handle: The persistent handle recorded in that profile.
 *
 * The key is derived: provisioning for the same profile brings it back.
 *
 * Return: 0, -ENOENT when the handle holds nothing, or a negative errno.
 */
int tpm_evict_profile_aik(struct tpm_context *ctx, uint32_t handle);

/**
 * tpm_aik_reseal_auth() - Re-seal the AIK userAuth to the current PCR state.
 * @ctx: Initialized TPM context.
 *
 * Adopts at-rest sealing on an enrolled host. Loads the auth if needed, writes
 * aik_auth.sealed and, in strict mode, drops the plaintext sidecar.
 *
 * Return: 0 or a negative errno.
 */
int tpm_aik_reseal_auth(struct tpm_context *ctx);

/**
 * tpm_reprovision_aik() - Replace the AIK userAuth.
 * @ctx: Initialized TPM context.
 * @out_key_changed: Set when the key's TPM Name differs or no key was there.
 *
 * Recovery for strict at-rest sealing after a boot-state change made the sealed
 * auth unrecoverable. The key is a primary: same template, same key.
 * seal_aik_auth and seal_aik_auth_strict select how the new auth is stored.
 * With a key at the handle, the record is loaded first if it is not already;
 * a missing record is written afresh.
 *
 * Return: 0, -ENOTSUP when the record says shared and
 * tpm_aik_allow_shared_key_replace() was not set, or a negative errno.
 */
int tpm_reprovision_aik(struct tpm_context *ctx, bool *out_key_changed);

/**
 * tpm_firmware_refuses_attestation() - Is this a non-UEFI (BIOS/CSM) host?
 * @ctx: Context; only @ctx->allow_env_tpm_overrides is read, which admits
 *       LOTA_UEFI_FIRMWARE_PATH. It need not be initialized.
 *
 * Return: 1 if refused, with the reason printed, else 0.
 */
int tpm_firmware_refuses_attestation(const struct tpm_context *ctx);

/**
 * tpm_aik_load_failure_blocks_reprovision() - Must this failure keep the key?
 * @load_rc: Return value of the load.
 *
 * Return: 0 for 0 and -ENOENT, else 1.
 */
int tpm_aik_load_failure_blocks_reprovision(int load_rc);

/**
 * tpm_aik_slot_census() - profile_aik_slot_tally() over profiles and handles.
 * @ctx: Initialized TPM context.
 * @base_dir: Profile directory, or NULL for the default.
 * @out: Receives the tally.
 *
 * Return: 0 or a negative errno.
 */
int tpm_aik_slot_census(struct tpm_context *ctx, const char *base_dir,
			struct profile_aik_slots *out);

/**
 * tpm_aik_handle_holds_profile_key() - Does the handle hold the profile's key?
 * @ctx: Context bound to a profile.
 *
 * Return: 1 if so, 0 if the handle is empty or holds another object,
 * or a negative errno.
 */
int tpm_aik_handle_holds_profile_key(struct tpm_context *ctx);

#ifdef LOTA_TPM_TESTING
typedef int (*tpm_test_prop_reader_fn)(struct tpm_context *ctx, TPM2_PT prop,
				       uint32_t *out_val);

int tpm_test_read_pcr14_baseline(const char *path, uint8_t out[LOTA_HASH_SIZE],
				 int *present);
int tpm_test_aik_check_shared_replace(struct tpm_context *ctx);
int tpm_test_esys_reconnect(struct tpm_context *ctx);
int tpm_test_seal_refusal_errno(struct tpm_context *ctx, uint32_t pcr_mask,
				const uint8_t *pcr_digest, uint32_t rc,
				int err);

/*
 * Pure helpers: the Name comparison behind tpm_aik_object_replaced(), and
 * the profile comparison deciding whether a bind carries a cached key across.
 */
int tpm_test_rc_is_stale_object_record(uint32_t rc);
int tpm_test_aik_object_changed(const uint8_t *seen, uint16_t seen_len,
				const uint8_t *live, uint16_t live_len);
int tpm_test_aik_binding_survives(const char *bound_id, uint32_t bound_handle,
				  const char *new_id, uint32_t new_handle);

/* Pure helper: expose the PCR-mask -> selection bitmap for unit tests. */
int tpm_test_pcr_mask_to_selection(uint32_t pcr_mask, uint8_t out_select[3],
				   uint32_t *out_count);

/* AIK-auth at-rest hardening test hooks (dispatch + path derivation). */
int tpm_test_aik_save_auth(struct tpm_context *ctx,
			   const uint8_t auth[TPM_AIK_AUTH_SIZE]);
int tpm_test_aik_load_auth(struct tpm_context *ctx);
int tpm_test_aik_plaintext_path(struct tpm_context *ctx, char *buf, size_t len);
int tpm_test_aik_sealed_path(struct tpm_context *ctx, char *buf, size_t len);
int tpm_test_aik_auth_record_exists(struct tpm_context *ctx);

void tpm_test_set_prop_reader(tpm_test_prop_reader_fn reader);
void tpm_test_reset_prop_reader(void);

/* Unit-test hooks into the internal TPM return-code dispatch. */
int tpm_test_rc_to_errno(uint32_t rc);
int tpm_test_rc_is_transient(uint32_t rc);
int tpm_test_rc_is_lockout(uint32_t rc);
int tpm_test_save_new_key_metadata(struct tpm_context *ctx);

/* Callback of tpm_call_with_backoff(). */
typedef TSS2_RC (*tpm_esys_thunk)(void *userdata);

/*
 * tpm_call_with_backoff() with the slot array passed directly,
 * for tests/test_aik_rotation.c.
 */
int tpm_test_call_with_backoff_array(struct tpm_context *ctx,
				     tpm_esys_thunk thunk, void *userdata,
				     uint32_t *out_rc, void **slots[],
				     size_t out_slot_count);

#endif

#endif /* LOTA_TPM_H */
