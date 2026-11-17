/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Publisher profile identity and on-disk layout.
 *
 * Each publisher gets a directory with its own AIK, certificate, enrollment
 * record and consent, named by the SHA-256 of its CA trust anchor's
 * SubjectPublicKeyInfo. The anchor, not the endpoint, names it: two publishers
 * may share a host, and one may move.
 */

#ifndef LOTA_AGENT_PROFILE_H
#define LOTA_AGENT_PROFILE_H

#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

#define LOTA_PROFILE_BASE_DIR "/var/lib/lota/profiles"

#define LOTA_PROFILE_ID_LEN 65

/* from TPM_AIK_PROFILE_HANDLE_BASE; at least LOTA_CONFIG_MAX_PROFILES */
#define LOTA_PROFILE_MAX_AIK_HANDLES 8

#define LOTA_PROFILE_ENROLL_STATE_FILE "enroll_state.dat"
#define LOTA_PROFILE_AIK_CERT_FILE "aik_cert.der"
#define LOTA_PROFILE_AIK_META_FILE "aik_meta.dat"
#define LOTA_PROFILE_AIK_HANDLE_FILE "aik_handle"
#define LOTA_PROFILE_CONSENT_FILE "consent"

/* the TPM layer puts these beside the AIK metadata */
#define LOTA_PROFILE_AIK_AUTH_FILE "aik_auth.dat"
#define LOTA_PROFILE_AIK_AUTH_SEALED_FILE "aik_auth.sealed"

/**
 * struct profile_paths - One publisher's directory and files.
 * @id: Lowercase hex identity.
 * @dir: The directory.
 * @enroll_state: struct enroll_state.
 * @aik_cert: Issued AIK certificate, DER.
 * @aik_meta: AIK metadata.
 * @aik_handle: Persistent handle the AIK occupies.
 * @consent: Consent record.
 */
struct profile_paths {
	char id[LOTA_PROFILE_ID_LEN];
	char dir[PATH_MAX];
	char enroll_state[PATH_MAX];
	char aik_cert[PATH_MAX];
	char aik_meta[PATH_MAX];
	char aik_handle[PATH_MAX];
	char consent[PATH_MAX];
};

/**
 * profile_id_from_anchor() - Derive a profile identity from a CA trust anchor.
 * @ca_cert_path: PEM or DER file; only the first certificate counts.
 * @out: Lowercase hex SHA-256 of its SubjectPublicKeyInfo.
 * @out_len: At least LOTA_PROFILE_ID_LEN.
 *
 * Return: 0, the access(2) errno when the file is not readable, or -EINVAL
 * when it holds no certificate or for a bad argument.
 */
int profile_id_from_anchor(const char *ca_cert_path, char *out, size_t out_len);

/**
 * profile_paths_from_anchor() - Lay out the profile an anchor names.
 * @ca_cert_path: CA trust anchor.
 * @out: Paths under LOTA_PROFILE_BASE_DIR.
 *
 * Return: As profile_id_from_anchor(), or -ENAMETOOLONG.
 */
int profile_paths_from_anchor(const char *ca_cert_path,
			      struct profile_paths *out);

/**
 * profile_paths_from_anchor_base() - The same under @base_dir.
 * @base_dir: Parent directory.
 * @ca_cert_path: CA trust anchor.
 * @out: Paths.
 *
 * Return: As profile_paths_from_anchor().
 */
int profile_paths_from_anchor_base(const char *base_dir,
				   const char *ca_cert_path,
				   struct profile_paths *out);

/**
 * profile_anchor_is_ca() - Whether the anchor's first certificate is a CA.
 * @ca_cert_path: CA trust anchor.
 *
 * A leaf that is re-keyed moves the identity, and with it the profile.
 *
 * Return: 1 for a CA, 0 for an end-entity certificate, the access() errno,
 * or -EINVAL when no certificate parses.
 */
int profile_anchor_is_ca(const char *ca_cert_path);

/**
 * profile_paths_from_id() - Lay out a profile from its identity.
 * @base_dir: Parent directory.
 * @id: 64 lowercase hex characters; it becomes a path.
 * @out: Paths.
 *
 * Return: 0, -EINVAL for any other @id, or -ENAMETOOLONG.
 */
int profile_paths_from_id(const char *base_dir, const char *id,
			  struct profile_paths *out);

/**
 * profile_dir_ensure() - Create the profile directory and its parent, 0700.
 * @paths: Profile.
 *
 * The enrollment record holds the token, and the directory name says which
 * publisher this host answers to.
 *
 * Return: 0, also when both exist, or a negative errno.
 */
int profile_dir_ensure(const struct profile_paths *paths);

/**
 * profile_aik_handle_load() - Read the handle this profile's AIK occupies.
 * @paths: Profile.
 * @out: Handle.
 *
 * Recorded, not derived from the profile's place in the configuration,
 * so removing a profile moves no other onto another publisher's key.
 *
 * Return: 0, -ENOENT when none is recorded, -EINVAL for a malformed record,
 * or a negative errno.
 */
int profile_aik_handle_load(const struct profile_paths *paths, uint32_t *out);

/**
 * profile_aik_handle_save() - Record the handle as a "0x%08X" line.
 * @paths: Profile; its directory is created.
 * @handle: Nonzero handle.
 *
 * Return: 0 or a negative errno.
 */
int profile_aik_handle_save(const struct profile_paths *paths, uint32_t handle);

/**
 * profile_aik_handle_forget() - Remove the handle record.
 * @paths: Profile.
 *
 * For a key that never reached the TPM; the caller checks the handle is empty.
 *
 * Return: 0, also when no record exists, or a negative errno.
 */
int profile_aik_handle_forget(const struct profile_paths *paths);

/**
 * profile_aik_handle_candidates() - Handles no profile records, lowest first.
 * @base_dir: Parent directory.
 * @base: First handle of the range.
 * @count: Handles in the range, at most LOTA_PROFILE_MAX_AIK_HANDLES.
 * @out: Candidates.
 * @out_max: Entries in @out.
 * @out_count: Entries written; 0 when all are recorded.
 *
 * Return: 0, -EINVAL, or the opendir() errno.
 */
int profile_aik_handle_candidates(const char *base_dir, uint32_t base,
				  uint32_t count, uint32_t *out, size_t out_max,
				  size_t *out_count);

/**
 * struct profile_aik_slots - Usage of the AIK handle range.
 * @total: Handles in the range.
 * @recorded: Handles a profile records.
 * @unrecorded: Handles holding an object no profile records; the allocator
 *	never evicts one.
 * @free_slots: Neither.
 * @unrecorded_handles: The @unrecorded handles.
 */
struct profile_aik_slots {
	uint32_t total;
	uint32_t recorded;
	uint32_t unrecorded;
	uint32_t free_slots;
	uint32_t unrecorded_handles[LOTA_PROFILE_MAX_AIK_HANDLES];
};

/**
 * profile_aik_slot_tally() - Classify each handle of a range.
 * @base: First handle.
 * @count: Handles, at most LOTA_PROFILE_MAX_AIK_HANDLES.
 * @recorded: Handles the profiles record.
 * @recorded_count: Entries in @recorded.
 * @in_use: Handles holding a TPM object.
 * @in_use_count: Entries in @in_use.
 * @out: Tally; handles outside the range are ignored.
 *
 * Return: 0 or -EINVAL.
 */
int profile_aik_slot_tally(uint32_t base, uint32_t count,
			   const uint32_t *recorded, size_t recorded_count,
			   const uint32_t *in_use, size_t in_use_count,
			   struct profile_aik_slots *out);

/**
 * profile_aik_handles_recorded() - Handles the profiles record.
 * @base_dir: Parent directory.
 * @out: Handles, in directory order.
 * @out_max: Entries in @out; more are dropped.
 * @out_count: Entries written.
 *
 * Return: 0, -EINVAL, or the opendir() errno.
 */
int profile_aik_handles_recorded(const char *base_dir, uint32_t *out,
				 size_t out_max, size_t *out_count);

/**
 * profile_aik_cert_stored() - Whether a certificate is on disk.
 * @paths: Profile.
 *
 * Return: true for a non-empty regular file.
 */
bool profile_aik_cert_stored(const struct profile_paths *paths);

/**
 * enum profile_aik_auth_state - Which AIK authorization files are present.
 * @PROFILE_AIK_AUTH_NONE: neither.
 * @PROFILE_AIK_AUTH_PLAINTEXT: the plaintext file only, the default.
 * @PROFILE_AIK_AUTH_SEALED: the sealed file only, as seal_aik_auth_strict
 *	leaves it.
 * @PROFILE_AIK_AUTH_BOTH: both, as seal_aik_auth leaves it.
 *
 * A file counts when it is a non-empty regular file.
 */
enum profile_aik_auth_state {
	PROFILE_AIK_AUTH_NONE = 0,
	PROFILE_AIK_AUTH_PLAINTEXT,
	PROFILE_AIK_AUTH_SEALED,
	PROFILE_AIK_AUTH_BOTH,
};

/**
 * profile_aik_auth_state() - Read the state off the profile directory.
 * @paths: Profile, or NULL for PROFILE_AIK_AUTH_NONE.
 *
 * Return: The state.
 */
enum profile_aik_auth_state
profile_aik_auth_state(const struct profile_paths *paths);

/**
 * profile_aik_auth_state_str() - Describe a state.
 * @state: State.
 *
 * Return: A sentence, never NULL.
 */
const char *profile_aik_auth_state_str(enum profile_aik_auth_state state);

/**
 * profile_aik_auth_exposed() - Whether a plaintext copy is on disk.
 * @state: State.
 *
 * Return: true for PLAINTEXT and BOTH.
 */
bool profile_aik_auth_exposed(enum profile_aik_auth_state state);

/**
 * profile_consent_record() - Record consent to answer to this publisher.
 * @paths: Profile; its directory is created.
 * @by: Uid recorded beside the time.
 *
 * Plain text, mode 0600.
 *
 * Return: 0 or a negative errno.
 */
int profile_consent_record(const struct profile_paths *paths, uid_t by);

/**
 * profile_consent_time() - When consent was recorded.
 * @paths: Profile.
 * @out: Time.
 *
 * Return: 0, -ENOENT when there is none, -EINVAL for a malformed record,
 * or a negative errno.
 */
int profile_consent_time(const struct profile_paths *paths, time_t *out);

#endif /* LOTA_AGENT_PROFILE_H */
