/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Publisher profile identity and on-disk layout.
 *
 * Player's machine has one state and several publishers judging it, each with
 * its own attestation CA.
 * Enrollment is therefore per publisher, not per host:
 * one enrollment record and one CA-issued AIK certificate under directory named
 * after the publisher.
 *
 * The name is the SHA-256 of the CA trust anchor's SubjectPublicKeyInfo.
 * The endpoint is mutable and spoofable -- DNS, port, shared hosting -- while
 * the anchor is what enrollment verifies against, so the identity survives address
 * change and cannot collide between two publishers that share hostname.
 *
 * It is also why enrollment requires an anchor:
 * without one there is nothing to key the state by, and second publisher would
 * land on the first one's AIK.
 */

#ifndef LOTA_AGENT_PROFILE_H
#define LOTA_AGENT_PROFILE_H

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

/* Parent of the per-publisher directories */
#define LOTA_PROFILE_BASE_DIR "/var/lib/lota/profiles"

/* SHA-256 as lowercase hex, plus the terminator */
#define LOTA_PROFILE_ID_LEN 65

/*
 * How many AIK persistent handles the layout can hand out.
 * TPM persistent slots are a scarce, shared resource, so the range is bounded
 * and sized to the configurable profile count
 * (asserted against LOTA_CONFIG_MAX_PROFILES in config.h);
 * the range itself lives in tpm.h, which owns handle assignment.
 */
#define LOTA_PROFILE_MAX_AIK_HANDLES 8

/* Files inside profile directory */
#define LOTA_PROFILE_ENROLL_STATE_FILE "enroll_state.dat"
#define LOTA_PROFILE_AIK_CERT_FILE "aik_cert.der"
#define LOTA_PROFILE_AIK_META_FILE "aik_meta.dat"
#define LOTA_PROFILE_AIK_HANDLE_FILE "aik_handle"

struct profile_paths {
	char id[LOTA_PROFILE_ID_LEN];
	char dir[PATH_MAX];
	char enroll_state[PATH_MAX];
	char aik_cert[PATH_MAX];

	/*
	 * The profile's own AIK:
	 * its rotation metadata, and the persistent handle that key occupies.
	 * userAuth sidecars are derived from the metadata's directory
	 * by the TPM layer, so they follow it here.
	 */
	char aik_meta[PATH_MAX];
	char aik_handle[PATH_MAX];
};

/*
 * Derive a profile identity from a CA trust anchor.
 *
 * @ca_cert_path: PEM or DER certificate file.
 * 		  File holding several certificates is keyed by the first one
 * 		  -- anchor names one publisher.
 * @out:          receives the lowercase hex SHA-256 of the anchor's SPKI.
 * @out_len:      size of @out; must be at least LOTA_PROFILE_ID_LEN.
 *
 * Returns 0, -ENOENT if the anchor cannot be opened, -EINVAL if it holds no
 * parsable certificate or the buffer is too small.
 */
int profile_id_from_anchor(const char *ca_cert_path, char *out, size_t out_len);

/* Fill @out with the paths of the profile the anchor identifies */
int profile_paths_from_anchor(const char *ca_cert_path,
			      struct profile_paths *out);

/* Path-parameterized variant behind the wrapper above (tests) */
int profile_paths_from_anchor_base(const char *base_dir,
				   const char *ca_cert_path,
				   struct profile_paths *out);

/*
 * Create the profile directory and its parent if they are missing,
 * 0700: the enrollment record carries the tenant admission token, and the directory
 * name itself says which publisher this host answers to.
 */
int profile_dir_ensure(const struct profile_paths *paths);

/*
 * The persistent handle this profile's AIK occupies.
 *
 * Recorded rather than derived from the profile's position in the config file:
 * removing one profile would otherwise shift every later profile onto another
 * publisher's key.
 * Record is advisory in the security sense -- the TPM is the authority on what
 * lives at a handle, and a quote signed by the wrong key fails against
 * the certificate the profile presents -- so it is a plain "0x%08X" line,
 * readable by operator listing what host has allocated.
 *
 * Load returns -ENOENT when this profile has no handle yet.
 */
int profile_aik_handle_load(const struct profile_paths *paths, uint32_t *out);
int profile_aik_handle_save(const struct profile_paths *paths, uint32_t handle);

/*
 * Handles in [base, base + count) that no profile under @base_dir has recorded,
 * lowest first, so caller can take the first one its TPM has no object at.
 *
 * @out/@out_max: caller's array and its capacity.
 * @out_count:    receives how many candidates were written.
 *
 * Returns 0 (with *out_count == 0 when every handle in the range is spoken
 * for), or a negative errno.
 * Profile directory that records nothing is skipped: it has not provisioned yet.
 */
int profile_aik_handle_candidates(const char *base_dir, uint32_t base,
				  uint32_t count, uint32_t *out, size_t out_max,
				  size_t *out_count);

#endif /* LOTA_AGENT_PROFILE_H */
