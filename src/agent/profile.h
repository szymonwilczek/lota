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
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include <time.h>

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
#define LOTA_PROFILE_CONSENT_FILE "consent"

/*
 * The AIK authorization, in each of the two forms it may be kept in.
 * Both sit beside the metadata, so the TPM layer derives their paths from that
 * directory; the names live here with the profile's other files so one place
 * says what a profile directory contains.
 */
#define LOTA_PROFILE_AIK_AUTH_FILE "aik_auth.dat"
#define LOTA_PROFILE_AIK_AUTH_SEALED_FILE "aik_auth.sealed"

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

	/*
	 * The record that somebody on this machine agreed to answer to this publisher.
	 * Written before the enrollment it authorises, which is what makes it
	 * decision rather than note about one.
	 */
	char consent[PATH_MAX];
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
 * Is this trust anchor a CA certificate, or a listener leaf?
 *
 * One --ca-cert serves two roles: the TLS trust anchor the CA server is verified
 * against, and the publisher's identity. A CA anchor serves both and outlives
 * the deployment. A TLS listener certificate serves the first and is rotated on
 * a schedule -- and a rotation with a new key moves the identity, so every host
 * of that publisher becomes a new device with a new AIK in a new persistent slot.
 *
 * Not a refusal: a self-signed leaf is a legitimate pin for a deployment that
 * wants one, and this cannot tell that apart from a listener certificate
 * somebody named by mistake. Callers say what the choice costs and continue.
 *
 * Returns 1 for a CA certificate, 0 for one that is not, negative errno when
 * the file cannot be read or parsed.
 */
int profile_anchor_is_ca(const char *ca_cert_path);

/*
 * Lay out a profile from its identity rather than from an anchor,
 * for the paths that meet a publisher by name: title handing over the hex,
 * and the inventory reading directories that are already there.
 * Identity is validated -- 64 lowercase hex characters -- because it becomes path.
 */
int profile_paths_from_id(const char *base_dir, const char *id,
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
 * Drop the handle record of a profile whose key never reached the TPM.
 *
 * The record is written when the profile is bound, before the key exists,
 * and everything that counts keys reads it. Caller must first confirm with
 * the TPM that nothing lives at the handle.
 *
 * Returns 0, also when no record exists, or a negative errno.
 */
int profile_aik_handle_forget(const struct profile_paths *paths);

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

/*
 * profile_aik_cert_stored - does this publisher have an enrollment
 * certificate on disk?
 *
 * The certificate is what names the key to a verifier, so its presence is
 * what makes a replaced key a problem worth reporting.
 * Reads nothing: the file either is there or is not.
 */
bool profile_aik_cert_stored(const struct profile_paths *paths);

/*
 * How this publisher's AIK authorization is kept at rest.
 *
 * The authorization opens the attestation key, so whether a copy of it is on
 * disk in the clear is what at-rest sealing exists to answer. The state is
 * read off the files, not taken from the verb that wrote them.
 *
 * The four states are what an auditor needs to tell apart:
 *
 *   NONE       neither file: this publisher holds no authorization yet
 *   PLAINTEXT  the sidecar only, which is the shipped default
 *   SEALED     the sealed copy only, which is seal_aik_auth_strict
 *   BOTH       sealed, with the sidecar kept -- adopted but not hardened,
 *              and a copy is still readable from a captured disk
 *
 * Reads no file contents and needs no TPM: the two files either are there
 * or are not, which is exactly what "is it on disk in the clear" asks.
 */
enum profile_aik_auth_state {
	PROFILE_AIK_AUTH_NONE = 0,
	PROFILE_AIK_AUTH_PLAINTEXT,
	PROFILE_AIK_AUTH_SEALED,
	PROFILE_AIK_AUTH_BOTH,
};

enum profile_aik_auth_state
profile_aik_auth_state(const struct profile_paths *paths);

/* The state's name, for a caller reporting it. Never NULL. */
const char *profile_aik_auth_state_str(enum profile_aik_auth_state state);

/*
 * Whether a copy of the authorization is readable from a powered-off disk.
 * True for PLAINTEXT and BOTH: sealing a second copy protects nothing while
 * the first one is still in the clear.
 */
bool profile_aik_auth_exposed(enum profile_aik_auth_state state);

/*
 * Consent to answer to a publisher.
 *
 * Minting AIK for publisher gives them stable handle on this machine,
 * so the host records that somebody agreed to it before the key exists.
 * Record is plain text, root-only like the directory holding it, and states when
 * it was made and by whom -- audit note, not secret: anyone who could forge it
 * could delete the profile instead.
 *
 * profile_consent_record() creates the profile directory if needed.
 * profile_consent_time() returns -ENOENT when this publisher has no consent.
 */
int profile_consent_record(const struct profile_paths *paths, uid_t by);
int profile_consent_time(const struct profile_paths *paths, time_t *out);
int profile_consent_forget(const struct profile_paths *paths);

#endif /* LOTA_AGENT_PROFILE_H */
