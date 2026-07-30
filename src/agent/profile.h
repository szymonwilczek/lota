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

/* Parent of the per-publisher directories */
#define LOTA_PROFILE_BASE_DIR "/var/lib/lota/profiles"

/* SHA-256 as lowercase hex, plus the terminator */
#define LOTA_PROFILE_ID_LEN 65

/* Files inside profile directory */
#define LOTA_PROFILE_ENROLL_STATE_FILE "enroll_state.dat"
#define LOTA_PROFILE_AIK_CERT_FILE "aik_cert.der"

struct profile_paths {
	char id[LOTA_PROFILE_ID_LEN];
	char dir[PATH_MAX];
	char enroll_state[PATH_MAX];
	char aik_cert[PATH_MAX];
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

#endif /* LOTA_AGENT_PROFILE_H */
