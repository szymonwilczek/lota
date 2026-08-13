/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Reading and destroying what this host stores per publisher.
 * See publishers.h for why the inventory avoids the TPM.
 */

#include <dirent.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/crypto.h>

#include "aik_cert.h"
#include "enroll.h"
#include "profile.h"
#include "publishers.h"

/* Fill one entry from a profile directory whose name is the identity */
static void read_entry(const char *base_dir, const char *id,
		       struct publisher_entry *e)
{
	struct profile_paths paths;
	struct enroll_state st;
	int64_t remaining = 0, total = 0;
	uint32_t handle = 0;
	time_t agreed = 0;

	memset(e, 0, sizeof(*e));
	snprintf(e->id, sizeof(e->id), "%s", id);

	/*
	 * Here the directory is all there is, so the layout comes from the name
	 * it carries.
	 * Caller has already checked that name is identity.
	 */
	if (profile_paths_from_id(base_dir, id, &paths) < 0)
		return;

	if (profile_consent_time(&paths, &agreed) == 0) {
		e->consented = true;
		e->consented_at = agreed;
	}

	if (enroll_state_load_path(paths.enroll_state, &st) == 0) {
		e->enrolled = true;
		snprintf(e->ca_server, sizeof(e->ca_server), "%s",
			 st.ca_server);
		e->ca_port = st.ca_port;
		OPENSSL_cleanse(&st, sizeof(st));
	}

	if (profile_aik_handle_load(&paths, &handle) == 0) {
		e->has_aik_handle = true;
		e->aik_handle = handle;
	}

	if (aik_cert_lifetime_path(paths.aik_cert, &remaining, &total) == 0) {
		e->has_cert = true;
		e->cert_remaining_sec = remaining;
	}
}

static bool name_is_identity(const char *name)
{
	return strlen(name) == LOTA_PROFILE_ID_LEN - 1 &&
	       strspn(name, "0123456789abcdef") == LOTA_PROFILE_ID_LEN - 1;
}

int publishers_list(const char *base_dir, struct publisher_entry *out,
		    size_t max, size_t *count)
{
	struct dirent *ent;
	size_t n = 0;
	DIR *dir;

	if (!base_dir || !out || !count || max == 0)
		return -EINVAL;

	*count = 0;

	dir = opendir(base_dir);
	if (!dir) {
		/* nothing has ever been stored, which is an answer */
		if (errno == ENOENT)
			return 0;
		return -errno;
	}

	while ((ent = readdir(dir)) != NULL && n < max) {
		if (!name_is_identity(ent->d_name))
			continue;
		read_entry(base_dir, ent->d_name, &out[n]);
		n++;
	}
	closedir(dir);

	*count = n;
	return 0;
}

int publishers_forget(const struct profile_paths *paths)
{
	static const char *const leaves[] = {
		LOTA_PROFILE_ENROLL_STATE_FILE,
		LOTA_PROFILE_AIK_CERT_FILE,
		LOTA_PROFILE_AIK_META_FILE,
		LOTA_PROFILE_AIK_HANDLE_FILE,
		LOTA_PROFILE_CONSENT_FILE,
		"aik_auth.dat",
		"aik_auth.sealed",
	};
	int first_error = 0;

	if (!paths || paths->dir[0] == '\0')
		return -EINVAL;

	for (size_t i = 0; i < sizeof(leaves) / sizeof(leaves[0]); i++) {
		char path[PATH_MAX];

		if (snprintf(path, sizeof(path), "%s/%s", paths->dir,
			     leaves[i]) >= (int)sizeof(path))
			continue;
		if (unlink(path) != 0 && errno != ENOENT && !first_error)
			first_error = -errno;
	}

	/*
	 * Remove the directory last and only when it is empty:
	 * something left behind means this host still stores part of that
	 * publisher's identity, and silent success would say otherwise.
	 */
	if (rmdir(paths->dir) != 0 && errno != ENOENT && !first_error)
		first_error = -errno;

	return first_error;
}
