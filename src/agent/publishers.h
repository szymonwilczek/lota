/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * What this host stores per publisher. The inventory reads the profile
 * directories only, never the TPM.
 */

#ifndef LOTA_AGENT_PUBLISHERS_H
#define LOTA_AGENT_PUBLISHERS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "profile.h"

/**
 * struct publisher_entry - One profile directory.
 * @id: Profile identity, the directory name.
 * @consented: A consent record is stored.
 * @consented_at: When it was given.
 * @enrolled: The enrollment record was read.
 * @ca_server: CA host it names.
 * @ca_port: CA port it names.
 * @enroll_unreadable: A record is stored but did not load.
 * @enroll_rc: Why it did not load.
 * @has_aik_handle: An AIK handle is stored.
 * @aik_handle: That handle.
 * @has_cert: A CA-issued certificate is stored.
 * @cert_remaining_sec: Its validity left.
 */
struct publisher_entry {
	char id[LOTA_PROFILE_ID_LEN];
	bool consented;
	time_t consented_at;
	bool enrolled;
	char ca_server[256];
	int ca_port;
	bool enroll_unreadable;
	int enroll_rc;
	bool has_aik_handle;
	uint32_t aik_handle;
	bool has_cert;
	int64_t cert_remaining_sec;
};

/**
 * publishers_list() - Read the profiles under @base_dir.
 * @base_dir: Profile base directory.
 * @out: Entries, in directory order.
 * @max: Size of @out; 0 is -EINVAL.
 * @count: Profiles found, also those past @max.
 *
 * A profile with nothing readable is still listed.
 *
 * Return: 0, also when @base_dir is missing; -ENOBUFS when more than @max
 * exist, with the first @max filled; or a negative errno.
 */
int publishers_list(const char *base_dir, struct publisher_entry *out,
		    size_t max, size_t *count);

/**
 * publishers_list_alloc() - Read every profile under @base_dir.
 * @base_dir: Profile base directory.
 * @out: Allocated entries, NULL when there are none; free() it.
 * @count: Entries in @out.
 *
 * Return: 0, or a negative errno; -ENOBUFS when a profile appeared while
 * reading.
 */
int publishers_list_alloc(const char *base_dir, struct publisher_entry **out,
			  size_t *count);

/**
 * publishers_keys_held() - Count the entries holding an AIK handle.
 * @list: Entries; NULL counts 0.
 * @count: Entries in @list.
 *
 * Return: the number with @has_aik_handle set.
 */
size_t publishers_keys_held(const struct publisher_entry *list, size_t count);

/**
 * publishers_default_key_in_use() - Whether the host attests with the
 * pre-profile AIK.
 * @publisher_count: Profiles listed.
 *
 * Once any publisher is listed, each attests with its own key.
 *
 * Return: true when no publisher is listed.
 */
static inline bool publishers_default_key_in_use(size_t publisher_count)
{
	return publisher_count == 0;
}

/**
 * publisher_anchor_names_another() - Whether the anchor @id enrolled with
 * now derives another identity.
 * @base_dir: Profile base directory.
 * @id: Profile identity.
 * @now_id: Receives the derived identity when it differs, or NULL.
 * @cap: Size of @now_id, at least LOTA_PROFILE_ID_LEN.
 *
 * As after a pinned listener certificate is re-issued over a new key.
 *
 * Return: 1 when it differs, 0 when it is still @id, -ENOENT when @id is
 * not enrolled or recorded no anchor, or a negative errno.
 */
int publisher_anchor_names_another(const char *base_dir, const char *id,
				   char *now_id, size_t cap);

/**
 * publishers_endpoint_shared() - Find another enrolled profile at the same
 * CA endpoint.
 * @base_dir: Profile base directory.
 * @self_id: Profile to skip, or NULL.
 * @ca_server: CA host.
 * @ca_port: CA port.
 * @other_id: Receives the first match in directory order.
 * @cap: Size of @other_id, at least LOTA_PROFILE_ID_LEN.
 *
 * An anchor re-issued over a new key leaves one: two profiles for one device
 * at the publisher.
 *
 * Return: 1 with @other_id filled, 0 when none, or a negative errno.
 */
int publishers_endpoint_shared(const char *base_dir, const char *self_id,
			       const char *ca_server, int ca_port,
			       char *other_id, size_t cap);

/**
 * publishers_forget() - Delete the files stored for one publisher.
 * @paths: The profile.
 *
 * Removes the directory last. The TPM key is not touched; the caller evicts
 * it first.
 *
 * Return: 0, or the first negative errno, also when the directory is not
 * left empty.
 */
int publishers_forget(const struct profile_paths *paths);

#endif /* LOTA_AGENT_PUBLISHERS_H */
