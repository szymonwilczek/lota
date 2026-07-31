/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * The publishers this host answers to.
 *
 * Player who cannot see which publishers hold a key on their machine,
 * or take one back, has been asked to consent to something they cannot inspect.
 * This is the inspection half: what is stored, who it is for, and how to destroy it.
 *
 * Reading the inventory is separate from the TPM on purpose -- it walks the profile
 * directories and nothing else, so it stays testable and player can run it
 * on machine whose agent will not start.
 */

#ifndef LOTA_AGENT_PUBLISHERS_H
#define LOTA_AGENT_PUBLISHERS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "profile.h"

struct publisher_entry {
	char id[LOTA_PROFILE_ID_LEN];

	/* somebody agreed to this publisher at this time */
	bool consented;
	time_t consented_at;

	/* enrollment record exists, naming where it was made */
	bool enrolled;
	char ca_server[256];
	int ca_port;

	/* the AIK this publisher's evidence is signed with */
	bool has_aik_handle;
	uint32_t aik_handle;

	/* validity left on the CA-issued certificate, when one is stored */
	bool has_cert;
	int64_t cert_remaining_sec;
};

/*
 * Read every profile under @base_dir into @out, in directory order.
 *
 * Directory that holds nothing readable is still listed: profile with consent
 * record and no enrollment is exactly the state between agreeing and title first
 * running, and hiding it would hide the answer to "why is this publisher not
 * working yet".
 *
 * Returns 0 (with *count set), or negative errno.
 * Missing base directory is not an error: this host has answered to nobody.
 */
int publishers_list(const char *base_dir, struct publisher_entry *out,
		    size_t max, size_t *count);

/*
 * Delete everything stored for one publisher.
 *
 * TPM key is not this function's business -- the caller evicts it first,
 * because a key with no directory left to name it is worse than either state alone.
 *
 * Returns 0, or negative errno.
 */
int publishers_forget(const struct profile_paths *paths);

#endif /* LOTA_AGENT_PUBLISHERS_H */
