/* SPDX-License-Identifier: MIT */
/*
 * LOTA - Which key verifies the enforcement object
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include "policy_pubkey.h"

#include <unistd.h>

const char *policy_pubkey_resolve(const char *configured,
				  const char *override_path,
				  const char *packaged_path)
{
	/* An upgrade can remove a path an older installer wrote. */
	if (configured && configured[0] && access(configured, R_OK) == 0)
		return configured;

	if (override_path && access(override_path, R_OK) == 0)
		return override_path;
	if (packaged_path && access(packaged_path, R_OK) == 0)
		return packaged_path;
	return NULL;
}
