/* SPDX-License-Identifier: MIT */
/*
 * LOTA - Which key verifies the enforcement object
 *
 * Shared by the agent, which verifies with the key, and the installer,
 * which reports it.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_POLICY_PUBKEY_H
#define LOTA_POLICY_PUBKEY_H

/*
 * policy_pubkey_resolve - Which key verifies the enforcement object.
 *
 * @configured:    policy_pubkey from the config file or the CLI, or NULL.
 * @override_path: operator-owned key no package owns.
 * @packaged_path: key the agent package shipped beside the object.
 *
 * Returns the first readable path in that order, or NULL; the agent refuses
 * to load an object it cannot verify. Paths are parameters so tests need not
 * touch /usr or /etc.
 */
const char *policy_pubkey_resolve(const char *configured,
				  const char *override_path,
				  const char *packaged_path);

#endif /* LOTA_POLICY_PUBKEY_H */
