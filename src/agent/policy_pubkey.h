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

/**
 * policy_pubkey_resolve() - Pick the key that verifies the enforcement object.
 * @configured: policy_pubkey from the config file, or NULL.
 * @override_path: The operator's key.
 * @packaged_path: The key the agent package ships.
 *
 * The paths are parameters so that tests need not touch /usr or /etc.
 *
 * Return: the first readable path in the order of the parameters, or NULL.
 */
const char *policy_pubkey_resolve(const char *configured,
				  const char *override_path,
				  const char *packaged_path);

#endif /* LOTA_POLICY_PUBKEY_H */
