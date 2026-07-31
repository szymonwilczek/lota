/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - Configuration file parser
 *
 * Parses /etc/lota/lota.conf (or user-supplied path) into a typed
 * struct.
 *
 * Every field has a sensible default. CLI flags override any value
 * loaded from the config file -- the caller applies config first,
 * then lets getopt overwrite individual fields.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#ifndef LOTA_CONFIG_H
#define LOTA_CONFIG_H

#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include "../../include/lota.h"
#include "profile.h"

/* Default config file path */
#define LOTA_CONFIG_DEFAULT_PATH "/etc/lota/lota.conf"

/*
 * Default endpoints.
 * Stated here rather than beside the CLI because the config file, the CLI
 * and every publisher profile all need the same two numbers, and config.h
 * is the header they can all reach.
 */
#define LOTA_DEFAULT_VERIFIER_PORT 8443
#define LOTA_DEFAULT_CA_PORT 8444

/* Maximum line length in config file */
#define LOTA_CONFIG_MAX_LINE 1024

/* Maximum number of trust-lib / protect-pid entries */
#define LOTA_CONFIG_MAX_LIBS 64

/*
 * Maximum number of fs-verity allowlist entries.
 * Must not exceed the BPF map capacity (allow_verity_digest.max_entries=1024).
 */
#define LOTA_CONFIG_MAX_VERITY 256

/*
 * Maximum number of operator UIDs that get a container-accessible
 * IPC listener at /run/user/<uid>/lota/lota.sock. Must match
 * IPC_MAX_EXTRA_LISTENERS so every entry has a slot in
 * struct ipc_context.extra[]. Asserted in main_utils.c.
 */
#define LOTA_CONFIG_MAX_CONTAINER_LISTENERS 4

/*
 * Publisher profiles.
 *
 * Player's machine has one state and several publishers judging it, each with
 * its own attestation CA, its own verifier and its own cadence.
 *
 * Profile list is how the agent is told about more than one of them, so that
 * buying a second game does not mean re-provisioning the host.
 *
 * The section name is an operator-facing label only.
 * Profile's identity is the SHA-256 of its CA trust anchor's SubjectPublicKeyInfo
 * -- the endpoint is mutable and spoofable, while the anchor is what enrollment
 *  actually verifies against, so it survives an address change and cannot collide
 *  between two publishers sharing a hostname.
 */
#define LOTA_CONFIG_MAX_PROFILES 8
#define LOTA_CONFIG_MAX_PROFILE_NAME 64

/* Every configured profile has to have an AIK handle to be given */
_Static_assert(LOTA_PROFILE_MAX_AIK_HANDLES >= LOTA_CONFIG_MAX_PROFILES,
	       "the AIK handle range must cover every configurable profile");

struct lota_profile {
	char name[LOTA_CONFIG_MAX_PROFILE_NAME];

	/* Attestation CA the profile enrolls against */
	char ca[256];
	int ca_port;

	/*
	 * Trust anchor for both the CA and the verifier connection.
	 * Required: it is what the profile's identity is derived from
	 */
	char ca_cert[PATH_MAX];

	/* Verifier the profile reports to */
	char verifier[256];
	int verifier_port;

	/* 0 = inherit the top-level attest_interval */
	int attest_interval;

	/*
	 * Report to this publisher only while a title of theirs is running.
	 *
	 * Player's machine is not a fleet asset:
	 * Verifier receiving quote every five minutes from boot to poweroff
	 * learns when the machine is on, and learns it for a publisher whose
	 * game is closed.
	 * Enforcement and the PCR 14 boot commitment stay always-on either way
	 * and never send a byte, which is what keeps a session's quote able to
	 * prove the whole boot-to-now window.
	 *
	 * Default for a profile; Operator fleet that wants continuous stream
	 * sets `reporting = continuous`
	 */
	bool session_gated;
};

struct lota_config {
	/* Verifier connection */
	char server[256];
	int port;
	char ca_cert[PATH_MAX];
	char pin_sha256[128]; /* hex string, parsed later */

	/* BPF / enforcement */
	char bpf_path[PATH_MAX];
	char mode[32]; /* "monitor", "enforce", "maintenance" */
	bool strict_mmap;
	bool strict_exec;
	bool block_ptrace;
	bool strict_modules;
	bool block_anon_exec;

	/* Attestation */
	int attest_interval; /* 0 = one-shot */
	uint32_t aik_ttl; /* seconds, 0 = default */
	uint32_t aik_handle; /* TPM persistent handle, 0 = default */
	char kernel_path[PATH_MAX];

	/*
	 * At-rest hardening for the AIK userAuth. Default off keeps the
	 * existing plaintext sidecar behaviour byte-for-byte. When on, the
	 * agent also writes a copy sealed to the boot/PCR state and prefers
	 * it on load. strict additionally drops the plaintext sidecar so the
	 * auth only exists sealed -- a boot-state change then forces
	 * re-provisioning.
	 */
	bool seal_aik_auth;
	bool seal_aik_auth_strict;

	/*
	 * Reuse a persistent seal storage primary (TPM_SEAL_PRIMARY_HANDLE)
	 * instead of deriving it per seal/unseal. Default off. Persist/evict
	 * the object with --seal-persist-primary / --seal-evict-primary.
	 */
	bool seal_persistent_primary;

	/* Daemon */
	bool daemon;
	char pid_file[PATH_MAX];

	/* Policy signing */
	char signing_key[PATH_MAX];
	char policy_pubkey[PATH_MAX];

	/* Trusted libraries */
	char trust_libs[LOTA_CONFIG_MAX_LIBS][PATH_MAX];
	int trust_lib_count;

	/* Allowed fs-verity files (paths are measured to digests at startup) */
	char allow_verity[LOTA_CONFIG_MAX_VERITY][PATH_MAX];
	int allow_verity_count;

	/* Protected PIDs: inline, capped at LOTA_MAX_PROTECTED_PIDS */
	uint32_t protect_pids[LOTA_MAX_PROTECTED_PIDS];
	int protect_pid_count;

	/*
	 * Operator UIDs that receive an additional listener under
	 * /run/user/<uid>/lota/lota.sock. Steam pressure-vessel only
	 * mounts /run/user/<uid> into the container, so each user that
	 * launches games needs a per-UID secondary socket.
	 * Empty list selects the single-operator mode instead: one secondary
	 * listener in the agent's own XDG_RUNTIME_DIR, which is what
	 * the documented systemd drop-in pins and what the SDK auto-detects.
	 */
	uint32_t container_listener_uids[LOTA_CONFIG_MAX_CONTAINER_LISTENERS];
	int container_listener_uid_count;

	/* Publisher profiles, in the order the config file lists them. */
	struct lota_profile profiles[LOTA_CONFIG_MAX_PROFILES];
	int profile_count;

	/* Log level: "debug", "info", "warn", "error" */
	char log_level[16];
};

void config_init(struct lota_config *cfg);

/*
 * config_load - Parse a config file into the struct.
 *
 * @cfg:  Pointer to an already-initialized config struct.
 * @path: File path. If NULL, uses LOTA_CONFIG_DEFAULT_PATH.
 *
 * Returns:
 *    0  on success (file parsed, all recognised keys applied)
 *   -ENOENT  if the file does not exist (non-fatal if default path)
 *   -EINVAL  if a line is malformed (logged to stderr, keeps going)
 *   -errno   on I/O error
 *
 * Unknown keys are logged to stderr and cause an error return (fail-closed).
 * Malformed lines are logged but do not stop parsing.
 *
 * Line of the form [profile "name"] opens a publisher profile.
 * Every key after it belongs to that profile until the next section header
 * or the end of the file; there is no way back to the top level,
 * so the top-level keys belong above the first profile.
 */
int config_load(struct lota_config *cfg, const char *path);

/*
 * config_load_from_fd - Parse configuration from an already-open fd.
 *
 * @cfg:      Pointer to an already-initialized config struct.
 * @fd:       Open read-only file descriptor for config file.
 * @filepath: Optional label for diagnostics (NULL -> "(fd)").
 *
 * This validates file security constraints and then parses from offset 0.
 * The caller keeps ownership of @fd.
 */
int config_load_from_fd(struct lota_config *cfg, int fd, const char *filepath);

/*
 * config_dump - Print current configuration to FILE.
 *
 * Writes all effective values in the same key = value format that
 * can be fed back into config_load().
 */
void config_dump(const struct lota_config *cfg, FILE *fp);

#endif /* LOTA_CONFIG_H */
