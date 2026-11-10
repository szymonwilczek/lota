/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - Configuration file parser
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

#define LOTA_CONFIG_DEFAULT_PATH "/etc/lota/lota.conf"

#define LOTA_DEFAULT_VERIFIER_PORT 8443
#define LOTA_DEFAULT_CA_PORT 8444

/*
 * Candidates of policy_pubkey_resolve(). The package owns the packaged key and
 * does not own the override path.
 */
#define LOTA_ENFORCEMENT_PUBKEY_PATH "/usr/lib/lota/enforcement.pub"
#define LOTA_POLICY_PUBKEY_OVERRIDE "/etc/lota/policy.pub"

/* Largest lota.conf config_profile_append() reads; a larger one is refused */
#define LOTA_CONFIG_MAX_FILE 262144

#define LOTA_CONFIG_MAX_LINE 1024

#define LOTA_CONFIG_MAX_LIBS 64

/* Must not exceed the allow_verity BPF map's max_entries (1024). */
#define LOTA_CONFIG_MAX_VERITY 256

/*
 * Operator UIDs with a container listener. Not above IPC_MAX_EXTRA_LISTENERS,
 * asserted in main_utils.c.
 */
#define LOTA_CONFIG_MAX_CONTAINER_LISTENERS 4

/*
 * Publisher profiles: one section per publisher, each with its own CA, verifier
 * and interval. The section name is a label. The profile's identity is the
 * SHA-256 of its CA trust anchor's SubjectPublicKeyInfo.
 */
#define LOTA_CONFIG_MAX_PROFILES 8
#define LOTA_CONFIG_MAX_PROFILE_NAME 64

_Static_assert(LOTA_PROFILE_MAX_AIK_HANDLES >= LOTA_CONFIG_MAX_PROFILES,
	       "the AIK handle range must cover every configurable profile");

struct lota_profile {
	char name[LOTA_CONFIG_MAX_PROFILE_NAME];

	/* Attestation CA the profile enrolls against */
	char ca[256];
	int ca_port;

	/*
	 * Trust anchor for the CA and the verifier connection. Required: the
	 * profile's identity is derived from it.
	 */
	char ca_cert[PATH_MAX];

	/*
	 * Verifier the profile reports to. `verifier = none` leaves it empty
	 * and sets token_only: nothing is reported to this publisher, and the
	 * target still enrolls, holds an AIK and renews its certificate.
	 * A profile that names neither is refused.
	 */
	char verifier[256];
	int verifier_port;
	bool token_only;

	/*
	 * SHA-256 of the certificate this publisher's verifier may present,
	 * in hex; empty pins nothing.
	 * A top-level pin_sha256 is refused beside profiles.
	 */
	char pin_sha256[128];

	/* 0 = inherit the top-level attest_interval */
	int attest_interval;

	/*
	 * Report to this publisher only while a title bound to it is connected.
	 * On by default; `reporting = continuous` turns it off.
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
	char mode[32]; /* "monitor", "enforce" */
	bool strict_mmap;
	bool strict_exec;
	bool block_ptrace;
	bool strict_modules;
	bool block_anon_exec;

	/* the agent writes what it costs; read at startup only */
	bool bench;

	/* Attestation */
	int attest_interval; /* 0: see attest_effective_interval() */
	uint32_t aik_handle; /* TPM persistent handle */
	char kernel_path[PATH_MAX];

	/*
	 * AIK userAuth at rest. seal_aik_auth adds a copy sealed to the PCR
	 * state and tries it first on load. seal_aik_auth_strict also seals,
	 * drops the plaintext sidecar and has no fallback to it.
	 */
	bool seal_aik_auth;
	bool seal_aik_auth_strict;

	/*
	 * Seal and unseal use the primary at TPM_SEAL_PRIMARY_HANDLE when it
	 * exists. --seal-persist-primary and --seal-evict-primary manage the
	 * object.
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

	uint32_t protect_pids[LOTA_MAX_PROTECTED_PIDS];
	int protect_pid_count;

	/*
	 * UIDs served a listener at /run/user/<uid>/lota/lota.sock.
	 * Empty: one listener in the agent's own XDG_RUNTIME_DIR, when it is set.
	 */
	uint32_t container_listener_uids[LOTA_CONFIG_MAX_CONTAINER_LISTENERS];
	int container_listener_uid_count;

	/* Publisher profiles, in the order the config file lists them. */
	struct lota_profile profiles[LOTA_CONFIG_MAX_PROFILES];
	int profile_count;

	/* "error", "warn", "info" or "debug" */
	char log_level[16];
};

void config_init(struct lota_config *cfg);

/**
 * config_log_priority() - Syslog priority of a log_level value.
 * @name: "error", "warn", "info" or "debug".
 *
 * Return: LOG_ERR, LOG_WARNING, LOG_INFO or LOG_DEBUG; -1 for any other name.
 */
int config_log_priority(const char *name);

/**
 * config_new() - Allocate a config and apply the defaults.
 *
 * The struct is over a megabyte, so callers allocate it.
 *
 * Return: the config, to release with config_free(), or NULL.
 */
struct lota_config *config_new(void);

/**
 * config_free() - Release a config from config_new().
 * @cfg: The config, or NULL.
 */
void config_free(struct lota_config *cfg);

/**
 * config_load() - Parse a config file into @cfg.
 * @cfg: An initialized config.
 * @path: File to read, or NULL for LOTA_CONFIG_DEFAULT_PATH.
 *
 * A symlink is not followed. A file that is not regular, is group- or
 * world-writable, or is owned by neither root nor the effective user is refused
 * before parsing. Parsing continues past a refused line, naming each on stderr,
 * and @cfg keeps the lines that applied.
 *
 * A line of the form [profile "name"] opens a publisher profile. Every key
 * after it belongs to that profile until the next header or the end of the
 * file, so top-level keys go above the first profile.
 *
 * Return: 0 on success; -EINVAL when a line or a profile was refused or the
 * file is not regular; -EPERM for its mode or owner; -EIO on a read error;
 * or the negative errno of the open, -ENOENT for a missing file.
 */
int config_load(struct lota_config *cfg, const char *path);

/**
 * config_load_from_fd() - Parse a config from an open file descriptor.
 * @cfg: An initialized config.
 * @fd: Open file, read from offset 0; it stays open.
 * @filepath: Label for diagnostics, or NULL for "(fd)".
 *
 * Applies the file checks and the rules of config_load(), except the symlink
 * one.
 *
 * Return: as config_load().
 */
int config_load_from_fd(struct lota_config *cfg, int fd, const char *filepath);

/* strict flags, applied in enforce mode only */
#define LOTA_STRICT_FLAG_COUNT 5

/**
 * config_inert_strict_flags() - Strict flags set but inert outside enforce.
 * @cfg: Configuration to read.
 * @names: Receives the key names, in the order config_dump() prints them.
 * @max: Capacity of @names.
 *
 * Return: the number of names written, or a negative errno.
 */
int config_inert_strict_flags(const struct lota_config *cfg,
			      const char *names[], int max);

/**
 * config_inert_strict_flags_of() - config_inert_strict_flags() on bare flags.
 * @mode_is_enforce: Whether the mode being applied is enforce.
 * @flags: The five flags, in the order config_dump() prints them.
 * @names: Receives the key names of those that are on and inert.
 * @max: Capacity of @names.
 *
 * Return: the number of names written, or a negative errno.
 */
int config_inert_strict_flags_of(bool mode_is_enforce,
				 const bool flags[LOTA_STRICT_FLAG_COUNT],
				 const char *names[], int max);

/**
 * config_dump() - Print a config in the syntax config_load() parses.
 * @cfg: Configuration to print.
 * @fp: Where to print it.
 */
void config_dump(const struct lota_config *cfg, FILE *fp);

/**
 * config_profile_name_defect() - Why the parser would refuse a profile label.
 * @name: Candidate for a [profile "name"] header.
 * @why: Receives a reason for an error message.
 * @why_cap: Size of @why.
 *
 * Return: 0 for an acceptable label, -EINVAL for an empty one or no @why,
 * or -EILSEQ for one too long or carrying a quote or a control character.
 */
int config_profile_name_defect(const char *name, char *why, size_t why_cap);

/**
 * config_profile_defect() - Why the writer would refuse a profile.
 * @p: The publisher a section would be written for.
 * @why: Receives a reason for an error message, naming the field.
 * @why_cap: Size of @why.
 *
 * Checks the label, ca, ca_cert, pin_sha256 and verifier. The ports and the
 * interval are not checked.
 *
 * Return: 0 when the checks pass, -EINVAL when the label, ca or ca_cert is
 * empty, or -EILSEQ when a check refuses a field.
 */
int config_profile_defect(const struct lota_profile *p, char *why,
			  size_t why_cap);

/**
 * config_profile_append_text() - Add a publisher profile to a config's text.
 * @existing: Current file contents; may be empty, not NULL.
 * @p: The publisher to add.
 * @out: Receives @existing unchanged, then the section.
 * @out_cap: Size of @out.
 *
 * @existing is searched as plain text, so a comment counts, and for the ca_cert
 * so do a top-level key and a longer path starting with @p's.
 *
 * Return: 1 when the section was appended; 0, with @out holding @existing, when
 * "ca_cert = " and @p's path occur in the text; -EEXIST when "[profile" with
 * the quoted label occurs; -E2BIG when "[profile" occurs
 * LOTA_CONFIG_MAX_PROFILES times or more; -EOVERFLOW when the section or the
 * result does not fit; or the errors of config_profile_defect().
 */
int config_profile_append_text(const char *existing,
			       const struct lota_profile *p, char *out,
			       size_t out_cap);

/**
 * config_profile_append() - Add a publisher profile to the file at @path.
 * @path: The config file; a missing one counts as empty.
 * @p: The publisher to add.
 *
 * Writes @path.new, reads it back with config_load() and renames it into place.
 *
 * Return: as config_profile_append_text(); -EBADMSG when the read-back fails,
 * with @path untouched; or another negative errno.
 */
int config_profile_append(const char *path, const struct lota_profile *p);

#endif /* LOTA_CONFIG_H */
