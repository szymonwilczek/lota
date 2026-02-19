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

/* Default config file path */
#define LOTA_CONFIG_DEFAULT_PATH "/etc/lota/lota.conf"

/* Maximum line length in config file */
#define LOTA_CONFIG_MAX_LINE 1024

/* Maximum number of trust-lib / protect-pid entries */
#define LOTA_CONFIG_MAX_LIBS 64
#define LOTA_CONFIG_MAX_LIBS 64

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
  bool block_ptrace;

  /* Attestation */
  int attest_interval; /* 0 = one-shot */
  uint32_t aik_ttl;    /* seconds, 0 = default */
  uint32_t aik_handle; /* TPM persistent handle, 0 = default */

  /* Daemon */
  bool daemon;
  char pid_file[PATH_MAX];

  /* Policy signing */
  char signing_key[PATH_MAX];
  char policy_pubkey[PATH_MAX];

  /* Trusted libraries */
  char trust_libs[LOTA_CONFIG_MAX_LIBS][PATH_MAX];
  int trust_lib_count;

  /* Protected PIDs */
  uint32_t *protect_pids;
  int protect_pid_count;

  /* Log level: "debug", "info", "warn", "error" */
  char log_level[16];
};

/*
 * config_init - Fill config with compiled-in defaults.
 */
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
 * Unknown keys are logged to stderr and skipped.
 * Malformed lines are logged but do not stop parsing.
 */
int config_load(struct lota_config *cfg, const char *path);

/*
 * config_dump - Print current configuration to FILE.
 *
 * Writes all effective values in the same key = value format that
 * can be fed back into config_load().
 */
void config_dump(const struct lota_config *cfg, FILE *fp);

#endif /* LOTA_CONFIG_H */
