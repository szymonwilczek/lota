/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
#ifndef LOTA_RELOAD_H
#define LOTA_RELOAD_H

#include <stdbool.h>
#include <stdint.h>
#include <limits.h>

#include "config.h"

/**
 * agent_reload_config() - Re-read the config file and apply it to the daemon.
 * @config_path: File to read, or NULL or empty for LOTA_CONFIG_DEFAULT_PATH.
 * @cfg: The daemon's config; updated when applied.
 * @mode: Current mode; updated when applied.
 * @strict_mmap: Current switch; updated when applied.
 * @strict_exec: Likewise.
 * @block_ptrace: Likewise.
 * @strict_modules: Likewise.
 * @block_anon_exec: Likewise.
 * @protect_pids: Current protected set; replaced when applied.
 * @protect_pid_count: Its size.
 * @trust_libs: Current trusted libraries; rewritten when applied.
 * @trust_lib_count: Their number.
 *
 * Leaving enforce for monitor needs the file's .sig to verify against the
 * policy_pubkey in @cfg. A change that fails to apply is logged and the old
 * state restored where the agent can, and the call still returns 0.
 * allow_verity, bench, kernel_path, the seal_* switches and
 * container_listener_uid wait for a restart, and a new aik_handle reaches only
 * @cfg. Readiness is reported to systemd on every path.
 *
 * Return: 0, also when the file is missing and nothing changes; or a negative
 * errno when the file cannot be opened or parsed, the config cannot be
 * allocated or the downgrade is not authorized, with nothing changed.
 */
int agent_reload_config(const char *config_path, struct lota_config *cfg,
			int *mode, bool *strict_mmap, bool *strict_exec,
			bool *block_ptrace, bool *strict_modules,
			bool *block_anon_exec, uint32_t **protect_pids,
			int *protect_pid_count,
			char trust_libs[LOTA_CONFIG_MAX_LIBS][PATH_MAX],
			int *trust_lib_count);

#endif /* LOTA_RELOAD_H */
