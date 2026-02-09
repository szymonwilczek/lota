/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - Steam Runtime Detection and Container-Aware IPC
 *
 * Detects Steam Runtime pressure-vessel containers (soldier, snappy,
 * medic, heavy) and resolves socket paths that are accessible from
 * inside the container sandbox.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_AGENT_STEAM_RUNTIME_H
#define LOTA_AGENT_STEAM_RUNTIME_H

#include <limits.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Steam Runtime container types.
 *
 * pressure-vessel ships multiple runtime versions selected by
 * the STEAM_COMPAT_TOOL_PATHS and per-game configuration:
 *
 *   STEAM_RT_NONE    - no container (native or Steam Runtime 1.0)
 *   STEAM_RT_SOLDIER - Steam Linux Runtime 2.0 (Ubuntu 18.04 base)
 *   STEAM_RT_SNIPER  - Steam Linux Runtime 3.0 (Ubuntu 20.04 base)
 *   STEAM_RT_MEDIC   - Steam Linux Runtime 1.0 (legacy, rare)
 *   STEAM_RT_HEAVY   - Steam Linux Runtime (Proton experimental)
 *   STEAM_RT_UNKNOWN - inside a container but type unrecognised
 */
enum steam_runtime_type {
  STEAM_RT_NONE = 0,
  STEAM_RT_SOLDIER,
  STEAM_RT_SNIPER,
  STEAM_RT_MEDIC,
  STEAM_RT_HEAVY,
  STEAM_RT_UNKNOWN,
};

/*
 * Container environment detection flags.
 */
#define STEAM_ENV_PRESSURE_VESSEL (1U << 0) /* inside pressure-vessel */
#define STEAM_ENV_FLATPAK (1U << 1)         /* inside Flatpak sandbox */
#define STEAM_ENV_STEAM_ACTIVE (1U << 2)    /* Steam client is running */
#define STEAM_ENV_XDG_AVAILABLE (1U << 3)   /* XDG_RUNTIME_DIR exists */
#define STEAM_ENV_PROTON (1U << 4)          /* Proton/Wine detected */

/*
 * Maximum number of extra socket paths the agent can manage.
 */
#define STEAM_RT_MAX_EXTRA_SOCKETS 4

/*
 * Container-accessible socket directory suffix.
 * Appended to $XDG_RUNTIME_DIR.
 */
#define STEAM_RT_SOCKET_DIR_SUFFIX "lota"

/*
 * Container-accessible socket filename.
 */
#define STEAM_RT_SOCKET_NAME "lota.sock"

/*
 * Steam Runtime environment information.
 */
struct steam_runtime_info {
  enum steam_runtime_type type;
  uint32_t env_flags;

  /* Detected paths */
  char xdg_runtime_dir[PATH_MAX];
  char container_socket_path[PATH_MAX];
  char steam_compat_path[PATH_MAX]; /* STEAM_COMPAT_DATA_PATH */

  char container_id[64];

  /* Steam app ID (if available) */
  uint32_t app_id;
};

/*
 * steam_runtime_detect - Detect Steam Runtime container environment.
 * @info: Output structure filled with detected information.
 *
 * Probes environment variables and filesystem markers to determine
 * whether LOTA is running on a host with Steam, inside a
 * pressure-vessel container, or inside a Flatpak sandbox.
 *
 * Returns: 0 on success (info is filled), negative errno on failure.
 */
int steam_runtime_detect(struct steam_runtime_info *info);

/*
 * steam_runtime_type_str - Human-readable runtime type string.
 * @type: Runtime type enum value.
 *
 * Returns: Static string, never NULL.
 */
const char *steam_runtime_type_str(enum steam_runtime_type type);

/*
 * steam_runtime_container_socket_dir - Build the container-accessible
 *   socket directory path.
 * @buf: Destination buffer (important: should be PATH_MAX).
 * @bufsz: Size of buf.
 *
 * Writes "$XDG_RUNTIME_DIR/lota" into buf.
 *
 * Returns: 0 on success, -ENOENT if XDG_RUNTIME_DIR is unset,
 *          -ENAMETOOLONG if path overflows.
 */
int steam_runtime_container_socket_dir(char *buf, size_t bufsz);

/*
 * steam_runtime_container_socket_path - Build the container-accessible
 *   socket path.
 * @buf: Destination buffer (should be PATH_MAX).
 * @bufsz: Size of buf.
 *
 * Writes "$XDG_RUNTIME_DIR/lota/lota.sock" into buf.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int steam_runtime_container_socket_path(char *buf, size_t bufsz);

/*
 * steam_runtime_ensure_socket_dir - Create the container-accessible
 *   socket directory with correct permissions.
 * @dir: Path to create (e.g: from steam_runtime_container_socket_dir).
 *
 * Creates the directory with mode 0750 and sets group to 'lota'
 * if the group exists, matching the primary socket directory setup.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int steam_runtime_ensure_socket_dir(const char *dir);

/*
 * steam_runtime_log_info - Log detected runtime information.
 * @info: Filled info structure from steam_runtime_detect().
 *
 * Prints a summary of the detected environment to stderr at
 * info level.
 */
void steam_runtime_log_info(const struct steam_runtime_info *info);

#endif /* LOTA_AGENT_STEAM_RUNTIME_H */
