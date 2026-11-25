/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - Steam Runtime detection and container socket paths
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_AGENT_STEAM_RUNTIME_H
#define LOTA_AGENT_STEAM_RUNTIME_H

#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

enum steam_runtime_type {
	STEAM_RT_NONE = 0, /* neither PRESSURE_VESSEL_RUNTIME nor _BASE set */
	STEAM_RT_SOLDIER,
	STEAM_RT_SNIPER,
	STEAM_RT_MEDIC,
	STEAM_RT_HEAVY,
	STEAM_RT_UNKNOWN, /* a value classify_runtime() did not recognise */
};

/*
 * env_flags, where "set" means not empty and not rejected as malformed:
 * PRESSURE_VESSEL: PRESSURE_VESSEL_RUNTIME or PRESSURE_VESSEL_RUNTIME_BASE set
 * FLATPAK: /.flatpak-info is a regular file
 * STEAM_ACTIVE: SteamAppId or STEAM_COMPAT_DATA_PATH set
 * XDG_AVAILABLE: XDG_RUNTIME_DIR set, and a directory itself, not a symlink
 * PROTON: PROTON_VERSION or STEAM_COMPAT_TOOL_PATHS set
 */
#define STEAM_ENV_PRESSURE_VESSEL (1U << 0)
#define STEAM_ENV_FLATPAK (1U << 1)
#define STEAM_ENV_STEAM_ACTIVE (1U << 2)
#define STEAM_ENV_XDG_AVAILABLE (1U << 3)
#define STEAM_ENV_PROTON (1U << 4)

/* appended to $XDG_RUNTIME_DIR */
#define STEAM_RT_SOCKET_DIR_SUFFIX "lota"

/* the socket directory's group, so titles in it can connect */
#define STEAM_RT_SOCKET_GROUP "lota"

#define STEAM_RT_SOCKET_NAME "lota.sock"

struct steam_runtime_info {
	enum steam_runtime_type type;
	uint32_t env_flags;

	char xdg_runtime_dir[PATH_MAX];
	char container_socket_path[PATH_MAX];
	char steam_compat_path[PATH_MAX]; /* STEAM_COMPAT_DATA_PATH */

	char container_id[64];

	/* SteamAppId; 0 when unset or not a uint32_t */
	uint32_t app_id;
};

/**
 * steam_runtime_detect() - Read this process's environment and /.flatpak-info.
 * @info: Receives the result.
 *
 * Return: 0, or -EINVAL when @info is NULL.
 */
int steam_runtime_detect(struct steam_runtime_info *info);

/**
 * steam_runtime_type_str() - Name a runtime type.
 * @type: The type.
 *
 * Return: a static string, never NULL.
 */
const char *steam_runtime_type_str(enum steam_runtime_type type);

/**
 * steam_runtime_runtime_dir() - Copy XDG_RUNTIME_DIR out.
 * @buf: Destination.
 * @bufsz: Its size.
 *
 * Return: 0, -EINVAL, -ENOENT when the variable is unset or rejected,
 * or -ENAMETOOLONG.
 */
int steam_runtime_runtime_dir(char *buf, size_t bufsz);

/**
 * steam_runtime_container_socket_dir() - Build the socket directory.
 * @buf: Destination.
 * @bufsz: Its size.
 *
 * Writes "$XDG_RUNTIME_DIR/lota".
 *
 * Return: as for steam_runtime_runtime_dir().
 */
int steam_runtime_container_socket_dir(char *buf, size_t bufsz);

/**
 * steam_runtime_container_socket_path() - Build the socket path.
 * @buf: Destination.
 * @bufsz: Its size.
 *
 * Writes "$XDG_RUNTIME_DIR/lota/lota.sock".
 *
 * Return: as for steam_runtime_runtime_dir().
 */
int steam_runtime_container_socket_path(char *buf, size_t bufsz);

/**
 * steam_runtime_ensure_socket_dir() - Make the socket directory, mode 0750.
 * @dir: Path to create or repair.
 * @gid: Group to hand it to, or (gid_t)-1 to leave it.
 *
 * Return: 0, -ENOTDIR when @dir is not a directory, or another negative
 * errno.
 */
int steam_runtime_ensure_socket_dir(const char *dir, gid_t gid);

/**
 * steam_runtime_log_info() - Log what steam_runtime_detect() found.
 * @info: Its result.
 */
void steam_runtime_log_info(const struct steam_runtime_info *info);

#endif /* LOTA_AGENT_STEAM_RUNTIME_H */
