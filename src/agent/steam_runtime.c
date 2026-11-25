/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - Steam Runtime detection and container socket paths
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include "steam_runtime.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/types.h>

#include "journal.h"

static enum steam_runtime_type classify_runtime(const char *runtime_str)
{
	if (!runtime_str || !runtime_str[0])
		return STEAM_RT_UNKNOWN;

	if (strstr(runtime_str, "soldier"))
		return STEAM_RT_SOLDIER;
	if (strstr(runtime_str, "sniper"))
		return STEAM_RT_SNIPER;
	if (strstr(runtime_str, "medic") || strstr(runtime_str, "scout"))
		return STEAM_RT_MEDIC;
	if (strstr(runtime_str, "heavy"))
		return STEAM_RT_HEAVY;

	return STEAM_RT_UNKNOWN;
}

static uint32_t parse_uint32(const char *s)
{
	unsigned long val;
	char *end;

	if (!s || !s[0])
		return 0;

	errno = 0;
	val = strtoul(s, &end, 10);
	if (end == s || *end != '\0' || errno == ERANGE || val > UINT32_MAX)
		return 0;

	return (uint32_t)val;
}

static int is_directory(const char *path)
{
	struct stat st;

	if (lstat(path, &st) != 0)
		return 0;
	return S_ISDIR(st.st_mode);
}

static int is_regular_file(const char *path)
{
	struct stat st;

	if (lstat(path, &st) != 0)
		return 0;
	return S_ISREG(st.st_mode);
}

/* NULL when unset, empty, longer than @max_len or holding a control char */
static const char *get_env_safe(const char *name, size_t max_len)
{
	const char *val = getenv(name);
	size_t len;

	if (!val || val[0] == '\0')
		return NULL;

	len = strlen(val);
	if (len > max_len) {
		lota_warn("steam_runtime: env var %s exceeds limit (%zu > "
			  "%zu), ignoring",
			  name, len, max_len);
		return NULL;
	}

	for (size_t i = 0; i < len; i++) {
		unsigned char c = (unsigned char)val[i];
		if (c < 0x20 || c == 0x7f) {
			lota_warn("steam_runtime: env var %s contains control "
				  "char 0x%02x, "
				  "ignoring",
				  name, c);
			return NULL;
		}
	}

	return val;
}

int steam_runtime_detect(struct steam_runtime_info *info)
{
	const char *env;

	if (!info)
		return -EINVAL;

	memset(info, 0, sizeof(*info));
	info->type = STEAM_RT_NONE;

	env = get_env_safe("PRESSURE_VESSEL_RUNTIME", PATH_MAX);
	if (env) {
		info->env_flags |= STEAM_ENV_PRESSURE_VESSEL;
		info->type = classify_runtime(env);
	}

	if (!(info->env_flags & STEAM_ENV_PRESSURE_VESSEL)) {
		env = get_env_safe("PRESSURE_VESSEL_RUNTIME_BASE", 256);
		if (env) {
			info->env_flags |= STEAM_ENV_PRESSURE_VESSEL;
			info->type = classify_runtime(env);
		}
	}

	if (is_regular_file("/.flatpak-info"))
		info->env_flags |= STEAM_ENV_FLATPAK;

	env = get_env_safe("SteamAppId", 32);
	if (env) {
		info->env_flags |= STEAM_ENV_STEAM_ACTIVE;
		info->app_id = parse_uint32(env);
	}

	env = get_env_safe("STEAM_COMPAT_DATA_PATH",
			   sizeof(info->steam_compat_path) - 1);
	if (env) {
		info->env_flags |= STEAM_ENV_STEAM_ACTIVE;
		snprintf(info->steam_compat_path,
			 sizeof(info->steam_compat_path), "%s", env);
	}

	env = get_env_safe("PROTON_VERSION", 64);
	if (!env)
		env = get_env_safe("STEAM_COMPAT_TOOL_PATHS", PATH_MAX);
	if (env)
		info->env_flags |= STEAM_ENV_PROTON;

	env = get_env_safe("XDG_RUNTIME_DIR",
			   sizeof(info->xdg_runtime_dir) - 1);
	if (env && is_directory(env)) {
		info->env_flags |= STEAM_ENV_XDG_AVAILABLE;
		snprintf(info->xdg_runtime_dir, sizeof(info->xdg_runtime_dir),
			 "%s", env);
	}

	if (info->env_flags & STEAM_ENV_XDG_AVAILABLE) {
		(void)steam_runtime_container_socket_path(
			info->container_socket_path,
			sizeof(info->container_socket_path));
	}

	env = get_env_safe("PRESSURE_VESSEL_INSTANCE_ID",
			   sizeof(info->container_id) - 1);
	if (env) {
		snprintf(info->container_id, sizeof(info->container_id), "%s",
			 env);
	} else if (info->env_flags & STEAM_ENV_PRESSURE_VESSEL) {
		snprintf(info->container_id, sizeof(info->container_id),
			 "pv-%u", info->app_id);
	}

	return 0;
}

const char *steam_runtime_type_str(enum steam_runtime_type type)
{
	switch (type) {
	case STEAM_RT_NONE:
		return "none";
	case STEAM_RT_SOLDIER:
		return "soldier";
	case STEAM_RT_SNIPER:
		return "sniper";
	case STEAM_RT_MEDIC:
		return "medic";
	case STEAM_RT_HEAVY:
		return "heavy";
	case STEAM_RT_UNKNOWN:
		return "unknown";
	}
	return "invalid";
}

int steam_runtime_runtime_dir(char *buf, size_t bufsz)
{
	const char *xdg;
	int n;

	if (!buf || bufsz == 0)
		return -EINVAL;

	xdg = get_env_safe("XDG_RUNTIME_DIR", PATH_MAX);
	if (!xdg)
		return -ENOENT;

	n = snprintf(buf, bufsz, "%s", xdg);
	if (n < 0 || (size_t)n >= bufsz)
		return -ENAMETOOLONG;

	return 0;
}

int steam_runtime_container_socket_dir(char *buf, size_t bufsz)
{
	const char *xdg;
	int n;

	if (!buf || bufsz == 0)
		return -EINVAL;

	xdg = get_env_safe("XDG_RUNTIME_DIR", PATH_MAX);
	if (!xdg)
		return -ENOENT;

	n = snprintf(buf, bufsz, "%s/%s", xdg, STEAM_RT_SOCKET_DIR_SUFFIX);
	if (n < 0 || (size_t)n >= bufsz)
		return -ENAMETOOLONG;

	return 0;
}

int steam_runtime_container_socket_path(char *buf, size_t bufsz)
{
	const char *xdg;
	int n;

	if (!buf || bufsz == 0)
		return -EINVAL;

	xdg = get_env_safe("XDG_RUNTIME_DIR", PATH_MAX);
	if (!xdg)
		return -ENOENT;

	n = snprintf(buf, bufsz, "%s/%s/%s", xdg, STEAM_RT_SOCKET_DIR_SUFFIX,
		     STEAM_RT_SOCKET_NAME);
	if (n < 0 || (size_t)n >= bufsz)
		return -ENAMETOOLONG;

	return 0;
}

int steam_runtime_ensure_socket_dir(const char *dir, gid_t gid)
{
	struct stat st;

	if (!dir || !dir[0])
		return -EINVAL;

	if (stat(dir, &st) == 0) {
		if (!S_ISDIR(st.st_mode))
			return -ENOTDIR;
	} else if (mkdir(dir, 0750) < 0 && errno != EEXIST) {
		return -errno;
	}

	/*
	 * An existing directory may carry another mode, and mkdir masks this
	 * one: the unit sets UMask=0077.
	 */
	if (chmod(dir, 0750) < 0)
		return -errno;

	if (lstat(dir, &st) < 0)
		return -errno;
	if (!S_ISDIR(st.st_mode))
		return -ENOTDIR;

	if (gid == (gid_t)-1)
		return 0;

	if (fchownat(AT_FDCWD, dir, (uid_t)-1, gid, AT_SYMLINK_NOFOLLOW) < 0)
		return -errno;

	return 0;
}

void steam_runtime_log_info(const struct steam_runtime_info *info)
{
	if (!info)
		return;

	lota_info("steam_runtime: type=%s flags=0x%x app_id=%u container=%s "
		  "socket=%s",
		  steam_runtime_type_str(info->type), info->env_flags,
		  info->app_id,
		  info->container_id[0] ? info->container_id : "(none)",
		  info->container_socket_path[0] ? info->container_socket_path :
						   "(none)");
}
