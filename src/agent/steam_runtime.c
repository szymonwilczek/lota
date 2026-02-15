/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - Steam Runtime Detection and Container-Aware IPC
 *
 * Detects Steam Runtime pressure-vessel containers and resolves
 * IPC socket paths accessible from inside the sandbox.
 *
 * Detection strategy:
 *  - Check PRESSURE_VESSEL_* env vars (definitive container signal)
 *  - Check /.flatpak-info (Flatpak sandbox)
 *  - Check STEAM_COMPAT_*, SteamAppId (Steam active)
 *  - Probe $XDG_RUNTIME_DIR availability and writability
 *  - Check PROTON_* / WINEPREFIX (Proton/Wine)
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include "steam_runtime.h"
#include "journal.h"

#include <errno.h>
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define LOTA_GROUP_NAME "lota"

/*
 * Classify the runtime version from PRESSURE_VESSEL_RUNTIME or
 * the /usr manifest inside the container.
 *
 * Known bases:
 *   soldier -> SteamLinuxRuntime_soldier (Ubuntu 18.04)
 *   sniper  -> SteamLinuxRuntime_sniper  (Ubuntu 20.04)
 *   medic   -> SteamLinuxRuntime (legacy 1.0 scout derivative)
 *   heavy   -> SteamLinuxRuntime_heavy   (experimental)
 */
static enum steam_runtime_type classify_runtime(const char *runtime_str) {
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

/*
 * Parse a uint32 from a string.  Returns 0 for NULL or invalid.
 */
static uint32_t parse_uint32(const char *s) {
  long val;
  char *end;

  if (!s || !s[0])
    return 0;

  val = strtol(s, &end, 10);
  if (end == s || val < 0 || val > (long)UINT32_MAX)
    return 0;

  return (uint32_t)val;
}

/*
 * Check if a path exists and is a directory (not a symlink).
 */
static int is_directory(const char *path) {
  struct stat st;

  if (lstat(path, &st) != 0)
    return 0;
  return S_ISDIR(st.st_mode);
}

/*
 * Check if a regular file exists (not a symlink).
 */
static int is_regular_file(const char *path) {
  struct stat st;

  if (lstat(path, &st) != 0)
    return 0;
  return S_ISREG(st.st_mode);
}

int steam_runtime_detect(struct steam_runtime_info *info) {
  const char *env;

  if (!info)
    return -EINVAL;

  memset(info, 0, sizeof(*info));
  info->type = STEAM_RT_NONE;

  /*
   * Detect pressure-vessel container.
   *
   * Inside a pressure-vessel container the following env vars
   * are set by the runtime's entry point:
   *   PRESSURE_VESSEL_RUNTIME       path to runtime sysroot
   *   PRESSURE_VESSEL_RUNTIME_BASE  base name of the runtime
   *   PRESSURE_VESSEL_LOCALE_I18N   locale mode
   *
   * Any of these is a definitive signal.
   */
  env = getenv("PRESSURE_VESSEL_RUNTIME");
  if (env && env[0]) {
    info->env_flags |= STEAM_ENV_PRESSURE_VESSEL;
    info->type = classify_runtime(env);
  }

  if (!(info->env_flags & STEAM_ENV_PRESSURE_VESSEL)) {
    env = getenv("PRESSURE_VESSEL_RUNTIME_BASE");
    if (env && env[0]) {
      info->env_flags |= STEAM_ENV_PRESSURE_VESSEL;
      info->type = classify_runtime(env);
    }
  }

  /*
   * Detect Flatpak sandbox.
   *
   * Steam installs from Flathub run inside a Flatpak sandbox.
   * /.flatpak-info exists only inside the sandbox.
   */
  if (is_regular_file("/.flatpak-info"))
    info->env_flags |= STEAM_ENV_FLATPAK;

  /*
   * Detect Steam client activity.
   *
   * SteamAppId is set for every game launched through Steam.
   * STEAM_COMPAT_DATA_PATH is set when using Proton.
   */
  env = getenv("SteamAppId");
  if (env && env[0]) {
    info->env_flags |= STEAM_ENV_STEAM_ACTIVE;
    info->app_id = parse_uint32(env);
  }

  env = getenv("STEAM_COMPAT_DATA_PATH");
  if (env && env[0]) {
    info->env_flags |= STEAM_ENV_STEAM_ACTIVE;
    snprintf(info->steam_compat_path, sizeof(info->steam_compat_path), "%s",
             env);
  }

  /*
   * Detect Proton/Wine.
   */
  env = getenv("PROTON_VERSION");
  if (!env)
    env = getenv("STEAM_COMPAT_TOOL_PATHS");
  if (env && env[0])
    info->env_flags |= STEAM_ENV_PROTON;

  /*
   * Probe XDG_RUNTIME_DIR.
   */
  env = getenv("XDG_RUNTIME_DIR");
  if (env && env[0] && is_directory(env)) {
    info->env_flags |= STEAM_ENV_XDG_AVAILABLE;
    snprintf(info->xdg_runtime_dir, sizeof(info->xdg_runtime_dir), "%s", env);
  }

  /*
   * Build container-accessible socket path.
   *
   * If XDG_RUNTIME_DIR is set, this will always succeed
   * because PATH_MAX is large enough for any sane path.
   */
  if (info->env_flags & STEAM_ENV_XDG_AVAILABLE) {
    (void)steam_runtime_container_socket_path(
        info->container_socket_path, sizeof(info->container_socket_path));
  }

  /*
   * Container ID
   */
  env = getenv("PRESSURE_VESSEL_INSTANCE_ID");
  if (env && env[0]) {
    snprintf(info->container_id, sizeof(info->container_id), "%s", env);
  } else if (info->env_flags & STEAM_ENV_PRESSURE_VESSEL) {
    snprintf(info->container_id, sizeof(info->container_id), "pv-%u",
             info->app_id);
  }

  return 0;
}

const char *steam_runtime_type_str(enum steam_runtime_type type) {
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

int steam_runtime_container_socket_dir(char *buf, size_t bufsz) {
  const char *xdg;
  int n;

  if (!buf || bufsz == 0)
    return -EINVAL;

  xdg = getenv("XDG_RUNTIME_DIR");
  if (!xdg || !xdg[0])
    return -ENOENT;

  n = snprintf(buf, bufsz, "%s/%s", xdg, STEAM_RT_SOCKET_DIR_SUFFIX);
  if (n < 0 || (size_t)n >= bufsz)
    return -ENAMETOOLONG;

  return 0;
}

int steam_runtime_container_socket_path(char *buf, size_t bufsz) {
  const char *xdg;
  int n;

  if (!buf || bufsz == 0)
    return -EINVAL;

  xdg = getenv("XDG_RUNTIME_DIR");
  if (!xdg || !xdg[0])
    return -ENOENT;

  n = snprintf(buf, bufsz, "%s/%s/%s", xdg, STEAM_RT_SOCKET_DIR_SUFFIX,
               STEAM_RT_SOCKET_NAME);
  if (n < 0 || (size_t)n >= bufsz)
    return -ENAMETOOLONG;

  return 0;
}

int steam_runtime_ensure_socket_dir(const char *dir) {
  struct stat st;

  if (!dir || !dir[0])
    return -EINVAL;

  if (stat(dir, &st) == 0) {
    if (S_ISDIR(st.st_mode))
      return 0;
    return -ENOTDIR;
  }

  if (mkdir(dir, 0750) < 0 && errno != EEXIST)
    return -errno;

  /*
   * Set group to 'lota' to match the primary socket directory
   * this allows members of the 'lota' group to access the socket
   */
  struct group *grp = getgrnam(LOTA_GROUP_NAME);
  if (grp) {
    if (chown(dir, 0, grp->gr_gid) < 0)
      lota_warn("steam_runtime: chown(%s, 0, %d): %s", dir, grp->gr_gid,
                strerror(errno));
  }

  return 0;
}

void steam_runtime_log_info(const struct steam_runtime_info *info) {
  if (!info)
    return;

  lota_info(
      "steam_runtime: type=%s flags=0x%x app_id=%u container=%s socket=%s",
      steam_runtime_type_str(info->type), info->env_flags, info->app_id,
      info->container_id[0] ? info->container_id : "(none)",
      info->container_socket_path[0] ? info->container_socket_path : "(none)");
}
