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
#include <fcntl.h>
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

/*
 * Safely get an environment variable with validation.
 * Returns pointer to value if valid, NULL otherwise.
 */
static const char *get_env_safe(const char *name, size_t max_len) {
  const char *val = getenv(name);
  size_t len;

  if (!val || val[0] == '\0')
    return NULL;

  len = strlen(val);
  if (len > max_len) {
    lota_warn("steam_runtime: env var %s exceeds limit (%zu > %zu), ignoring",
              name, len, max_len);
    return NULL;
  }

  for (size_t i = 0; i < len; i++) {
    unsigned char c = (unsigned char)val[i];
    if (c < 0x20 || c == 0x7f) {
      lota_warn("steam_runtime: env var %s contains control char 0x%02x, "
                "ignoring",
                name, c);
      return NULL;
    }
  }

  return val;
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
  env = get_env_safe("SteamAppId", 32);
  if (env) {
    info->env_flags |= STEAM_ENV_STEAM_ACTIVE;
    info->app_id = parse_uint32(env);
  }

  env = get_env_safe("STEAM_COMPAT_DATA_PATH",
                     sizeof(info->steam_compat_path) - 1);
  if (env) {
    info->env_flags |= STEAM_ENV_STEAM_ACTIVE;
    snprintf(info->steam_compat_path, sizeof(info->steam_compat_path), "%s",
             env);
  }

  /*
   * Detect Proton/Wine.
   */
  env = get_env_safe("PROTON_VERSION", 64);
  if (!env)
    env = get_env_safe("STEAM_COMPAT_TOOL_PATHS", PATH_MAX);
  if (env)
    info->env_flags |= STEAM_ENV_PROTON;

  /*
   * Probe XDG_RUNTIME_DIR.
   */
  env = get_env_safe("XDG_RUNTIME_DIR", sizeof(info->xdg_runtime_dir) - 1);
  if (env && is_directory(env)) {
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
  env = get_env_safe("PRESSURE_VESSEL_INSTANCE_ID",
                     sizeof(info->container_id) - 1);
  if (env) {
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

  xdg = get_env_safe("XDG_RUNTIME_DIR", PATH_MAX);
  if (!xdg)
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

  xdg = get_env_safe("XDG_RUNTIME_DIR", PATH_MAX);
  if (!xdg)
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

  int fd = open(dir, O_PATH | O_NOFOLLOW | O_DIRECTORY);
  if (fd < 0) {
    if (errno == ELOOP || errno == ENOTDIR)
      lota_warn("steam_runtime: %s is not a directory or is a symlink!", dir);
    return -errno;
  }

  /*
   * Set group to 'lota' to match the primary socket directory
   * this allows members of the 'lota' group to access the socket
   */
  struct group *grp = getgrnam(LOTA_GROUP_NAME);
  if (grp) {
    if (fchown(fd, -1, grp->gr_gid) < 0) {
      lota_warn("steam_runtime: fchown(%s, -1, %d): %s", dir, grp->gr_gid,
                strerror(errno));
    }
  }

  close(fd);
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
