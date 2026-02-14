/* SPDX-License-Identifier: MIT */
/*
 * LOTA Steam Runtime Detection Unit Tests
 *
 * Tests the container detection, socket path resolution, and
 * directory management functions.
 *
 * Build:
 *   gcc -Wall -Wextra -Werror -O2 -g -Iinclude -D_GNU_SOURCE \
 *       -o build/test_steam_runtime \
 *       tests/test_steam_runtime.c src/agent/steam_runtime.c
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../src/agent/steam_runtime.h"

static int tests_run;
static int tests_passed;

#define TEST(name)                                                             \
  do {                                                                         \
    tests_run++;                                                               \
    printf("  [%d] %-55s ", tests_run, name);                                  \
  } while (0)

#define PASS()                                                                 \
  do {                                                                         \
    tests_passed++;                                                            \
    printf("PASS\n");                                                          \
  } while (0)

#define FAIL(msg)                                                              \
  do {                                                                         \
    printf("FAIL: %s\n", msg);                                                 \
  } while (0)

/* temp directory for test artifacts */
static char tmpdir[64];

static void setup_tmpdir(void) {
  snprintf(tmpdir, sizeof(tmpdir), "/tmp/lota_test_srt_XXXXXX");
  if (!mkdtemp(tmpdir)) {
    fprintf(stderr, "mkdtemp failed: %s\n", strerror(errno));
    exit(1);
  }
}

static void cleanup_tmpdir(void) {
  char cmd[128];
  snprintf(cmd, sizeof(cmd), "rm -rf %s", tmpdir);
  int ret = system(cmd);
  (void)ret;
}

struct saved_env {
  char *pressure_vessel_runtime;
  char *pressure_vessel_runtime_base;
  char *pressure_vessel_instance_id;
  char *xdg_runtime_dir;
  char *steam_app_id;
  char *steam_compat_data_path;
  char *steam_compat_tool_paths;
  char *proton_version;
  char *lota_ipc_socket;
};

static struct saved_env saved;

static char *save_env(const char *name) {
  const char *val = getenv(name);
  return val ? strdup(val) : NULL;
}

static void restore_env(const char *name, char *saved_val) {
  if (saved_val) {
    setenv(name, saved_val, 1);
    free(saved_val);
  } else {
    unsetenv(name);
  }
}

static void clear_steam_env(void) {
  saved.pressure_vessel_runtime = save_env("PRESSURE_VESSEL_RUNTIME");
  saved.pressure_vessel_runtime_base = save_env("PRESSURE_VESSEL_RUNTIME_BASE");
  saved.pressure_vessel_instance_id = save_env("PRESSURE_VESSEL_INSTANCE_ID");
  saved.xdg_runtime_dir = save_env("XDG_RUNTIME_DIR");
  saved.steam_app_id = save_env("SteamAppId");
  saved.steam_compat_data_path = save_env("STEAM_COMPAT_DATA_PATH");
  saved.steam_compat_tool_paths = save_env("STEAM_COMPAT_TOOL_PATHS");
  saved.proton_version = save_env("PROTON_VERSION");
  saved.lota_ipc_socket = save_env("LOTA_IPC_SOCKET");

  unsetenv("PRESSURE_VESSEL_RUNTIME");
  unsetenv("PRESSURE_VESSEL_RUNTIME_BASE");
  unsetenv("PRESSURE_VESSEL_INSTANCE_ID");
  unsetenv("XDG_RUNTIME_DIR");
  unsetenv("SteamAppId");
  unsetenv("STEAM_COMPAT_DATA_PATH");
  unsetenv("STEAM_COMPAT_TOOL_PATHS");
  unsetenv("PROTON_VERSION");
  unsetenv("LOTA_IPC_SOCKET");
}

static void restore_steam_env(void) {
  restore_env("PRESSURE_VESSEL_RUNTIME", saved.pressure_vessel_runtime);
  restore_env("PRESSURE_VESSEL_RUNTIME_BASE",
              saved.pressure_vessel_runtime_base);
  restore_env("PRESSURE_VESSEL_INSTANCE_ID", saved.pressure_vessel_instance_id);
  restore_env("XDG_RUNTIME_DIR", saved.xdg_runtime_dir);
  restore_env("SteamAppId", saved.steam_app_id);
  restore_env("STEAM_COMPAT_DATA_PATH", saved.steam_compat_data_path);
  restore_env("STEAM_COMPAT_TOOL_PATHS", saved.steam_compat_tool_paths);
  restore_env("PROTON_VERSION", saved.proton_version);
  restore_env("LOTA_IPC_SOCKET", saved.lota_ipc_socket);
}

static void test_detect_clean_host(void) {
  struct steam_runtime_info info;

  TEST("detect: clean host (no Steam env) -> NONE");

  int ret = steam_runtime_detect(&info);
  if (ret != 0) {
    FAIL("returned error");
    return;
  }
  if (info.type != STEAM_RT_NONE) {
    FAIL("wrong type");
    return;
  }
  if (info.env_flags & STEAM_ENV_PRESSURE_VESSEL) {
    FAIL("pv flag set");
    return;
  }
  if (info.env_flags & STEAM_ENV_STEAM_ACTIVE) {
    FAIL("steam flag set");
    return;
  }
  PASS();
}

static void test_detect_soldier_container(void) {
  struct steam_runtime_info info;

  TEST("detect: soldier container via PRESSURE_VESSEL_RUNTIME");

  setenv("PRESSURE_VESSEL_RUNTIME", "/usr/lib/SteamLinuxRuntime_soldier", 1);
  setenv("SteamAppId", "730", 1);

  int ret = steam_runtime_detect(&info);

  unsetenv("PRESSURE_VESSEL_RUNTIME");
  unsetenv("SteamAppId");

  if (ret != 0) {
    FAIL("returned error");
    return;
  }
  if (info.type != STEAM_RT_SOLDIER) {
    FAIL("wrong type");
    return;
  }
  if (!(info.env_flags & STEAM_ENV_PRESSURE_VESSEL)) {
    FAIL("no pv flag");
    return;
  }
  if (!(info.env_flags & STEAM_ENV_STEAM_ACTIVE)) {
    FAIL("no steam flag");
    return;
  }
  if (info.app_id != 730) {
    FAIL("wrong app_id");
    return;
  }
  PASS();
}

static void test_detect_sniper_via_base(void) {
  struct steam_runtime_info info;

  TEST("detect: sniper container via PRESSURE_VESSEL_RUNTIME_BASE");

  setenv("PRESSURE_VESSEL_RUNTIME_BASE", "SteamLinuxRuntime_sniper", 1);

  int ret = steam_runtime_detect(&info);

  unsetenv("PRESSURE_VESSEL_RUNTIME_BASE");

  if (ret != 0) {
    FAIL("returned error");
    return;
  }
  if (info.type != STEAM_RT_SNIPER) {
    FAIL("wrong type");
    return;
  }
  if (!(info.env_flags & STEAM_ENV_PRESSURE_VESSEL)) {
    FAIL("no pv flag");
    return;
  }
  PASS();
}

static void test_detect_medic_container(void) {
  struct steam_runtime_info info;

  TEST("detect: medic/scout runtime classification");

  setenv("PRESSURE_VESSEL_RUNTIME", "/opt/steam-runtime/medic/files", 1);

  int ret = steam_runtime_detect(&info);

  unsetenv("PRESSURE_VESSEL_RUNTIME");

  if (ret != 0) {
    FAIL("returned error");
    return;
  }
  if (info.type != STEAM_RT_MEDIC) {
    FAIL("wrong type");
    return;
  }
  PASS();
}

static void test_detect_heavy_container(void) {
  struct steam_runtime_info info;

  TEST("detect: heavy runtime classification");

  setenv("PRESSURE_VESSEL_RUNTIME", "/opt/SteamLinuxRuntime_heavy", 1);

  int ret = steam_runtime_detect(&info);

  unsetenv("PRESSURE_VESSEL_RUNTIME");

  if (ret != 0) {
    FAIL("returned error");
    return;
  }
  if (info.type != STEAM_RT_HEAVY) {
    FAIL("wrong type");
    return;
  }
  PASS();
}

static void test_detect_unknown_container(void) {
  struct steam_runtime_info info;

  TEST("detect: unknown runtime -> STEAM_RT_UNKNOWN");

  setenv("PRESSURE_VESSEL_RUNTIME", "/opt/future_runtime_v99", 1);

  int ret = steam_runtime_detect(&info);

  unsetenv("PRESSURE_VESSEL_RUNTIME");

  if (ret != 0) {
    FAIL("returned error");
    return;
  }
  if (info.type != STEAM_RT_UNKNOWN) {
    FAIL("wrong type");
    return;
  }
  if (!(info.env_flags & STEAM_ENV_PRESSURE_VESSEL)) {
    FAIL("no pv flag");
    return;
  }
  PASS();
}

static void test_detect_xdg_runtime_dir(void) {
  struct steam_runtime_info info;

  TEST("detect: XDG_RUNTIME_DIR sets flag and path");

  setenv("XDG_RUNTIME_DIR", tmpdir, 1);

  int ret = steam_runtime_detect(&info);

  unsetenv("XDG_RUNTIME_DIR");

  if (ret != 0) {
    FAIL("returned error");
    return;
  }
  if (!(info.env_flags & STEAM_ENV_XDG_AVAILABLE)) {
    FAIL("no xdg flag");
    return;
  }
  if (strcmp(info.xdg_runtime_dir, tmpdir) != 0) {
    FAIL("wrong xdg path");
    return;
  }
  if (!info.container_socket_path[0]) {
    FAIL("no socket path");
    return;
  }
  PASS();
}

static void test_detect_proton(void) {
  struct steam_runtime_info info;

  TEST("detect: PROTON_VERSION sets proton flag");

  setenv("PROTON_VERSION", "9.0-4", 1);

  int ret = steam_runtime_detect(&info);

  unsetenv("PROTON_VERSION");

  if (ret != 0) {
    FAIL("returned error");
    return;
  }
  if (!(info.env_flags & STEAM_ENV_PROTON)) {
    FAIL("no proton flag");
    return;
  }
  PASS();
}

static void test_detect_null_arg(void) {
  TEST("detect: NULL info pointer -> -EINVAL");

  int ret = steam_runtime_detect(NULL);
  if (ret != -EINVAL) {
    FAIL("wrong return");
    return;
  }
  PASS();
}

static void test_detect_instance_id(void) {
  struct steam_runtime_info info;

  TEST("detect: PRESSURE_VESSEL_INSTANCE_ID captured");

  setenv("PRESSURE_VESSEL_RUNTIME", "/opt/soldier", 1);
  setenv("PRESSURE_VESSEL_INSTANCE_ID", "pv-abc123", 1);

  int ret = steam_runtime_detect(&info);

  unsetenv("PRESSURE_VESSEL_RUNTIME");
  unsetenv("PRESSURE_VESSEL_INSTANCE_ID");

  if (ret != 0) {
    FAIL("returned error");
    return;
  }
  if (strcmp(info.container_id, "pv-abc123") != 0) {
    FAIL("wrong id");
    return;
  }
  PASS();
}

static void test_detect_compat_data_path(void) {
  struct steam_runtime_info info;

  TEST("detect: STEAM_COMPAT_DATA_PATH sets steam flag");

  setenv("STEAM_COMPAT_DATA_PATH", "/home/user/.steam/compatdata/730", 1);

  int ret = steam_runtime_detect(&info);

  unsetenv("STEAM_COMPAT_DATA_PATH");

  if (ret != 0) {
    FAIL("returned error");
    return;
  }
  if (!(info.env_flags & STEAM_ENV_STEAM_ACTIVE)) {
    FAIL("no steam flag");
    return;
  }
  if (strcmp(info.steam_compat_path, "/home/user/.steam/compatdata/730") != 0) {
    FAIL("wrong compat path");
    return;
  }
  PASS();
}

static void test_type_str_all(void) {
  TEST("type_str: all enum values produce non-NULL strings");

  const char *s;
  s = steam_runtime_type_str(STEAM_RT_NONE);
  if (!s || strcmp(s, "none") != 0) {
    FAIL("none");
    return;
  }
  s = steam_runtime_type_str(STEAM_RT_SOLDIER);
  if (!s || strcmp(s, "soldier") != 0) {
    FAIL("soldier");
    return;
  }
  s = steam_runtime_type_str(STEAM_RT_SNIPER);
  if (!s || strcmp(s, "sniper") != 0) {
    FAIL("sniper");
    return;
  }
  s = steam_runtime_type_str(STEAM_RT_MEDIC);
  if (!s || strcmp(s, "medic") != 0) {
    FAIL("medic");
    return;
  }
  s = steam_runtime_type_str(STEAM_RT_HEAVY);
  if (!s || strcmp(s, "heavy") != 0) {
    FAIL("heavy");
    return;
  }
  s = steam_runtime_type_str(STEAM_RT_UNKNOWN);
  if (!s || strcmp(s, "unknown") != 0) {
    FAIL("unknown");
    return;
  }
  PASS();
}

static void test_socket_dir_with_xdg(void) {
  char buf[PATH_MAX];
  char expected[PATH_MAX];

  TEST("socket_dir: XDG set -> $XDG_RUNTIME_DIR/lota");

  setenv("XDG_RUNTIME_DIR", "/run/user/1000", 1);

  int ret = steam_runtime_container_socket_dir(buf, sizeof(buf));

  unsetenv("XDG_RUNTIME_DIR");

  if (ret != 0) {
    FAIL("returned error");
    return;
  }
  snprintf(expected, sizeof(expected), "/run/user/1000/lota");
  if (strcmp(buf, expected) != 0) {
    FAIL("wrong path");
    return;
  }
  PASS();
}

static void test_socket_dir_no_xdg(void) {
  char buf[PATH_MAX];

  TEST("socket_dir: no XDG -> -ENOENT");

  int ret = steam_runtime_container_socket_dir(buf, sizeof(buf));
  if (ret != -ENOENT) {
    FAIL("expected -ENOENT");
    return;
  }
  PASS();
}

static void test_socket_dir_null_buf(void) {
  TEST("socket_dir: NULL buf -> -EINVAL");

  int ret = steam_runtime_container_socket_dir(NULL, 0);
  if (ret != -EINVAL) {
    FAIL("expected -EINVAL");
    return;
  }
  PASS();
}

static void test_socket_dir_tiny_buf(void) {
  char buf[4];

  TEST("socket_dir: tiny buffer -> -ENAMETOOLONG");

  setenv("XDG_RUNTIME_DIR", "/run/user/1000", 1);

  int ret = steam_runtime_container_socket_dir(buf, sizeof(buf));

  unsetenv("XDG_RUNTIME_DIR");

  if (ret != -ENAMETOOLONG) {
    FAIL("expected -ENAMETOOLONG");
    return;
  }
  PASS();
}

static void test_socket_path_with_xdg(void) {
  char buf[PATH_MAX];

  TEST("socket_path: XDG set -> $XDG_RUNTIME_DIR/lota/lota.sock");

  setenv("XDG_RUNTIME_DIR", "/run/user/1000", 1);

  int ret = steam_runtime_container_socket_path(buf, sizeof(buf));

  unsetenv("XDG_RUNTIME_DIR");

  if (ret != 0) {
    FAIL("returned error");
    return;
  }
  if (strcmp(buf, "/run/user/1000/lota/lota.sock") != 0) {
    FAIL("wrong path");
    return;
  }
  PASS();
}

static void test_socket_path_no_xdg(void) {
  char buf[PATH_MAX];

  TEST("socket_path: no XDG -> -ENOENT");

  int ret = steam_runtime_container_socket_path(buf, sizeof(buf));
  if (ret != -ENOENT) {
    FAIL("expected -ENOENT");
    return;
  }
  PASS();
}

static void test_ensure_dir_creates(void) {
  char dir[PATH_MAX];
  struct stat st;

  TEST("ensure_socket_dir: creates directory with mode 0750");

  snprintf(dir, sizeof(dir), "%s/lota_test_dir", tmpdir);

  int ret = steam_runtime_ensure_socket_dir(dir);
  if (ret != 0) {
    FAIL("returned error");
    return;
  }
  if (stat(dir, &st) != 0) {
    FAIL("dir does not exist");
    return;
  }
  if (!S_ISDIR(st.st_mode)) {
    FAIL("not a directory");
    return;
  }
  if ((st.st_mode & 0777) != 0750) {
    FAIL("wrong mode");
    return;
  }
  PASS();
}

static void test_ensure_dir_exists(void) {
  TEST("ensure_socket_dir: succeeds if directory already exists");

  int ret = steam_runtime_ensure_socket_dir(tmpdir);
  if (ret != 0) {
    FAIL("returned error");
    return;
  }
  PASS();
}

static void test_ensure_dir_not_a_dir(void) {
  char path[PATH_MAX];
  int fd;

  TEST("ensure_socket_dir: rejects non-directory -> -ENOTDIR");

  snprintf(path, sizeof(path), "%s/notadir", tmpdir);
  fd = open(path, O_CREAT | O_WRONLY, 0644);
  if (fd >= 0)
    close(fd);

  int ret = steam_runtime_ensure_socket_dir(path);
  if (ret != -ENOTDIR) {
    FAIL("expected -ENOTDIR");
    return;
  }
  PASS();
}

static void test_ensure_dir_null(void) {
  TEST("ensure_socket_dir: NULL -> -EINVAL");

  int ret = steam_runtime_ensure_socket_dir(NULL);
  if (ret != -EINVAL) {
    FAIL("expected -EINVAL");
    return;
  }
  PASS();
}

static void test_ensure_dir_empty(void) {
  TEST("ensure_socket_dir: empty string -> -EINVAL");

  int ret = steam_runtime_ensure_socket_dir("");
  if (ret != -EINVAL) {
    FAIL("expected -EINVAL");
    return;
  }
  PASS();
}

static void test_log_info_null(void) {
  TEST("log_info: NULL pointer does not crash");

  steam_runtime_log_info(NULL);
  PASS();
}

static void test_log_info_prints(void) {
  struct steam_runtime_info info;

  TEST("log_info: prints without error for populated info");

  memset(&info, 0, sizeof(info));
  info.type = STEAM_RT_SOLDIER;
  info.env_flags = STEAM_ENV_PRESSURE_VESSEL | STEAM_ENV_STEAM_ACTIVE;
  info.app_id = 570;
  snprintf(info.container_id, sizeof(info.container_id), "pv-test");
  snprintf(info.container_socket_path, sizeof(info.container_socket_path),
           "/run/user/1000/lota/lota.sock");

  int saved_fd = dup(STDERR_FILENO);
  int devnull = open("/dev/null", O_WRONLY);
  if (devnull >= 0) {
    dup2(devnull, STDERR_FILENO);
    close(devnull);
  }

  steam_runtime_log_info(&info);

  if (saved_fd >= 0) {
    dup2(saved_fd, STDERR_FILENO);
    close(saved_fd);
  }

  PASS();
}

int main(void) {
  printf("=== LOTA Steam Runtime Unit Tests ===\n\n");

  setup_tmpdir();
  clear_steam_env();

  /* steam_runtime_detect */
  test_detect_clean_host();
  test_detect_soldier_container();
  test_detect_sniper_via_base();
  test_detect_medic_container();
  test_detect_heavy_container();
  test_detect_unknown_container();
  test_detect_xdg_runtime_dir();
  test_detect_proton();
  test_detect_null_arg();
  test_detect_instance_id();
  test_detect_compat_data_path();

  /* type_str */
  test_type_str_all();

  /* socket_dir */
  test_socket_dir_with_xdg();
  test_socket_dir_no_xdg();
  test_socket_dir_null_buf();
  test_socket_dir_tiny_buf();

  /* socket_path */
  test_socket_path_with_xdg();
  test_socket_path_no_xdg();

  /* ensure_socket_dir */
  test_ensure_dir_creates();
  test_ensure_dir_exists();
  test_ensure_dir_not_a_dir();
  test_ensure_dir_null();
  test_ensure_dir_empty();

  /* log_info */
  test_log_info_null();
  test_log_info_prints();

  restore_steam_env();
  cleanup_tmpdir();

  printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
  return (tests_passed == tests_run) ? 0 : 1;
}
