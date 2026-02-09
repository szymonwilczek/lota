/* SPDX-License-Identifier: MIT */
/*
 * LOTA Wine/Proton Hook Unit Tests
 *
 * Tests the internal helper functions of the LD_PRELOAD hook library.
 * #define LOTA_HOOK_TESTING is to suppress the constructor/destructor
 * and allow direct access to static functions.
 *
 * Build:
 *   gcc -Wall -Wextra -Werror -O2 -g -Iinclude -D_GNU_SOURCE \
 *       -DLOTA_HOOK_TESTING \
 *       -o build/test_wine_hook \
 *       tests/test_wine_hook.c src/sdk/lota_gaming.c -lpthread
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

/* skip constructor/destructor when testing */
#ifndef LOTA_HOOK_TESTING
#define LOTA_HOOK_TESTING
#endif
#include "../src/sdk/lota_wine_hook.c"

#include <assert.h>
#include <sys/stat.h>

static int tests_run;
static int tests_passed;

#define TEST(name)                                                             \
  do {                                                                         \
    tests_run++;                                                               \
    printf("  [%d] %-50s ", tests_run, name);                                  \
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
  snprintf(tmpdir, sizeof(tmpdir), "/tmp/lota_test_hook_XXXXXX");
  if (!mkdtemp(tmpdir)) {
    fprintf(stderr, "mkdtemp failed: %s\n", strerror(errno));
    exit(1);
  }
}

static void cleanup_tmpdir(void) {
  char cmd[128];
  snprintf(cmd, sizeof(cmd), "rm -rf %s", tmpdir);
  (void)system(cmd);
}

/* read entire file contents */
static ssize_t read_file_contents(const char *path, char *buf, size_t buflen) {
  int fd;
  ssize_t n;

  fd = open(path, O_RDONLY);
  if (fd < 0)
    return -errno;

  n = read(fd, buf, buflen - 1);
  close(fd);

  if (n < 0)
    return -errno;

  buf[n] = '\0';
  return n;
}

/* check if file exists */
static int file_exists(const char *path) {
  struct stat st;
  return stat(path, &st) == 0;
}

static void test_parse_log_level_debug(void) {
  TEST("parse_log_level(\"debug\") -> DEBUG");
  if (parse_log_level("debug") != HOOK_LOG_DEBUG) {
    FAIL("wrong level");
    return;
  }
  PASS();
}

static void test_parse_log_level_info(void) {
  TEST("parse_log_level(\"info\") -> INFO");
  if (parse_log_level("info") != HOOK_LOG_INFO) {
    FAIL("wrong level");
    return;
  }
  PASS();
}

static void test_parse_log_level_warn(void) {
  TEST("parse_log_level(\"warn\") -> WARN");
  if (parse_log_level("warn") != HOOK_LOG_WARN) {
    FAIL("wrong level");
    return;
  }
  PASS();
}

static void test_parse_log_level_error(void) {
  TEST("parse_log_level(\"error\") -> ERROR");
  if (parse_log_level("error") != HOOK_LOG_ERROR) {
    FAIL("wrong level");
    return;
  }
  PASS();
}

static void test_parse_log_level_silent(void) {
  TEST("parse_log_level(\"silent\") -> SILENT");
  if (parse_log_level("silent") != HOOK_LOG_SILENT) {
    FAIL("wrong level");
    return;
  }
  PASS();
}

static void test_parse_log_level_null(void) {
  TEST("parse_log_level(NULL) -> WARN default");
  if (parse_log_level(NULL) != HOOK_LOG_WARN) {
    FAIL("wrong default");
    return;
  }
  PASS();
}

static void test_parse_log_level_invalid(void) {
  TEST("parse_log_level(\"garbage\") -> WARN default");
  if (parse_log_level("garbage") != HOOK_LOG_WARN) {
    FAIL("wrong default");
    return;
  }
  PASS();
}

static void test_resolve_token_dir_explicit(void) {
  TEST("resolve_token_dir: LOTA_HOOK_TOKEN_DIR takes priority");

  setenv("LOTA_HOOK_TOKEN_DIR", "/custom/token/path", 1);
  setenv("XDG_RUNTIME_DIR", "/run/user/9999", 1);

  memset(g_hook.token_dir, 0, sizeof(g_hook.token_dir));
  resolve_token_dir();

  unsetenv("LOTA_HOOK_TOKEN_DIR");
  unsetenv("XDG_RUNTIME_DIR");

  if (strcmp(g_hook.token_dir, "/custom/token/path") != 0) {
    FAIL("wrong dir");
    return;
  }
  PASS();
}

static void test_resolve_token_dir_xdg(void) {
  TEST("resolve_token_dir: XDG_RUNTIME_DIR + /lota");

  unsetenv("LOTA_HOOK_TOKEN_DIR");
  setenv("XDG_RUNTIME_DIR", "/run/user/1234", 1);

  memset(g_hook.token_dir, 0, sizeof(g_hook.token_dir));
  resolve_token_dir();

  unsetenv("XDG_RUNTIME_DIR");

  if (strcmp(g_hook.token_dir, "/run/user/1234/lota") != 0) {
    FAIL("wrong dir");
    return;
  }
  PASS();
}

static void test_resolve_token_dir_fallback(void) {
  char expected[PATH_MAX];

  TEST("resolve_token_dir: fallback to /tmp/lota-<uid>");

  unsetenv("LOTA_HOOK_TOKEN_DIR");
  unsetenv("XDG_RUNTIME_DIR");

  memset(g_hook.token_dir, 0, sizeof(g_hook.token_dir));
  resolve_token_dir();

  snprintf(expected, sizeof(expected), "/tmp/lota-%u", (unsigned)getuid());

  if (strcmp(g_hook.token_dir, expected) != 0) {
    FAIL("wrong fallback dir");
    return;
  }
  PASS();
}

static void test_ensure_token_dir_creates(void) {
  struct stat st;

  TEST("ensure_token_dir creates directory with mode 0700");

  snprintf(g_hook.token_dir, sizeof(g_hook.token_dir), "%s/subdir", tmpdir);

  if (ensure_token_dir() != 0) {
    FAIL("ensure_token_dir failed");
    return;
  }
  if (stat(g_hook.token_dir, &st) != 0) {
    FAIL("directory does not exist");
    return;
  }
  if (!S_ISDIR(st.st_mode)) {
    FAIL("not a directory");
    return;
  }
  if ((st.st_mode & 0777) != 0700) {
    FAIL("wrong mode");
    return;
  }
  PASS();
}

static void test_ensure_token_dir_exists(void) {
  TEST("ensure_token_dir succeeds if directory exists");

  /* tmpdir already exists */
  snprintf(g_hook.token_dir, sizeof(g_hook.token_dir), "%s", tmpdir);

  if (ensure_token_dir() != 0) {
    FAIL("ensure_token_dir failed");
    return;
  }
  PASS();
}

static void test_ensure_token_dir_not_a_dir(void) {
  char path[sizeof(g_hook.token_dir)];
  int fd;

  TEST("ensure_token_dir rejects non-directory");

  snprintf(path, sizeof(path), "%s/file_not_dir", tmpdir);
  fd = open(path, O_CREAT | O_WRONLY, 0644);
  if (fd >= 0)
    close(fd);

  snprintf(g_hook.token_dir, sizeof(g_hook.token_dir), "%s", path);

  /* suppress stderr for this test */
  g_hook.log_level = HOOK_LOG_SILENT;
  int ret = ensure_token_dir();
  g_hook.log_level = HOOK_LOG_WARN;

  if (ret != -ENOTDIR) {
    FAIL("expected -ENOTDIR");
    return;
  }
  PASS();
}

static void test_atomic_write_creates_file(void) {
  char path[PATH_MAX];
  char buf[128];
  ssize_t n;

  TEST("atomic_write creates file with correct content");

  snprintf(path, sizeof(path), "%s/test_write", tmpdir);

  if (atomic_write(path, "hello\n", 6) != 0) {
    FAIL("atomic_write failed");
    return;
  }
  n = read_file_contents(path, buf, sizeof(buf));
  if (n != 6 || memcmp(buf, "hello\n", 6) != 0) {
    FAIL("content mismatch");
    return;
  }
  PASS();
}

static void test_atomic_write_overwrites(void) {
  char path[PATH_MAX];
  char buf[128];
  ssize_t n;

  TEST("atomic_write atomically overwrites existing file");

  snprintf(path, sizeof(path), "%s/test_overwrite", tmpdir);

  atomic_write(path, "first", 5);
  if (atomic_write(path, "second", 6) != 0) {
    FAIL("second write failed");
    return;
  }
  n = read_file_contents(path, buf, sizeof(buf));
  if (n != 6 || memcmp(buf, "second", 6) != 0) {
    FAIL("content mismatch");
    return;
  }
  PASS();
}

static void test_atomic_write_no_tmp_leftover(void) {
  char path[256];
  char tmp_pattern[300];

  TEST("atomic_write leaves no .tmp files on success");

  snprintf(path, sizeof(path), "%s/test_notmp", tmpdir);
  snprintf(tmp_pattern, sizeof(tmp_pattern), "%s.tmp.%d", path, (int)getpid());

  atomic_write(path, "data", 4);

  if (file_exists(tmp_pattern)) {
    FAIL(".tmp file left behind");
    return;
  }
  PASS();
}

static void test_atomic_write_file_mode(void) {
  char path[PATH_MAX];
  struct stat st;

  TEST("atomic_write creates file with mode 0600");

  snprintf(path, sizeof(path), "%s/test_mode", tmpdir);
  atomic_write(path, "x", 1);

  if (stat(path, &st) != 0) {
    FAIL("stat failed");
    return;
  }
  if ((st.st_mode & 0777) != 0600) {
    char msg[64];
    snprintf(msg, sizeof(msg), "mode=%o", st.st_mode & 0777);
    FAIL(msg);
    return;
  }
  PASS();
}

static void test_write_status_attested(void) {
  char buf[1024];
  ssize_t n;
  struct lota_status status;

  TEST("write_status: attested system generates correct file");

  snprintf(g_hook.status_path, sizeof(g_hook.status_path), "%s/status_att",
           tmpdir);

  memset(&status, 0, sizeof(status));
  status.flags = LOTA_FLAG_ATTESTED | LOTA_FLAG_TPM_OK | LOTA_FLAG_BPF_LOADED;
  status.valid_until = 1738957200;
  status.attest_count = 42;
  status.fail_count = 1;

  if (write_status(&status) != 0) {
    FAIL("write_status failed");
    return;
  }
  n = read_file_contents(g_hook.status_path, buf, sizeof(buf));
  if (n <= 0) {
    FAIL("read failed");
    return;
  }
  if (!strstr(buf, "LOTA_ATTESTED=1")) {
    FAIL("missing LOTA_ATTESTED=1");
    return;
  }
  if (!strstr(buf, "LOTA_FLAGS=0x0000000b")) {
    FAIL("wrong flags");
    return;
  }
  if (!strstr(buf, "LOTA_VALID_UNTIL=1738957200")) {
    FAIL("wrong valid_until");
    return;
  }
  if (!strstr(buf, "LOTA_ATTEST_COUNT=42")) {
    FAIL("wrong attest_count");
    return;
  }
  if (!strstr(buf, "LOTA_FAIL_COUNT=1")) {
    FAIL("wrong fail_count");
    return;
  }
  if (!strstr(buf, "LOTA_UPDATED=")) {
    FAIL("missing LOTA_UPDATED");
    return;
  }
  if (!strstr(buf, "LOTA_PID=")) {
    FAIL("missing LOTA_PID");
    return;
  }
  PASS();
}

static void test_write_status_not_attested(void) {
  char buf[1024];
  ssize_t n;
  struct lota_status status;

  TEST("write_status: non-attested system writes LOTA_ATTESTED=0");

  snprintf(g_hook.status_path, sizeof(g_hook.status_path), "%s/status_noatt",
           tmpdir);

  memset(&status, 0, sizeof(status));
  status.flags = LOTA_FLAG_TPM_OK;

  if (write_status(&status) != 0) {
    FAIL("write_status failed");
    return;
  }
  n = read_file_contents(g_hook.status_path, buf, sizeof(buf));
  if (n <= 0) {
    FAIL("read failed");
    return;
  }
  if (!strstr(buf, "LOTA_ATTESTED=0")) {
    FAIL("missing LOTA_ATTESTED=0");
    return;
  }
  PASS();
}

static void test_write_status_zero_flags(void) {
  char buf[1024];
  ssize_t n;
  struct lota_status status;

  TEST("write_status: zero flags produces valid output");

  snprintf(g_hook.status_path, sizeof(g_hook.status_path), "%s/status_zero",
           tmpdir);

  memset(&status, 0, sizeof(status));

  if (write_status(&status) != 0) {
    FAIL("write_status failed");
    return;
  }
  n = read_file_contents(g_hook.status_path, buf, sizeof(buf));
  if (n <= 0) {
    FAIL("read failed");
    return;
  }
  if (!strstr(buf, "LOTA_ATTESTED=0")) {
    FAIL("missing LOTA_ATTESTED=0");
    return;
  }
  if (!strstr(buf, "LOTA_FLAGS=0x00000000")) {
    FAIL("wrong flags");
    return;
  }
  PASS();
}

static void test_hook_active_when_not_started(void) {
  TEST("lota_hook_active() returns 0 when not initialized");

  g_hook.thread_started = 0;
  g_hook.running = 0;

  if (lota_hook_active() != 0) {
    FAIL("expected 0");
    return;
  }
  PASS();
}

static void test_hook_status_path_when_set(void) {
  TEST("lota_hook_status_path() returns path when set");

  snprintf(g_hook.status_path, sizeof(g_hook.status_path),
           "/run/user/1000/lota/lota-status");

  const char *p = lota_hook_status_path();
  if (!p || strcmp(p, "/run/user/1000/lota/lota-status") != 0) {
    FAIL("wrong path");
    return;
  }
  PASS();
}

static void test_hook_status_path_when_empty(void) {
  TEST("lota_hook_status_path() returns NULL when empty");

  g_hook.status_path[0] = '\0';

  if (lota_hook_status_path() != NULL) {
    FAIL("expected NULL");
    return;
  }
  PASS();
}

static void test_hook_token_path_when_set(void) {
  TEST("lota_hook_token_path() returns path when set");

  snprintf(g_hook.token_path, sizeof(g_hook.token_path),
           "/run/user/1000/lota/lota-token.bin");

  const char *p = lota_hook_token_path();
  if (!p || strcmp(p, "/run/user/1000/lota/lota-token.bin") != 0) {
    FAIL("wrong path");
    return;
  }
  PASS();
}

static void test_hook_token_path_when_empty(void) {
  TEST("lota_hook_token_path() returns NULL when empty");

  g_hook.token_path[0] = '\0';

  if (lota_hook_token_path() != NULL) {
    FAIL("expected NULL");
    return;
  }
  PASS();
}

int main(void) {
  printf("=== LOTA Wine Hook Unit Tests ===\n\n");

  setup_tmpdir();

  /* silence hook logs during tests */
  g_hook.log_level = HOOK_LOG_SILENT;

  /* parse_log_level */
  test_parse_log_level_debug();
  test_parse_log_level_info();
  test_parse_log_level_warn();
  test_parse_log_level_error();
  test_parse_log_level_silent();
  test_parse_log_level_null();
  test_parse_log_level_invalid();

  /* resolve_token_dir */
  test_resolve_token_dir_explicit();
  test_resolve_token_dir_xdg();
  test_resolve_token_dir_fallback();

  /* ensure_token_dir */
  test_ensure_token_dir_creates();
  test_ensure_token_dir_exists();
  test_ensure_token_dir_not_a_dir();

  /* atomic_write */
  test_atomic_write_creates_file();
  test_atomic_write_overwrites();
  test_atomic_write_no_tmp_leftover();
  test_atomic_write_file_mode();

  /* write_status */
  test_write_status_attested();
  test_write_status_not_attested();
  test_write_status_zero_flags();

  /* exported query functions */
  test_hook_active_when_not_started();
  test_hook_status_path_when_set();
  test_hook_status_path_when_empty();
  test_hook_token_path_when_set();
  test_hook_token_path_when_empty();

  cleanup_tmpdir();

  printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
  return (tests_passed == tests_run) ? 0 : 1;
}
