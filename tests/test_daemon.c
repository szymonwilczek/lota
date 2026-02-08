/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for daemon utilities (daemon.h / daemon.c).
 *
 * Tests PID file management, signal installation, and output
 * redirection.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "../src/agent/daemon.h"

static int tests_run;
static int tests_passed;

#define TEST(name)                                                             \
  do {                                                                         \
    tests_run++;                                                               \
    printf("  [%2d] %-50s ", tests_run, name);                                 \
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

static char tmp_dir[128];

static void setup_tmp_dir(void) {
  snprintf(tmp_dir, sizeof(tmp_dir), "/tmp/lota_td_%d", getpid());
  mkdir(tmp_dir, 0755);
}

static void cleanup_tmp_dir(void) {
  char cmd[512];
  snprintf(cmd, sizeof(cmd), "rm -rf %s", tmp_dir);
  (void)system(cmd);
}

static void test_pidfile_create_remove(void) {
  char path[256];
  int fd;
  char buf[32];
  ssize_t n;

  TEST("pidfile_create + pidfile_remove");

  snprintf(path, sizeof(path), "%s/test.pid", tmp_dir);

  fd = pidfile_create(path);
  if (fd < 0) {
    FAIL("pidfile_create returned error");
    return;
  }

  /* verify file exists and contains our PID */
  {
    int rfd = open(path, O_RDONLY);
    if (rfd < 0) {
      FAIL("PID file not readable");
      pidfile_remove(path, fd);
      return;
    }
    n = read(rfd, buf, sizeof(buf) - 1);
    close(rfd);

    if (n <= 0) {
      FAIL("PID file empty");
      pidfile_remove(path, fd);
      return;
    }
    buf[n] = '\0';

    int file_pid = atoi(buf);
    if (file_pid != getpid()) {
      FAIL("PID file contains wrong PID");
      pidfile_remove(path, fd);
      return;
    }
  }

  pidfile_remove(path, fd);

  /* verify file removed */
  if (access(path, F_OK) == 0) {
    FAIL("PID file not removed");
    return;
  }

  PASS();
}

static void test_pidfile_double_lock(void) {
  char path[256];
  int fd1, fd2;

  TEST("pidfile double lock -> -EEXIST");

  snprintf(path, sizeof(path), "%s/lock.pid", tmp_dir);

  fd1 = pidfile_create(path);
  if (fd1 < 0) {
    FAIL("first pidfile_create failed");
    return;
  }

  /* second call should fail with -EEXIST */
  fd2 = pidfile_create(path);
  if (fd2 != -EEXIST) {
    char msg[128];
    snprintf(msg, sizeof(msg), "expected -EEXIST, got %d", fd2);
    FAIL(msg);
    if (fd2 >= 0)
      close(fd2);
    pidfile_remove(path, fd1);
    return;
  }

  pidfile_remove(path, fd1);
  PASS();
}

static void test_pidfile_lock_release_on_close(void) {
  char path[256];
  int fd1, fd2;

  TEST("pidfile lock released after close");

  snprintf(path, sizeof(path), "%s/release.pid", tmp_dir);

  fd1 = pidfile_create(path);
  if (fd1 < 0) {
    FAIL("first pidfile_create failed");
    return;
  }

  /* close fd -> lock released */
  close(fd1);
  unlink(path);

  /* now second create should succeed */
  fd2 = pidfile_create(path);
  if (fd2 < 0) {
    char msg[128];
    snprintf(msg, sizeof(msg), "second pidfile_create failed: %d", fd2);
    FAIL(msg);
    return;
  }

  pidfile_remove(path, fd2);
  PASS();
}

static void test_pidfile_default_path(void) {
  int fd;

  TEST("pidfile_create(NULL) uses default path");

  fd = pidfile_create(NULL);
  if (fd >= 0) {
    /* running as root - clean up */
    pidfile_remove(NULL, fd);
    PASS();
    return;
  }

  /*
   * non-root: expect -EACCES or -ENOENT or -ENOTDIR
   * important thing is it does not crash
   */
  if (fd == -EACCES || fd == -ENOENT || fd == -ENOTDIR || fd == -EPERM) {
    PASS();
  } else {
    char msg[128];
    snprintf(msg, sizeof(msg), "unexpected error: %d (%s)", fd, strerror(-fd));
    FAIL(msg);
  }
}

static void test_pidfile_creates_parent_dir(void) {
  char path[256];
  int fd;
  struct stat st;

  TEST("pidfile_create creates parent directory");

  snprintf(path, sizeof(path), "%s/subdir/nested.pid", tmp_dir);

  fd = pidfile_create(path);
  if (fd < 0) {
    char msg[128];
    snprintf(msg, sizeof(msg), "pidfile_create failed: %d (%s)", fd,
             strerror(-fd));
    FAIL(msg);
    return;
  }

  /* verify parent dir exists */
  {
    char dir[256];
    snprintf(dir, sizeof(dir), "%s/subdir", tmp_dir);
    if (stat(dir, &st) < 0 || !S_ISDIR(st.st_mode)) {
      FAIL("parent directory not created");
      pidfile_remove(path, fd);
      return;
    }
  }

  pidfile_remove(path, fd);
  PASS();
}

static void test_signal_install(void) {
  volatile sig_atomic_t running = 1;
  volatile sig_atomic_t reload = 0;
  int ret;

  TEST("daemon_install_signals installs handlers");

  ret = daemon_install_signals(&running, &reload);
  if (ret < 0) {
    char msg[128];
    snprintf(msg, sizeof(msg), "daemon_install_signals failed: %d", ret);
    FAIL(msg);
    return;
  }

  /* verify handlers are installed by checking sigaction */
  {
    struct sigaction sa;
    sigaction(SIGTERM, NULL, &sa);
    if (sa.sa_handler == SIG_DFL || sa.sa_handler == SIG_IGN) {
      FAIL("SIGTERM handler not installed");
      return;
    }

    sigaction(SIGHUP, NULL, &sa);
    if (sa.sa_handler == SIG_DFL || sa.sa_handler == SIG_IGN) {
      FAIL("SIGHUP handler not installed");
      return;
    }

    sigaction(SIGPIPE, NULL, &sa);
    if (sa.sa_handler != SIG_IGN) {
      FAIL("SIGPIPE not ignored");
      return;
    }
  }

  PASS();
}

static void test_signal_null_args(void) {
  int ret;

  TEST("daemon_install_signals(NULL, ...) -> -EINVAL");

  ret = daemon_install_signals(NULL, NULL);
  if (ret != -EINVAL) {
    char msg[128];
    snprintf(msg, sizeof(msg), "expected -EINVAL, got %d", ret);
    FAIL(msg);
    return;
  }

  PASS();
}

static void test_sighup_sets_reload(void) {
  volatile sig_atomic_t running = 1;
  volatile sig_atomic_t reload = 0;

  TEST("SIGHUP sets reload flag");

  daemon_install_signals(&running, &reload);

  /* send SIGHUP to self */
  kill(getpid(), SIGHUP);

  if (reload != 1) {
    FAIL("reload flag not set");
    return;
  }

  if (running != 1) {
    FAIL("running flag should still be 1");
    return;
  }

  PASS();
}

static void test_sigterm_clears_running(void) {
  volatile sig_atomic_t running = 1;
  volatile sig_atomic_t reload = 0;

  TEST("SIGTERM clears running flag");

  pid_t child = fork();
  if (child < 0) {
    FAIL("fork failed");
    return;
  }

  if (child == 0) {
    /* child */
    daemon_install_signals(&running, &reload);
    kill(getpid(), SIGTERM);

    /* running should be 0 */
    _exit(running == 0 ? 0 : 1);
  }

  int status;
  waitpid(child, &status, 0);

  if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
    PASS();
  } else {
    FAIL("child did not exit cleanly with running=0");
  }
}

static void test_redirect_to_devnull(void) {
  TEST("daemon_redirect_output(NULL) -> /dev/null");

  pid_t child = fork();
  if (child < 0) {
    FAIL("fork failed");
    return;
  }

  if (child == 0) {
    int ret = daemon_redirect_output(NULL);
    if (ret < 0)
      _exit(1);

    /* stdout should now be /dev/null - write should succeed silently */
    if (printf("test\n") < 0)
      _exit(2);

    _exit(0);
  }

  int status;
  waitpid(child, &status, 0);
  if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
    PASS();
  } else {
    FAIL("redirect to /dev/null failed in child");
  }
}

static void test_redirect_to_file(void) {
  char log_path[256];

  TEST("daemon_redirect_output(file) appends log");

  snprintf(log_path, sizeof(log_path), "%s/test.log", tmp_dir);

  pid_t child = fork();
  if (child < 0) {
    FAIL("fork failed");
    return;
  }

  if (child == 0) {
    int ret = daemon_redirect_output(log_path);
    if (ret < 0)
      _exit(1);

    printf("stdout line\n");
    fflush(stdout);
    fprintf(stderr, "stderr line\n");
    fflush(stderr);

    _exit(0);
  }

  int status;
  waitpid(child, &status, 0);

  if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
    FAIL("child process failed");
    return;
  }

  /* verify log file contents */
  {
    FILE *f = fopen(log_path, "r");
    if (!f) {
      FAIL("log file not created");
      return;
    }
    char buf[256];
    int found_stdout = 0, found_stderr = 0;
    while (fgets(buf, sizeof(buf), f)) {
      if (strstr(buf, "stdout line"))
        found_stdout = 1;
      if (strstr(buf, "stderr line"))
        found_stderr = 1;
    }
    fclose(f);

    if (!found_stdout || !found_stderr) {
      FAIL("log file missing expected content");
      return;
    }
  }

  PASS();
}

static void test_daemonize(void) {
  char marker_path[256];

  TEST("daemonize -> grandchild writes marker file");

  snprintf(marker_path, sizeof(marker_path), "%s/daemon_marker", tmp_dir);

  pid_t child = fork();
  if (child < 0) {
    FAIL("fork failed");
    return;
  }

  if (child == 0) {
    int ret = daemonize();
    if (ret < 0)
      _exit(1);

    /* grandchild daemon now */
    FILE *f = fopen(marker_path, "w");
    if (f) {
      fprintf(f, "%d\n", getpid());
      fclose(f);
    }
    _exit(0);
  }

  /* wait for the child */
  int status;
  waitpid(child, &status, 0);

  /* give the grandchild a moment to write the marker */
  usleep(200000); /* 200ms */

  if (access(marker_path, F_OK) == 0) {
    FILE *f = fopen(marker_path, "r");
    if (f) {
      int daemon_pid = 0;
      if (fscanf(f, "%d", &daemon_pid) == 1) {
        if (daemon_pid != child && daemon_pid != getpid()) {
          PASS();
        } else {
          FAIL("daemon PID should differ from child and parent");
        }
      } else {
        FAIL("could not read daemon PID from marker");
      }
      fclose(f);
    } else {
      FAIL("could not open marker file");
    }
  } else {
    FAIL("daemon did not write marker file");
  }
}

int main(void) {
  printf("=== Daemon Module Tests ===\n\n");

  setup_tmp_dir();

  /* PID file tests */
  test_pidfile_create_remove();
  test_pidfile_double_lock();
  test_pidfile_lock_release_on_close();
  test_pidfile_default_path();
  test_pidfile_creates_parent_dir();

  /* signal tests */
  test_signal_install();
  test_signal_null_args();
  test_sighup_sets_reload();
  test_sigterm_clears_running();

  /* output redirection */
  test_redirect_to_devnull();
  test_redirect_to_file();

  /* daemonize */
  test_daemonize();

  cleanup_tmp_dir();

  printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
  return (tests_passed == tests_run) ? 0 : 1;
}
