/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - Daemon utilities
 *
 * Unix daemonization, PID file management, and signal handling.
 *
 * When running under systemd (Type=simple), daemonization is NOT needed
 * because systemd manages the process lifecycle.  In that case, only
 * the PID file and signal handlers are relevant.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include "daemon.h"

#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * Pointers to the caller's flags, set by daemon_install_signals().
 * These are module-level so that the async-signal-safe handlers
 * (which cannot take arguments) can reach them.
 */
static volatile sig_atomic_t *g_daemon_running;
static volatile sig_atomic_t *g_daemon_reload;

/*
 * Signal handler: graceful shutdown (SIGTERM, SIGINT).
 * Async-signal-safe: only writes to a volatile sig_atomic_t.
 */
static void sigterm_handler(int sig) {
  (void)sig;
  if (g_daemon_running)
    *g_daemon_running = 0;
}

/*
 * Signal handler: configuration reload (SIGHUP).
 * Async-signal-safe: only writes to a volatile sig_atomic_t.
 */
static void sighup_handler(int sig) {
  (void)sig;
  if (g_daemon_reload)
    *g_daemon_reload = 1;
}

int daemonize(void) {
  pid_t pid;
  int fd;

  /*
   * first fork: detach from parent process
   */
  pid = fork();
  if (pid < 0)
    return -errno;
  if (pid > 0)
    _exit(0); /* parent exits */

  /*
   * create new session and process group
   */
  if (setsid() < 0)
    return -errno;

  /*
   * second fork: ensure the daemon can never accidentally
   * re-acquire a controlling terminal
   * Grandchild is NOT a session leader
   */
  pid = fork();
  if (pid < 0)
    return -errno;
  if (pid > 0)
    _exit(0); /* session leader exits */

  if (chdir("/") < 0)
    return -errno;

  umask(0077);

  /*
   * close inherited file descriptors and redirect standard
   * streams to /dev/null
   */
  fd = open("/dev/null", O_RDWR);
  if (fd < 0)
    return -errno;

  if (dup2(fd, STDIN_FILENO) < 0 || dup2(fd, STDOUT_FILENO) < 0 ||
      dup2(fd, STDERR_FILENO) < 0) {
    int err = errno;
    close(fd);
    return -err;
  }

  if (fd > STDERR_FILENO)
    close(fd);

  return 0;
}

/*
 * Create parent directories for a path.
 * Only creates the final directory component's parent.
 */
static int ensure_parent_dir(const char *path) {
  char *pathcopy;
  char *dir;
  struct stat st;
  int ret = 0;

  pathcopy = strdup(path);
  if (!pathcopy)
    return -ENOMEM;

  dir = dirname(pathcopy);

  if (stat(dir, &st) == 0) {
    if (!S_ISDIR(st.st_mode))
      ret = -ENOTDIR;
    goto out;
  }

  if (mkdir(dir, 0755) < 0 && errno != EEXIST) {
    ret = -errno;
    goto out;
  }

out:
  free(pathcopy);
  return ret;
}

int pidfile_create(const char *path) {
  int fd;
  int ret;
  char pidbuf[DAEMON_PID_STR_MAX];
  ssize_t len;

  if (!path)
    path = DAEMON_DEFAULT_PID_FILE;

  ret = ensure_parent_dir(path);
  if (ret < 0)
    return ret;

  fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC, 0644);
  if (fd < 0)
    return -errno;

  if (flock(fd, LOCK_EX | LOCK_NB) < 0) {
    int err = errno;
    close(fd);
    return (err == EWOULDBLOCK) ? -EEXIST : -err;
  }

  if (ftruncate(fd, 0) < 0) {
    ret = -errno;
    close(fd);
    unlink(path);
    return ret;
  }

  len = snprintf(pidbuf, sizeof(pidbuf), "%d\n", (int)getpid());
  if (len < 0 || write(fd, pidbuf, (size_t)len) != len) {
    ret = (len < 0) ? -EIO : -errno;
    close(fd);
    unlink(path);
    return ret;
  }

  fsync(fd);

  /* fd stays open -> lock persists until process exit */
  return fd;
}

void pidfile_remove(const char *path, int fd) {
  if (!path)
    path = DAEMON_DEFAULT_PID_FILE;

  unlink(path);

  if (fd >= 0)
    close(fd);
}

int daemon_install_signals(volatile sig_atomic_t *running,
                           volatile sig_atomic_t *reload) {
  struct sigaction sa;

  if (!running || !reload)
    return -EINVAL;

  g_daemon_running = running;
  g_daemon_reload = reload;

  /*
   * SIGTERM / SIGINT -> graceful shutdown.
   * SA_RESTART: restart interrupted syscalls
   */
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = sigterm_handler;
  sa.sa_flags = SA_RESTART;
  sigemptyset(&sa.sa_mask);

  if (sigaction(SIGTERM, &sa, NULL) < 0)
    return -errno;
  if (sigaction(SIGINT, &sa, NULL) < 0)
    return -errno;

  /*
   * SIGHUP -> reload configuration
   */
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = sighup_handler;
  sa.sa_flags = SA_RESTART;
  sigemptyset(&sa.sa_mask);

  if (sigaction(SIGHUP, &sa, NULL) < 0)
    return -errno;

  /*
   * SIGPIPE -> ignore
   */
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = SIG_IGN;
  sa.sa_flags = 0;
  sigemptyset(&sa.sa_mask);

  if (sigaction(SIGPIPE, &sa, NULL) < 0)
    return -errno;

  return 0;
}

int daemon_redirect_output(const char *log_path) {
  int fd;

  if (!log_path)
    log_path = "/dev/null";

  fd = open(log_path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0640);
  if (fd < 0)
    return -errno;

  if (dup2(fd, STDOUT_FILENO) < 0 || dup2(fd, STDERR_FILENO) < 0) {
    int err = errno;
    close(fd);
    return -err;
  }

  if (fd > STDERR_FILENO)
    close(fd);

  return 0;
}
