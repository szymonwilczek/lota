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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
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

  umask(0);

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

