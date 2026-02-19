/* SPDX-License-Identifier: MIT */

#include "daemon_loop.h"

#include <errno.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <unistd.h>

#include "journal.h"
#include "main_utils.h"
#include "reload.h"
#include "sdnotify.h"

int agent_run_event_loop(int epoll_fd, int sfd, bool wd_enabled,
                         uint64_t wd_usec, const char *config_path,
                         struct lota_config *cfg, int *mode, bool *strict_mmap,
                         bool *block_ptrace, bool *strict_modules,
                         bool *block_anon_exec, uint32_t **protect_pids,
                         int *protect_pid_count, char trust_libs[][PATH_MAX],
                         int *trust_lib_count, struct ipc_context *ipc_ctx,
                         struct dbus_context *dbus_ctx,
                         struct bpf_loader_ctx *bpf_ctx,
                         volatile sig_atomic_t *running) {
  struct epoll_event events[16];

  while (*running) {
    int timeout = -1;
    if (wd_enabled && wd_usec > 0)
      timeout = (int)(wd_usec / 2000);

    int nfds = epoll_wait(epoll_fd, events, 16, timeout);

    if (nfds < 0) {
      if (errno == EINTR)
        continue;
      lota_err("epoll_wait failed: %s", strerror(errno));
      break;
    }

    if (nfds == 0 && wd_enabled) {
      sdnotify_watchdog_ping();
      continue;
    }

    for (int i = 0; i < nfds; i++) {
      if (events[i].data.fd == sfd) {
        struct signalfd_siginfo fdsi;
        ssize_t got = read(sfd, &fdsi, sizeof(struct signalfd_siginfo));
        if (got != sizeof(struct signalfd_siginfo))
          continue;

        if (fdsi.ssi_signo == SIGTERM || fdsi.ssi_signo == SIGINT) {
          lota_info("Signal received, stopping...");
          *running = 0;
        } else if (fdsi.ssi_signo == SIGHUP) {
          sdnotify_reloading();
          lota_info("SIGHUP received, reloading configuration");

          (void)agent_reload_config(
              config_path, cfg, mode, strict_mmap, block_ptrace, strict_modules,
              block_anon_exec, protect_pids, protect_pid_count, trust_libs,
              trust_lib_count);
        }
      } else if (events[i].data.fd == ipc_get_fd(ipc_ctx)) {
        ipc_process(ipc_ctx, 0);
      } else if (dbus_ctx && events[i].data.fd == dbus_get_fd(dbus_ctx)) {
        dbus_process(dbus_ctx, 0);
      } else if (events[i].data.fd == bpf_loader_get_event_fd(bpf_ctx)) {
        bpf_loader_consume(bpf_ctx);
      }
    }

    if (wd_enabled)
      sdnotify_watchdog_ping();
  }

  return 0;
}
