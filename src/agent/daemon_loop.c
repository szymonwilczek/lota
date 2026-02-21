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

int agent_run_event_loop(struct agent_loop_ctx *ctx) {
  struct epoll_event events[16];

  while (*ctx->running) {
    int timeout = -1;
    if (ctx->wd_enabled && ctx->wd_usec > 0)
      timeout = (int)(ctx->wd_usec / 2000);

    int nfds = epoll_wait(ctx->epoll_fd, events, 16, timeout);

    if (nfds < 0) {
      if (errno == EINTR)
        continue;
      lota_err("epoll_wait failed: %s", strerror(errno));
      break;
    }

    if (nfds == 0 && ctx->wd_enabled) {
      sdnotify_watchdog_ping();
      continue;
    }

    for (int i = 0; i < nfds; i++) {
      if (events[i].data.fd == ctx->sfd) {
        struct signalfd_siginfo fdsi;
        ssize_t got = read(ctx->sfd, &fdsi, sizeof(struct signalfd_siginfo));
        if (got != sizeof(struct signalfd_siginfo))
          continue;

        if (fdsi.ssi_signo == SIGTERM || fdsi.ssi_signo == SIGINT) {
          lota_info("Signal received, stopping...");
          *ctx->running = 0;
        } else if (fdsi.ssi_signo == SIGHUP) {
          sdnotify_reloading();
          lota_info("SIGHUP received, reloading configuration");

          (void)agent_reload_config(
              ctx->config_path, ctx->cfg, ctx->mode, ctx->strict_mmap,
              ctx->strict_exec, ctx->block_ptrace, ctx->strict_modules,
              ctx->block_anon_exec, ctx->protect_pids, ctx->protect_pid_count,
              ctx->trust_libs, ctx->trust_lib_count);
        }
      } else if (events[i].data.fd == ipc_get_fd(ctx->ipc_ctx)) {
        ipc_process(ctx->ipc_ctx, 0);
      } else if (ctx->dbus_ctx &&
                 events[i].data.fd == dbus_get_fd(ctx->dbus_ctx)) {
        dbus_process(ctx->dbus_ctx, 0);
      } else if (events[i].data.fd == bpf_loader_get_event_fd(ctx->bpf_ctx)) {
        bpf_loader_consume(ctx->bpf_ctx);
      }
    }

    if (ctx->wd_enabled)
      sdnotify_watchdog_ping();
  }

  return 0;
}
