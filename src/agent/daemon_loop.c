/* SPDX-License-Identifier: MIT */

#include "daemon_loop.h"

#include <errno.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <time.h>
#include <unistd.h>

#include "../../include/lota_ipc.h"
#include "journal.h"
#include "main_utils.h"
#include "reload.h"
#include "sdnotify.h"

/*
 * Ringbuf drop telemetry.
 *
 * The BPF programs increment STAT_RINGBUF_DROPS whenever
 * bpf_ringbuf_reserve() returns NULL while a hook is about to emit
 * an event. Enforcement is unaffected (a blocked event still
 * returns -EPERM at the LSM hook), but the forensic audit stream
 * for that specific allow/deny is lost. The loop polls the counter
 * at most every RINGBUF_DROP_POLL_INTERVAL_NS to bound the
 * overhead and, on any positive delta, logs a security event and
 * raises LOTA_STATUS_RINGBUF_DROPS so monitoring (D-Bus / IPC /
 * Prometheus scrape) sees the gap.
 *
 * The bit is sticky: once set, it stays raised until the daemon
 * exits and a fresh attestation re-publishes the status. Operators
 * are expected to treat any raised bit as "investigate the
 * forensic gap for the time window between the last clean reading
 * and now".
 */
#define RINGBUF_DROP_POLL_INTERVAL_NS (1000ULL * 1000ULL * 1000ULL)

static uint64_t monotonic_ns(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
    return 0;
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/*
 * agent_ringbuf_drop_delta() lives in daemon_loop_telemetry.c so the
 * pure delta logic can be unit-tested without dragging the global
 * agent context and libbpf/libtss2/libsystemd into the test target.
 */
static void poll_ringbuf_drops(struct agent_loop_ctx *ctx, uint64_t *last_drops,
                               uint64_t *last_poll_ns) {
  uint64_t now_ns;

  if (!ctx->bpf_ctx || !ctx->bpf_ctx->loaded || !ctx->ipc_ctx)
    return;

  now_ns = monotonic_ns();
  if (now_ns == 0)
    return;
  if (*last_poll_ns != 0 &&
      now_ns - *last_poll_ns < RINGBUF_DROP_POLL_INTERVAL_NS)
    return;
  *last_poll_ns = now_ns;

  struct bpf_extended_stats stats;
  if (bpf_loader_get_extended_stats(ctx->bpf_ctx, &stats) < 0)
    return;

  uint64_t delta = agent_ringbuf_drop_delta(stats.drops, last_drops);
  if (delta == 0)
    return;

  lota_err("SECURITY: BPF events ringbuf dropped %lu events (total=%lu); "
           "forensic stream incomplete - enforcement unaffected",
           (unsigned long)delta, (unsigned long)stats.drops);

  ipc_update_status(ctx->ipc_ctx,
                    ctx->ipc_ctx->status_flags | LOTA_STATUS_RINGBUF_DROPS, 0);
}

int agent_run_event_loop(struct agent_loop_ctx *ctx) {
  struct epoll_event events[16];
  uint64_t last_drops = 0;
  uint64_t last_drop_poll_ns = 0;

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

    poll_ringbuf_drops(ctx, &last_drops, &last_drop_poll_ns);

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
