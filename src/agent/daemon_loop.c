/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */

#include "daemon_loop.h"

#include <errno.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>

#include "../../include/lota.h"
#include "journal.h"
#include "reload.h"
#include "sdnotify.h"
#include "bench_bpf.h"
#include "bench_protected.h"
#include "bench_snapshot.h"
#include "bpf_loader.h"
#include "dbus.h"
#include "ipc.h"
#include "status_flags.h"
#include "watchdog.h"

/*
 * A hook decides the same when its event is left out; only the log loses it.
 * Permitted events past their budget stay out of the sum: an ordinary boot
 * spends it.
 */
#define EVENT_LOSS_POLL_INTERVAL_NS (1000ULL * 1000ULL * 1000ULL)

static uint64_t monotonic_ns(void)
{
	struct timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
		return 0;
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void poll_event_loss(struct agent_loop_ctx *ctx, uint64_t *last_lost,
			    uint64_t *last_poll_ns)
{
	uint64_t now_ns;

	if (!ctx->bpf_ctx || !ctx->bpf_ctx->loaded || !ctx->ipc_ctx)
		return;

	now_ns = monotonic_ns();
	if (now_ns == 0)
		return;
	if (*last_poll_ns != 0 &&
	    now_ns - *last_poll_ns < EVENT_LOSS_POLL_INTERVAL_NS)
		return;
	*last_poll_ns = now_ns;

	struct bpf_extended_stats stats;
	if (bpf_loader_get_extended_stats(ctx->bpf_ctx, &stats) < 0)
		return;

	uint64_t delta = agent_ringbuf_drop_delta(
		stats.drops + stats.events_yielded + stats.blocked_suppressed,
		last_lost);
	if (delta == 0)
		return;

	lota_err("SECURITY: kernel left out %lu events (full=%lu yielded=%lu "
		 "blocked_budget=%lu); log incomplete - enforcement unaffected",
		 (unsigned long)delta, (unsigned long)stats.drops,
		 (unsigned long)stats.events_yielded,
		 (unsigned long)stats.blocked_suppressed);

	ipc_set_events_lost(ctx->ipc_ctx);
}

/*
 * --add-publisher writes lota.conf while the daemon runs. A failed rebuild
 * keeps the previous list.
 */
static void agent_reload_publishers(struct agent_loop_ctx *ctx)
{
	size_t count = 0;
	int ret;

	if (!ctx->targets || !ctx->target_count || ctx->target_max == 0)
		return;

	count = *ctx->target_count;
	ret = attest_targets_rebuild(
		ctx->cfg,
		(ctx->cfg && ctx->cfg->server[0]) ? ctx->cfg->server : NULL,
		ctx->cfg ? ctx->cfg->port : 0,
		ctx->cfg ? ctx->cfg->ca_cert : NULL,
		ctx->cfg ? ctx->cfg->attest_interval : 0, ctx->targets,
		ctx->target_max, &count);
	if (ret < 0)
		return;

	*ctx->target_count = count;
	ipc_set_profiles(ctx->ipc_ctx, ctx->targets, count);
	lota_info("Publisher list reloaded: %zu publisher(s)", count);

	/* name unreadable anchors on reload, as startup does */
	for (size_t i = 0; i < count; i++) {
		if (!ctx->targets[i].profile_error)
			continue;
		lota_warn("Cannot read the CA trust anchor %s (%s): answering "
			  "for %s without a publisher profile, so a title "
			  "naming them is refused",
			  ctx->targets[i].ca_cert,
			  strerror(-ctx->targets[i].profile_error),
			  ctx->targets[i].label);
	}
}

/* logged when it changes, not every second */
static void bench_poll(struct agent_loop_ctx *ctx, int *last_err)
{
	static struct bench_bpf bpf;
	static struct bench_pid pids[LOTA_MAX_PROTECTED_PIDS];
	static struct bench_protected prot;
	struct bench_protected_sum sum;
	uint64_t now = monotonic_ns();
	bool have_bpf;
	int ret, n;

	if (!bench_due(ctx->bench, now))
		return;

	have_bpf =
		bench_bpf_sample(ctx->bpf_ctx, ctx->bench->stats_fd >= 0, &bpf);
	n = bench_bpf_protected(ctx->bpf_ctx, pids, LOTA_MAX_PROTECTED_PIDS);
	if (n >= 0)
		bench_protected_sample(
			&prot, pids, (size_t)n,
			ctx->bench->seq % LOTA_BENCH_PSS_EVERY == 0, &sum);
	ret = bench_write(ctx->bench, now, have_bpf ? &bpf : NULL,
			  n >= 0 ? &sum : NULL);
	if (ret == -EMSGSIZE || ret == *last_err)
		return;
	if (ret < 0)
		lota_warn("Bench: cannot write %s: %s", LOTA_BENCH_PATH,
			  strerror(-ret));
	else
		lota_info("Bench: writing %s again", LOTA_BENCH_PATH);
	*last_err = ret;
}

int agent_run_event_loop(struct agent_loop_ctx *ctx)
{
	struct epoll_event events[16];
	uint64_t last_lost = 0;
	uint64_t last_loss_poll_ns = 0;
	int bench_err = 0;

	while (*ctx->running) {
		int timeout = -1;
		int status_due;

		ipc_status_tick(ctx->ipc_ctx, monotonic_ns());
		if (ctx->wd_enabled && ctx->wd_usec > 0)
			timeout = (int)(ctx->wd_usec / 2000);
		status_due =
			ipc_status_timeout_ms(ctx->ipc_ctx, monotonic_ns());
		if (status_due >= 0 && (timeout < 0 || status_due < timeout))
			timeout = status_due;
		if (ctx->bench) {
			int due = bench_timeout_ms(ctx->bench, monotonic_ns());

			if (timeout < 0 || due < timeout)
				timeout = due;
		}

		int nfds = epoll_wait(ctx->epoll_fd, events, 16, timeout);

		if (nfds < 0) {
			int err = errno;

			if (err == EINTR)
				continue;
			lota_err("epoll_wait failed: %s", strerror(err));
			return -err;
		}

		poll_event_loss(ctx, &last_lost, &last_loss_poll_ns);
		if (ctx->bench)
			bench_poll(ctx, &bench_err);

		if (nfds == 0) {
			if (ctx->wd_enabled)
				watchdog_beat();
			continue;
		}

		for (int i = 0; i < nfds; i++) {
			if (events[i].data.fd == ctx->sfd) {
				struct signalfd_siginfo fdsi;
				ssize_t got =
					read(ctx->sfd, &fdsi,
					     sizeof(struct signalfd_siginfo));
				if (got != sizeof(struct signalfd_siginfo))
					continue;

				if (fdsi.ssi_signo == SIGTERM ||
				    fdsi.ssi_signo == SIGINT) {
					lota_info(
						"Signal received, stopping...");
					*ctx->running = 0;
				} else if (fdsi.ssi_signo == SIGHUP) {
					sdnotify_reloading();
					lota_info("SIGHUP received, reloading "
						  "configuration");

					(void)agent_reload_config(
						ctx->config_path, ctx->cfg,
						ctx->mode, ctx->strict_mmap,
						ctx->strict_exec,
						ctx->block_ptrace,
						ctx->strict_modules,
						ctx->block_anon_exec,
						ctx->protect_pids,
						ctx->protect_pid_count,
						ctx->trust_libs,
						ctx->trust_lib_count);
					ipc_set_mode(ctx->ipc_ctx,
						     (uint8_t)*ctx->mode);
					ipc_set_policy(
						ctx->ipc_ctx,
						lota_status_policy_keys(
							*ctx->strict_mmap,
							*ctx->strict_exec,
							*ctx->strict_modules,
							*ctx->block_anon_exec,
							*ctx->block_ptrace));
					agent_reload_publishers(ctx);
				}
			} else if (events[i].data.fd ==
				   ipc_get_fd(ctx->ipc_ctx)) {
				ipc_process(ctx->ipc_ctx, 0);
			} else if (ctx->dbus_ctx &&
				   events[i].data.fd ==
					   dbus_get_fd(ctx->dbus_ctx)) {
				dbus_process(ctx->dbus_ctx, 0);
			} else if (events[i].data.fd ==
				   bpf_loader_get_event_fd(ctx->bpf_ctx)) {
				bpf_loader_consume(ctx->bpf_ctx);
			} else if (ipc_socket_watch_fd(ctx->ipc_ctx) >= 0 &&
				   events[i].data.fd ==
					   ipc_socket_watch_fd(ctx->ipc_ctx)) {
				(void)ipc_recheck_socket(ctx->ipc_ctx);
			} else if (ctx->container_watch &&
				   (events[i].data.fd ==
					    container_watch_fd(
						    ctx->container_watch) ||
				    events[i].data.fd ==
					    container_watch_mount_fd(
						    ctx->container_watch))) {
				(void)container_watch_process(
					ctx->container_watch);
			}
		}

		/* the supervisor thread pings; the loop only reports progress */
		if (ctx->wd_enabled)
			watchdog_beat();
	}

	return 0;
}
