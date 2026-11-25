/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
#ifndef LOTA_DAEMON_LOOP_H
#define LOTA_DAEMON_LOOP_H

#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>

#include "attest_targets.h"
#include "bench_snapshot.h"
#include "bpf_loader.h"
#include "config.h"
#include "container_watch.h"
#include "dbus.h"
#include "ipc.h"

struct agent_loop_ctx {
	int epoll_fd;
	int sfd;
	bool wd_enabled;
	uint64_t wd_usec;

	const char *config_path;
	struct lota_config *cfg;
	int *mode;
	bool *strict_mmap;
	bool *strict_exec;
	bool *block_ptrace;
	bool *strict_modules;
	bool *block_anon_exec;
	uint32_t **protect_pids;
	int *protect_pid_count;
	char (*trust_libs)[PATH_MAX];
	int *trust_lib_count;

	/* the IPC layer answers from it; SIGHUP rebuilds it in place */
	struct attest_target *targets;
	size_t *target_count;
	size_t target_max;

	struct ipc_context *ipc_ctx;
	struct dbus_context *dbus_ctx;
	struct bpf_loader_ctx *bpf_ctx;
	struct container_watch *container_watch;
	struct bench_state *bench; /* NULL without --bench */
	volatile sig_atomic_t *running;
};

/**
 * agent_run_event_loop() - Serve until asked to stop.
 * @ctx: The loop's state.
 *
 * SIGTERM, SIGINT and the IPC shutdown request end the loop, and so does
 * a failing epoll_wait(), with an error logged.
 *
 * Return: 0.
 */
int agent_run_event_loop(struct agent_loop_ctx *ctx);

/**
 * agent_ringbuf_drop_delta() - Increase of the event loss counters.
 * @current: Sum of the counters from bpf_loader_get_extended_stats().
 * @last: Previous sum; set to @current.
 *
 * Return: @current minus @last, or 0 when @current is not above @last or @last
 * is NULL.
 */
uint64_t agent_ringbuf_drop_delta(uint64_t current, uint64_t *last);

#endif
