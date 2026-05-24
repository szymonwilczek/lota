/* SPDX-License-Identifier: MIT */
#ifndef LOTA_DAEMON_LOOP_H
#define LOTA_DAEMON_LOOP_H

#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>

#include "bpf_loader.h"
#include "config.h"
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

  struct ipc_context *ipc_ctx;
  struct dbus_context *dbus_ctx;
  struct bpf_loader_ctx *bpf_ctx;
  volatile sig_atomic_t *running;
};

int agent_run_event_loop(struct agent_loop_ctx *ctx);

/*
 * agent_ringbuf_drop_delta - compute alertable BPF ringbuf drop delta
 * @current: current drop counter snapshot returned by
 *           bpf_loader_get_extended_stats().drops
 * @last:    in/out pointer to the last observed counter; updated to
 *           @current on return so successive calls report monotonic
 *           increments
 *
 * Returns the increase since the last call. A non-zero return is the
 * forensic signal: every step the agent failed to push an event to
 * user-space because the BPF ringbuf was full. A counter rollback
 * (BPF stats reset across map reload) is treated as zero delta and
 * just resets the baseline so the next monotonic delta reads cleanly.
 */
uint64_t agent_ringbuf_drop_delta(uint64_t current, uint64_t *last);

#endif
