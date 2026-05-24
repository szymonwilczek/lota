/* SPDX-License-Identifier: MIT */
/*
 * LOTA agent - event-loop telemetry helpers.
 *
 * Kept in its own translation unit so the pure-function half of the
 * loop (drop-counter delta, future per-loop accumulators) can be
 * unit-tested without pulling the global agent context, libbpf,
 * libtss2, libsystemd, or any other heavy dependency of the live
 * event loop in daemon_loop.c.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include "daemon_loop.h"

uint64_t agent_ringbuf_drop_delta(uint64_t current, uint64_t *last) {
  if (!last)
    return 0;
  if (current <= *last) {
    *last = current;
    return 0;
  }
  uint64_t delta = current - *last;
  *last = current;
  return delta;
}
