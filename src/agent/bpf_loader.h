/* SPDX-License-Identifier: MIT */
/*
 * LOTA - BPF Program Loader
 * Loads and manages eBPF LSM programs using libbpf
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_BPF_LOADER_H
#define LOTA_BPF_LOADER_H

#include <stdbool.h>
#include <stdint.h>

struct bpf_object;
struct ring_buffer;

/*
 * BPF loader context
 */
struct bpf_loader_ctx {
  struct bpf_object *obj;      /* libbpf object */
  struct ring_buffer *ringbuf; /* Ring buffer for events */
  int ringbuf_fd;              /* Ring buffer map fd */
  int stats_fd;                /* Stats map fd */
  bool loaded;                 /* Program is loaded and attached */
};

/*
 * Callback for ring buffer events
 */
typedef int (*bpf_event_handler_t)(void *ctx, void *data, size_t len);

/*
 * bpf_loader_init - Initialize BPF loader context
 * @ctx: Context to initialize
 *
 * Returns: 0 on success, negative errno on failure
 */
int bpf_loader_init(struct bpf_loader_ctx *ctx);

/*
 * bpf_loader_load - Load and attach BPF program
 * @ctx: Initialized context
 * @bpf_obj_path: Path to compiled BPF object file (.bpf.o)
 *
 * Loads the BPF object, verifies it, and attaches LSM hooks.
 *
 * Returns: 0 on success, negative errno on failure
 */
int bpf_loader_load(struct bpf_loader_ctx *ctx, const char *bpf_obj_path);

/*
 * bpf_loader_setup_ringbuf - Set up ring buffer for events
 * @ctx: Loaded context
 * @handler: Callback for processing events
 * @handler_ctx: User context passed to handler
 *
 * Returns: 0 on success, negative errno on failure
 */
int bpf_loader_setup_ringbuf(struct bpf_loader_ctx *ctx,
                             bpf_event_handler_t handler, void *handler_ctx);

/*
 * bpf_loader_poll - Poll ring buffer for events
 * @ctx: Context with set up ring buffer
 * @timeout_ms: Timeout in milliseconds (-1 for infinite)
 *
 * Calls the handler for each event received.
 *
 * Returns: Number of events processed, or negative errno
 */
int bpf_loader_poll(struct bpf_loader_ctx *ctx, int timeout_ms);

/*
 * bpf_loader_get_stats - Get BPF statistics
 * @ctx: Loaded context
 * @total_execs: Output - total exec events seen
 * @events_sent: Output - events sent to ring buffer
 * @errors: Output - error count
 * @drops: Output - ring buffer drops
 *
 * Returns: 0 on success, negative errno on failure
 */
int bpf_loader_get_stats(struct bpf_loader_ctx *ctx, uint64_t *total_execs,
                         uint64_t *events_sent, uint64_t *errors,
                         uint64_t *drops);

/*
 * bpf_loader_cleanup - Unload BPF program and clean up
 * @ctx: Context to clean up
 */
void bpf_loader_cleanup(struct bpf_loader_ctx *ctx);

#endif /* LOTA_BPF_LOADER_H */
