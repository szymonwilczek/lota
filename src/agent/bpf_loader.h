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
struct bpf_link;

#define BPF_MAX_LSM_LINKS 16

/*
 * BPF loader context
 */
struct bpf_loader_ctx {
  struct bpf_object *obj;                    /* libbpf object */
  struct ring_buffer *ringbuf;               /* Ring buffer for events */
  struct bpf_link *links[BPF_MAX_LSM_LINKS]; /* attached LSM program links */
  int link_count;                            /* number of attached links */
  int ringbuf_fd;                            /* Ring buffer map fd */
  int stats_fd;                              /* Stats map fd */
  int config_fd;                             /* 'lota_config' map fd */
  int integrity_fd;                          /* 'integrity_config' map fd */
  int bpf_admin_tgid_fd;                     /* 'bpf_admin_tgid' map fd */
  int agent_identity_fd;                     /* 'lota_agent_identity' map fd */
  int trusted_libs_fd;                       /* 'trusted_libs' map fd */
  int protected_pids_fd;                     /* Protected PIDs map fd */
  int allow_verity_digest_fd;                /* 'allow_verity_digest' map fd */
  bool loaded; /* Program is loaded and attached */
};

/*
 * bpf_loader_allow_verity_digest - Add an allowed fs-verity digest to the map
 * @ctx: Loaded context
 * @digest: 32-byte fs-verity digest
 *
 * Returns: 0 on success, negative errno on failure
 */
int bpf_loader_allow_verity_digest(struct bpf_loader_ctx *ctx,
                                   const uint8_t digest[32]);

/*
 * bpf_loader_disallow_verity_digest - Remove an allowed fs-verity digest
 * @ctx: Loaded context
 * @digest: 32-byte fs-verity digest
 */
int bpf_loader_disallow_verity_digest(struct bpf_loader_ctx *ctx,
                                      const uint8_t digest[32]);

/*
 * bpf_loader_measure_verity_digest - Measure fs-verity digest for a path
 * @path: Absolute path to a fs-verity-enabled regular file
 * @out: 32-byte output digest
 */
int bpf_loader_measure_verity_digest(const char *path, uint8_t out[32]);

/*
 * bpf_loader_allow_verity_path - Measure a path's fs-verity digest and allow it
 * @ctx: Loaded context
 * @path: Absolute path to a fs-verity-enabled regular file
 *
 * Returns: 0 on success, negative errno on failure
 */
int bpf_loader_allow_verity_path(struct bpf_loader_ctx *ctx, const char *path);

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
 * bpf_loader_get_event_fd - Get the epoll fd for the ring buffer
 * @ctx: Context
 *
 * Returns: file descriptor (>= 0) or negative errno
 */
int bpf_loader_get_event_fd(struct bpf_loader_ctx *ctx);

/*
 * bpf_loader_consume - Consume available events without blocking
 * @ctx: Context
 *
 * Returns: Number of events processed, or negative errno
 */
int bpf_loader_consume(struct bpf_loader_ctx *ctx);

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
 * bpf_loader_set_mode - Set enforcement mode
 * @ctx: Loaded context
 * @mode: enum lota_mode value (MONITOR, ENFORCE, MAINTENANCE)
 *
 * Controls whether LSM hooks block or just monitor.
 *
 * Returns: 0 on success, negative errno on failure
 */
int bpf_loader_set_mode(struct bpf_loader_ctx *ctx, uint32_t mode);

/*
 * bpf_loader_get_mode - Get current enforcement mode
 * @ctx: Loaded context
 * @mode: Output - current mode
 *
 * Returns: 0 on success, negative errno on failure
 */
int bpf_loader_get_mode(struct bpf_loader_ctx *ctx, uint32_t *mode);

/*
 * bpf_loader_set_config - Set a runtime configuration value
 * @ctx: Loaded context
 * @key: Config key (LOTA_CFG_*)
 * @value: Config value
 *
 * Returns: 0 on success, negative errno on failure
 */
int bpf_loader_set_config(struct bpf_loader_ctx *ctx, uint32_t key,
                          uint32_t value);

/*
 * bpf_loader_set_agent_pid - Set runtime lota-agent identity in BPF map
 * @ctx: Loaded context
 * @pid: Agent TGID (process id)
 *
 * Returns: 0 on success, negative errno on failure
 */
int bpf_loader_set_agent_pid(struct bpf_loader_ctx *ctx, uint32_t pid);

/*
 * bpf_loader_protect_pid - Add a PID to the protected set
 * @ctx: Loaded context
 * @pid: Process ID to protect
 *
 * Protected PIDs get extra security in ENFORCE mode:
 *   - ptrace on these PIDs is blocked
 *
 * Identity is bound to PID start time from /proc/<pid>/stat
 * to prevent trust leakage on PID reuse.
 *
 * Returns: 0 on success, negative errno on failure
 */
int bpf_loader_protect_pid(struct bpf_loader_ctx *ctx, uint32_t pid);

/*
 * bpf_loader_unprotect_pid - Remove a PID from the protected set
 * @ctx: Loaded context
 * @pid: Process ID to unprotect
 *
 * Returns: 0 on success, negative errno on failure
 */
int bpf_loader_unprotect_pid(struct bpf_loader_ctx *ctx, uint32_t pid);

/*
 * bpf_loader_trust_lib - Add a library path to the trusted whitelist
 * @ctx: Loaded context
 * @path: Full path to the shared library
 *
 * Trusted libraries are allowed to be loaded via mmap(PROT_EXEC)
 * even when strict mmap enforcement is enabled.
 *
 * Returns: 0 on success, negative errno on failure
 */
int bpf_loader_trust_lib(struct bpf_loader_ctx *ctx, const char *path);

/*
 * bpf_loader_untrust_lib - Remove a library path from the trusted whitelist
 * @ctx: Loaded context
 * @path: Full path to the shared library
 *
 * Returns: 0 on success, negative errno on failure
 */
int bpf_loader_untrust_lib(struct bpf_loader_ctx *ctx, const char *path);

unsigned long resolve_kernel_symbol(const char *name);

struct bpf_extended_stats {
  uint64_t total_execs;
  uint64_t events_sent;
  uint64_t errors;
  uint64_t drops;
  uint64_t modules_blocked;
  uint64_t mmap_execs;
  uint64_t mmap_blocked;
  uint64_t ptrace_attempts;
  uint64_t ptrace_blocked;
  uint64_t setuid_events;
  uint64_t bpf_syscall_blocked;
};

/*
 * bpf_loader_get_extended_stats - Get all statistics including new hooks
 * @ctx: Loaded context
 * @stats: Output statistics structure
 *
 * Returns: 0 on success, negative errno on failure
 */
int bpf_loader_get_extended_stats(struct bpf_loader_ctx *ctx,
                                  struct bpf_extended_stats *stats);

/*
 * bpf_loader_cleanup - Unload BPF program and clean up
 * @ctx: Context to clean up
 */
void bpf_loader_cleanup(struct bpf_loader_ctx *ctx);

#endif /* LOTA_BPF_LOADER_H */
