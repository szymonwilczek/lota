// SPDX-License-Identifier: GPL-2.0-only
/*
 * LOTA - eBPF LSM Program
 * Hooks security_bprm_check to monitor binary executions
 *
 * This program runs in kernel space and sends events to user-space
 * via BPF ring buffer.
 *
 * Copyright (C) 2026 Szymon Wilczek
 *
 * Build requirements:
 *   - CONFIG_BPF_LSM=y
 *   - CONFIG_DEBUG_INFO_BTF=y
 *   - LSM must include "bpf" (check /sys/kernel/security/lsm)
 *
 * Compile with:
 *   clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
 *     -I../../include -c lota_lsm.bpf.c -o lota_lsm.bpf.o
 */

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "lota.h"

char LICENSE[] SEC("license") = "GPL";

/*
 * Ring buffer for sending events to user-space.
 * Size is defined in user-space when creating the map.
 */
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, LOTA_RINGBUF_SIZE);
} events SEC(".maps");

/*
 * Per-CPU array for temporary event storage.
 * We build the event here before submitting to ring buffer.
 * This avoids stack size limits (512 bytes in BPF).
 */
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct lota_exec_event);
} event_scratch SEC(".maps");

/*
 * Statistics counters
 */
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 4);
  __type(key, u32);
  __type(value, u64);
} stats SEC(".maps");

#define STAT_TOTAL_EXECS 0
#define STAT_EVENTS_SENT 1
#define STAT_ERRORS 2
#define STAT_RINGBUF_DROPS 3

/*
 * Increment a statistics counter
 */
static __always_inline void inc_stat(u32 idx) {
  u64 *val = bpf_map_lookup_elem(&stats, &idx);
  if (val)
    __sync_fetch_and_add(val, 1);
}

/*
 * Calculate a simple hash of the first N bytes of a file.
 *
 * Due to BPF limitations:
 * - cant read the entire file
 * - cant use crypto APIs
 * - limited loop iterations
 *
 * This is a "fingerprint" for quick comparison, not a secure hash.
 * TODO: The full SHA-256 will be computed in user-space for critical files.
 *
 * For now, it's: simple rolling hash of first 4KB + metadata
 */
static __always_inline void compute_partial_hash(struct file *file,
                                                 u8 hash[LOTA_HASH_SIZE]) {
  struct inode *inode;
  u64 ino, size;

  /* For file metadata */
  inode = BPF_CORE_READ(file, f_inode);
  if (!inode) {
    __builtin_memset(hash, 0, LOTA_HASH_SIZE);
    return;
  }

  ino = BPF_CORE_READ(inode, i_ino);
  size = BPF_CORE_READ(inode, i_size);

  /*
   * For now (will be changed), encode inode and size into hash.
   * Real implementation would read file content.
   *
   * Format: [8 bytes ino][8 bytes size][16 bytes zero]
   */
  __builtin_memset(hash, 0, LOTA_HASH_SIZE);
  __builtin_memcpy(hash, &ino, sizeof(ino));
  __builtin_memcpy(hash + 8, &size, sizeof(size));
}

/*
 * LSM hook: security_bprm_check
 *
 * Called when a new program is about to be executed.
 * This is after the binary is loaded but before it runs.
 *
 * @bprm: Binary program descriptor containing:
 *   - file: The executable file
 *   - filename: Path to the executable
 *   - cred: Credentials to use
 *
 * Return: 0 to allow, negative to deny (always allow in monitor mode)
 */
SEC("lsm/bprm_check_security")
int BPF_PROG(lota_bprm_check, struct linux_binprm *bprm, int ret) {
  struct lota_exec_event *event;
  struct task_struct *task;
  struct file *file;
  u32 key = 0;
  int err;

  /* dont interfere with previous hook denial */
  if (ret != 0)
    return ret;

  inc_stat(STAT_TOTAL_EXECS);

  /* scratch space for building event */
  event = bpf_map_lookup_elem(&event_scratch, &key);
  if (!event) {
    inc_stat(STAT_ERRORS);
    return 0;
  }

  __builtin_memset(event, 0, sizeof(*event));

  event->timestamp_ns = bpf_ktime_get_ns();
  event->event_type = LOTA_EVENT_EXEC;

  /* current task info */
  task = (struct task_struct *)bpf_get_current_task();

  event->pid = BPF_CORE_READ(task, pid);
  event->tgid = BPF_CORE_READ(task, tgid);
  event->uid = BPF_CORE_READ(task, cred, uid.val);
  event->gid = BPF_CORE_READ(task, cred, gid.val);

  /* process name */
  bpf_get_current_comm(event->comm, sizeof(event->comm));

  const char *filename = BPF_CORE_READ(bprm, filename);
  if (filename) {
    bpf_probe_read_kernel_str(event->filename, sizeof(event->filename),
                              filename);
  }

  /* compute partial hash of binary */
  file = BPF_CORE_READ(bprm, file);
  if (file) {
    compute_partial_hash(file, event->hash);
  }

  /*
   * Submit event to ring buffer.
   * If ring buffer is full, event is dropped (BPF_RB_NO_WAKEUP skips
   * waking up user-space if buffer was empty - more efficient).
   */
  struct lota_exec_event *rb_event;
  rb_event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
  if (!rb_event) {
    inc_stat(STAT_RINGBUF_DROPS);
    return 0;
  }

  /* copy event data to ring buffer */
  __builtin_memcpy(rb_event, event, sizeof(*event));

  bpf_ringbuf_submit(rb_event, 0);
  inc_stat(STAT_EVENTS_SENT);

  /* Always allow execution - just monitoring */
  return 0;
}

/*
 * TODO description
 */
SEC("lsm/kernel_module_request")
int BPF_PROG(lota_module_request, char *kmod_name, int ret) {
  struct lota_exec_event *event;
  u32 key = 0;

  if (ret != 0)
    return ret;

  event = bpf_map_lookup_elem(&event_scratch, &key);
  if (!event)
    return 0;

  __builtin_memset(event, 0, sizeof(*event));
  event->timestamp_ns = bpf_ktime_get_ns();
  event->event_type = LOTA_EVENT_MODULE_LOAD;
  event->pid = bpf_get_current_pid_tgid() >> 32;
  event->tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

  bpf_get_current_comm(event->comm, sizeof(event->comm));

  if (kmod_name) {
    bpf_probe_read_kernel_str(event->filename, sizeof(event->filename),
                              kmod_name);
  }

  struct lota_exec_event *rb_event;
  rb_event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
  if (rb_event) {
    __builtin_memcpy(rb_event, event, sizeof(*event));
    bpf_ringbuf_submit(rb_event, 0);
  }

  return 0;
}
