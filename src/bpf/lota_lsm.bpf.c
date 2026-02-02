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
  __uint(max_entries, 8);
  __type(key, u32);
  __type(value, u64);
} stats SEC(".maps");

#define STAT_TOTAL_EXECS 0
#define STAT_EVENTS_SENT 1
#define STAT_ERRORS 2
#define STAT_RINGBUF_DROPS 3
#define STAT_MODULES_BLOCKED 4

/*
 * Configuration map for runtime policy control.
 * Key 0 = enforcement mode (enum lota_mode)
 */
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, LOTA_CFG_MAX_ENTRIES);
  __type(key, u32);
  __type(value, u32);
} lota_config SEC(".maps");

/*
 * Module whitelist map.
 * Key: module filename (eg. "nvidia.ko")
 * Value: 1 = allowed
 *
 * Userspace can populate this to allow specific modules in ENFORCE mode.
 */
#define MODULE_NAME_MAX 64
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 256);
  __type(key, char[MODULE_NAME_MAX]);
  __type(value, u32);
} module_whitelist SEC(".maps");

/*
 * Increment a statistics counter
 */
static __always_inline void inc_stat(u32 idx) {
  u64 *val = bpf_map_lookup_elem(&stats, &idx);
  if (val)
    __sync_fetch_and_add(val, 1);
}

/*
 * Get current enforcement mode
 */
static __always_inline u32 get_mode(void) {
  u32 key = LOTA_CFG_MODE;
  u32 *mode = bpf_map_lookup_elem(&lota_config, &key);
  return mode ? *mode : LOTA_MODE_MONITOR;
}

/*
 * Check if path starts with allowed module directory.
 * Returns 1 if path is allowed, 0 if blocked.
 *
 * Allowed paths (Im writing this on Fedora):
 *   /usr/lib/modules/   - Standard Fedora/RHEL module location
 *   /lib/modules/       - Legacy/symlink compatibility
 */
static __always_inline int is_allowed_module_path(const char *path) {
  char buf[64];
  int ret;

  if (!path)
    return 0;

  ret = bpf_probe_read_kernel_str(buf, sizeof(buf), path);
  if (ret < 0)
    return 0;

  /* /usr/lib/modules/ prefix */
  if (buf[0] == '/' && buf[1] == 'u' && buf[2] == 's' && buf[3] == 'r' &&
      buf[4] == '/' && buf[5] == 'l' && buf[6] == 'i' && buf[7] == 'b' &&
      buf[8] == '/' && buf[9] == 'm' && buf[10] == 'o' && buf[11] == 'd' &&
      buf[12] == 'u' && buf[13] == 'l' && buf[14] == 'e' && buf[15] == 's' &&
      buf[16] == '/') {
    return 1;
  }

  /* /lib/modules/ prefix */
  if (buf[0] == '/' && buf[1] == 'l' && buf[2] == 'i' && buf[3] == 'b' &&
      buf[4] == '/' && buf[5] == 'm' && buf[6] == 'o' && buf[7] == 'd' &&
      buf[8] == 'u' && buf[9] == 'l' && buf[10] == 'e' && buf[11] == 's' &&
      buf[12] == '/') {
    return 1;
  }

  return 0;
}

/*
 * Check if module name is in whitelist.
 */
static __always_inline int is_module_whitelisted(const unsigned char *name) {
  char key[MODULE_NAME_MAX] = {};
  u32 *allowed;
  int ret;

  if (!name)
    return 0;

  ret = bpf_probe_read_kernel_str(key, sizeof(key), name);
  if (ret < 0)
    return 0;

  allowed = bpf_map_lookup_elem(&module_whitelist, key);
  return allowed && *allowed;
}

/*
 * Try to determine if module is from standard location.
 * Walks up dentry parents looking for "modules" directory.
 *
 * Returns 1 if appears to be from /lib/modules or /usr/lib/modules
 */
static __always_inline int is_standard_module_location(struct dentry *dentry) {
  struct dentry *parent;
  const unsigned char *pname;
  char buf[12];

  if (!dentry)
    return 0;

  /*
   * Walk up to 6 levels of parent directories.
   * Looking for pattern: .../lib/modules/... or .../usr/lib/modules/...
   */
  parent = BPF_CORE_READ(dentry, d_parent);
#pragma unroll
  for (int i = 0; i < 6 && parent; i++) {
    pname = BPF_CORE_READ(parent, d_name.name);
    if (!pname)
      goto next;

    if (bpf_probe_read_kernel_str(buf, sizeof(buf), pname) < 0)
      goto next;

    /* Check if this directory is "modules" */
    if (buf[0] == 'm' && buf[1] == 'o' && buf[2] == 'd' && buf[3] == 'u' &&
        buf[4] == 'l' && buf[5] == 'e' && buf[6] == 's' && buf[7] == '\0') {
      return 1;
    }

  next:
    parent = BPF_CORE_READ(parent, d_parent);
  }

  return 0;
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
 * LSM hook: kernel_module_request
 * Called when kernel requests a module by name (eg., via modprobe).
 * This is triggered by request_module() in kernel code.
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

/*
 * LSM hook: security_kernel_read_file
 *
 * Called when kernel reads a file for internal use (modules, firmware, etc.)
 * This is the enforcement point for blocking unauthorized kernel modules.
 *
 * @file: The file being read
 * @id: Type of read operation (enum kernel_read_file_id):
 *        READING_MODULE = 2 - Kernel module (.ko file)
 *        READING_FIRMWARE = 1 - Device firmware
 *        READING_KEXEC_IMAGE = 5 - Kexec kernel image
 * @contents: Whether contents are being read (vs just opened)
 *
 * Return: 0 to allow, -EPERM to deny
 */
SEC("lsm/kernel_read_file")
int BPF_PROG(lota_kernel_read_file, struct file *file,
             enum kernel_read_file_id id, bool contents, int ret) {
  struct lota_exec_event *event;
  struct dentry *dentry;
  const unsigned char *name;
  char path_buf[64];
  u32 mode;
  u32 key = 0;
  int blocked = 0;

  /* Dont interfere with previous hook denial */
  if (ret != 0)
    return ret;

  /*
   * Only enforce on kernel module loads (id == 2 - READING_MODULE).
   */
  if (id != 2)
    return 0;

  mode = get_mode();

  if (mode == LOTA_MODE_MAINTENANCE)
    return 0;

  /* for path validation */
  dentry = BPF_CORE_READ(file, f_path.dentry);

  /*
   * Read the path from file structure.
   * TODO: resolve the full path in BPF!!!!
   */
  name = BPF_CORE_READ(dentry, d_name.name);

  __builtin_memset(path_buf, 0, sizeof(path_buf));
  if (name) {
    bpf_probe_read_kernel_str(path_buf, sizeof(path_buf), name);
  }

  /*
   * In ENFORCE mode, LOTA block modules not from standard paths.
   * LOTA check:
   *   1. Is module on explicit whitelist? -> allow
   *   2. Is module from /lib/modules/ or /usr/lib/modules/? -> allow
   *   3. Otherwise -> block
   */
  if (mode == LOTA_MODE_ENFORCE) {
    if (is_module_whitelisted(name)) {
      blocked = 0;
    } else if (is_standard_module_location(dentry)) {
      blocked = 0;
    } else {
      blocked = 1;
    }
  }

  /* for logging */
  event = bpf_map_lookup_elem(&event_scratch, &key);
  if (event) {
    __builtin_memset(event, 0, sizeof(*event));
    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type =
        blocked ? LOTA_EVENT_MODULE_BLOCKED : LOTA_EVENT_MODULE_LOAD;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event->uid = 0; /* will be root for module loads */

    bpf_get_current_comm(event->comm, sizeof(event->comm));

    __builtin_memcpy(event->filename, path_buf, sizeof(path_buf));

    struct lota_exec_event *rb_event;
    rb_event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (rb_event) {
      __builtin_memcpy(rb_event, event, sizeof(*event));
      bpf_ringbuf_submit(rb_event, 0);
    }
  }

  if (blocked) {
    inc_stat(STAT_MODULES_BLOCKED);
    return -1; /* -EPERM */
  }

  return 0;
}

/*
 * LSM hook: security_kernel_load_data
 *
 * Called when kernel loads data directly from memory (not file).
 * This catches finit_module() with data loaded into memory, e.g.,
 * when module is loaded from initramfs or via direct memory copy.
 *
 * @id: Type of data being loaded (enum kernel_load_data_id):
 *        LOADING_MODULE = 2 - Kernel module from memory
 *
 * Return: 0 to allow, -EPERM to deny
 */
SEC("lsm/kernel_load_data")
int BPF_PROG(lota_kernel_load_data, enum kernel_load_data_id id, bool contents,
             int ret) {
  struct lota_exec_event *event;
  u32 mode;
  u32 key = 0;
  int blocked = 0;

  /* Dont interfere with previous hook denial */
  if (ret != 0)
    return ret;

  /*
   * Only enforce on kernel module loads (id == 2 - LOADING_MODULE).
   */
  if (id != 2)
    return 0;

  mode = get_mode();

  if (mode == LOTA_MODE_MAINTENANCE)
    return 0;

  /*
   * In ENFORCE mode, block ALL memory-loaded modules.
   * Memory loading bypasses file-based path checks, so LOTA is strict here.
   * Only initramfs modules (loaded before LOTA starts) should use this path.
   */
  if (mode == LOTA_MODE_ENFORCE) {
    blocked = 1;
  }

  /* for logging */
  event = bpf_map_lookup_elem(&event_scratch, &key);
  if (event) {
    __builtin_memset(event, 0, sizeof(*event));
    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type =
        blocked ? LOTA_EVENT_MODULE_BLOCKED : LOTA_EVENT_MODULE_LOAD;
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

    bpf_get_current_comm(event->comm, sizeof(event->comm));

    /* memory-loaded module */
    __builtin_memcpy(event->filename, "[memory]", 9);

    struct lota_exec_event *rb_event;
    rb_event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (rb_event) {
      __builtin_memcpy(rb_event, event, sizeof(*event));
      bpf_ringbuf_submit(rb_event, 0);
    }
  }

  if (blocked) {
    inc_stat(STAT_MODULES_BLOCKED);
    return -1; /* -EPERM */
  }

  return 0;
}
