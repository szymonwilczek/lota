// SPDX-License-Identifier: GPL-2.0-only
/*
 * LOTA - eBPF LSM Program
 * Runtime memory integrity monitoring and enforcement
 *
 * Copyright (C) 2026 Szymon Wilczek
 *
 * This program runs in kernel space and sends events to user-space
 * via BPF ring buffer. It hooks multiple LSM points to monitor:
 *
 *   - Binary execution (bprm_check_security)
 *   - Kernel module loading (kernel_module_request, kernel_read_file,
 *     kernel_load_data)
 *   - Library loading / executable mmap (security_mmap_file)
 *   - Debugger attachment (security_ptrace_access_check)
 *   - Privilege escalation (task_fix_setuid)
 *
 * In ENFORCE mode, unauthorized operations are blocked:
 *   - Modules from non-standard paths
 *   - Executable mmaps from untrusted locations
 *   - ptrace on protected processes
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
 * Separate per-CPU scratch for sleepable hooks (lsm.s).
 * Sleepable programs can be preempted mid-execution, allowing a
 * non-sleepable hook on the same CPU to clobber the shared buffer.
 */
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct lota_exec_event);
} event_scratch_sleepable SEC(".maps");

/*
 * Statistics counters.
 * Extended to 16 entries for new hooks.
 */
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 16);
  __type(key, u32);
  __type(value, u64);
} stats SEC(".maps");

#define STAT_TOTAL_EXECS 0
#define STAT_EVENTS_SENT 1
#define STAT_ERRORS 2
#define STAT_RINGBUF_DROPS 3
#define STAT_MODULES_BLOCKED 4
#define STAT_MMAP_EXECS 5
#define STAT_MMAP_BLOCKED 6
#define STAT_PTRACE_ATTEMPTS 7
#define STAT_PTRACE_BLOCKED 8
#define STAT_SETUID_EVENTS 9
#define STAT_ANON_EXEC 10
#define STAT_ANON_EXEC_BLOCKED 11
#define STAT_EXEC_BLOCKED 12

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
 * Trusted library whitelist map.
 * Key: library path (eg: "/opt/game/lib/libanticheat.so")
 * Value: 1 = allowed
 *
 * Userspace populates this to allow game-specific libraries
 * in ENFORCE mode, beyond the standard /usr/lib paths.
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, LOTA_MAX_TRUSTED_LIBS);
  __type(key, char[LOTA_MAX_PATH_LEN]);
  __type(value, u32);
} trusted_libs SEC(".maps");

/*
 * Per-CPU scratch buffer for resolving file paths.
 * Used by lota_mmap_file to resolve full paths from dentry for
 * trusted library map lookups and path prefix checks.
 */
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, char[LOTA_MAX_PATH_LEN]);
} path_scratch SEC(".maps");

/*
 * Protected PID map.
 * Key: PID (u32)
 * Value: 1 = protected
 *
 * Processes in this map receive extra protection in ENFORCE mode:
 *   - ptrace attach is blocked
 *   - All executable mmaps are logged
 *
 * Userspace should add game server PIDs here.
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, LOTA_MAX_PROTECTED_PIDS);
  __type(key, u32);
  __type(value, u32);
} protected_pids SEC(".maps");

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
 * Get a boolean config value, defaults to 0 (disabled).
 */
static __always_inline u32 get_config(u32 key) {
  u32 *val = bpf_map_lookup_elem(&lota_config, &key);
  return val ? *val : 0;
}

/*
 * Check if a PID is in the protected set.
 */
static __always_inline int is_protected_pid(u32 pid) {
  u32 *val = bpf_map_lookup_elem(&protected_pids, &pid);
  return val && *val;
}

/*
 * Resolve full file path using bpf_d_path.
 *
 * bpf_d_path() walks the dentry/mount tree in kernel and produces the
 * absolute path string.  It is only available from sleepable BPF
 * programs attached to functions on the d_path allowlist.
 *
 * @file: kernel struct file pointer (must be a trusted/BTF pointer)
 * @buf:  destination buffer
 * @sz:   buffer size
 *
 * Returns: >= 0 on success (bytes written), negative on error
 */
static __always_inline long resolve_file_path(struct file *file, char *buf,
                                              u32 sz) {
  struct path *fpath;
  long ret;

  if (!file || sz == 0)
    return -1;

  fpath = (struct path *)__builtin_preserve_access_index(&file->f_path);
  ret = bpf_d_path(fpath, buf, sz);
  if (ret >= 0)
    return ret;

  /*
   * fallback: read basename from dentry.
   */
  {
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    const unsigned char *name;

    if (!dentry)
      goto zero;

    name = BPF_CORE_READ(dentry, d_name.name);
    if (!name)
      goto zero;

    ret = bpf_probe_read_kernel_str(buf, sz, name);
    return ret;
  }

zero:
  buf[0] = '\0';
  return 0;
}

/*
 * Check if a library path is in the trusted whitelist.
 * Path must be a resolved full path (eg: "/opt/game/lib/libfoo.so").
 */
static __always_inline int is_trusted_lib(const char *resolved_path) {
  u32 *allowed;

  if (!resolved_path)
    return 0;

  allowed = bpf_map_lookup_elem(&trusted_libs, resolved_path);
  return allowed && *allowed;
}

/*
 * Check if path starts with a trusted library directory.
 *
 * Trusted prefixes:
 *   /usr/lib/      - Standard library location
 *   /usr/lib64/    - 64-bit libraries (Fedora, RHEL, SUSE)
 *   /lib/          - Essential libraries
 *   /lib64/        - Essential 64-bit libraries
 *
 * Uses byte-by-byte comparison because BPF cannot call strncmp.
 * Path must be a resolved full path.
 */
static __always_inline int is_trusted_lib_path(const char *resolved_path) {
  if (!resolved_path)
    return 0;

  /* /usr/lib64/ */
  if (resolved_path[0] == '/' && resolved_path[1] == 'u' &&
      resolved_path[2] == 's' && resolved_path[3] == 'r' &&
      resolved_path[4] == '/' && resolved_path[5] == 'l' &&
      resolved_path[6] == 'i' && resolved_path[7] == 'b' &&
      resolved_path[8] == '6' && resolved_path[9] == '4' &&
      resolved_path[10] == '/') {
    return 1;
  }

  /* /usr/lib/ */
  if (resolved_path[0] == '/' && resolved_path[1] == 'u' &&
      resolved_path[2] == 's' && resolved_path[3] == 'r' &&
      resolved_path[4] == '/' && resolved_path[5] == 'l' &&
      resolved_path[6] == 'i' && resolved_path[7] == 'b' &&
      resolved_path[8] == '/') {
    return 1;
  }

  /* /lib64/ */
  if (resolved_path[0] == '/' && resolved_path[1] == 'l' &&
      resolved_path[2] == 'i' && resolved_path[3] == 'b' &&
      resolved_path[4] == '6' && resolved_path[5] == '4' &&
      resolved_path[6] == '/') {
    return 1;
  }

  /* /lib/ */
  if (resolved_path[0] == '/' && resolved_path[1] == 'l' &&
      resolved_path[2] == 'i' && resolved_path[3] == 'b' &&
      resolved_path[4] == '/') {
    return 1;
  }

  return 0;
}

/*
 * Check if path starts with allowed module directory.
 * Returns 1 if path is allowed, 0 if blocked.
 *
 * Allowed paths:
 *   /usr/lib/modules/   - Standard module location
 *   /lib/modules/       - Legacy/symlink path
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
 * Check if dentry is under a trusted library directory.
 * Walks up dentry parents looking for patterns like:
 *   .../usr/lib/...   .../usr/lib64/...
 *   .../lib/...       .../lib64/...
 *   .../usr/bin/...   .../usr/sbin/...
 *   .../bin/...       .../sbin/...
 *
 * Returns 1 if file appears to be in a trusted system directory.
 */
static __always_inline int is_trusted_system_path(struct dentry *dentry) {
  struct dentry *parent;
  const unsigned char *pname;
  char buf[12];

  if (!dentry)
    return 0;

  parent = BPF_CORE_READ(dentry, d_parent);

#pragma unroll
  for (int i = 0; i < 8 && parent; i++) {
    pname = BPF_CORE_READ(parent, d_name.name);
    if (!pname)
      goto next_trusted;

    if (bpf_probe_read_kernel_str(buf, sizeof(buf), pname) < 0)
      goto next_trusted;

    /* "lib64" */
    if (buf[0] == 'l' && buf[1] == 'i' && buf[2] == 'b' && buf[3] == '6' &&
        buf[4] == '4' && buf[5] == '\0') {
      return 1;
    }

    /* "libexec" - (/usr/libexec/) */
    if (buf[0] == 'l' && buf[1] == 'i' && buf[2] == 'b' && buf[3] == 'e' &&
        buf[4] == 'x' && buf[5] == 'e' && buf[6] == 'c' && buf[7] == '\0') {
      return 1;
    }

    /* "lib" */
    if (buf[0] == 'l' && buf[1] == 'i' && buf[2] == 'b' && buf[3] == '\0') {
      return 1;
    }

    /* "bin" */
    if (buf[0] == 'b' && buf[1] == 'i' && buf[2] == 'n' && buf[3] == '\0') {
      return 1;
    }

    /* "sbin" */
    if (buf[0] == 's' && buf[1] == 'b' && buf[2] == 'i' && buf[3] == 'n' &&
        buf[4] == '\0') {
      return 1;
    }

    /* "modules" (for kernel module compat) */
    if (buf[0] == 'm' && buf[1] == 'o' && buf[2] == 'd' && buf[3] == 'u' &&
        buf[4] == 'l' && buf[5] == 'e' && buf[6] == 's' && buf[7] == '\0') {
      return 1;
    }

  next_trusted:
    parent = BPF_CORE_READ(parent, d_parent);
  }

  return 0;
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
 * Calculate a metadata fingerprint of a file.
 *
 * This is NOT a cryptographic hash. It is a metadata fingerprint that
 * captures all available inode attributes that change when a file is
 * modified. The full SHA-256 content hash is computed in user-space
 * (by the agent via tpm_hash_file) for critical verification.
 *
 * Metadata included in fingerprint:
 *   - i_ino:        inode number (unique per filesystem)
 *   - i_size:       file size in bytes
 *   - i_blocks:     512-byte blocks allocated on disk
 *   - i_mtime_sec:  content modification time (seconds)
 *   - i_mtime_nsec: content modification time (nanoseconds)
 *   - i_ctime_sec:  inode status change time (seconds)
 *   - i_ctime_nsec: inode status change time (nanoseconds)
 *   - i_mode:       file type and permissions
 *   - i_uid/i_gid:  file ownership
 *   - i_nlink:      hard link count
 *   - i_generation: filesystem generation counter
 *   - i_version:    inode version (incremented on any change)
 *
 * Important security note: this fingerprint detects accidental and naive
 * modifications but is NOT tamper-proof against a privileged attacker who can
 * control timestamps and metadata. The TPM-backed attestation (PCR values +
 * signed quote) is the actual trust anchor.
 */

/*
 * 64-bit mixing step: XOR value into accumulator, multiply by a large
 * odd constant, then shift-mix to propagate bit changes.
 * Constants chosen from splitmix64 / murmurhash3 finalizer research.
 */
static __always_inline u64 fprint_mix(u64 h, u64 val) {
  h ^= val;
  h *= 0xbf58476d1ce4e5b9ULL;
  h ^= h >> 31;
  h *= 0x94d049bb133111ebULL;
  h ^= h >> 31;
  return h;
}

static __always_inline void compute_partial_hash(struct file *file,
                                                 u8 hash[LOTA_HASH_SIZE]) {
  struct inode *inode;
  u64 h0, h1, h2, h3;
  u64 ino, size, blocks;
  u64 mtime_sec, ctime_sec;
  u32 mtime_nsec, ctime_nsec;
  u32 mode, nlink, generation;
  u32 uid_val, gid_val;
  u64 i_version;

  inode = BPF_CORE_READ(file, f_inode);
  if (!inode) {
    __builtin_memset(hash, 0, LOTA_HASH_SIZE);
    return;
  }

  /* gather all available inode metadata */
  ino = BPF_CORE_READ(inode, i_ino);
  size = BPF_CORE_READ(inode, i_size);
  blocks = BPF_CORE_READ(inode, i_blocks);
  mode = BPF_CORE_READ(inode, i_mode);
  uid_val = BPF_CORE_READ(inode, i_uid.val);
  gid_val = BPF_CORE_READ(inode, i_gid.val);
  nlink = BPF_CORE_READ(inode, i_nlink);
  generation = BPF_CORE_READ(inode, i_generation);

  /*
   * Timestamps: mtime changes on content write, ctime changes on
   * any metadata change.
   */
  mtime_sec = BPF_CORE_READ(inode, i_mtime_sec);
  mtime_nsec = BPF_CORE_READ(inode, i_mtime_nsec);
  ctime_sec = BPF_CORE_READ(inode, i_ctime_sec);
  ctime_nsec = BPF_CORE_READ(inode, i_ctime_nsec);

  /*
   * i_version: kernel-maintained counter incremented on every inode
   * modification. Strongest anti-tamper signal available from BPF.
   * Stored as atomic64_t, read the counter value directly.
   */
  i_version = BPF_CORE_READ(inode, i_version.counter);

  /*
   * Mix metadata into 4 independent 64-bit hash lanes.
   * Initial values are arbitrary non-zero constants to avoid
   * zero-state degeneracy.
   */
  h0 = fprint_mix(0x243f6a8885a308d3ULL, ino);       /* pi fractional */
  h1 = fprint_mix(0x13198a2e03707344ULL, size);      /* pi fractional */
  h2 = fprint_mix(0xa4093822299f31d0ULL, blocks);    /* e fractional  */
  h3 = fprint_mix(0x082efa98ec4e6c89ULL, i_version); /* e fractional  */

  h0 = fprint_mix(h0, mtime_sec);
  h1 = fprint_mix(h1, (u64)mtime_nsec);
  h2 = fprint_mix(h2, ctime_sec);
  h3 = fprint_mix(h3, (u64)ctime_nsec);

  h0 = fprint_mix(h0, (u64)mode | ((u64)nlink << 16) | ((u64)generation << 32));
  h1 = fprint_mix(h1, (u64)uid_val | ((u64)gid_val << 32));

  h0 ^= h2;
  h1 ^= h3;
  h2 = fprint_mix(h2, h0);
  h3 = fprint_mix(h3, h1);
  h0 = fprint_mix(h0, h3);
  h1 = fprint_mix(h1, h2);

  /* 32-byte fingerprint (4 x 8 bytes) */
  __builtin_memcpy(hash, &h0, 8);
  __builtin_memcpy(hash + 8, &h1, 8);
  __builtin_memcpy(hash + 16, &h2, 8);
  __builtin_memcpy(hash + 24, &h3, 8);
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
  struct dentry *dentry;
  u32 key = 0;
  u32 mode;
  int blocked = 0;

  /* dont interfere with previous hook denial */
  if (ret != 0)
    return ret;

  inc_stat(STAT_TOTAL_EXECS);

  mode = get_mode();

  if (mode == LOTA_MODE_MAINTENANCE)
    return 0;

  /* scratch space for building event */
  event = bpf_map_lookup_elem(&event_scratch, &key);
  if (!event) {
    inc_stat(STAT_ERRORS);
    return 0;
  }

  __builtin_memset(event, 0, sizeof(*event));

  event->timestamp_ns = bpf_ktime_get_ns();

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
   * In ENFORCE mode with STRICT_EXEC enabled, block binaries from
   * untrusted paths. Uses dentry walk since bprm_check_security is
   * non-sleepable and bpf_d_path is not available.
   */
  if (mode == LOTA_MODE_ENFORCE && get_config(LOTA_CFG_STRICT_EXEC)) {
    dentry = file ? BPF_CORE_READ(file, f_path.dentry) : NULL;
    if (!dentry || !is_trusted_system_path(dentry))
      blocked = 1;
  }

  event->event_type = blocked ? LOTA_EVENT_EXEC_BLOCKED : LOTA_EVENT_EXEC;

  /*
   * Submit event to ring buffer.
   * If ring buffer is full, event is dropped (BPF_RB_NO_WAKEUP skips
   * waking up user-space if buffer was empty - more efficient).
   */
  struct lota_exec_event *rb_event;
  rb_event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
  if (rb_event) {
    __builtin_memcpy(rb_event, event, sizeof(*event));
    bpf_ringbuf_submit(rb_event, 0);
    inc_stat(STAT_EVENTS_SENT);
  } else {
    inc_stat(STAT_RINGBUF_DROPS);
  }

  if (blocked) {
    inc_stat(STAT_EXEC_BLOCKED);
    return -1; /* -EPERM */
  }

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
  event->tgid = bpf_get_current_pid_tgid() >> 32;
  event->pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

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
SEC("lsm.s/kernel_read_file")
int BPF_PROG(lota_kernel_read_file, struct file *file,
             enum kernel_read_file_id id, bool contents, int ret) {
  struct lota_exec_event *event;
  struct dentry *dentry;
  const unsigned char *name;
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

  /* also get dentry name for whitelist lookup */
  name = BPF_CORE_READ(dentry, d_name.name);

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
  event = bpf_map_lookup_elem(&event_scratch_sleepable, &key);
  if (event) {
    __builtin_memset(event, 0, sizeof(*event));
    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type =
        blocked ? LOTA_EVENT_MODULE_BLOCKED : LOTA_EVENT_MODULE_LOAD;
    event->tgid = bpf_get_current_pid_tgid() >> 32;
    event->pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event->uid = 0; /* will be root for module loads */

    bpf_get_current_comm(event->comm, sizeof(event->comm));

    resolve_file_path(file, event->filename, sizeof(event->filename));

    /* compute fingerprint of module file */
    compute_partial_hash(file, event->hash);

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
    event->tgid = bpf_get_current_pid_tgid() >> 32;
    event->pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;

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

/* ======================================================================
 * LSM hook: security_mmap_file
 *
 * Called when a file is being memory-mapped with executable permission.
 * This is the primary entry point for shared library loading (ld.so calls
 * mmap(PROT_READ|PROT_EXEC) for every .so it opens).
 *
 * In ENFORCE mode, LOTA blocks executable mmaps from untrusted paths.
 * This defeats:
 *   - LD_PRELOAD injection (cheat libraries)
 *   - dlopen() of unauthorized .so files
 *   - Manual mmap of shellcode from files
 *
 * @file: The file being mapped (NULL for anonymous mappings)
 * @reqprot: Requested protection flags
 * @prot: Actual protection flags (may differ from reqprot)
 * @flags: MAP_* flags
 *
 * Return: 0 to allow, -EPERM to deny
 * ====================================================================== */
SEC("lsm/mmap_file")
int BPF_PROG(lota_mmap_file, struct file *file, unsigned long reqprot,
             unsigned long prot, unsigned long flags, int ret) {
  struct lota_exec_event *event;
  struct dentry *dentry;
  u32 key = 0;
  u32 mode;
  int blocked = 0;

  /* dont interfere with previous hook denial */
  if (ret != 0)
    return ret;

  /*
   * only care about executable mappings.
   */
  if (!(prot & 0x4))
    return 0;

  /*
   * Anonymous executable mappings (file == NULL).
   *
   * In ENFORCE mode with LOTA_CFG_BLOCK_ANON_EXEC enabled, these are
   * blocked and logged. Otherwise, they are logged only.
   */
  if (!file) {
    int anon_blocked = 0;

    inc_stat(STAT_ANON_EXEC);

    mode = get_mode();

    if (mode == LOTA_MODE_MAINTENANCE)
      return 0;

    if (mode == LOTA_MODE_ENFORCE && get_config(LOTA_CFG_BLOCK_ANON_EXEC)) {
      anon_blocked = 1;
    }

    event = bpf_map_lookup_elem(&event_scratch, &key);
    if (event) {
      __builtin_memset(event, 0, sizeof(*event));
      event->timestamp_ns = bpf_ktime_get_ns();
      event->event_type =
          anon_blocked ? LOTA_EVENT_ANON_EXEC_BLOCKED : LOTA_EVENT_ANON_EXEC;
      event->tgid = bpf_get_current_pid_tgid() >> 32;
      event->pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
      event->uid = (u32)(bpf_get_current_uid_gid() & 0xFFFFFFFF);

      bpf_get_current_comm(event->comm, sizeof(event->comm));
      __builtin_memcpy(event->filename, "(anon-exec)", 12);

      struct lota_exec_event *rb_event;
      rb_event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
      if (rb_event) {
        __builtin_memcpy(rb_event, event, sizeof(*event));
        bpf_ringbuf_submit(rb_event, 0);
        inc_stat(STAT_EVENTS_SENT);
      } else {
        inc_stat(STAT_RINGBUF_DROPS);
      }
    }

    if (anon_blocked) {
      inc_stat(STAT_ANON_EXEC_BLOCKED);
      return -1; /* -EPERM */
    }

    return 0;
  }

  inc_stat(STAT_MMAP_EXECS);

  mode = get_mode();

  if (mode == LOTA_MODE_MAINTENANCE)
    return 0;

  /* get the file path for policy decision */
  dentry = BPF_CORE_READ(file, f_path.dentry);

  /*
   * In ENFORCE mode with strict mmap enabled, block libs from
   * untrusted paths. Allow if:
   *  - library is in trusted_libs whitelist map (game-specific)
   *  - library is from standard system paths (/usr/lib, etc)
   *  - otherwise -> block
   *
   * Resolve full path via bpf_d_path into scratch buffer for
   * map lookups and prefix checks. Falls back to dentry walk.
   */
  if (mode == LOTA_MODE_ENFORCE && get_config(LOTA_CFG_STRICT_MMAP)) {
    u32 pkey = 0;
    char *pathbuf = bpf_map_lookup_elem(&path_scratch, &pkey);
    int resolved = 0;

    if (pathbuf) {
      long pret = resolve_file_path(file, pathbuf, LOTA_MAX_PATH_LEN);
      if (pret >= 0 && pathbuf[0] == '/')
        resolved = 1;
    }

    if (resolved && is_trusted_lib(pathbuf)) {
      blocked = 0;
    } else if (resolved && is_trusted_lib_path(pathbuf)) {
      blocked = 0;
    } else if (is_trusted_system_path(dentry)) {
      /*
       * dentry walk: check if any parent directory is a trusted
       * system directory. Fallback when bpf_d_path is unavailable.
       */
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
        blocked ? LOTA_EVENT_MMAP_BLOCKED : LOTA_EVENT_MMAP_EXEC;
    event->tgid = bpf_get_current_pid_tgid() >> 32;
    event->pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event->uid = (u32)(bpf_get_current_uid_gid() & 0xFFFFFFFF);

    bpf_get_current_comm(event->comm, sizeof(event->comm));

    resolve_file_path(file, event->filename, sizeof(event->filename));

    /* compute fingerprint of mapped file */
    compute_partial_hash(file, event->hash);

    struct lota_exec_event *rb_event;
    rb_event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (rb_event) {
      __builtin_memcpy(rb_event, event, sizeof(*event));
      bpf_ringbuf_submit(rb_event, 0);
      inc_stat(STAT_EVENTS_SENT);
    } else {
      inc_stat(STAT_RINGBUF_DROPS);
    }
  }

  if (blocked) {
    inc_stat(STAT_MMAP_BLOCKED);
    return -1; /* -EPERM */
  }

  return 0;
}

/* ======================================================================
 * LSM hook: security_ptrace_access_check
 *
 * Called when one process attempts to trace/debug another via ptrace.
 *
 * In ENFORCE mode, ptrace on protected PIDs is blocked entirely.
 * In MONITOR mode, all ptrace attempts are logged for forensic review.
 *
 * @child: The process being traced (target)
 * @mode: PTRACE_MODE_* flags (read, attach, etc)
 *
 * Return: 0 to allow, -EPERM to deny
 * ====================================================================== */
SEC("lsm/ptrace_access_check")
int BPF_PROG(lota_ptrace_access_check, struct task_struct *child,
             unsigned int mode, int ret) {
  struct lota_exec_event *event;
  u32 key = 0;
  u32 lota_mode;
  u32 child_pid;
  int blocked = 0;

  /* dont interfere with previous hook denial */
  if (ret != 0)
    return ret;

  inc_stat(STAT_PTRACE_ATTEMPTS);

  lota_mode = get_mode();

  if (lota_mode == LOTA_MODE_MAINTENANCE)
    return 0;

  child_pid = BPF_CORE_READ(child, pid);

  /*
   * In ENFORCE mode, block ptrace on protected PIDs.
   * Protected PIDs are managed by user-space.
   *
   * Also block if LOTA_CFG_BLOCK_PTRACE is set.
   */
  if (lota_mode == LOTA_MODE_ENFORCE) {
    if (is_protected_pid(child_pid)) {
      blocked = 1;
    } else if (get_config(LOTA_CFG_BLOCK_PTRACE)) {
      blocked = 1;
    }
  }

  /* for logging */
  event = bpf_map_lookup_elem(&event_scratch, &key);
  if (event) {
    __builtin_memset(event, 0, sizeof(*event));
    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type = blocked ? LOTA_EVENT_PTRACE_BLOCKED : LOTA_EVENT_PTRACE;
    event->tgid = bpf_get_current_pid_tgid() >> 32;
    event->pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event->uid = (u32)(bpf_get_current_uid_gid() & 0xFFFFFFFF);
    event->target_pid = child_pid;

    bpf_get_current_comm(event->comm, sizeof(event->comm));

    /* try to get the target process name */
    const char *child_comm = BPF_CORE_READ(child, comm);
    if (child_comm) {
      bpf_probe_read_kernel_str(event->filename, LOTA_MAX_COMM_LEN, child_comm);
    }

    struct lota_exec_event *rb_event;
    rb_event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (rb_event) {
      __builtin_memcpy(rb_event, event, sizeof(*event));
      bpf_ringbuf_submit(rb_event, 0);
      inc_stat(STAT_EVENTS_SENT);
    } else {
      inc_stat(STAT_RINGBUF_DROPS);
    }
  }

  if (blocked) {
    inc_stat(STAT_PTRACE_BLOCKED);
    return -1; /* -EPERM */
  }

  return 0;
}

/* ======================================================================
 * LSM hook: task_fix_setuid
 *
 * Called when a process changes its effective UID (privilege escalation).
 * This monitors setuid/setgid transitions and is for detecting:
 *  - unauthorized privilege escalation
 *  - SUID binary abuse
 *  - container escape attempts
 *
 * @new: New credentials being applied
 * @old: Current credentials of the task
 * @flags: LSM_SETID_* flags indicating what changed
 *
 * Return: 0 (always allow - just monitoring)
 * ====================================================================== */
SEC("lsm/task_fix_setuid")
int BPF_PROG(lota_task_fix_setuid, struct cred *new, const struct cred *old,
             int flags, int ret) {
  struct lota_exec_event *event;
  u32 key = 0;
  u32 old_uid, new_uid;

  /* dont interfere with previous hook denial */
  if (ret != 0)
    return ret;

  old_uid = BPF_CORE_READ(old, uid.val);
  new_uid = BPF_CORE_READ(new, uid.val);

  /* only log actual UID changes, not no-ops */
  if (old_uid == new_uid)
    return 0;

  inc_stat(STAT_SETUID_EVENTS);

  if (get_mode() == LOTA_MODE_MAINTENANCE)
    return 0;

  event = bpf_map_lookup_elem(&event_scratch, &key);
  if (event) {
    __builtin_memset(event, 0, sizeof(*event));
    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type = LOTA_EVENT_SETUID;
    event->tgid = bpf_get_current_pid_tgid() >> 32;
    event->pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event->uid = old_uid;
    event->target_uid = new_uid;

    bpf_get_current_comm(event->comm, sizeof(event->comm));

    struct lota_exec_event *rb_event;
    rb_event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
    if (rb_event) {
      __builtin_memcpy(rb_event, event, sizeof(*event));
      bpf_ringbuf_submit(rb_event, 0);
      inc_stat(STAT_EVENTS_SENT);
    } else {
      inc_stat(STAT_RINGBUF_DROPS);
    }
  }

  /* kernel handles setuid policy via capabilities */
  return 0;
}
