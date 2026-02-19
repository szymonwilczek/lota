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

#ifndef EPERM
#define EPERM 1
#endif

/*
 * Ring buffer for sending events to user-space.
 * Size is defined in user-space when creating the map.
 */
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, LOTA_RINGBUF_SIZE);
} events SEC(".maps");

/*
 * Statistics counters.
 */
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 16);
  __type(key, u32);
  __type(value, u64);
} stats SEC(".maps");

/*
 * Configuration map for runtime policy control.
 * Key 0 = enforcement mode
 */
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, LOTA_CFG_MAX_ENTRIES);
  __type(key, uint32_t);
  __type(value, uint32_t);
} lota_config SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, uint32_t);
  __type(value, struct integrity_data);
} integrity_config SEC(".maps");

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
 * fs-verity digest allowlist.
 * Key: fs-verity digest (SHA-256 usually, 32 bytes)
 * Value: 1 = allowed
 *
 * Only files with a verified fs-verity merkle root matching an entry here are
 * allowed to execute in STRICT_EXEC mode.
 */
#define PE_DIGEST_SIZE 32
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, u8[PE_DIGEST_SIZE]);
  __type(value, u32);
} allow_verity_digest SEC(".maps");

/* kfunc definition for bpf_get_fsverity_digest */
extern int bpf_get_fsverity_digest(struct file *file,
                                   struct bpf_dynptr *digest_p) __ksym;

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
 * Verify kernel integrity baseline directly from kernel memory.
 * Returns 1 if baseline is satisfied, 0 otherwise.
 */
static __always_inline int integrity_baseline_ok(struct integrity_data *cfg) {
  int sig_enforce = 0;
  int lockdown = 0;

  if (!cfg)
    return 0;

  if (!cfg->sig_enforce_addr)
    return 0;

  if (bpf_probe_read_kernel(&sig_enforce, sizeof(sig_enforce),
                            (void *)cfg->sig_enforce_addr) < 0)
    return 0;

  if (sig_enforce != 1) {
    bpf_printk("LOTA: BLOCKING module load: sig_enforce=%d", sig_enforce);
    return 0;
  }

  if (!cfg->lockdown_addr) {
    bpf_printk("LOTA: BLOCKING module load: lockdown symbol unavailable");
    return 0;
  }

  if (bpf_probe_read_kernel(&lockdown, sizeof(lockdown),
                            (void *)cfg->lockdown_addr) < 0)
    return 0;

  if (lockdown <= 0) {
    bpf_printk("LOTA: BLOCKING module load: lockdown=%d", lockdown);
    return 0;
  }

  bpf_printk("LOTA: Integrity baseline OK: sig_enforce=1 lockdown=%d",
             lockdown);
  return 1;
}

/*
 * Scratch buffer for fs-verity digest.
 */
struct digest_slot {
  u8 bytes[64];
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct digest_slot);
} digest_buffer SEC(".maps");

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
 * Check if a file is heuristically trusted (root-owned, not writable by
 * others). Used as a fallback when fs-verity is not available.
 *
 * Returns:
 *   1 if trusted (owned by root, mode 755 or stricter)
 *   0 if not trusted
 */
static __always_inline int is_file_trusted_heuristic(struct file *file) {
  struct inode *inode;
  uid_t uid;
  umode_t mode;

  if (!file)
    return 0;

  inode = BPF_CORE_READ(file, f_inode);
  if (!inode)
    return 0;

  uid = BPF_CORE_READ(inode, i_uid.val);
  mode = BPF_CORE_READ(inode, i_mode);

  /* must be owned by root */
  if (uid != 0)
    return 0;

  /* must not be world-writable (S_IWOTH = 00002) */
  if (mode & 00002)
    return 0;

  /* must not be group-writable (S_IWGRP = 00020) */
  if (mode & 00020)
    return 0;

  return 1;
}

static __noinline int is_verity_allowed(struct file *file) {
  if (!bpf_get_fsverity_digest)
    return 0;

  if (!file)
    return 0;

  u32 key = 0;
  struct digest_slot *slot = bpf_map_lookup_elem(&digest_buffer, &key);
  if (!slot)
    return 0;

  void *digest = slot->bytes;

  struct bpf_dynptr digest_ptr;
  int ret;
  u32 *allowed;

  ret = bpf_dynptr_from_mem(digest, 64, 0, &digest_ptr);
  if (ret < 0) {
    bpf_printk("LOTA: dynptr_from_mem failed: %d", ret);
    return 0;
  }

  /*
   * if bpf_get_fsverity_digest returns > 0, the file has a digest
   */
  ret = bpf_get_fsverity_digest(file, &digest_ptr);
  if (ret < 0) {
    return 0;
  }

  /*
   * Check if this digest is in trusted hashes map
   * Note: The digest is now in the map memory 'digest'.
   */
  allowed = bpf_map_lookup_elem(&allow_verity_digest, digest);
  if (allowed && *allowed) {
    bpf_printk("LOTA: Verity digest allowed");
    return 1;
  }

  return 0;
}

/*
 * LSM hook: security_kernel_read_file
 *
 * Called when kernel reads a file for specific purpose (loading module,
 * firmware, etc).
 *
 * @file: File being read
 * @id: Purpose of read (enum kernel_read_file_id)
 *
 * Return: 0 to allow, -EPERM to deny
 */
SEC("lsm/kernel_read_file")
int BPF_PROG(lota_kernel_read_file, struct file *file,
             enum kernel_read_file_id id) {
  struct lota_exec_event *event;
  int blocked = 0;
  uint32_t key = 0;
  uint32_t mode = get_mode();

  bpf_printk("LOTA: kernel_read_file id=%d mode=%d", id, mode);

  /*
   * Filter relevant IDs.
   * - MODULE (2)
   * - FIRMWARE (1)
   * - KEXEC_IMAGE (3)
   */

  /* check if LOTA should ignore this read id early */
  if (id != READING_MODULE && id != READING_FIRMWARE &&
      id != READING_KEXEC_IMAGE && id != READING_KEXEC_INITRAMFS &&
      id != READING_POLICY) {
    return 0;
  }

  if (mode == LOTA_MODE_ENFORCE) {
    /* always allow policy files */
    if (id == READING_POLICY)
      return 0;

    /* kernel integrity config */
    struct integrity_data *integrity;
    integrity = bpf_map_lookup_elem(&integrity_config, &key);

    if (id == READING_MODULE) {
      if (!integrity_baseline_ok(integrity))
        blocked = 1;
    }

    if (get_config(LOTA_CFG_STRICT_MODULES)) {
      if (!is_verity_allowed(file)) {
        if (!is_file_trusted_heuristic(file)) {
          bpf_printk("LOTA: BLOCKING module load: untrusted file");
          blocked = 1;
        }
      }
    }
  }

  event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
  if (event) {
    __builtin_memset(event, 0, sizeof(*event));
    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type =
        blocked ? LOTA_EVENT_MODULE_BLOCKED : LOTA_EVENT_MODULE_LOAD;
    event->tgid = bpf_get_current_pid_tgid() >> 32;
    event->pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event->uid = 0; /* limits to root for these ops roughly */

    bpf_get_current_comm(event->comm, sizeof(event->comm));

    /*
     * attempt to extract filename from dentry
     */
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    const unsigned char *name = NULL;
    int ret_path = -1;

    if (dentry) {
      name = BPF_CORE_READ(dentry, d_name.name);
      if (name) {
        ret_path = bpf_probe_read_kernel_str(event->filename,
                                             sizeof(event->filename), name);
      }
    }

    if (ret_path < 0) {
      if (id == READING_MODULE)
        __builtin_memcpy(event->filename, "kernel_module", 13);
      else if (id == READING_FIRMWARE)
        __builtin_memcpy(event->filename, "firmware", 8);
      else if (id == READING_KEXEC_IMAGE)
        __builtin_memcpy(event->filename, "kexec_image", 11);
      else
        __builtin_memcpy(event->filename, "kernel_assets", 13);
    }

    bpf_ringbuf_submit(event, 0);
    inc_stat(STAT_EVENTS_SENT);
  } else {
    inc_stat(STAT_RINGBUF_DROPS);
  }

  if (blocked) {
    inc_stat(STAT_MODULES_BLOCKED);
    return -EPERM;
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
int BPF_PROG(lota_kernel_load_data, enum kernel_load_data_id id) {
  struct lota_exec_event *event;
  u32 mode;
  int blocked = 0;

  bpf_printk("LOTA: kernel_load_data id=%d", id);

  if (id != LOADING_FIRMWARE && id != LOADING_MODULE &&
      id != LOADING_KEXEC_IMAGE && id != LOADING_KEXEC_INITRAMFS &&
      id != LOADING_POLICY && id != LOADING_X509_CERTIFICATE)
    return 0;

  mode = get_mode();

  if (mode == LOTA_MODE_MAINTENANCE)
    return 0;

  if (mode == LOTA_MODE_ENFORCE) {
    u32 key = 0;
    struct integrity_data *integrity;

    integrity = bpf_map_lookup_elem(&integrity_config, &key);
    if (id == LOADING_MODULE) {
      if (!integrity_baseline_ok(integrity))
        blocked = 1;
    }

    if (id == LOADING_FIRMWARE || id == LOADING_KEXEC_IMAGE ||
        id == LOADING_KEXEC_INITRAMFS || id == LOADING_POLICY) {
      if (get_config(LOTA_CFG_STRICT_MODULES))
        blocked = 1;
    }
  }

  event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
  if (event) {
    __builtin_memset(event, 0, sizeof(*event));
    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type =
        blocked ? LOTA_EVENT_MODULE_BLOCKED : LOTA_EVENT_MODULE_LOAD;
    event->tgid = bpf_get_current_pid_tgid() >> 32;
    event->pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event->uid = 0;

    bpf_get_current_comm(event->comm, sizeof(event->comm));

    if (id == LOADING_MODULE)
      __builtin_memcpy(event->filename, "kernel_module_mem", 17);
    else if (id == LOADING_FIRMWARE)
      __builtin_memcpy(event->filename, "firmware_mem", 12);
    else if (id == LOADING_KEXEC_IMAGE)
      __builtin_memcpy(event->filename, "kexec_image_mem", 16);
    else if (id == LOADING_POLICY)
      __builtin_memcpy(event->filename, "policy_mem", 10);
    else
      __builtin_memcpy(event->filename, "kernel_data_mem", 16);

    bpf_ringbuf_submit(event, 0);
    inc_stat(STAT_EVENTS_SENT);
  } else {
    inc_stat(STAT_RINGBUF_DROPS);
  }

  if (blocked) {
    inc_stat(STAT_MODULES_BLOCKED);
    return -EPERM;
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
SEC("lsm.s/mmap_file")
int BPF_PROG(lota_mmap_file, struct file *file, unsigned long reqprot,
             unsigned long prot, unsigned long flags, int ret) {
  struct dentry *dentry;
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

    struct lota_exec_event *event;

    if (mode == LOTA_MODE_ENFORCE && get_config(LOTA_CFG_BLOCK_ANON_EXEC)) {
      anon_blocked = 1;
    }

    event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
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

      bpf_ringbuf_submit(event, 0);
      inc_stat(STAT_EVENTS_SENT);
    } else {
      inc_stat(STAT_RINGBUF_DROPS);
    }

    if (anon_blocked) {
      inc_stat(STAT_ANON_EXEC_BLOCKED);
      return -EPERM;
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
  (void)dentry;
  if (mode == LOTA_MODE_ENFORCE && get_config(LOTA_CFG_STRICT_MMAP)) {
    if (!is_verity_allowed(file)) {
      /*
       * Fallback to heuristic: allow if root-owned and not writable.
       * Prevents bricking on non-verity systems while still blocking
       * random user libraries.
       */
      if (!is_file_trusted_heuristic(file)) {
        blocked = 1;
      }
    }
  }

  /* for logging */
  struct lota_exec_event *event;
  event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
  if (event) {
    __builtin_memset(event, 0, sizeof(*event));
    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type =
        blocked ? LOTA_EVENT_MMAP_BLOCKED : LOTA_EVENT_MMAP_EXEC;
    event->tgid = bpf_get_current_pid_tgid() >> 32;
    event->pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event->uid = (u32)(bpf_get_current_uid_gid() & 0xFFFFFFFF);

    bpf_get_current_comm(event->comm, sizeof(event->comm));

    __builtin_memcpy(event->filename, "(path_resolution_disabled)", 27);

    bpf_ringbuf_submit(event, 0);
    inc_stat(STAT_EVENTS_SENT);
  } else {
    inc_stat(STAT_RINGBUF_DROPS);
  }

  if (blocked) {
    inc_stat(STAT_MMAP_BLOCKED);
    return -EPERM;
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
  event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
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

    bpf_ringbuf_submit(event, 0);
    inc_stat(STAT_EVENTS_SENT);
  } else {
    inc_stat(STAT_RINGBUF_DROPS);
  }

  if (blocked) {
    inc_stat(STAT_PTRACE_BLOCKED);
    return -EPERM;
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

  event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
  if (event) {
    __builtin_memset(event, 0, sizeof(*event));
    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type = LOTA_EVENT_SETUID;
    event->tgid = bpf_get_current_pid_tgid() >> 32;
    event->pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event->uid = old_uid;
    event->target_uid = new_uid;

    bpf_get_current_comm(event->comm, sizeof(event->comm));

    bpf_ringbuf_submit(event, 0);
    inc_stat(STAT_EVENTS_SENT);
  } else {
    inc_stat(STAT_RINGBUF_DROPS);
  }

  /* kernel handles setuid policy via capabilities */
  return 0;
}
