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

/* signal numbers */
#ifndef SIGTERM
#define SIGTERM 15
#endif
#ifndef SIGKILL
#define SIGKILL 9
#endif
#ifndef SIGSTOP
#define SIGSTOP 19
#endif

/* siginfo.si_code value for kernel-generated signals */
#ifndef SI_KERNEL
#define SI_KERNEL 0x80
#endif

/*
 * Executable page protection bit.
 */
#define LOTA_PROT_EXEC 0x4

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
#define STAT_BPF_SYSCALL_BLOCKED 13

/*
 * Authorized LOTA agent identity allowed to perform bpf() syscalls
 * while BPF lock is enabled.
 *
 * Key 0 -> (TGID + start_time_ticks).
 */
struct lota_identity_entry {
  u32 tgid;
  u32 pad;
  u64 start_time_ticks;
};

/*
 * Runtime lota-agent identity configured from user-space.
 *
 * Key 0 -> (TGID + start_time_ticks).
 */
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct lota_identity_entry);
} lota_agent_identity SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct lota_identity_entry);
} bpf_admin_tgid SEC(".maps");

/*
 * Protected process map.
 * Key: TGID (u32) ("process ID" as seen from user-space)
 * Value: identity binding for that TGID instance.
 *
 * start_time_ticks is /proc/<tgid>/stat field 22 (clock ticks since boot).
 * Binding TGID with start time prevents trust leakage via PID reuse.
 */
struct protected_pid_entry {
  u64 start_time_ticks;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, LOTA_MAX_PROTECTED_PIDS);
  __type(key, u32);
  __type(value, struct protected_pid_entry);
} protected_pids SEC(".maps");

/*
 * Trusted shared libraries allowlist.
 *
 * Keys are inode identities (device + inode) so enforcement does not rely on
 * reconstructing full paths in BPF context.
 */
struct trusted_lib_key {
  u64 dev;
  u64 ino;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, LOTA_MAX_TRUSTED_LIBS);
  __type(key, struct trusted_lib_key);
  __type(value, u32);
} trusted_libs SEC(".maps");

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

  return 1;
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
#define LOTA_USER_HZ 100ULL
#define LOTA_NSEC_PER_SEC 1000000000ULL

static __always_inline u64 get_task_start_ticks(struct task_struct *task) {
  u64 start_ns;

  if (!task)
    return 0;

  if (bpf_core_field_exists(task->start_boottime))
    start_ns = BPF_CORE_READ(task, start_boottime);
  else
    start_ns = BPF_CORE_READ(task, start_time);

  return start_ns / (LOTA_NSEC_PER_SEC / LOTA_USER_HZ);
}

static __always_inline int is_protected_task(struct task_struct *task) {
  u32 tgid;
  u64 task_start_ticks;
  struct protected_pid_entry *entry;

  if (!task)
    return 0;

  tgid = BPF_CORE_READ(task, tgid);
  entry = bpf_map_lookup_elem(&protected_pids, &tgid);
  if (!entry)
    return 0;

  struct task_struct *leader = BPF_CORE_READ(task, group_leader);
  if (leader)
    task_start_ticks = get_task_start_ticks(leader);
  else
    task_start_ticks = get_task_start_ticks(task);
  return task_start_ticks && entry->start_time_ticks == task_start_ticks;
}

static __always_inline int is_bpf_admin_task(void) {
  struct task_struct *task;
  struct task_struct *leader;
  u32 key = 0;
  u32 current_tgid = (u32)(bpf_get_current_pid_tgid() >> 32);
  struct lota_identity_entry *admin =
      bpf_map_lookup_elem(&bpf_admin_tgid, &key);
  u64 current_start_ticks;

  if (!admin || admin->tgid == 0 || admin->start_time_ticks == 0)
    return 0;

  if (admin->tgid != current_tgid)
    return 0;

  task = (struct task_struct *)bpf_get_current_task_btf();
  if (!task)
    return 0;

  leader = BPF_CORE_READ(task, group_leader);
  if (leader)
    current_start_ticks = get_task_start_ticks(leader);
  else
    current_start_ticks = get_task_start_ticks(task);

  return current_start_ticks && current_start_ticks == admin->start_time_ticks;
}

static __always_inline int is_lota_agent_task(struct task_struct *task) {
  u32 key = 0;
  u32 task_tgid;
  struct task_struct *leader;
  u64 task_start_ticks;
  struct lota_identity_entry *agent;

  if (!task)
    return 0;

  agent = bpf_map_lookup_elem(&lota_agent_identity, &key);
  if (!agent || agent->tgid == 0 || agent->start_time_ticks == 0)
    return 0;

  task_tgid = BPF_CORE_READ(task, tgid);
  if (task_tgid != agent->tgid)
    return 0;

  leader = BPF_CORE_READ(task, group_leader);
  if (leader)
    task_start_ticks = get_task_start_ticks(leader);
  else
    task_start_ticks = get_task_start_ticks(task);

  return task_start_ticks && task_start_ticks == agent->start_time_ticks;
}

/*
 * Returns 1 when current task runs in a non-initial user namespace.
 *
 * In ENFORCE mode LOTA treat user namespaces as untrusted for executable
 * mappings and module-loading paths to avoid UID-based trust confusion.
 */
static __always_inline int in_non_init_userns(void) {
  struct task_struct *task;
  const struct cred *cred;
  struct user_namespace *user_ns;
  u32 level;

  task = (struct task_struct *)bpf_get_current_task_btf();
  if (!task)
    return 0;

  cred = BPF_CORE_READ(task, cred);
  if (!cred)
    return 0;

  user_ns = BPF_CORE_READ(cred, user_ns);
  if (!user_ns)
    return 0;

  level = BPF_CORE_READ(user_ns, level);
  return level > 0;
}

static __noinline int is_verity_allowed(struct file *file) {
  if (!bpf_get_fsverity_digest)
    return 0;

  if (!file)
    return 0;

  u8 digest[PE_DIGEST_SIZE];
  __builtin_memset(digest, 0, sizeof(digest));

  struct bpf_dynptr digest_ptr;
  int ret;
  u32 *allowed;

  ret = bpf_dynptr_from_mem(digest, sizeof(digest), 0, &digest_ptr);
  if (ret < 0)
    return 0;

  ret = bpf_get_fsverity_digest(file, &digest_ptr);
  if (ret != PE_DIGEST_SIZE)
    return 0;

  allowed = bpf_map_lookup_elem(&allow_verity_digest, digest);
  return (allowed && *allowed) ? 1 : 0;
}

static __always_inline int is_trusted_lib(struct file *file) {
  struct inode *inode;
  struct super_block *sb;
  struct trusted_lib_key key = {};
  u32 *allowed;

  if (!file)
    return 0;

  inode = BPF_CORE_READ(file, f_inode);
  if (!inode)
    return 0;

  sb = BPF_CORE_READ(inode, i_sb);
  if (!sb)
    return 0;

  key.dev = (u64)BPF_CORE_READ(sb, s_dev);
  key.ino = (u64)BPF_CORE_READ(inode, i_ino);
  if (key.dev == 0 || key.ino == 0)
    return 0;

  allowed = bpf_map_lookup_elem(&trusted_libs, &key);
  return (allowed && *allowed) ? 1 : 0;
}

/* =====================================================================
 * LSM hook: bprm_check_security
 *
 * Called during execve() before the new image is committed.
 *
 * This is the place to enforce integrity: if STRICT_EXEC
 * is enabled in ENFORCE mode, only fs-verity-allowed files can be executed.
 * ====================================================================== */
SEC("lsm/bprm_check_security")
int BPF_PROG(lota_bprm_check_security, struct linux_binprm *bprm) {
  struct file *file;
  struct lota_exec_event *event;
  u32 mode;
  int blocked = 0;
  u8 digest[PE_DIGEST_SIZE];
  int have_digest = 0;

  inc_stat(STAT_TOTAL_EXECS);

  mode = get_mode();
  if (mode == LOTA_MODE_MAINTENANCE)
    return 0;

  file = BPF_CORE_READ(bprm, file);

  /* fetch fs-verity digest once (if supported) and reuse it below */
  if (bpf_get_fsverity_digest && file) {
    __builtin_memset(digest, 0, sizeof(digest));
    struct bpf_dynptr digest_ptr;
    int ret = bpf_dynptr_from_mem(digest, sizeof(digest), 0, &digest_ptr);
    if (ret == 0) {
      /*
       * Note on TOCTOU:
       * - bprm->file is an already-open file; path renames after open(2) do
       *   not change the inode behind this file descriptor.
       * - fs-verity is enforced by the kernel: enabling verity makes the inode
       *   content immutable and the helper returns an error if verity is not
       *   enabled for this file.
       */
      ret = bpf_get_fsverity_digest(file, &digest_ptr);
      if (ret == PE_DIGEST_SIZE)
        have_digest = 1;
    }
  }

  if (mode == LOTA_MODE_ENFORCE && get_config(LOTA_CFG_STRICT_EXEC)) {
    if (!have_digest) {
      blocked = 1;
    } else {
      u8 *allowed = bpf_map_lookup_elem(&allow_verity_digest, digest);
      if (!(allowed && *allowed))
        blocked = 1;
    }
  }

  event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
  if (event) {
    __builtin_memset(event, 0, sizeof(*event));
    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type = blocked ? LOTA_EVENT_EXEC_BLOCKED : LOTA_EVENT_EXEC;
    event->tgid = bpf_get_current_pid_tgid() >> 32;
    event->pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    event->uid = (u32)(bpf_get_current_uid_gid() & 0xFFFFFFFF);
    event->gid = (u32)(bpf_get_current_uid_gid() >> 32);

    bpf_get_current_comm(event->comm, sizeof(event->comm));

    /* best-effort filename from binprm; may be relative */
    {
      const char *fn = BPF_CORE_READ(bprm, filename);
      if (fn)
        bpf_probe_read_kernel_str(event->filename, sizeof(event->filename), fn);
    }

    /* if fs-verity digest is present, include it as event->hash (32 bytes) */
    if (have_digest)
      __builtin_memcpy(event->hash, digest, PE_DIGEST_SIZE);

    bpf_ringbuf_submit(event, 0);
    inc_stat(STAT_EVENTS_SENT);
  } else {
    inc_stat(STAT_RINGBUF_DROPS);
  }

  if (blocked) {
    inc_stat(STAT_EXEC_BLOCKED);
    return -EPERM;
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
    if (id == READING_KEXEC_IMAGE || id == READING_KEXEC_INITRAMFS)
      blocked = 1;

    if (in_non_init_userns())
      blocked = 1;

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
        bpf_printk("LOTA: BLOCKING module load: no allowed fs-verity digest");
        blocked = 1;
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
    if (id == LOADING_KEXEC_IMAGE || id == LOADING_KEXEC_INITRAMFS)
      blocked = 1;

    if (in_non_init_userns())
      blocked = 1;

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
  u32 mode;
  int blocked = 0;

  /* dont interfere with previous hook denial */
  if (ret != 0)
    return ret;

  /*
   * only care about executable mappings.
   */
  if (!(prot & LOTA_PROT_EXEC))
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

  /*
   * In ENFORCE mode with strict mmap enabled, block executable mmaps
   * from untrusted sources.
   */
  if (mode == LOTA_MODE_ENFORCE && get_config(LOTA_CFG_STRICT_MMAP)) {
    if (!is_verity_allowed(file) && !is_trusted_lib(file)) {
      blocked = 1;
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
      __builtin_memcpy(event->filename, "(path_resolution_disabled)", 27);
    }

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
 * LSM hook: security_file_mprotect
 *
 * Called when protection of existing VMA is changed (mprotect).
 *
 * This closes W^X bypass where attacker maps RW first and later upgrades
 * mapping to executable via mprotect(PROT_EXEC).
 *
 * @vma: Target VMA
 * @reqprot: Requested protection flags
 * @prot: Effective protection flags
 *
 * Return: 0 to allow, -EPERM to deny
 * ====================================================================== */
SEC("lsm/file_mprotect")
int BPF_PROG(lota_file_mprotect, struct vm_area_struct *vma,
             unsigned long reqprot, unsigned long prot, int ret) {
  struct file *file;
  struct lota_exec_event *event;
  u32 mode;
  int blocked = 0;

  (void)reqprot;

  if (ret != 0)
    return ret;

  /* only care when resulting mapping is executable */
  if (!(prot & LOTA_PROT_EXEC))
    return 0;

  mode = get_mode();
  if (mode == LOTA_MODE_MAINTENANCE)
    return 0;

  file = BPF_CORE_READ(vma, vm_file);

  if (!file) {
    int anon_blocked = 0;

    inc_stat(STAT_ANON_EXEC);

    if (mode == LOTA_MODE_ENFORCE && get_config(LOTA_CFG_BLOCK_ANON_EXEC))
      anon_blocked = 1;

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
      __builtin_memcpy(event->filename, "(anon-mprotect-exec)", 20);

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

  if (mode == LOTA_MODE_ENFORCE && get_config(LOTA_CFG_STRICT_MMAP)) {
    if (!is_verity_allowed(file) && !is_trusted_lib(file)) {
      blocked = 1;
    }
  }

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
      __builtin_memcpy(event->filename, "(mprotect-path_resolution_disabled)",
                       35);
    }

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

  if (is_lota_agent_task(child)) {
    blocked = 1;
  }

  /*
   * In ENFORCE mode, block ptrace on protected PIDs.
   * Protected PIDs are managed by user-space.
   *
   * Also block if LOTA_CFG_BLOCK_PTRACE is set.
   */
  if (!blocked && lota_mode == LOTA_MODE_ENFORCE) {
    if (is_protected_task(child)) {
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
 * LSM hook: task_kill
 *
 * Blocks selected signal delivery to lota-agent from foreign tasks.
 *
 * SECURITY: Only block signals that would terminate/stop the daemon.
 * Allow signals from PID 1 (systemd/init) and kernel-generated signals.
 * ====================================================================== */
SEC("lsm/task_kill")
int BPF_PROG(lota_task_kill, struct task_struct *p, struct kernel_siginfo *info,
             int sig, const struct cred *cred) {
  u32 sender_tgid;
  struct lota_exec_event *event;

  (void)cred;

  if (!is_lota_agent_task(p))
    return 0;

  sender_tgid = (u32)(bpf_get_current_pid_tgid() >> 32);
  {
    struct task_struct *current =
        (struct task_struct *)bpf_get_current_task_btf();
    if (is_lota_agent_task(current))
      return 0;
  }

  /* allow init/systemd to manage the daemon */
  if (sender_tgid == 1)
    return 0;

  /* allow benign signals; only block termination/stop signals */
  if (sig != SIGKILL && sig != SIGSTOP && sig != SIGTERM)
    return 0;

  /* allow kernel-generated signals */
  if (!info)
    return 0;
  {
    int si_code = BPF_CORE_READ(info, si_code);
    if (si_code == SI_KERNEL)
      return 0;
  }

  /* audit trail for blocked kill attempts */
  event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
  if (event) {
    __builtin_memset(event, 0, sizeof(*event));
    event->timestamp_ns = bpf_ktime_get_ns();
    event->event_type = LOTA_EVENT_KILL_BLOCKED;
    event->tgid = sender_tgid;
    event->pid = (u32)(bpf_get_current_pid_tgid() & 0xFFFFFFFF);
    event->uid = (u32)(bpf_get_current_uid_gid() & 0xFFFFFFFF);
    event->target_pid = BPF_CORE_READ(p, tgid);

    bpf_get_current_comm(event->comm, sizeof(event->comm));
    __builtin_memcpy(event->filename, "(kill)", 6);

    bpf_ringbuf_submit(event, 0);
    inc_stat(STAT_EVENTS_SENT);
  } else {
    inc_stat(STAT_RINGBUF_DROPS);
  }

  return -EPERM;
}

/* ======================================================================
 * LSM hook: task_free
 *
 * Called when task exits and resources are being freed.
 * Removes stale protected PID entries to reduce residency window and
 * prevent stale metadata accumulation.
 * ====================================================================== */
SEC("lsm/task_free")
int BPF_PROG(lota_task_free, struct task_struct *task) {
  u32 pid;
  u32 tgid;

  if (!task)
    return 0;

  pid = BPF_CORE_READ(task, pid);
  tgid = BPF_CORE_READ(task, tgid);

  if (pid != tgid)
    return 0;

  bpf_map_delete_elem(&protected_pids, &tgid);
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

/* ======================================================================
 * LSM hook: bpf
 *
 * Called on bpf() syscall. In ENFORCE mode with LOTA_CFG_LOCK_BPF enabled,
 * deny destructive bpf() operations from processes other than the authorized
 * agent.
 *
 * This prevents root-level attackers from detaching/overwriting LOTA links
 * via bpftool while runtime protection is active.
 * ====================================================================== */
SEC("lsm/bpf")
int BPF_PROG(lota_bpf, int cmd, union bpf_attr *attr, unsigned int size,
             int ret) {
  u32 mode;
  int deny = 0;

  (void)size;

  /*
   * Unlike most of other LSM programs, the in-kernel LSM hook prototype
   * for bpf() does not include a 'ret' argument.
   *
   * The 'ret' parameter here is the BPF trampoline's current return value and
   * exists to support chaining multiple BPF LSM programs attached to the same
   * hook. If a previous program already denied, do not override it.
   */
  if (ret != 0)
    return ret;

  if (!attr)
    return 0;

  mode = get_mode();
  if (mode != LOTA_MODE_ENFORCE)
    return 0;

  if (!get_config(LOTA_CFG_LOCK_BPF))
    return 0;

  if (is_bpf_admin_task())
    return 0;

  switch (cmd) {
  case BPF_PROG_LOAD:
  case BPF_LINK_CREATE:
  case BPF_LINK_UPDATE:
  case BPF_MAP_CREATE:
  case BPF_PROG_DETACH:
  case BPF_LINK_DETACH:
  case BPF_MAP_UPDATE_ELEM:
  case BPF_MAP_DELETE_ELEM:
    deny = 1;
    break;
  default:
    break;
  }

  if (!deny)
    return 0;

  inc_stat(STAT_BPF_SYSCALL_BLOCKED);
  return -EPERM;
}
