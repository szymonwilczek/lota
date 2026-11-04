/* SPDX-License-Identifier: GPL-2.0-only */
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
 *   - Bind-mount overwrite on trusted library paths, on both mount APIs
 *     (security_sb_mount, security_move_mount)
 *   - In-place write/truncate on trusted library inodes (security_file_open)
 *   - Direct kernel memory device access (/dev/mem, /dev/kmem, /dev/port)
 *   - Debugger attachment (security_ptrace_access_check)
 *   - Cross-process memory access fallback (__ptrace_may_access)
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
#include "lota_devt.h"
#include "lota_event_budget.h"

char LICENSE[] SEC("license") = "GPL";

#ifndef EPERM
#define EPERM 1
#endif

#ifndef ENOMEM
#define ENOMEM 12
#endif

#ifndef EEXIST
#define EEXIST 17
#endif

#ifndef EINVAL
#define EINVAL 22
#endif

#ifndef AF_UNIX
#define AF_UNIX 1
#endif

#ifndef FMODE_WRITE
#define FMODE_WRITE ((fmode_t)(1U << 1))
#endif

#ifndef BINPRM_FLAGS_PATH_INACCESSIBLE
#define BINPRM_FLAGS_PATH_INACCESSIBLE (1U << 2)
#endif
/* siginfo.si_code value for kernel-generated signals */
#ifndef SI_KERNEL
#define SI_KERNEL 0x80
#endif

#ifndef MS_BIND
#define MS_BIND 4096
#endif

#ifndef LOTA_O_ACCMODE
#define LOTA_O_ACCMODE 00000003
#endif
#ifndef LOTA_O_WRONLY
#define LOTA_O_WRONLY 00000001
#endif
#ifndef LOTA_O_RDWR
#define LOTA_O_RDWR 00000002
#endif
#ifndef LOTA_O_TRUNC
#define LOTA_O_TRUNC 00001000
#endif

#ifndef S_IFMT
#define S_IFMT 00170000
#endif
#ifndef S_IFCHR
#define S_IFCHR 0020000
#endif

#ifndef VM_WRITE
#define VM_WRITE 0x00000002
#endif
#ifndef VM_MAYWRITE
#define VM_MAYWRITE 0x00000020
#endif

/*
 * Executable page protection bit.
 */
#define LOTA_PROT_EXEC 0x4
#define LOTA_PROT_WRITE 0x2

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
	__uint(max_entries, 24);
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
} integrity_cfg SEC(".maps");

#define STAT_TOTAL_EXECS 0
#define STAT_EVENTS_SENT 1
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
#define STAT_ALLOW_EVENTS_SUPPRESSED 14
#define STAT_BLOCKED_EVENTS_SUPPRESSED 15
#define STAT_MOUNTS_BLOCKED 16
#define STAT_KILL_GUARD_BLOCKED 17
#define STAT_EVENTS_YIELDED 18
#define STAT_KILL_PROBES 19 /* permitted sig 0, counted, not journalled */
#define STAT_MAPPED_WRITE_BLOCKED 20 /* write refused to a pinned library */
#define STAT_MAPPED_PIN_REFUSED 21 /* mapping not pinned, so not measured */
#define STAT_EXEC_HISTORY_LOST \
	22 /* exec mapping of a protected task unrecorded */
#define STAT_INSTANCE_PEERS_LOST \
	23 /* reach into an instance socket unrecorded */

/*
 * Rate-limit window per enum lota_event_type (see lota_event_budget.h):
 * a class-wide window would let one flooding type silence the rest of its class.
 */
struct event_budget_window {
	u64 window_start_ns;
	u32 emitted;
	u32 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, LOTA_EVENT_TYPE_COUNT);
	__type(key, u32);
	__type(value, struct event_budget_window);
} event_budget SEC(".maps");

struct lota_task_auth_entry {
	u32 flags;
	u32 pad;
};

#define LOTA_TASK_AUTH_ADMIN (1U << 0)
#define LOTA_TASK_AUTH_AGENT (1U << 1)

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct lota_task_auth_entry);
} lota_task_auth SEC(".maps");

/*
 * Protection a task took from the protected process that created it, named
 * by the process registered through protected_pids at the root of the tree.
 * The entry lives and dies with the task, so it needs no start-time binding
 * against TGID reuse and has no capacity for a fork to run out of.
 */
struct lota_instance_entry {
	u64 root_start_ticks;
	u32 root_tgid;
	u32 pad;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct lota_instance_entry);
} lota_instance SEC(".maps");

/*
 * Scratch holds what the kernel writes and the key built from it.
 * The kernel fills a struct fsverity_digest -- header, then digest
 * -- so the raw buffer is not itself a key.
 */
struct lota_verity_scratch {
	__u8 buf[LOTA_FSVERITY_DIGEST_BUF_SIZE];
	struct lota_verity_digest_key key;
};

/*
 * Per-CPU scratch map for the fs-verity digest key passed to
 * bpf_dynptr_from_mem(). The kernel BPF verifier on 6.6+ refuses
 * PTR_TO_STACK as the data argument of bpf_dynptr_from_mem and
 * requires PTR_TO_MAP_VALUE / PTR_TO_BUF
 *
 * bpf_map_lookup_elem returns PTR_TO_MAP_VALUE which dynptr accepts,
 * and per-CPU scoping means concurrent exec hook invocations on
 * different CPUs do not race on the same buffer
 */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct lota_verity_scratch);
} verity_scratch SEC(".maps");

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
 * Files whose write kills the agent past security_task_kill:
 * cgroup.kill of its cgroup and every ancestor.
 * Key: superblock dev + inode
 * Value: LOTA_GUARD_*
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, LOTA_MAX_GUARDED_FILES);
	__type(key, struct trusted_lib_key);
	__type(value, u32);
} guarded_files SEC(".maps");

/*
 * Cgroup ids of the cgroup the agent was moved to and of its ancestors, by
 * level; zero past its depth and before any move. guarded_files names the
 * cgroup the agent started in, this one where it went. Only BPF writes it.
 */
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, LOTA_AGENT_CGROUP_DEPTH);
	__type(key, u32);
	__type(value, u64);
} agent_cgroups SEC(".maps");

/*
 * Libraries the agent pinned for a protected process; lota_file_open refuses
 * their write opens, as the kernel does for a running executable.
 * Renaming over one works. Only the agent writes it. Name fits 16 bytes.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, LOTA_MAX_MAPPED_EXEC_GUARDS);
	__type(key, struct trusted_lib_key);
	__type(value, u32);
} mapped_exec SEC(".maps");

/*
 * Size and ctime of every executable mapping, any task: protection is asked
 * for after the loader maps. LRU: a lost record costs only a measurement.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, LOTA_MAX_MAPPED_SEEN);
	__type(key, struct trusted_lib_key);
	__type(value, struct lota_mapped_seen);
} mapped_seen SEC(".maps");

/* see struct lota_exec_history_key; not LRU, a loss is counted instead */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, LOTA_MAX_EXEC_HISTORY);
	__type(key, struct lota_exec_history_key);
	__type(value, struct lota_exec_history_val);
} exec_history SEC(".maps");

/*
 * The instance a unix socket belongs to: set when a process of the
 * instance creates, binds or listens on it, never cleared.
 */
struct lota_sock_owner {
	struct lota_instance_entry id;
	u32 tgid;
	u32 pad;
	char comm[LOTA_MAX_COMM_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_SK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct lota_sock_owner);
} lota_sock_owner SEC(".maps");

/* see struct lota_instance_peer_key; not LRU, a loss is counted instead */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, LOTA_MAX_INSTANCE_PEERS);
	__type(key, struct lota_instance_peer_key);
	__type(value, struct lota_instance_peer_val);
} instance_peers SEC(".maps");

/*
 * fs-verity digest allowlist.
 * Key: digest length + digest bytes (SHA-512 only)
 * Value: 1 = allowed
 *
 * Only files with a verified fs-verity merkle root matching an entry here are
 * allowed to execute in STRICT_EXEC mode.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct lota_verity_digest_key);
	__type(value, u32);
} allow_verity SEC(".maps");

/*
 * Kernel content hashes the agent asked for, keyed by thread id.
 * bpf_ima_file_hash() needs the struct file, so the agent marks its slot
 * ASKED, opens the file and reads the answer back.
 * Not keyed by inode: on a filesystem with a device per subvolume,
 * s_dev differs from stat(2)'s.
 */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, LOTA_MAX_EXE_HASH_SLOTS);
	__type(key, u32);
	__type(value, struct lota_exe_hash_slot);
} exe_hash_slots SEC(".maps");

/* RCU read section for task walks in sleepable hooks */
extern void bpf_rcu_read_lock(void) __ksym;
extern void bpf_rcu_read_unlock(void) __ksym;

/* a referenced task by global pid, for a hook that only has a struct pid */
extern struct task_struct *bpf_task_from_pid(s32 pid) __ksym;
extern void bpf_task_release(struct task_struct *p) __ksym;

/* kfunc definition for bpf_get_fsverity_digest */
extern int bpf_get_fsverity_digest(struct file *file,
				   struct bpf_dynptr *digest_p) __ksym;

/*
 * Increment a statistics counter
 */
static __always_inline void inc_stat(u32 idx)
{
	u64 *val = bpf_map_lookup_elem(&stats, &idx);
	if (val)
		__sync_fetch_and_add(val, 1);
}

/*
 * Get current enforcement mode
 */
static __always_inline u32 get_mode(void)
{
	u32 key = LOTA_CFG_MODE;
	u32 *mode = bpf_map_lookup_elem(&lota_config, &key);
	return mode ? *mode : LOTA_MODE_ENFORCE;
}

/*
 * Verify the kernel integrity baseline the agent's startup gate established.
 *
 * The gate reads both properties out of sysfs and refuses to start without them,
 * and neither can fall while the kernel runs, so the verdict in the map is the
 * same answer a read of kernel memory would give -- from the one producer,
 * on a road that exists whatever the daemon's mount namespace hides.
 * A zero value is the map before the agent has written it.
 *
 * Returns 1 if baseline is satisfied, 0 otherwise.
 */
static __always_inline int integrity_baseline_ok(struct integrity_data *cfg)
{
	if (!cfg)
		return 0;

	if (!cfg->sig_enforce)
		return 0;

	if (!cfg->lockdown)
		return 0;

	return 1;
}

/*
 * Get a boolean config value, defaults to 0 (disabled).
 */
static __always_inline u32 get_config(u32 key)
{
	u32 *val = bpf_map_lookup_elem(&lota_config, &key);
	return val ? *val : 0;
}

/*
 * Event emission policy:
 * - outside ENFORCE mode nothing is budgeted
 * - in ENFORCE mode each event type has a per-second window; blocked events
 *   get the larger cap and are tallied in stats regardless, so only per-event
 *   detail is dropped
 * - past the ring pressure watermark a type that spent its share of the
 *   window yields the rest of the ring to quieter types
 */
static __always_inline int should_emit_event(u32 mode, int blocked, u32 type)
{
	struct event_budget_window *win;
	u64 now_ns, window, avail;
	u32 limit, count;

	limit = lota_event_budget_limit(mode == LOTA_MODE_ENFORCE, blocked);
	if (limit == 0)
		return 1;

	if (type >= LOTA_EVENT_TYPE_COUNT)
		return 0;

	win = bpf_map_lookup_elem(&event_budget, &type);
	if (!win)
		return 0;

	/*
	 * Map entry is shared by every CPU emitting this type, so the window
	 * rotation and the counter must be atomic across CPUs.
	 * One CPU wins the CMPXCHG and zeroes the counter; every caller
	 * then claims a slot with fetch-and-add and emits only when the
	 * old value was under the budget.
	 * Caller racing the rotation may charge the outgoing window and be
	 * discarded by the XCHG reset, so the budget can overshoot by at most
	 * the callers in flight during the flip - bounded by the CPU count,
	 * once per second.
	 */
	now_ns = bpf_ktime_get_ns();
	window = win->window_start_ns;
	if (lota_event_budget_window_expired(now_ns, window)) {
		if (__sync_val_compare_and_swap(&win->window_start_ns, window,
						now_ns) == window)
			(void)__sync_lock_test_and_set(&win->emitted, 0);
	}

	count = __sync_fetch_and_add(&win->emitted, 1);

	if (lota_event_budget_exhausted(count, limit)) {
		inc_stat(blocked ? STAT_BLOCKED_EVENTS_SUPPRESSED :
				   STAT_ALLOW_EVENTS_SUPPRESSED);
		return 0;
	}

	avail = bpf_ringbuf_query(&events, BPF_RB_AVAIL_DATA);
	if (lota_event_type_yields(count, avail, LOTA_RINGBUF_SIZE)) {
		inc_stat(STAT_EVENTS_YIELDED);
		return 0;
	}

	return 1;
}

/*
 * Check if a PID is in the protected set.
 */
#define LOTA_USER_HZ 100ULL
#define LOTA_NSEC_PER_SEC 1000000000ULL

static __always_inline u64 get_task_start_ticks(struct task_struct *task)
{
	u64 start_ns;

	if (!task)
		return 0;

	if (bpf_core_field_exists(task->start_boottime))
		start_ns = BPF_CORE_READ(task, start_boottime);
	else
		start_ns = BPF_CORE_READ(task, start_time);

	return start_ns / (LOTA_NSEC_PER_SEC / LOTA_USER_HZ);
}

/* Is @task the process protected_pids names? Its start time in @start_ticks. */
static __always_inline int is_registered_task(struct task_struct *task,
					      u64 *start_ticks)
{
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
	*start_ticks = task_start_ticks;
	return task_start_ticks && entry->start_time_ticks == task_start_ticks;
}

static __always_inline struct task_struct *
auth_subject_task(struct task_struct *task)
{
	struct task_struct *leader;

	if (!task)
		return NULL;

	/*
	 * Direct field access -- not BPF_CORE_READ -- so the verifier
	 * keeps task->group_leader as a trusted struct task_struct
	 * pointer. bpf_task_storage_get() refuses scalar arguments
	 * with
	 *   "R2 type=scalar expected=ptr_, trusted_ptr_, rcu_ptr_"
	 * which is what BPF_CORE_READ produces here because
	 * bpf_probe_read_kernel copies the pointer value into the
	 * register file untyped. Callers always pass a trusted
	 * task_struct (LSM hook arg or bpf_get_current_task_btf()),
	 * so the trusted-pointer chain is preserved by direct deref.
	 */
	leader = task->group_leader;
	return leader ? leader : task;
}

/*
 * The instance @task belongs to, in @id: the one it inherited, or its own
 * when protected_pids names it. Returns 1 when @task is protected.
 * The caller holds the RCU read lock, which a sleepable hook needs for task
 * storage; task_instance() takes it.
 */
static __always_inline int task_instance_rcu(struct task_struct *task,
					     struct lota_instance_entry *id)
{
	struct lota_instance_entry *entry;
	struct task_struct *subject;
	u64 start_ticks = 0;

	if (!task)
		return 0;

	subject = auth_subject_task(task);
	entry = bpf_task_storage_get(&lota_instance, subject, 0, 0);
	if (entry) {
		*id = *entry;
		return 1;
	}

	if (!is_registered_task(task, &start_ticks))
		return 0;

	id->root_start_ticks = start_ticks;
	id->root_tgid = BPF_CORE_READ(task, tgid);
	id->pad = 0;
	return 1;
}

static __always_inline int task_instance(struct task_struct *task,
					 struct lota_instance_entry *id)
{
	int ret;

	bpf_rcu_read_lock();
	ret = task_instance_rcu(task, id);
	bpf_rcu_read_unlock();

	return ret;
}

/* Is @task held by a tracer, and is that tracer inside instance @id? */
static __always_inline int
task_tracer_inside(struct task_struct *task,
		   const struct lota_instance_entry *id, int *traced)
{
	struct lota_instance_entry tracer_id = {};
	struct task_struct *tracer;
	int tracer_protected = 0;

	*traced = BPF_CORE_READ(task, ptrace) != 0;
	if (!*traced)
		return 0;

	bpf_rcu_read_lock();
	tracer = task->parent;
	if (tracer)
		tracer_protected = task_instance_rcu(tracer, &tracer_id);
	bpf_rcu_read_unlock();

	return lota_inside_instance(tracer_protected, tracer_id.root_tgid,
				    tracer_id.root_start_ticks, 1,
				    id->root_tgid, id->root_start_ticks);
}

static __always_inline int is_protected_task(struct task_struct *task)
{
	struct lota_instance_entry id;

	return task_instance(task, &id);
}

static __always_inline int has_task_auth_flag(struct task_struct *task,
					      u32 flag)
{
	struct task_struct *subject;
	struct lota_task_auth_entry *entry;

	if (!task || !flag)
		return 0;

	subject = auth_subject_task(task);
	if (!subject)
		return 0;

	entry = bpf_task_storage_get(&lota_task_auth, subject, 0, 0);
	return entry && (entry->flags & flag);
}

static __always_inline int is_bpf_admin_task(void)
{
	struct task_struct *task;

	task = (struct task_struct *)bpf_get_current_task_btf();
	if (!task)
		return 0;

	return has_task_auth_flag(task, LOTA_TASK_AUTH_ADMIN);
}

/*
 * mmap_file / file_mprotect gates are scoped to opted-in processes
 * tracked in protected_pids. Cheats that run as a separate process
 * are out of scope for the library-load gate; the ptrace / task_kill
 * hooks already scope to the same set and cover the cross-process
 * threat model (see is_protected_task() usage in lota_ptrace and
 * lota_task_kill).
 *
 * Side effect of the scope: hosts that boot the agent without
 * registering any process can run strict_mmap=enforce safely with an
 * empty trust set, because no task is enforced against. A protected
 * process opts in via LOTA_IPC_CMD_PROTECT_PID or the --protect-pid
 * CLI/config knob.
 */
static __always_inline int is_protected_current_task(void)
{
	struct task_struct *task;

	task = (struct task_struct *)bpf_get_current_task_btf();
	if (!task)
		return 0;

	return is_protected_task(task);
}

static __always_inline int is_current_lota_agent_task(void)
{
	struct task_struct *task;

	task = (struct task_struct *)bpf_get_current_task_btf();
	if (!task)
		return 0;

	return has_task_auth_flag(task, LOTA_TASK_AUTH_AGENT);
}

static __always_inline int is_lota_agent_task(struct task_struct *task)
{
	if (!task)
		return 0;

	return has_task_auth_flag(task, LOTA_TASK_AUTH_AGENT);
}

static __always_inline int is_lota_managed_map(struct bpf_map *map)
{
	char name[16] = {};

	if (!map)
		return 0;

	bpf_core_read(&name, sizeof(name), &map->name);

	if (__builtin_memcmp(name, "lota_config", sizeof("lota_config")) == 0)
		return 1;
	if (__builtin_memcmp(name, "protected_pids",
			     sizeof("protected_pids")) == 0)
		return 1;
	if (__builtin_memcmp(name, "trusted_libs", sizeof("trusted_libs")) == 0)
		return 1;
	if (__builtin_memcmp(name, "trusted_inodes",
			     sizeof("trusted_inodes")) == 0)
		return 1;
	if (__builtin_memcmp(name, "guarded_files", sizeof("guarded_files")) ==
	    0)
		return 1;
	if (__builtin_memcmp(name, "agent_cgroups", sizeof("agent_cgroups")) ==
	    0)
		return 1;
	if (__builtin_memcmp(name, "mapped_exec", sizeof("mapped_exec")) == 0)
		return 1;
	if (__builtin_memcmp(name, "mapped_seen", sizeof("mapped_seen")) == 0)
		return 1;
	if (__builtin_memcmp(name, "exec_history", sizeof("exec_history")) == 0)
		return 1;
	if (__builtin_memcmp(name, "lota_sock_owner",
			     sizeof("lota_sock_owner")) == 0)
		return 1;
	if (__builtin_memcmp(name, "instance_peers",
			     sizeof("instance_peers")) == 0)
		return 1;
	if (__builtin_memcmp(name, "events", sizeof("events")) == 0)
		return 1;
	if (__builtin_memcmp(name, "stats", sizeof("stats")) == 0)
		return 1;
	if (__builtin_memcmp(name, "event_budget", sizeof("event_budget")) == 0)
		return 1;
	if (__builtin_memcmp(name, "integrity_cfg", sizeof("integrity_cfg")) ==
	    0)
		return 1;
	if (__builtin_memcmp(name, "allow_verity", sizeof("allow_verity")) == 0)
		return 1;
	if (__builtin_memcmp(name, "verity_scratch",
			     sizeof("verity_scratch")) == 0)
		return 1;
	if (__builtin_memcmp(name, "lota_task_auth",
			     sizeof("lota_task_auth")) == 0)
		return 1;
	if (__builtin_memcmp(name, "lota_instance", sizeof("lota_instance")) ==
	    0)
		return 1;
	if (__builtin_memcmp(name, "exe_hash_slots",
			     sizeof("exe_hash_slots")) == 0)
		return 1;

	return 0;
}

/*
 * Returns 1 when current task runs in a non-initial user namespace.
 *
 * In ENFORCE mode LOTA treat user namespaces as untrusted for executable
 * mappings and module-loading paths to avoid UID-based trust confusion.
 */
static __always_inline int in_non_init_userns(void)
{
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

static __noinline int is_verity_allowed(struct file *file)
{
	struct lota_verity_scratch *scratch;
	struct bpf_dynptr digest_ptr;
	u32 zero = 0;
	u32 *allowed;
	int ret;

	if (!bpf_get_fsverity_digest)
		return 0;

	if (!file)
		return 0;

	/*
	 * Per-CPU scratch.
	 * See the comment on verity_scratch above: the verifier accepts only
	 * a map value as the data argument of bpf_dynptr_from_mem,
	 * so the buffer has to live in one.
	 */
	scratch = bpf_map_lookup_elem(&verity_scratch, &zero);
	if (!scratch)
		return 0;
	__builtin_memset(scratch, 0, sizeof(*scratch));

	ret = bpf_dynptr_from_mem(scratch->buf, sizeof(scratch->buf), 0,
				  &digest_ptr);
	if (ret < 0)
		return 0;

	/* success is 0, and the digest is what the header points past */
	if (bpf_get_fsverity_digest(file, &digest_ptr) != 0)
		return 0;
	if (lota_verity_key_from_digest_buf(scratch->buf, &scratch->key) != 0)
		return 0;

	allowed = bpf_map_lookup_elem(&allow_verity, &scratch->key);
	return (allowed && *allowed) ? 1 : 0;
}

static __always_inline int is_trusted_lib(struct file *file)
{
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

static __always_inline int is_trusted_inode(struct inode *inode)
{
	struct super_block *sb;
	struct trusted_lib_key key = {};
	u32 *allowed;

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

/* LOTA_GUARD_* of @file, or 0; keyed by superblock dev, not stat's st_dev */
static __always_inline u32 guarded_file_kind(struct file *file)
{
	struct super_block *sb;
	struct trusted_lib_key key = {};
	struct inode *inode;
	u32 *kind;

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

	kind = bpf_map_lookup_elem(&guarded_files, &key);
	return kind ? *kind : 0;
}

/*
 * Enforcement map key of a file. s_dev, not stat(2)'s st_dev:
 * they differ on a filesystem with a device per subvolume.
 */
static __always_inline int inode_key(struct inode *inode,
				     struct trusted_lib_key *key)
{
	struct super_block *sb;

	if (!inode)
		return 0;

	sb = BPF_CORE_READ(inode, i_sb);
	if (!sb)
		return 0;

	key->dev = (u64)BPF_CORE_READ(sb, s_dev);
	key->ino = (u64)BPF_CORE_READ(inode, i_ino);
	if (key->dev == 0 || key->ino == 0)
		return 0;

	return 1;
}

static __always_inline int file_inode_key(struct file *file,
					  struct trusted_lib_key *key)
{
	if (!file)
		return 0;

	return inode_key(BPF_CORE_READ(file, f_inode), key);
}

static __always_inline int is_inode_mapped_exec_guarded(struct inode *inode)
{
	struct trusted_lib_key key = {};
	u32 *guarded;

	if (!inode_key(inode, &key))
		return 0;

	guarded = bpf_map_lookup_elem(&mapped_exec, &key);
	return (guarded && *guarded) ? 1 : 0;
}

static __always_inline int is_mapped_exec_guarded(struct file *file)
{
	if (!file)
		return 0;

	return is_inode_mapped_exec_guarded(BPF_CORE_READ(file, f_inode));
}

/* enough to tell a file from one swapped in */
static __always_inline void inode_seen(struct inode *inode,
				       struct lota_mapped_seen *seen)
{
	seen->size = (u64)BPF_CORE_READ(inode, i_size);
	seen->ctime_sec = (u64)BPF_CORE_READ(inode, i_ctime_sec);
	seen->ctime_nsec = (u32)BPF_CORE_READ(inode, i_ctime_nsec);
	seen->pad = 0;
}

/* every mode and task: which records will be needed is not known yet */
static __always_inline void remember_mapped_exec(struct file *file)
{
	struct trusted_lib_key key = {};
	struct lota_mapped_seen seen = {};
	struct inode *inode;

	if (!file_inode_key(file, &key))
		return;

	inode = BPF_CORE_READ(file, f_inode);
	if (!inode)
		return;

	inode_seen(inode, &seen);
	bpf_map_update_elem(&mapped_seen, &key, &seen, BPF_ANY);
}

#define LOTA_TMPFS_MAGIC 0x01021994
#define LOTA_HUGETLBFS_MAGIC 0x958458f6
#define LOTA_F_SEAL_WRITE 0x0008
#define LOTA_F_SEAL_FUTURE_WRITE 0x0010

/* seals of a tmpfs or hugetlbfs inode */
static __always_inline u32 memory_inode_seals(struct inode *inode,
					      unsigned long magic)
{
	struct hugetlbfs_inode_info *h;
	struct shmem_inode_info *s;

	if (magic == LOTA_HUGETLBFS_MAGIC) {
		h = (void *)((char *)inode -
			     bpf_core_field_offset(struct hugetlbfs_inode_info,
						   vfs_inode));
		return BPF_CORE_READ(h, seals);
	}
	s = (void *)((char *)inode -
		     bpf_core_field_offset(struct shmem_inode_info, vfs_inode));
	return BPF_CORE_READ(s, seals);
}

/* who else could change the code of @inode right now */
static __always_inline u32 exec_history_flags(struct inode *inode)
{
	unsigned long magic;
	u32 flags = 0;

	if (!inode)
		return 0;

	/* negative i_writecount: writes denied, e.g. a running exe */
	if (BPF_CORE_READ(inode, i_writecount.counter) > 0 ||
	    BPF_CORE_READ(inode, i_mapping, i_mmap_writable.counter) > 0)
		flags |= LOTA_EXEC_HISTORY_WRITABLE;

	magic = BPF_CORE_READ(inode, i_sb, s_magic);
	if (magic != LOTA_TMPFS_MAGIC && magic != LOTA_HUGETLBFS_MAGIC)
		return flags;

	flags |= LOTA_EXEC_HISTORY_MEMORY;

	/*
	 * A memfd or shm segment has no name to open: its fds never count
	 * in i_writecount, and any holder can write until a seal forbids it.
	 */
	if (BPF_CORE_READ(inode, __i_nlink) == 0 &&
	    !(memory_inode_seals(inode, magic) &
	      (LOTA_F_SEAL_WRITE | LOTA_F_SEAL_FUTURE_WRITE)))
		flags |= LOTA_EXEC_HISTORY_WRITABLE;

	return flags;
}

/* first attempt per file names it; the flags gather every attempt's */
static __always_inline void remember_protected_exec(struct file *file)
{
	struct lota_exec_history_key key = {};
	struct lota_exec_history_val val = {};
	struct lota_exec_history_val *seen;
	struct trusted_lib_key ik = {};
	struct task_struct *task;
	struct task_struct *leader;
	const unsigned char *name;
	struct inode *inode;
	long err;

	task = (struct task_struct *)bpf_get_current_task_btf();
	if (!task || !is_protected_task(task))
		return;

	if (!file_inode_key(file, &ik)) {
		inc_stat(STAT_EXEC_HISTORY_LOST);
		return;
	}

	leader = BPF_CORE_READ(task, group_leader);
	key.tgid = BPF_CORE_READ(task, tgid);
	key.start_ticks = get_task_start_ticks(leader ? leader : task);
	key.dev = ik.dev;
	key.ino = ik.ino;

	inode = BPF_CORE_READ(file, f_inode);
	val.flags = exec_history_flags(inode);

	seen = bpf_map_lookup_elem(&exec_history, &key);
	if (seen) {
		if (val.flags & ~seen->flags)
			__sync_fetch_and_or(&seen->flags, val.flags);
		return;
	}

	val.size = inode ? (u64)BPF_CORE_READ(inode, i_size) : 0;
	name = BPF_CORE_READ(file, f_path.dentry, d_name.name);
	if (name)
		bpf_probe_read_kernel_str(val.name, sizeof(val.name), name);

	err = bpf_map_update_elem(&exec_history, &key, &val, BPF_NOEXIST);
	if (err == -EEXIST) {
		seen = bpf_map_lookup_elem(&exec_history, &key);
		if (seen)
			__sync_fetch_and_or(&seen->flags, val.flags);
	} else if (err) {
		inc_stat(STAT_EXEC_HISTORY_LOST);
	}
}

/*
 * Fill @slot with @file's key, whether it is the file mapped, and its writers:
 * a pin cannot recall a write open already granted.
 */
static __always_inline void answer_pin_question(struct file *file,
						struct lota_exe_hash_slot *slot)
{
	struct trusted_lib_key key = {};
	struct lota_mapped_seen now = {};
	struct lota_mapped_seen *seen;
	struct inode *inode;
	int writers;

	slot->algo = 0;
	slot->err = 0;
	slot->dev = 0;
	slot->ino = 0;
	slot->writers = 0;
	slot->seen = LOTA_EXE_MAP_SEEN_MISSING;
	slot->state = LOTA_EXE_HASH_ANSWERED;

	inode = BPF_CORE_READ(file, f_inode);
	if (!inode || !file_inode_key(file, &key)) {
		slot->err = EINVAL;
		return;
	}

	slot->dev = key.dev;
	slot->ino = key.ino;

	/* negative i_writecount: writes denied, e.g. a running exe */
	writers = BPF_CORE_READ(inode, i_writecount.counter);
	if (writers > 0)
		slot->writers = (u32)writers;

	seen = bpf_map_lookup_elem(&mapped_seen, &key);
	if (!seen)
		return;

	inode_seen(inode, &now);
	slot->seen =
		(now.size == seen->size && now.ctime_sec == seen->ctime_sec &&
		 now.ctime_nsec == seen->ctime_nsec) ?
			LOTA_EXE_MAP_SEEN_OK :
			LOTA_EXE_MAP_SEEN_CHANGED;
}

/* count objects the agent will not pin */
static __always_inline void count_pin_refusal(struct lota_exe_hash_slot *slot)
{
	/* not enforcing, or already pinned: nothing refused */
	if (slot->err != 0 || slot->guard)
		return;
	if (slot->seen != LOTA_EXE_MAP_SEEN_OK || slot->writers > 0)
		inc_stat(STAT_MAPPED_PIN_REFUSED);
}

static __always_inline int is_write_open_flags(int flags)
{
	int acc_mode = flags & LOTA_O_ACCMODE;

	if (acc_mode == LOTA_O_WRONLY || acc_mode == LOTA_O_RDWR)
		return 1;

	if (flags & LOTA_O_TRUNC)
		return 1;

	return 0;
}

static __always_inline unsigned int lota_dev_major(dev_t dev)
{
	return LOTA_DEVT_MAJOR(dev);
}

static __always_inline unsigned int lota_dev_minor(dev_t dev)
{
	return LOTA_DEVT_MINOR(dev);
}

static __always_inline int is_kernel_mem_device(struct file *file)
{
	struct inode *inode;
	dev_t rdev;
	unsigned int major;
	unsigned int minor;

	if (!file)
		return 0;

	inode = BPF_CORE_READ(file, f_inode);
	if (!inode)
		return 0;

	if ((BPF_CORE_READ(inode, i_mode) & S_IFMT) != S_IFCHR)
		return 0;

	rdev = BPF_CORE_READ(inode, i_rdev);
	major = lota_dev_major(rdev);
	minor = lota_dev_minor(rdev);

	/* char major 1: mem=1, kmem=2, port=4 */
	if (major != 1)
		return 0;

	return minor == 1 || minor == 2 || minor == 4;
}

static __always_inline int is_shebang_binprm(struct linux_binprm *bprm)
{
	char c0;
	char c1;

	if (!bprm)
		return 0;

	c0 = BPF_CORE_READ(bprm, buf[0]);
	c1 = BPF_CORE_READ(bprm, buf[1]);
	return c0 == '#' && c1 == '!';
}

static __always_inline int is_inaccessible_exec_path(struct linux_binprm *bprm)
{
	unsigned int interp_flags;
	const char *fdpath;

	if (!bprm)
		return 0;

	interp_flags = BPF_CORE_READ(bprm, interp_flags);
	if (interp_flags & BINPRM_FLAGS_PATH_INACCESSIBLE)
		return 1;

	fdpath = BPF_CORE_READ(bprm, fdpath);
	return fdpath ? 1 : 0;
}

/*
 * A mount refusal, reported.
 *
 * The refusal is the point of these hooks and the caller only learns
 * "permission denied", so the record an operator reads afterwards is
 * the event.
 * @what names which mount API asked, since the two take the same privilege
 * and have the same effect.
 */
static __always_inline void report_blocked_mount(const char *what, u32 len)
{
	struct lota_exec_event *event;

	inc_stat(STAT_MOUNTS_BLOCKED);

	if (!should_emit_event(LOTA_MODE_ENFORCE, 1, LOTA_EVENT_MOUNT_BLOCKED))
		return;

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		inc_stat(STAT_RINGBUF_DROPS);
		return;
	}

	__builtin_memset(event, 0, sizeof(*event));
	event->timestamp_ns = bpf_ktime_get_ns();
	event->event_type = LOTA_EVENT_MOUNT_BLOCKED;
	event->tgid = bpf_get_current_pid_tgid() >> 32;
	event->pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
	event->uid = (u32)(bpf_get_current_uid_gid() & 0xFFFFFFFF);
	bpf_get_current_comm(event->comm, sizeof(event->comm));
	if (len > 0 && len < sizeof(event->filename))
		bpf_probe_read_kernel(event->filename, len, what);

	bpf_ringbuf_submit(event, 0);
	inc_stat(STAT_EVENTS_SENT);
}

/*
 * Block bind mounts over trusted-library inodes and parent mountpoints.
 */
SEC("lsm/sb_mount")
int BPF_PROG(lota_sb_mount, const char *dev_name, const struct path *path,
	     const char *type, unsigned long flags, void *data, int ret)
{
	struct dentry *dentry;
	struct inode *inode;
	u32 mode;

	(void)dev_name;
	(void)type;
	(void)data;

	if (ret != 0)
		return -EPERM;

	if (!(flags & MS_BIND))
		return 0;

	mode = get_mode();
	if (mode != LOTA_MODE_ENFORCE)
		return 0;

	if (!get_config(LOTA_CFG_STRICT_MMAP))
		return 0;

	if (!path)
		return 0;

	dentry = BPF_CORE_READ(path, dentry);
	if (!dentry)
		return 0;

	inode = BPF_CORE_READ(dentry, d_inode);
	if (!inode)
		return 0;

	if (!is_trusted_inode(inode))
		return 0;

	report_blocked_mount("bind mount over a trusted file", 31);
	return -EPERM;
}

/*
 * The other mount API.
 * open_tree(2) clones a mount and move_mount(2) puts it somewhere, which shadows
 * the destination exactly as MS_BIND does and takes the same privilege,
 * so the same predicate has to hold here.
 * There is no MS_BIND to gate on: every move_mount lands a mount over
 * the destination.
 */
SEC("lsm/move_mount")
int BPF_PROG(lota_move_mount, const struct path *from_path,
	     const struct path *to_path, int ret)
{
	struct dentry *dentry;
	struct inode *inode;
	u32 mode;

	(void)from_path;

	if (ret != 0)
		return -EPERM;

	mode = get_mode();
	if (mode != LOTA_MODE_ENFORCE)
		return 0;

	if (!get_config(LOTA_CFG_STRICT_MMAP))
		return 0;

	if (!to_path)
		return 0;

	dentry = BPF_CORE_READ(to_path, dentry);
	if (!dentry)
		return 0;

	inode = BPF_CORE_READ(dentry, d_inode);
	if (!inode)
		return 0;

	if (!is_trusted_inode(inode))
		return 0;

	report_blocked_mount("move_mount over a trusted file", 31);
	return -EPERM;
}

/*
 * Agent/admin check for lsm.s hooks: without the RCU read lock the task
 * pointer is untrusted and bpf_task_storage_get() rejects it.
 */
static __always_inline int sleepable_task_is_agent_or_admin(void)
{
	struct task_struct *task;
	int ret;

	task = (struct task_struct *)bpf_get_current_task_btf();
	if (!task)
		return 0;

	bpf_rcu_read_lock();
	ret = has_task_auth_flag(task, LOTA_TASK_AUTH_AGENT) ||
	      has_task_auth_flag(task, LOTA_TASK_AUTH_ADMIN);
	bpf_rcu_read_unlock();

	return ret;
}

#define LOTA_PROC_SUPER_MAGIC 0x9fa0

/*
 * An open of a /proc memory entry of the agent or of a protected process,
 * from outside it; see lota_proc_entry_reads_mm(). The ptrace verdict,
 * asked of the open itself because CAP_PERFMON passes the kernel's check
 * without it. Returns 1 to deny; @target_pid is the process refused.
 */
static __always_inline int denies_proc_mm_open(struct file *file,
					       u32 *target_pid)
{
	struct lota_instance_entry target_id = {};
	struct lota_instance_entry actor_id = {};
	char name[LOTA_PROC_NAME_MAX] = {};
	struct task_struct *current;
	struct task_struct *target;
	int target_protected;
	struct dentry *dentry;
	struct proc_inode *pi;
	struct inode *inode;
	int target_agent;
	int actor_agent;
	int inside = 0;
	u32 len;
	s32 nr;

	inode = BPF_CORE_READ(file, f_inode);
	if (!inode ||
	    BPF_CORE_READ(inode, i_sb, s_magic) != LOTA_PROC_SUPER_MAGIC)
		return 0;

	dentry = BPF_CORE_READ(file, f_path.dentry);
	len = BPF_CORE_READ(dentry, d_name.len);
	if (len == 0 || len >= LOTA_PROC_NAME_MAX)
		return 0;
	if (bpf_probe_read_kernel(name, len & (LOTA_PROC_NAME_MAX - 1),
				  BPF_CORE_READ(dentry, d_name.name)))
		return 0;
	if (!lota_proc_entry_reads_mm(name, len))
		return 0;

	pi = (void *)((char *)inode -
		      bpf_core_field_offset(struct proc_inode, vfs_inode));
	nr = BPF_CORE_READ(pi, pid, numbers[0].nr);
	if (nr <= 0)
		return 0;

	target = bpf_task_from_pid(nr);
	if (!target)
		return 0;

	*target_pid = target->tgid;
	if (target->tgid == bpf_get_current_pid_tgid() >> 32) {
		bpf_task_release(target);
		return 0;
	}

	current = (struct task_struct *)bpf_get_current_task_btf();
	bpf_rcu_read_lock();
	actor_agent = has_task_auth_flag(current, LOTA_TASK_AUTH_AGENT);
	target_agent = has_task_auth_flag(target, LOTA_TASK_AUTH_AGENT);
	bpf_rcu_read_unlock();

	target_protected = task_instance(target, &target_id);
	bpf_task_release(target);

	if (lota_ptrace_agent_read_exempt(LOTA_PTRACE_MODE_READ, actor_agent))
		return 0;

	if (target_protected)
		inside = lota_inside_instance(
			task_instance(current, &actor_id), actor_id.root_tgid,
			actor_id.root_start_ticks, target_protected,
			target_id.root_tgid, target_id.root_start_ticks);

	return lota_ptrace_denied(LOTA_PTRACE_MODE_READ, LOTA_MODE_MONITOR, 0,
				  target_agent, target_protected && !inside);
}

/* the reader sees only EPERM; logged as PTRACE_BLOCKED, naming the entry */
static __always_inline void report_blocked_proc_mm(struct file *file,
						   u32 target_pid)
{
	struct lota_exec_event *event;

	inc_stat(STAT_PTRACE_BLOCKED);

	if (!should_emit_event(LOTA_MODE_ENFORCE, 1, LOTA_EVENT_PTRACE_BLOCKED))
		return;

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		inc_stat(STAT_RINGBUF_DROPS);
		return;
	}

	__builtin_memset(event, 0, sizeof(*event));
	event->timestamp_ns = bpf_ktime_get_ns();
	event->event_type = LOTA_EVENT_PTRACE_BLOCKED;
	event->tgid = bpf_get_current_pid_tgid() >> 32;
	event->pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
	event->uid = (u32)(bpf_get_current_uid_gid() & 0xFFFFFFFF);
	event->target_pid = target_pid;
	bpf_get_current_comm(event->comm, sizeof(event->comm));
	bpf_probe_read_kernel_str(event->filename, LOTA_PROC_NAME_MAX,
				  BPF_CORE_READ(file, f_path.dentry,
						d_name.name));

	bpf_ringbuf_submit(event, 0);
	inc_stat(STAT_EVENTS_SENT);
}

/* report a refused guarded-file open; logged as KILL_BLOCKED */
static __always_inline void report_blocked_kill_guard(const char *what, u32 len)
{
	struct lota_exec_event *event;

	inc_stat(STAT_KILL_GUARD_BLOCKED);

	if (!should_emit_event(LOTA_MODE_ENFORCE, 1,
			       LOTA_EVENT_KILL_GUARD_BLOCKED))
		return;

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		inc_stat(STAT_RINGBUF_DROPS);
		return;
	}

	__builtin_memset(event, 0, sizeof(*event));
	event->timestamp_ns = bpf_ktime_get_ns();
	event->event_type = LOTA_EVENT_KILL_GUARD_BLOCKED;
	event->tgid = bpf_get_current_pid_tgid() >> 32;
	event->pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
	event->uid = (u32)(bpf_get_current_uid_gid() & 0xFFFFFFFF);
	bpf_get_current_comm(event->comm, sizeof(event->comm));
	if (len > 0 && len < sizeof(event->filename))
		bpf_probe_read_kernel(event->filename, len, what);

	bpf_ringbuf_submit(event, 0);
	inc_stat(STAT_EVENTS_SENT);
}

/* the writer sees only EPERM; tell the event stream */
static __always_inline void report_blocked_mapped_write(struct dentry *dentry)
{
	struct lota_exec_event *event;
	const unsigned char *name = NULL;

	inc_stat(STAT_MAPPED_WRITE_BLOCKED);

	if (!should_emit_event(LOTA_MODE_ENFORCE, 1,
			       LOTA_EVENT_MAPPED_WRITE_BLOCKED))
		return;

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		inc_stat(STAT_RINGBUF_DROPS);
		return;
	}

	__builtin_memset(event, 0, sizeof(*event));
	event->timestamp_ns = bpf_ktime_get_ns();
	event->event_type = LOTA_EVENT_MAPPED_WRITE_BLOCKED;
	event->tgid = bpf_get_current_pid_tgid() >> 32;
	event->pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
	event->uid = (u32)(bpf_get_current_uid_gid() & 0xFFFFFFFF);
	bpf_get_current_comm(event->comm, sizeof(event->comm));

	if (dentry)
		name = BPF_CORE_READ(dentry, d_name.name);
	if (!name ||
	    bpf_probe_read_kernel_str(event->filename, sizeof(event->filename),
				      name) < 0)
		__builtin_memcpy(event->filename, "(unnamed)", 10);

	bpf_ringbuf_submit(event, 0);
	inc_stat(STAT_EVENTS_SENT);
}

/* the verdict lives in include/lota.h, shared with the tests */
#define LOTA_CGROUP2_SUPER_MAGIC 0x63677270

/*
 * LOTA_GUARD_* of @file when it is cgroup.kill or cgroup.freeze of the
 * cgroup the agent was moved to, or of an ancestor; see agent_cgroups.
 */
static __always_inline u32 moved_agent_cgroup_kind(struct file *file)
{
	char name[LOTA_PROC_NAME_MAX] = {};
	struct dentry *dentry;
	struct inode *inode;
	struct kernfs_node *kn;
	u32 kind;
	u32 len;
	u64 id;

	inode = BPF_CORE_READ(file, f_inode);
	if (!inode ||
	    BPF_CORE_READ(inode, i_sb, s_magic) != LOTA_CGROUP2_SUPER_MAGIC)
		return 0;

	dentry = BPF_CORE_READ(file, f_path.dentry);
	len = BPF_CORE_READ(dentry, d_name.len);
	if (len == 0 || len >= LOTA_PROC_NAME_MAX)
		return 0;
	if (bpf_probe_read_kernel(name, len & (LOTA_PROC_NAME_MAX - 1),
				  BPF_CORE_READ(dentry, d_name.name)))
		return 0;
	if (lota_name_is(name, len, "cgroup.kill"))
		kind = LOTA_GUARD_CGROUP_KILL;
	else if (lota_name_is(name, len, "cgroup.freeze"))
		kind = LOTA_GUARD_CGROUP_FREEZE;
	else
		return 0;

	/* the cgroup's directory node carries the cgroup id */
	kn = BPF_CORE_READ(dentry, d_parent, d_inode, i_private);
	id = BPF_CORE_READ(kn, id);
	if (!id)
		return 0;

	for (u32 i = 0; i < LOTA_AGENT_CGROUP_DEPTH; i++) {
		u32 key = i;
		u64 *level = bpf_map_lookup_elem(&agent_cgroups, &key);

		if (!level || !*level)
			return 0;
		if (*level == id)
			return kind;
	}

	return 0;
}

/* LOTA_GUARD_* of a refused write open of a guarded file, or 0 */
static __always_inline u32 denies_kill_guard_open(struct file *file)
{
	u32 kind;

	if (!is_write_open_flags(BPF_CORE_READ(file, f_flags)))
		return 0;

	kind = guarded_file_kind(file);
	if (!kind)
		kind = moved_agent_cgroup_kind(file);
	if (!kind)
		return 0;

	if (!lota_kill_guard_denied(1, 1, sleepable_task_is_agent_or_admin()))
		return 0;

	return kind;
}

/*
 * Block in-place writes/truncation on trusted-library inodes,
 * and writes to the files that would end a protected task without a signal.
 */
SEC("lsm.s/file_open")
int BPF_PROG(lota_file_open, struct file *file, int ret)
{
	u32 target_pid = 0;
	u32 guard;
	u32 mode;
	int flags;

	if (ret != 0)
		return -EPERM;

	if (!file)
		return 0;

	/* kernel memory, kill protection and pins are not policy */
	if (is_kernel_mem_device(file))
		return -EPERM;

	if (denies_proc_mm_open(file, &target_pid)) {
		report_blocked_proc_mm(file, target_pid);
		return -EPERM;
	}

	guard = denies_kill_guard_open(file);
	if (guard == LOTA_GUARD_CGROUP_FREEZE) {
		report_blocked_kill_guard("(cgroup.freeze)", 16);
		return -EPERM;
	}
	if (guard) {
		report_blocked_kill_guard("(cgroup.kill)", 14);
		return -EPERM;
	}

	/* pinned library: unwritable like a running executable */
	if (is_write_open_flags(BPF_CORE_READ(file, f_flags)) &&
	    is_mapped_exec_guarded(file)) {
		report_blocked_mapped_write(BPF_CORE_READ(file, f_path.dentry));
		return -EPERM;
	}

	mode = get_mode();
	if (mode != LOTA_MODE_ENFORCE)
		return 0;

	if (!get_config(LOTA_CFG_STRICT_MMAP))
		return 0;

	if (!is_trusted_lib(file))
		return 0;

	flags = BPF_CORE_READ(file, f_flags);
	if (!is_write_open_flags(flags))
		return 0;

	return -EPERM;
}

/* =====================================================================
 * LSM hook: path_truncate
 *
 * truncate(2) shortens a file by path, with no open for lota_file_open
 * to refuse. A pinned library stays as unwritable as a running
 * executable, which the kernel will not truncate either.
 * ===================================================================== */
SEC("lsm/path_truncate")
int BPF_PROG(lota_path_truncate, const struct path *path, int ret)
{
	struct dentry *dentry;

	if (ret != 0)
		return ret;

	if (!path)
		return 0;

	dentry = BPF_CORE_READ(path, dentry);
	if (!dentry)
		return 0;

	if (!is_inode_mapped_exec_guarded(BPF_CORE_READ(dentry, d_inode)))
		return 0;

	report_blocked_mapped_write(dentry);
	return -EPERM;
}

/* =====================================================================
 * LSM hook: file_post_open (sleepable), measurement
 *
 * Hashes the opens the agent asked about, in every mode. Not file_open:
 * the file is not open there yet, so bpf_ima_file_hash() cannot read it.
 * Any other open costs one map lookup.
 * ===================================================================== */
SEC("lsm.s/file_post_open")
int BPF_PROG(lota_file_post_open_measure, struct file *file, int mask)
{
	struct lota_exe_hash_slot *slot;
	u32 tid;
	u32 want;
	long hashed;

	if (!file)
		return 0;

	tid = (u32)bpf_get_current_pid_tgid();
	slot = bpf_map_lookup_elem(&exe_hash_slots, &tid);
	if (!slot)
		return 0;
	want = slot->state;
	if (want != LOTA_EXE_HASH_ASKED && want != LOTA_EXE_HASH_ASKED_PIN)
		return 0;

	/* user space writes this map: confirm the caller is the agent */
	if (!sleepable_task_is_agent_or_admin()) {
		slot->state = LOTA_EXE_HASH_ANSWERED;
		slot->algo = 0;
		slot->guard = 0;
		slot->err = EPERM;
		return 0;
	}

	slot->guard = is_mapped_exec_guarded(file) ? 1 : 0;

	if (want == LOTA_EXE_HASH_ASKED_PIN) {
		answer_pin_question(file, slot);
		count_pin_refusal(slot);
		return 0;
	}

	/* returns the hash_info algorithm id, not a length */
	hashed = bpf_ima_file_hash(file, slot->digest, sizeof(slot->digest));
	if (hashed < 0) {
		slot->algo = 0;
		slot->err = (u32)-hashed;
	} else {
		slot->algo = (u32)hashed;
		slot->err = 0;
	}
	slot->state = LOTA_EXE_HASH_ANSWERED;

	return 0;
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
int BPF_PROG(lota_bprm_check_security, struct linux_binprm *bprm)
{
	struct file *file;
	struct lota_exec_event *event = NULL;
	struct lota_verity_scratch *scratch;
	u32 zero = 0;
	u32 mode;
	int blocked = 0;
	int have_digest = 0;

	inc_stat(STAT_TOTAL_EXECS);

	mode = get_mode();

	/*
	 * Direct field access -- not BPF_CORE_READ -- so the verifier
	 * keeps bprm->file as a PTR_TO_BTF_ID(struct file). The kfunc
	 * bpf_get_fsverity_digest() requires its first argument to be
	 * a trusted struct file pointer; BPF_CORE_READ copies bytes via
	 * bpf_probe_read_kernel and the result lands in the register
	 * file as a scalar, which the verifier then rejects with
	 *   "arg#0 pointer type STRUCT file must point to scalar"
	 * LSM hook arguments are themselves trusted PTR_TO_BTF_ID, so
	 * the field chain bprm->file stays in trusted-pointer territory.
	 */
	file = bprm->file;

	scratch = bpf_map_lookup_elem(&verity_scratch, &zero);
	if (!scratch)
		return 0;
	__builtin_memset(scratch, 0, sizeof(*scratch));

	/* fetch fs-verity digest once (if supported) and reuse it below */
	if (bpf_get_fsverity_digest && file) {
		struct bpf_dynptr digest_ptr;
		int ret = bpf_dynptr_from_mem(
			scratch->buf, sizeof(scratch->buf), 0, &digest_ptr);
		if (ret == 0) {
			/*
			 * Note on TOCTOU:
			 * - bprm->file is an already-open file; path renames
			 * after open(2) do not change the inode behind this
			 * file descriptor.
			 * - fs-verity is enforced by the kernel: enabling
			 * verity makes the inode content immutable and the
			 * helper returns an error if verity is not enabled for
			 * this file.
			 *
			 * The kernel reports success as 0, not as a length,
			 * and writes a header before the digest. Reading the
			 * return value as a length leaves every file without
			 * a digest, which under STRICT_EXEC blocks even the
			 * files the allowlist names.
			 */
			ret = bpf_get_fsverity_digest(file, &digest_ptr);
			if (ret == 0 &&
			    lota_verity_key_from_digest_buf(scratch->buf,
							    &scratch->key) == 0)
				have_digest = 1;
		}
	}

	if (mode == LOTA_MODE_ENFORCE && get_config(LOTA_CFG_STRICT_EXEC)) {
		if (is_shebang_binprm(bprm) ||
		    BPF_CORE_READ(bprm, interpreter) ||
		    is_inaccessible_exec_path(bprm)) {
			blocked = 1;
		} else if (!have_digest) {
			blocked = 1;
		} else {
			u8 *allowed = bpf_map_lookup_elem(&allow_verity,
							  &scratch->key);
			if (!(allowed && *allowed))
				blocked = 1;
		}
	}

	if (should_emit_event(mode, blocked,
			      blocked ? LOTA_EVENT_EXEC_BLOCKED :
					LOTA_EVENT_EXEC)) {
		event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
		if (event) {
			__builtin_memset(event, 0, sizeof(*event));
			event->timestamp_ns = bpf_ktime_get_ns();
			event->event_type = blocked ? LOTA_EVENT_EXEC_BLOCKED :
						      LOTA_EVENT_EXEC;
			event->tgid = bpf_get_current_pid_tgid() >> 32;
			event->pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
			event->uid =
				(u32)(bpf_get_current_uid_gid() & 0xFFFFFFFF);

			bpf_get_current_comm(event->comm, sizeof(event->comm));

			/*
			 * best-effort filename from binprm; may be relative.
			 *
			 * Direct field access -- not BPF_CORE_READ -- so the
			 * compiler does not allocate a stack temporary for the
			 * fetched pointer. The earlier bpf_dynptr_from_mem()
			 * call leaves its dynptr metadata occupying a stack
			 * slot that the verifier tracks as a live dynptr
			 * through the rest of the program; if the compiler
			 * reuses that slot for the BPF_CORE_READ() probe-read
			 * target, the verifier rejects the program with
			 *   "potential write to dynptr at off=-N disallowed".
			 * Direct access keeps the pointer in a register, which
			 * sidesteps the stack-slot collision.
			 */
			{
				const char *fn = bprm->filename;
				if (fn)
					bpf_probe_read_kernel_str(
						event->filename,
						sizeof(event->filename), fn);
			}

			/* if fs-verity digest is present, include first 32
			 * bytes in event hash */
			if (have_digest)
				__builtin_memcpy(event->hash,
						 scratch->key.digest,
						 LOTA_HASH_SIZE);

			bpf_ringbuf_submit(event, 0);
			inc_stat(STAT_EVENTS_SENT);
		} else {
			inc_stat(STAT_RINGBUF_DROPS);
		}
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
	     enum kernel_read_file_id id)
{
	struct lota_exec_event *event = NULL;
	struct integrity_data *integrity;
	int blocked;
	int emit_event = 0;
	int verity = 0;
	int strict;
	uint32_t key = 0;
	uint32_t mode = get_mode();

	strict = mode == LOTA_MODE_ENFORCE &&
		 get_config(LOTA_CFG_STRICT_MODULES);

	/* an unknown purpose counts only while strict */
	if (!(strict && !lota_kread_is_known(id)) &&
	    !lota_kread_is_watched(id, 1))
		return 0;

	integrity = bpf_map_lookup_elem(&integrity_cfg, &key);

	/* the digest is read only where the verdict asks for it */
	if (strict && (lota_kread_is_module(id) || id == LOTA_KREAD_FIRMWARE))
		verity = is_verity_allowed(file);

	/* the verdict lives in include/lota.h, shared with the tests */
	blocked = lota_kread_denied(id, 1, mode == LOTA_MODE_ENFORCE,
				    get_config(LOTA_CFG_STRICT_MODULES),
				    integrity_baseline_ok(integrity), verity,
				    in_non_init_userns());

	emit_event = should_emit_event(mode, blocked,
				       blocked ? LOTA_EVENT_MODULE_BLOCKED :
						 LOTA_EVENT_MODULE_LOAD);
	if (emit_event) {
		event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	}
	if (event) {
		__builtin_memset(event, 0, sizeof(*event));
		event->timestamp_ns = bpf_ktime_get_ns();
		event->event_type = blocked ? LOTA_EVENT_MODULE_BLOCKED :
					      LOTA_EVENT_MODULE_LOAD;
		event->tgid = bpf_get_current_pid_tgid() >> 32;
		event->pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
		event->uid = 0; /* limits to root for these ops roughly */

		bpf_get_current_comm(event->comm, sizeof(event->comm));

		struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
		const unsigned char *name = NULL;
		int ret_path = -1;

		if (dentry) {
			name = BPF_CORE_READ(dentry, d_name.name);
			if (name) {
				ret_path = bpf_probe_read_kernel_str(
					event->filename,
					sizeof(event->filename), name);
			}
		}

		if (ret_path < 0) {
			if (lota_kread_is_module(id))
				__builtin_memcpy(event->filename,
						 "kernel_module", 13);
			else if (id == LOTA_KREAD_FIRMWARE)
				__builtin_memcpy(event->filename, "firmware",
						 8);
			else if (id == LOTA_KREAD_KEXEC_IMAGE)
				__builtin_memcpy(event->filename, "kexec_image",
						 11);
			else
				__builtin_memcpy(event->filename,
						 "kernel_assets", 13);
		}

		bpf_ringbuf_submit(event, 0);
		inc_stat(STAT_EVENTS_SENT);
	} else if (emit_event) {
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
int BPF_PROG(lota_kernel_load_data, enum kernel_load_data_id id)
{
	struct lota_exec_event *event = NULL;
	struct integrity_data *integrity;
	u32 key = 0;
	u32 mode;
	int blocked;
	int emit_event = 0;
	int strict;

	mode = get_mode();
	strict = mode == LOTA_MODE_ENFORCE &&
		 get_config(LOTA_CFG_STRICT_MODULES);

	/* the same filter as kernel_read_file */
	if (!(strict && !lota_kread_is_known(id)) &&
	    !lota_kread_is_watched(id, 0))
		return 0;

	integrity = bpf_map_lookup_elem(&integrity_cfg, &key);

	/* nothing handed over from memory has a file to check */
	blocked = lota_kread_denied(id, 0, mode == LOTA_MODE_ENFORCE,
				    get_config(LOTA_CFG_STRICT_MODULES),
				    integrity_baseline_ok(integrity), 0,
				    in_non_init_userns());

	emit_event = should_emit_event(mode, blocked,
				       blocked ? LOTA_EVENT_MODULE_BLOCKED :
						 LOTA_EVENT_MODULE_LOAD);
	if (emit_event) {
		event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	}
	if (event) {
		__builtin_memset(event, 0, sizeof(*event));
		event->timestamp_ns = bpf_ktime_get_ns();
		event->event_type = blocked ? LOTA_EVENT_MODULE_BLOCKED :
					      LOTA_EVENT_MODULE_LOAD;
		event->tgid = bpf_get_current_pid_tgid() >> 32;
		event->pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
		event->uid = 0;

		bpf_get_current_comm(event->comm, sizeof(event->comm));

		if (lota_kread_is_module(id))
			__builtin_memcpy(event->filename, "kernel_module_mem",
					 17);
		else if (id == LOTA_KREAD_FIRMWARE)
			__builtin_memcpy(event->filename, "firmware_mem", 12);
		else if (id == LOTA_KREAD_KEXEC_IMAGE)
			__builtin_memcpy(event->filename, "kexec_image_mem",
					 16);
		else if (id == LOTA_KREAD_POLICY)
			__builtin_memcpy(event->filename, "policy_mem", 10);
		else
			__builtin_memcpy(event->filename, "kernel_data_mem",
					 16);

		bpf_ringbuf_submit(event, 0);
		inc_stat(STAT_EVENTS_SENT);
	} else if (emit_event) {
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
 *   - Manual mmap of shellcode from files (including RWX/COW abuse)
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
	     unsigned long prot, unsigned long flags, int ret)
{
	u32 mode;
	int blocked = 0;

	/* dont interfere with previous hook denial */
	if (ret != 0)
		return -EPERM;

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
		int emit_event = 0;

		inc_stat(STAT_ANON_EXEC);

		mode = get_mode();

		/* must be NULL: read below even when the event budget
		 * skips the reserve */
		struct lota_exec_event *event = NULL;

		if (mode == LOTA_MODE_ENFORCE &&
		    get_config(LOTA_CFG_BLOCK_ANON_EXEC) &&
		    is_protected_current_task()) {
			anon_blocked = 1;
		}

		emit_event = should_emit_event(
			mode, anon_blocked,
			anon_blocked ? LOTA_EVENT_ANON_EXEC_BLOCKED :
				       LOTA_EVENT_ANON_EXEC);
		if (emit_event) {
			event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
		}
		if (event) {
			__builtin_memset(event, 0, sizeof(*event));
			event->timestamp_ns = bpf_ktime_get_ns();
			event->event_type =
				anon_blocked ? LOTA_EVENT_ANON_EXEC_BLOCKED :
					       LOTA_EVENT_ANON_EXEC;
			event->tgid = bpf_get_current_pid_tgid() >> 32;
			event->pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
			event->uid =
				(u32)(bpf_get_current_uid_gid() & 0xFFFFFFFF);

			bpf_get_current_comm(event->comm, sizeof(event->comm));
			__builtin_memcpy(event->filename, "(anon-exec)", 12);

			bpf_ringbuf_submit(event, 0);
			inc_stat(STAT_EVENTS_SENT);
		} else if (emit_event) {
			inc_stat(STAT_RINGBUF_DROPS);
		}

		if (anon_blocked) {
			inc_stat(STAT_ANON_EXEC_BLOCKED);
			return -EPERM;
		}

		return 0;
	}

	inc_stat(STAT_MMAP_EXECS);

	/*
	 * Every task, before any verdict: the loader maps most libraries
	 * before the process asks to be protected.
	 */
	remember_mapped_exec(file);
	remember_protected_exec(file);

	mode = get_mode();

	/*
	 * In ENFORCE mode with strict mmap enabled, block executable mmaps
	 * from untrusted sources. Scoped to protected_pids: a task that
	 * has not opted in via LOTA_IPC_CMD_PROTECT_PID (or the
	 * --protect-pid CLI/config knob) bypasses the verdict and is
	 * logged only. Keeps enforce-mode safe to enable host-wide
	 * without a complete trust set.
	 */
	if (mode == LOTA_MODE_ENFORCE && get_config(LOTA_CFG_STRICT_MMAP) &&
	    is_protected_current_task()) {
		if ((prot & LOTA_PROT_WRITE) || (reqprot & LOTA_PROT_WRITE)) {
			blocked = 1;
		} else if (!is_verity_allowed(file) && !is_trusted_lib(file)) {
			blocked = 1;
		}
	}

	/* for logging */
	struct lota_exec_event *event;
	int emit_event = should_emit_event(mode, blocked,
					   blocked ? LOTA_EVENT_MMAP_BLOCKED :
						     LOTA_EVENT_MMAP_EXEC);
	if (emit_event) {
		event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	} else {
		event = NULL;
	}
	if (event) {
		__builtin_memset(event, 0, sizeof(*event));
		event->timestamp_ns = bpf_ktime_get_ns();
		event->event_type = blocked ? LOTA_EVENT_MMAP_BLOCKED :
					      LOTA_EVENT_MMAP_EXEC;
		if (is_protected_current_task())
			event->flags |= LOTA_EVENT_FLAG_PROTECTED;
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
				ret_path = bpf_probe_read_kernel_str(
					event->filename,
					sizeof(event->filename), name);
			}
		}

		if (ret_path < 0) {
			__builtin_memcpy(event->filename,
					 "(path_resolution_disabled)", 27);
		}

		bpf_ringbuf_submit(event, 0);
		inc_stat(STAT_EVENTS_SENT);
	} else if (emit_event) {
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
	     unsigned long reqprot, unsigned long prot)
{
	struct file *file;
	struct lota_exec_event *event = NULL;
	unsigned long vm_flags;
	u32 mode;
	int blocked = 0;

	(void)reqprot;

	/* only care when resulting mapping is executable */
	if (!(prot & LOTA_PROT_EXEC))
		return 0;

	mode = get_mode();

	/*
	 * Direct field access -- not BPF_CORE_READ -- keeps file as a
	 * trusted PTR_TO_BTF_ID for the bpf_get_fsverity_digest kfunc
	 * call chained through is_verity_allowed(). See the bprm->file
	 * comment in lota_bprm_check_security for the verifier
	 * reasoning behind avoiding the probe-read code path here.
	 */
	file = vma->vm_file;

	if (!file) {
		int anon_blocked = 0;
		int emit_event = 0;

		inc_stat(STAT_ANON_EXEC);

		if (mode == LOTA_MODE_ENFORCE &&
		    get_config(LOTA_CFG_BLOCK_ANON_EXEC) &&
		    is_protected_current_task())
			anon_blocked = 1;

		emit_event = should_emit_event(
			mode, anon_blocked,
			anon_blocked ? LOTA_EVENT_ANON_EXEC_BLOCKED :
				       LOTA_EVENT_ANON_EXEC);
		if (emit_event) {
			event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
		}
		if (event) {
			__builtin_memset(event, 0, sizeof(*event));
			event->timestamp_ns = bpf_ktime_get_ns();
			event->event_type =
				anon_blocked ? LOTA_EVENT_ANON_EXEC_BLOCKED :
					       LOTA_EVENT_ANON_EXEC;
			event->tgid = bpf_get_current_pid_tgid() >> 32;
			event->pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
			event->uid =
				(u32)(bpf_get_current_uid_gid() & 0xFFFFFFFF);

			bpf_get_current_comm(event->comm, sizeof(event->comm));
			__builtin_memcpy(event->filename,
					 "(anon-mprotect-exec)", 20);

			bpf_ringbuf_submit(event, 0);
			inc_stat(STAT_EVENTS_SENT);
		} else if (emit_event) {
			inc_stat(STAT_RINGBUF_DROPS);
		}

		if (anon_blocked) {
			inc_stat(STAT_ANON_EXEC_BLOCKED);
			return -EPERM;
		}

		return 0;
	}

	inc_stat(STAT_MMAP_EXECS);
	vm_flags = BPF_CORE_READ(vma, vm_flags);

	/* mprotect(PROT_EXEC) maps code too */
	remember_mapped_exec(file);
	remember_protected_exec(file);

	/*
	 * mprotect(PROT_EXEC) on a file-backed VMA closes the W^X bypass
	 * where an attacker maps RW first and upgrades to executable later.
	 * Same scoping as lota_mmap_file: enforce against protected_pids
	 * only, so unscoped processes never trip the gate.
	 */
	if (mode == LOTA_MODE_ENFORCE && get_config(LOTA_CFG_STRICT_MMAP) &&
	    is_protected_current_task()) {
		if (vm_flags & (VM_WRITE | VM_MAYWRITE)) {
			blocked = 1;
		} else if (!is_verity_allowed(file) && !is_trusted_lib(file)) {
			blocked = 1;
		}
	}

	{
		int emit_event =
			should_emit_event(mode, blocked,
					  blocked ? LOTA_EVENT_MMAP_BLOCKED :
						    LOTA_EVENT_MMAP_EXEC);
		if (emit_event) {
			event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
		}
		if (event) {
			__builtin_memset(event, 0, sizeof(*event));
			event->timestamp_ns = bpf_ktime_get_ns();
			event->event_type = blocked ? LOTA_EVENT_MMAP_BLOCKED :
						      LOTA_EVENT_MMAP_EXEC;
			if (is_protected_current_task())
				event->flags |= LOTA_EVENT_FLAG_PROTECTED;
			event->tgid = bpf_get_current_pid_tgid() >> 32;
			event->pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
			event->uid =
				(u32)(bpf_get_current_uid_gid() & 0xFFFFFFFF);

			bpf_get_current_comm(event->comm, sizeof(event->comm));

			struct dentry *dentry =
				BPF_CORE_READ(file, f_path.dentry);
			const unsigned char *name = NULL;
			int ret_path = -1;

			if (dentry) {
				name = BPF_CORE_READ(dentry, d_name.name);
				if (name) {
					ret_path = bpf_probe_read_kernel_str(
						event->filename,
						sizeof(event->filename), name);
				}
			}

			if (ret_path < 0) {
				__builtin_memcpy(
					event->filename,
					"(mprotect-path_resolution_disabled)",
					35);
			}

			bpf_ringbuf_submit(event, 0);
			inc_stat(STAT_EVENTS_SENT);
		} else if (emit_event) {
			inc_stat(STAT_RINGBUF_DROPS);
		}
	}

	if (blocked) {
		inc_stat(STAT_MMAP_BLOCKED);
		return -EPERM;
	}

	return 0;
}

/* ======================================================================
 * Who reached a process of an instance
 *
 * instance_peers records, per instance, every process that reached one of
 * its processes on a road the gate lets through:
 *
 *   - a process outside the instance that connects to, or sends to, a unix
 *     socket a process of the instance created, bound or listens on: a
 *     process of the instance can act on a request that came that way;
 *   - a process of the instance that ptrace-accesses another one, or
 *     signals it: what the wineserver does to the processes it hosts, and
 *     what the gate allows inside an instance and refuses from outside.
 *
 * Nothing is refused here.
 * ====================================================================== */
static __always_inline void mark_instance_socket(struct sock *sk)
{
	struct lota_instance_entry id = {};
	struct lota_sock_owner *owner;
	struct task_struct *task;

	if (!sk || BPF_CORE_READ(sk, __sk_common.skc_family) != AF_UNIX)
		return;

	task = (struct task_struct *)bpf_get_current_task_btf();
	if (!task || !task_instance(task, &id))
		return;

	owner = bpf_sk_storage_get(&lota_sock_owner, sk, 0,
				   BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!owner) {
		inc_stat(STAT_INSTANCE_PEERS_LOST);
		return;
	}
	if (owner->tgid)
		return;

	owner->id = id;
	bpf_get_current_comm(owner->comm, sizeof(owner->comm));
	owner->tgid = BPF_CORE_READ(task, tgid);
}

/*
 * Count one reach of @task into process @owner_tgid, named @owner_comm,
 * of the instance @root.
 */
static __always_inline void
note_instance_peer(struct task_struct *task,
		   const struct lota_instance_entry *root, u32 owner_tgid,
		   const char *owner_comm, u32 kind)
{
	struct lota_instance_peer_key key = {};
	struct lota_instance_peer_val val = {};
	struct trusted_lib_key ik = {};
	struct lota_instance_peer_val *seen;
	struct task_struct *leader;
	long err;

	leader = BPF_CORE_READ(task, group_leader);
	key.root_start_ticks = root->root_start_ticks;
	key.root_tgid = root->root_tgid;
	key.peer_tgid = BPF_CORE_READ(task, tgid);
	key.peer_start_ticks = get_task_start_ticks(leader ? leader : task);
	key.owner_tgid = owner_tgid;
	key.kind = kind;

	seen = bpf_map_lookup_elem(&instance_peers, &key);
	if (seen) {
		__sync_fetch_and_add(&seen->count, 1);
		return;
	}

	val.count = 1;
	if (file_inode_key(BPF_CORE_READ(task, mm, exe_file), &ik)) {
		val.exe_dev = ik.dev;
		val.exe_ino = ik.ino;
	}
	val.uid = (u32)(bpf_get_current_uid_gid() & 0xFFFFFFFF);
	bpf_get_current_comm(val.comm, sizeof(val.comm));
	__builtin_memcpy(val.owner_comm, owner_comm, sizeof(val.owner_comm));

	err = bpf_map_update_elem(&instance_peers, &key, &val, BPF_NOEXIST);
	if (err == -EEXIST) {
		seen = bpf_map_lookup_elem(&instance_peers, &key);
		if (seen)
			__sync_fetch_and_add(&seen->count, 1);
	} else if (err) {
		inc_stat(STAT_INSTANCE_PEERS_LOST);
	}
}

/* @other was reached from the current task; counted when from outside */
static __always_inline void record_instance_peer(struct sock *other, u32 kind)
{
	struct lota_instance_entry id = {};
	struct lota_sock_owner *owner;
	struct task_struct *task;

	if (!other)
		return;
	owner = bpf_sk_storage_get(&lota_sock_owner, other, 0, 0);
	if (!owner || !owner->tgid)
		return;

	task = (struct task_struct *)bpf_get_current_task_btf();
	if (!task)
		return;
	if (lota_inside_instance(task_instance(task, &id), id.root_tgid,
				 id.root_start_ticks, 1, owner->id.root_tgid,
				 owner->id.root_start_ticks))
		return;

	note_instance_peer(task, &owner->id, owner->tgid, owner->comm, kind);
}

/* @target of instance @root was reached from the current task, inside it */
static __always_inline void
record_instance_access(struct task_struct *target,
		       const struct lota_instance_entry *root, u32 kind)
{
	char target_comm[LOTA_MAX_COMM_LEN] = {};
	struct task_struct *task;

	task = (struct task_struct *)bpf_get_current_task_btf();
	if (!task)
		return;
	bpf_probe_read_kernel_str(target_comm, sizeof(target_comm),
				  &target->comm);
	note_instance_peer(task, root, BPF_CORE_READ(target, tgid), target_comm,
			   kind);
}

/* ======================================================================
 * LSM hook: security_ptrace_access_check
 *
 * Called when one process attempts to trace/debug another via ptrace,
 * and by procfs for a read of another process's /proc.
 *
 * Ptrace on the agent and on protected PIDs is blocked in every mode,
 * except between two processes of one instance, which is logged.
 * In ENFORCE mode an attach on any other task is blocked while
 * block_ptrace is set; otherwise it is logged.
 *
 * @child: The process being traced (target)
 * @mode: PTRACE_MODE_* flags (read, attach, etc)
 *
 * Return: 0 to allow, -EPERM to deny
 * ====================================================================== */
SEC("lsm/ptrace_access_check")
int BPF_PROG(lota_ptrace_access_check, struct task_struct *child,
	     unsigned int mode, int ret)
{
	struct lota_instance_entry target_id = {};
	struct lota_instance_entry actor_id = {};
	struct lota_exec_event *event = NULL;
	struct task_struct *current;
	int target_protected;
	int inside = 0;
	u32 lota_mode;
	u32 child_pid;
	int blocked = 0;
	int emit_event = 0;

	/* dont interfere with previous hook denial */
	if (ret != 0)
		return -EPERM;

	lota_mode = get_mode();

	child_pid = BPF_CORE_READ(child, pid);

	/* the agent's own read exemption; see lota_ptrace_agent_read_exempt() */
	if (lota_ptrace_agent_read_exempt(mode, is_current_lota_agent_task())) {
		inc_stat(STAT_PTRACE_ATTEMPTS);
		return 0;
	}

	target_protected = task_instance(child, &target_id);
	if (target_protected) {
		current = (struct task_struct *)bpf_get_current_task_btf();
		inside = lota_inside_instance(
			task_instance(current, &actor_id), actor_id.root_tgid,
			actor_id.root_start_ticks, target_protected,
			target_id.root_tgid, target_id.root_start_ticks);
	}

	blocked = lota_ptrace_denied(mode, lota_mode,
				     get_config(LOTA_CFG_BLOCK_PTRACE),
				     is_lota_agent_task(child),
				     target_protected && !inside);

	/* for logging */
	emit_event = should_emit_event(lota_mode, blocked,
				       blocked ? LOTA_EVENT_PTRACE_BLOCKED :
						 LOTA_EVENT_PTRACE);
	if (emit_event) {
		event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	}
	if (event) {
		__builtin_memset(event, 0, sizeof(*event));
		event->timestamp_ns = bpf_ktime_get_ns();
		event->event_type = blocked ? LOTA_EVENT_PTRACE_BLOCKED :
					      LOTA_EVENT_PTRACE;
		if (inside)
			event->flags |= LOTA_EVENT_FLAG_INSIDE_INSTANCE;
		event->tgid = bpf_get_current_pid_tgid() >> 32;
		event->pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
		event->uid = (u32)(bpf_get_current_uid_gid() & 0xFFFFFFFF);
		event->target_pid = child_pid;

		bpf_get_current_comm(event->comm, sizeof(event->comm));

		/* try to get the target process name */
		const char *child_comm = BPF_CORE_READ(child, comm);
		if (child_comm) {
			bpf_probe_read_kernel_str(
				event->filename, LOTA_MAX_COMM_LEN, child_comm);
		}

		bpf_ringbuf_submit(event, 0);
		inc_stat(STAT_EVENTS_SENT);
	} else if (emit_event) {
		inc_stat(STAT_RINGBUF_DROPS);
	}

	if (blocked) {
		inc_stat(STAT_PTRACE_BLOCKED);
		return -EPERM;
	}

	/* the ring buffer drops; the instance's record does not */
	if (inside)
		record_instance_access(
			child, &target_id,
			lota_ptrace_is_attach(mode) ?
				LOTA_INSTANCE_PEER_PTRACE_ATTACH :
				LOTA_INSTANCE_PEER_PTRACE_READ);

	return 0;
}

/* ======================================================================
 * LSM hook: task_kill
 *
 * Blocks signal delivery to the agent from foreign tasks, and records every
 * signal at the agent or a protected task.
 *
 * SECURITY: Never trust sender PID/namespace for privileged signal paths.
 * Only authenticated LOTA task identities and kernel-generated signals can
 * bypass protected-target signal restrictions.
 * ====================================================================== */
SEC("lsm/task_kill")
int BPF_PROG(lota_task_kill, struct task_struct *p, struct kernel_siginfo *info,
	     int sig, const struct cred *cred)
{
	struct lota_instance_entry target_id = {};
	struct lota_instance_entry sender_id = {};
	struct task_struct *current;
	u32 sender_tgid;
	u32 target_tgid;
	u32 lota_mode;
	int target_is_agent;
	int target_is_protected = 0;
	int blocked;
	int event_type;
	int emit_event;
	struct lota_exec_event *event = NULL;

	(void)cred;

	if (!p)
		return 0;

	lota_mode = get_mode();
	target_is_agent = is_lota_agent_task(p);
	if (!target_is_agent)
		target_is_protected = task_instance(p, &target_id);

	if (!target_is_agent && !target_is_protected)
		return 0;

	sender_tgid = (u32)(bpf_get_current_pid_tgid() >> 32);
	target_tgid = BPF_CORE_READ(p, tgid);

	/* allow self-signals */
	if (sender_tgid == target_tgid)
		return 0;

	current = (struct task_struct *)bpf_get_current_task_btf();
	if (!current)
		return 0;

	if (is_lota_agent_task(current) || is_bpf_admin_task())
		return 0;

	/* allow kernel-generated signals */
	if (!info)
		return 0;
	{
		int si_code = BPF_CORE_READ(info, si_code);
		if (si_code == SI_KERNEL)
			return 0;
	}

	/* a signal between two processes of one instance is in its record */
	if (sig && target_is_protected &&
	    lota_inside_instance(
		    task_instance(current, &sender_id), sender_id.root_tgid,
		    sender_id.root_start_ticks, 1, target_id.root_tgid,
		    target_id.root_start_ticks))
		record_instance_access(p, &target_id,
				       LOTA_INSTANCE_PEER_SIGNAL);

	/* the verdict lives in include/lota.h, shared with the tests */
	blocked = lota_signal_denied(sig, target_is_agent);

	/* report every signal but a permitted probe, which is only counted */
	event_type = lota_signal_event(sig, blocked);
	if (!event_type) {
		inc_stat(STAT_KILL_PROBES);
		return 0;
	}

	emit_event = should_emit_event(lota_mode, blocked, event_type);
	if (emit_event)
		event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (event) {
		__builtin_memset(event, 0, sizeof(*event));
		event->timestamp_ns = bpf_ktime_get_ns();
		event->event_type = (u32)event_type;
		event->tgid = sender_tgid;
		event->pid = (u32)(bpf_get_current_pid_tgid() & 0xFFFFFFFF);
		event->uid = (u32)(bpf_get_current_uid_gid() & 0xFFFFFFFF);
		event->target_pid = target_tgid;
		event->signal = (u32)sig;

		bpf_get_current_comm(event->comm, sizeof(event->comm));
		__builtin_memcpy(event->filename, "(kill)", 6);

		bpf_ringbuf_submit(event, 0);
		inc_stat(STAT_EVENTS_SENT);
	} else if (emit_event) {
		inc_stat(STAT_RINGBUF_DROPS);
	}

	if (blocked)
		return -EPERM;

	return 0;
}

/* ======================================================================
 * Unix sockets of an instance: the sockets carry it, a reach from outside
 * is counted (record_instance_peer())
 * ====================================================================== */
SEC("lsm/socket_post_create")
int BPF_PROG(lota_socket_post_create, struct socket *sock, int family, int type,
	     int protocol, int kern, int ret)
{
	if (ret || kern || family != AF_UNIX || !sock)
		return ret;
	mark_instance_socket(sock->sk);
	return 0;
}

SEC("lsm/socket_bind")
int BPF_PROG(lota_socket_bind, struct socket *sock, struct sockaddr *address,
	     int addrlen, int ret)
{
	if (ret || !sock)
		return ret;
	mark_instance_socket(sock->sk);
	return 0;
}

SEC("lsm/socket_listen")
int BPF_PROG(lota_socket_listen, struct socket *sock, int backlog, int ret)
{
	if (ret || !sock)
		return ret;
	mark_instance_socket(sock->sk);
	return 0;
}

SEC("lsm/unix_stream_connect")
int BPF_PROG(lota_unix_stream_connect, struct sock *sock, struct sock *other,
	     struct sock *newsk, int ret)
{
	if (ret)
		return ret;
	record_instance_peer(other, LOTA_INSTANCE_PEER_CONNECT);
	return 0;
}

SEC("lsm/unix_may_send")
int BPF_PROG(lota_unix_may_send, struct socket *sock, struct socket *other,
	     int ret)
{
	if (ret || !other)
		return ret;
	record_instance_peer(other->sk, LOTA_INSTANCE_PEER_SEND);
	return 0;
}

/* ======================================================================
 * LSM hook: task_alloc
 *
 * A process created by a protected one is marked here, before it first
 * runs. If the mark cannot be stored the clone fails: a child that runs
 * unprotected is the window this closes. A protected process held by a
 * tracer outside its instance creates nothing, threads included, since
 * the tracer would follow it into the child.
 * ====================================================================== */
SEC("lsm/task_alloc")
int BPF_PROG(lota_task_alloc, struct task_struct *task,
	     unsigned long clone_flags, int ret)
{
	struct lota_instance_entry id = {};
	struct lota_instance_entry *entry;
	struct task_struct *current;
	int creator_protected;
	int tracer_inside;
	int traced;

	if (ret != 0)
		return ret;

	current = (struct task_struct *)bpf_get_current_task_btf();
	creator_protected = task_instance(current, &id);
	if (!creator_protected)
		return 0;

	tracer_inside = task_tracer_inside(current, &id, &traced);
	if (lota_clone_refused(creator_protected, traced, tracer_inside))
		return -EPERM;

	if (!lota_clone_inherits_protection(clone_flags, creator_protected))
		return 0;

	entry = bpf_task_storage_get(&lota_instance, task, 0,
				     BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!entry)
		return -ENOMEM;

	entry->root_start_ticks = id.root_start_ticks;
	entry->root_tgid = id.root_tgid;
	return 0;
}

/* ======================================================================
 * LSM hook: task_free
 *
 * Called when task exits and resources are being freed.
 * Removes stale protected PID entries to reduce residency window and
 * prevent stale metadata accumulation.
 * ====================================================================== */
SEC("lsm/task_free")
int BPF_PROG(lota_task_free, struct task_struct *task)
{
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
	     int flags, int ret)
{
	struct lota_exec_event *event;
	u32 old_uid, new_uid;

	/* dont interfere with previous hook denial */
	if (ret != 0)
		return -EPERM;

	old_uid = BPF_CORE_READ(old, uid.val);
	new_uid = BPF_CORE_READ(new, uid.val);

	/* only log actual UID changes, not no-ops */
	if (old_uid == new_uid)
		return 0;

	inc_stat(STAT_SETUID_EVENTS);

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
 * LSM hook: bpf_map
 *
 * Per-map policy hook invoked when creating a userspace FD for a BPF map.
 * Under LOCK_BPF, deny write-capable FDs for LOTA-owned maps unless caller
 * matches the authorized LOTA BPF admin identity.
 *
 * This keeps non-LOTA eBPF userspace intact while preventing runtime tampering
 * of LOTA map state.
 * ====================================================================== */
SEC("lsm/bpf_map")
int BPF_PROG(lota_bpf_map, struct bpf_map *map, fmode_t fmode, int ret)
{
	(void)fmode;

	if (ret != 0)
		return -EPERM;

	if (!map)
		return 0;

	if (!get_config(LOTA_CFG_LOCK_BPF))
		return 0;

	if (is_bpf_admin_task())
		return 0;

	if (!is_lota_managed_map(map))
		return 0;

	inc_stat(STAT_BPF_SYSCALL_BLOCKED);
	return -EPERM;
}

/* ======================================================================
 * LSM hook: bpf
 *
 * Keep global bpf() hook non-invasive. Object-specific access control is
 * enforced in lota_bpf_map where map identity is available. The exception is
 * BPF_LINK_DETACH, which takes a program off its hook and names its link by a
 * descriptor the caller can swap after this hook read it, so one link cannot
 * be told from another here.
 * ====================================================================== */
SEC("lsm/bpf")
int BPF_PROG(lota_bpf, int cmd, union bpf_attr *attr, unsigned int size,
	     int ret)
{
	(void)size;
	(void)attr;

	/*
	 * Unlike most LSM programs, the in-kernel LSM hook prototype for
	 * bpf() does not include a 'ret' argument; the 'ret' parameter
	 * here is the BPF trampoline's current return value across chained
	 * LSM programs.
	 *
	 * Returning the trampoline 'ret' verbatim (`return ret;`) is
	 * rejected by the verifier when this hook has no other code paths:
	 * clang collapses the body to `r0 = *(ctx + 24)` and the verifier
	 * leaves R0 as an unconstrained scalar
	 *   "At program exit the register R0 has smin=0 smax=4294967295,
	 *    should have been in [-4095, 0]".
	 * A clamp written in C
	 *   if (r > 0) r = 0; if (r < -4095) r = -EPERM;
	 * still goes through alu32 ops and zero-extends -1 into
	 * 0x00000000FFFFFFFF (umax=4294967295), so the same rejection
	 * fires.
	 *
	 * The hook is non-invasive: it only needs to preserve a prior
	 * denial as a denial, not the exact errno of the upstream hook.
	 * Map both branches to compile-time constants so the verifier
	 * sees R0 as either 0 or -EPERM and trivially bounds it inside
	 * [-MAX_ERRNO, 0].
	 */
	if (ret != 0)
		return -EPERM;

	if (cmd == BPF_LINK_DETACH && get_config(LOTA_CFG_LOCK_BPF) &&
	    !is_bpf_admin_task()) {
		inc_stat(STAT_BPF_SYSCALL_BLOCKED);
		return -EPERM;
	}
	return 0;
}

/* =====================================================================
 * Tracepoint: cgroup_attach_task
 *
 * Moving a task between cgroups has no security hook. A move of the agent
 * takes it out of the cgroup whose cgroup.kill and cgroup.freeze the loader
 * guarded, so the guard follows it: agent_cgroups records the destination
 * and its ancestors, and lota_file_open refuses their files the same way.
 * The move itself is journalled.
 * ===================================================================== */
SEC("tp_btf/cgroup_attach_task")
int BPF_PROG(lota_cgroup_attach_task, struct cgroup *dst_cgrp, const char *path,
	     struct task_struct *task, bool threadgroup)
{
	struct lota_exec_event *event;
	int level;

	if (!dst_cgrp || !is_lota_agent_task(task))
		return 0;

	level = BPF_CORE_READ(dst_cgrp, level);
	for (u32 i = 0; i < LOTA_AGENT_CGROUP_DEPTH; i++) {
		struct cgroup *anc = NULL;
		u32 key = i;
		u64 id = 0;

		if ((int)i <= level) {
			bpf_core_read(&anc, sizeof(anc),
				      &dst_cgrp->ancestors[i]);
			if (anc)
				id = BPF_CORE_READ(anc, kn, id);
		}
		bpf_map_update_elem(&agent_cgroups, &key, &id, BPF_ANY);
	}

	/* a threadgroup move visits every thread; report the process once */
	if (BPF_CORE_READ(task, pid) != BPF_CORE_READ(task, tgid))
		return 0;

	if (!should_emit_event(LOTA_MODE_ENFORCE, 1, LOTA_EVENT_AGENT_MOVED))
		return 0;

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		inc_stat(STAT_RINGBUF_DROPS);
		return 0;
	}

	__builtin_memset(event, 0, sizeof(*event));
	event->timestamp_ns = bpf_ktime_get_ns();
	event->event_type = LOTA_EVENT_AGENT_MOVED;
	event->tgid = bpf_get_current_pid_tgid() >> 32;
	event->pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
	event->uid = (u32)(bpf_get_current_uid_gid() & 0xFFFFFFFF);
	event->target_pid = BPF_CORE_READ(task, tgid);
	bpf_get_current_comm(event->comm, sizeof(event->comm));
	if (path)
		bpf_probe_read_kernel_str(event->filename,
					  sizeof(event->filename), path);

	bpf_ringbuf_submit(event, 0);
	inc_stat(STAT_EVENTS_SENT);
	return 0;
}
