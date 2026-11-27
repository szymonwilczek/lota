/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * LOTA - BPF LSM and tracing programs of the agent.
 *
 * Copyright (C) 2026 Szymon Wilczek
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
#ifndef PF_EXITING
#define PF_EXITING 0x00000004
#endif

#ifndef MS_BIND
#define MS_BIND 4096
#endif

#ifndef MS_MOVE
#define MS_MOVE 8192
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

#ifndef S_PRIVATE
#define S_PRIVATE (1 << 9)
#endif

#ifndef VM_WRITE
#define VM_WRITE 0x00000002
#endif
#ifndef VM_MAYWRITE
#define VM_MAYWRITE 0x00000020
#endif

#define LOTA_PROT_EXEC 0x4
#define LOTA_PROT_WRITE 0x2

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, LOTA_RINGBUF_SIZE);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 25);
	__type(key, u32);
	__type(value, u64);
} stats SEC(".maps");

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
#define STAT_INSTANCE_ACTORS_LOST \
	23 /* reach into an instance socket unrecorded */
#define STAT_INSTANCE_STOPS_LOST 24 /* stop of an instance thread unrecorded */

/* a window per event type, so a flooding type spends only its own */
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
 * Set on a process whose image was executed under protection: its history
 * starts before the first mapping of that image. A fork does not take it, the
 * parent's history can die with the parent; the agent drops it with protection.
 */
struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, u32);
} born_protected SEC(".maps");

/*
 * How long instance threads stood stopped, held on the root task. The clock
 * runs while at least one thread stands: since_ns is when the first stopped,
 * total_ns what ended periods add up to. bpf_ktime_get_ns() skips a suspend.
 */
struct lota_instance_stops {
	struct bpf_spin_lock lock;
	u32 stopped_threads;
	u64 since_ns;
	u64 total_ns;
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct lota_instance_stops);
} instance_stops SEC(".maps");

/*
 * The last executable mapping refused a process, held on its group leader.
 * The agent reads it through the caller's pidfd, under the lock: a process
 * that takes the PID later is another task and has none.
 */
struct lota_refusal_entry {
	struct bpf_spin_lock lock;
	u32 pad;
	u64 at_ns;
	char object[LOTA_MAX_PATH_LEN];
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct lota_refusal_entry);
} lota_refusal SEC(".maps");

/*
 * Scratch holds what the kernel writes and the key built from it.
 * The kernel fills a struct fsverity_digest -- header, then digest
 * -- so the raw buffer is not itself a key.
 */
struct lota_verity_scratch {
	__u8 buf[LOTA_FSVERITY_DIGEST_BUF_SIZE];
	struct lota_verity_digest_key key;
};

/* the verifier takes only a map value as bpf_dynptr_from_mem() data */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct lota_verity_scratch);
} verity_scratch SEC(".maps");

/* keyed by TGID, bound to one process by /proc/<tgid>/stat field 22 */
struct protected_pid_entry {
	u64 start_time_ticks;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, LOTA_MAX_PROTECTED_PIDS);
	__type(key, u32);
	__type(value, struct protected_pid_entry);
} protected_pids SEC(".maps");

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

/* cgroup.kill and cgroup.freeze of the agent's cgroups, valued LOTA_GUARD_* */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, LOTA_MAX_GUARDED_FILES);
	__type(key, struct trusted_lib_key);
	__type(value, u32);
} guarded_files SEC(".maps");

/*
 * Libraries the agent pinned for a protected process; lota_file_open refuses
 * their write opens, as the kernel does for a running executable.
 * Renaming over one works.
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

/* see struct lota_exec_history_key; plain hash, a full map counts a loss */
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

/* see struct lota_instance_actor_key; plain hash, a full map counts a loss */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, LOTA_MAX_INSTANCE_ACTORS);
	__type(key, struct lota_instance_actor_key);
	__type(value, struct lota_instance_actor_val);
} instance_actors SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct lota_verity_digest_key);
	__type(value, u32);
} allow_verity SEC(".maps");

/*
 * Kernel content hashes the agent asked for, keyed by thread id.
 * bpf_ima_file_hash() needs the struct file, so the agent marks its slot
 * ASKED, opens the file and reads the answer back. The thread id ties an
 * answer to the open that asked; an inode key from stat(2) carries another
 * device on a filesystem with a device per subvolume.
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
extern struct task_struct *bpf_task_acquire(struct task_struct *p) __ksym;
extern void bpf_task_release(struct task_struct *p) __ksym;
extern int bpf_send_signal_task(struct task_struct *task, int sig,
				enum pid_type type, u64 value) __ksym;
extern int bpf_iter_task_new(struct bpf_iter_task *it, struct task_struct *task,
			     unsigned int flags) __ksym;
extern struct task_struct *bpf_iter_task_next(struct bpf_iter_task *it) __ksym;
extern void bpf_iter_task_destroy(struct bpf_iter_task *it) __ksym;

extern int bpf_get_fsverity_digest(struct file *file,
				   struct bpf_dynptr *digest_p) __ksym;

static __always_inline void inc_stat(u32 idx)
{
	u64 *val = bpf_map_lookup_elem(&stats, &idx);
	if (val)
		__sync_fetch_and_add(val, 1);
}

static __always_inline u32 get_mode(void)
{
	u32 key = LOTA_CFG_MODE;
	u32 *mode = bpf_map_lookup_elem(&lota_config, &key);
	return mode ? *mode : LOTA_MODE_ENFORCE;
}

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

static __always_inline u32 get_config(u32 key)
{
	u32 *val = bpf_map_lookup_elem(&lota_config, &key);
	return val ? *val : 0;
}

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
	 * Every CPU shares the entry. One wins the CMPXCHG and zeroes the
	 * counter; a caller racing it charges the old window, so a window
	 * can overshoot by the callers in flight during the flip.
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
	 * A direct read keeps group_leader a trusted pointer for
	 * bpf_task_storage_get(); BPF_CORE_READ() yields a scalar.
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

/* @map is one of the maps this object declares in .maps */
static __always_inline int is_lota_managed_map(struct bpf_map *map)
{
	return map == (struct bpf_map *)&events ||
	       map == (struct bpf_map *)&stats ||
	       map == (struct bpf_map *)&lota_config ||
	       map == (struct bpf_map *)&integrity_cfg ||
	       map == (struct bpf_map *)&event_budget ||
	       map == (struct bpf_map *)&lota_task_auth ||
	       map == (struct bpf_map *)&lota_instance ||
	       map == (struct bpf_map *)&born_protected ||
	       map == (struct bpf_map *)&instance_stops ||
	       map == (struct bpf_map *)&lota_refusal ||
	       map == (struct bpf_map *)&verity_scratch ||
	       map == (struct bpf_map *)&protected_pids ||
	       map == (struct bpf_map *)&trusted_libs ||
	       map == (struct bpf_map *)&guarded_files ||
	       map == (struct bpf_map *)&mapped_exec ||
	       map == (struct bpf_map *)&mapped_seen ||
	       map == (struct bpf_map *)&exec_history ||
	       map == (struct bpf_map *)&lota_sock_owner ||
	       map == (struct bpf_map *)&instance_actors ||
	       map == (struct bpf_map *)&allow_verity ||
	       map == (struct bpf_map *)&exe_hash_slots;
}

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

/* LOTA_GUARD_* of @file, or 0 */
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
 * Enforcement map key of a file. s_dev differs from stat(2)'s st_dev on a
 * filesystem with a device per subvolume.
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

/* the kernel's I_CTIME_QUERIED: the first stat since a change sets this bit */
#define LOTA_CTIME_NSEC_MASK 0x7fffffff

/* enough to tell a file from one swapped in */
static __always_inline void inode_seen(struct inode *inode,
				       struct lota_mapped_seen *seen)
{
	seen->size = (u64)BPF_CORE_READ(inode, i_size);
	seen->ctime_sec = (u64)BPF_CORE_READ(inode, i_ctime_sec);
	seen->ctime_nsec = (u32)BPF_CORE_READ(inode, i_ctime_nsec) &
			   LOTA_CTIME_NSEC_MASK;
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

/* count a keyed, unpinned file changed since it was mapped or open for write */
static __always_inline void count_pin_refusal(struct lota_exe_hash_slot *slot)
{
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

/* report a refused mount; @what names the mount API that asked */
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

/* enforce mode, strict_mmap: refuse a bind or move onto a trusted library */
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

	if (!(flags & (MS_BIND | MS_MOVE)))
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

	if (flags & MS_BIND)
		report_blocked_mount("bind mount over a trusted file", 31);
	else
		report_blocked_mount("move mount over a trusted file", 31);
	return -EPERM;
}

/* the same refusal for move_mount(2), which lands a mount over @to_path */
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
 * Deny an open of a /proc memory entry (lota_proc_entry_reads_mm()) of the
 * agent or of a protected process from outside it. mm_access() lets
 * CAP_PERFMON read past the ptrace hook, so the open asks the same verdict.
 * Return: 1 to deny, with @target_pid the process refused.
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

/* logged as PTRACE_BLOCKED with the name of the entry or device */
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

/* report a refused write open of a guarded file */
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

/* LOTA_GUARD_* of a refused write open of a guarded file, or 0 */
static __always_inline u32 denies_kill_guard_open(struct file *file)
{
	u32 kind;

	if (!is_write_open_flags(BPF_CORE_READ(file, f_flags)))
		return 0;

	kind = guarded_file_kind(file);
	if (!kind)
		return 0;

	if (!lota_kill_guard_denied(1, 1, sleepable_task_is_agent_or_admin()))
		return 0;

	return kind;
}

/*
 * Refuse opens of kernel memory devices and the /proc entries
 * denies_proc_mm_open() refuses, write opens of guarded files by all but
 * the agent and the admin identity and of pinned files, and in enforce mode
 * with strict_mmap write opens of trusted libraries.
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

	/* refused in every mode */
	if (is_kernel_mem_device(file)) {
		report_blocked_proc_mm(file, 0);
		return -EPERM;
	}

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

	/* a pinned library is unwritable like a running executable */
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
 * to refuse. Refuses a pinned file, and in enforce mode with strict_mmap a
 * trusted library.
 * ===================================================================== */
SEC("lsm/path_truncate")
int BPF_PROG(lota_path_truncate, const struct path *path, int ret)
{
	struct dentry *dentry;
	struct inode *inode;

	if (ret != 0)
		return ret;

	if (!path)
		return 0;

	dentry = BPF_CORE_READ(path, dentry);
	if (!dentry)
		return 0;

	inode = BPF_CORE_READ(dentry, d_inode);
	if (is_inode_mapped_exec_guarded(inode)) {
		report_blocked_mapped_write(dentry);
		return -EPERM;
	}

	if (get_mode() == LOTA_MODE_ENFORCE &&
	    get_config(LOTA_CFG_STRICT_MMAP) && is_trusted_inode(inode))
		return -EPERM;

	return 0;
}

/* =====================================================================
 * LSM hook: file_post_open (sleepable), measurement
 *
 * Hashes the opens the agent asked about, in every mode. The kernel hashes
 * a file by reading it, and on file_open it is not open yet.
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
 * In enforce mode with strict_exec, refuses an exec of a file starting with
 * "#!", of an interpreter a binfmt handler hands the exec to, through a
 * descriptor (fdpath set), and of a file without an fs-verity digest in
 * allow_verity.
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

	/* a direct read keeps bprm->file trusted for the fs-verity kfunc */
	file = bprm->file;

	scratch = bpf_map_lookup_elem(&verity_scratch, &zero);
	if (!scratch)
		return 0;
	__builtin_memset(scratch, 0, sizeof(*scratch));

	if (bpf_get_fsverity_digest && file) {
		struct bpf_dynptr digest_ptr;
		int ret = bpf_dynptr_from_mem(
			scratch->buf, sizeof(scratch->buf), 0, &digest_ptr);
		if (ret == 0) {
			/* 0 on success; a header precedes the digest */
			ret = bpf_get_fsverity_digest(file, &digest_ptr);
			if (ret == 0 &&
			    lota_verity_key_from_digest_buf(scratch->buf,
							    &scratch->key) == 0)
				have_digest = 1;
		}
	}

	if (mode == LOTA_MODE_ENFORCE && get_config(LOTA_CFG_STRICT_EXEC)) {
		/* a binfmt handing off renames interp before the next pass */
		if (is_shebang_binprm(bprm) ||
		    BPF_CORE_READ(bprm, interp) !=
			    BPF_CORE_READ(bprm, filename) ||
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
			 * A direct read keeps the pointer off the stack:
			 * the verifier refuses a write to the slot of the live
			 * dynptr, which BPF_CORE_READ() may reuse.
			 */
			{
				const char *fn = bprm->filename;
				if (fn)
					bpf_probe_read_kernel_str(
						event->filename,
						sizeof(event->filename), fn);
			}

			/* the first LOTA_HASH_SIZE bytes of the digest */
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
		event->uid = 0;

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

/*
 * Count one reach of @task into process @owner_tgid, named @owner_comm,
 * of the instance @root.
 */
static __always_inline void
note_instance_actor(struct task_struct *task,
		    const struct lota_instance_entry *root, u32 owner_tgid,
		    const char *owner_comm, u32 kind)
{
	struct lota_instance_actor_key key = {};
	struct lota_instance_actor_val val = {};
	struct trusted_lib_key ik = {};
	struct lota_instance_actor_val *seen;
	struct task_struct *leader;
	long err;

	leader = BPF_CORE_READ(task, group_leader);
	key.root_start_ticks = root->root_start_ticks;
	key.root_tgid = root->root_tgid;
	key.actor_tgid = BPF_CORE_READ(task, tgid);
	key.actor_start_ticks = get_task_start_ticks(leader ? leader : task);
	key.owner_tgid = owner_tgid;
	key.kind = kind;

	seen = bpf_map_lookup_elem(&instance_actors, &key);
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

	err = bpf_map_update_elem(&instance_actors, &key, &val, BPF_NOEXIST);
	if (err == -EEXIST) {
		seen = bpf_map_lookup_elem(&instance_actors, &key);
		if (seen)
			__sync_fetch_and_add(&seen->count, 1);
	} else if (err) {
		inc_stat(STAT_INSTANCE_ACTORS_LOST);
	}
}

/* the current task made anonymous memory executable, refused or not */
static __always_inline void record_anon_exec(void)
{
	struct lota_instance_entry id = {};
	char comm[LOTA_MAX_COMM_LEN] = {};
	struct task_struct *task;

	task = (struct task_struct *)bpf_get_current_task_btf();
	if (!task || !task_instance(task, &id))
		return;

	bpf_get_current_comm(comm, sizeof(comm));
	note_instance_actor(task, &id, BPF_CORE_READ(task, tgid), comm,
			    LOTA_INSTANCE_ACTOR_ANON_EXEC);
}

/*
 * Memory reached through a file with no name on disk: S_PRIVATE (SysV shm,
 * a shared anonymous mapping), an unlinked tmpfs or hugetlbfs inode (memfd,
 * MAP_HUGETLB) or /dev/zero.
 */
static __always_inline int is_anon_memory_file(struct file *file)
{
	struct inode *inode = BPF_CORE_READ(file, f_inode);
	unsigned long magic;
	dev_t rdev;

	if (!inode)
		return 0;

	if (BPF_CORE_READ(inode, i_flags) & S_PRIVATE)
		return 1;

	if ((BPF_CORE_READ(inode, i_mode) & S_IFMT) == S_IFCHR) {
		rdev = BPF_CORE_READ(inode, i_rdev);
		return lota_dev_major(rdev) == 1 && lota_dev_minor(rdev) == 5;
	}

	magic = BPF_CORE_READ(inode, i_sb, s_magic);
	return (magic == LOTA_TMPFS_MAGIC || magic == LOTA_HUGETLBFS_MAGIC) &&
	       BPF_CORE_READ(inode, __i_nlink) == 0;
}

/*
 * Keep @file as the current process's last refused mapping: its path when
 * @full_path, which only a sleepable hook resolves, else or failing that its
 * name. Not an event, so the event budget does not drop it.
 */
static __always_inline void note_refusal(struct file *file, int full_path)
{
	union {
		char str[LOTA_MAX_PATH_LEN];
		u64 align;
	} object;
	struct lota_refusal_entry *entry;
	const unsigned char *name;
	struct task_struct *task;
	u64 now = bpf_ktime_get_ns();
	long ret = -1;

	__builtin_memset(&object, 0, sizeof(object));
	if (full_path)
		ret = bpf_d_path((struct path *)&file->f_path, object.str,
				 sizeof(object.str));
	if (ret < 0) {
		name = BPF_CORE_READ(file, f_path.dentry, d_name.name);
		if (!name || bpf_probe_read_kernel_str(
				     object.str, sizeof(object.str), name) < 0)
			return;
	}

	task = (struct task_struct *)bpf_get_current_task_btf();
	bpf_rcu_read_lock();
	entry = bpf_task_storage_get(&lota_refusal, auth_subject_task(task), 0,
				     BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (entry) {
		bpf_spin_lock(&entry->lock);
		entry->at_ns = now;
		__builtin_memcpy(entry->object, object.str, sizeof(object.str));
		bpf_spin_unlock(&entry->lock);
	}
	bpf_rcu_read_unlock();
}

/*
 * Anonymous memory made executable: @file is NULL or an is_anon_memory_file().
 * With block_anon_exec a protected task is refused. A memory file reports only
 * its refusal; allowed, it goes on as a file mapping.
 *
 * Return: 1 on a refusal, else 0.
 */
static __always_inline int anon_exec_refused(struct file *file, u32 mode,
					     int mprotect)
{
	struct lota_exec_event *event = NULL;
	const unsigned char *name;
	int blocked = 0;
	int emit_event;
	u32 type;

	inc_stat(STAT_ANON_EXEC);
	record_anon_exec();

	if (mode == LOTA_MODE_ENFORCE && get_config(LOTA_CFG_BLOCK_ANON_EXEC) &&
	    is_protected_current_task())
		blocked = 1;

	if (file && !blocked)
		return 0;

	type = blocked ? LOTA_EVENT_ANON_EXEC_BLOCKED : LOTA_EVENT_ANON_EXEC;
	emit_event = should_emit_event(mode, blocked, type);
	if (emit_event)
		event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (event) {
		__builtin_memset(event, 0, sizeof(*event));
		event->timestamp_ns = bpf_ktime_get_ns();
		event->event_type = type;
		event->tgid = bpf_get_current_pid_tgid() >> 32;
		event->pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
		event->uid = (u32)(bpf_get_current_uid_gid() & 0xFFFFFFFF);

		bpf_get_current_comm(event->comm, sizeof(event->comm));

		name = file ? BPF_CORE_READ(file, f_path.dentry, d_name.name) :
			      NULL;
		if (!name || bpf_probe_read_kernel_str(event->filename,
						       sizeof(event->filename),
						       name) < 0) {
			if (mprotect)
				__builtin_memcpy(event->filename,
						 "(anon-mprotect-exec)", 21);
			else
				__builtin_memcpy(event->filename, "(anon-exec)",
						 12);
		}

		bpf_ringbuf_submit(event, 0);
		inc_stat(STAT_EVENTS_SENT);
	} else if (emit_event) {
		inc_stat(STAT_RINGBUF_DROPS);
	}

	if (blocked) {
		inc_stat(STAT_ANON_EXEC_BLOCKED);
		if (file)
			note_refusal(file, 0);
		return 1;
	}

	return 0;
}

/* ======================================================================
 * LSM hook: mmap_file
 *
 * In enforce mode, for a protected task: with strict_mmap refuses an
 * executable file mapping that is writable or neither in allow_verity nor
 * a trusted library; with block_anon_exec refuses an anonymous one or one
 * of an is_anon_memory_file().
 * ====================================================================== */
SEC("lsm.s/mmap_file")
int BPF_PROG(lota_mmap_file, struct file *file, unsigned long reqprot,
	     unsigned long prot, unsigned long flags, int ret)
{
	u32 mode;
	int blocked = 0;

	if (ret != 0)
		return -EPERM;

	if (!(prot & LOTA_PROT_EXEC))
		return 0;

	if (!file)
		return anon_exec_refused(NULL, get_mode(), 0) ? -EPERM : 0;

	inc_stat(STAT_MMAP_EXECS);

	/*
	 * Every task, before any verdict: the loader maps most libraries
	 * before the process asks to be protected.
	 */
	remember_mapped_exec(file);
	remember_protected_exec(file);

	mode = get_mode();

	if (is_anon_memory_file(file) && anon_exec_refused(file, mode, 0))
		return -EPERM;

	if (mode == LOTA_MODE_ENFORCE && get_config(LOTA_CFG_STRICT_MMAP) &&
	    is_protected_current_task()) {
		if ((prot & LOTA_PROT_WRITE) || (reqprot & LOTA_PROT_WRITE)) {
			blocked = 1;
		} else if (!is_verity_allowed(file) && !is_trusted_lib(file)) {
			blocked = 1;
		}
	}

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

		/* the path names the object the player has to cover */
		int ret_path = bpf_d_path((struct path *)&file->f_path,
					  event->filename,
					  sizeof(event->filename));
		struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
		const unsigned char *name = NULL;

		if (ret_path < 0 && dentry) {
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
		note_refusal(file, 1);
		return -EPERM;
	}

	return 0;
}

/* the file shmem_zero_setup() gives a shared anonymous mapping */
static __always_inline int is_shared_anon_file(struct file *file)
{
	union {
		char str[9];
		u64 word;
	} name = {};
	const unsigned char *dname;

	if (!(BPF_CORE_READ(file, f_inode, i_flags) & S_PRIVATE))
		return 0;

	dname = BPF_CORE_READ(file, f_path.dentry, d_name.name);
	if (bpf_probe_read_kernel_str(name.str, sizeof(name.str), dname) !=
	    sizeof(name.str))
		return 0;

	return name.word == *(const u64 *)"dev/zero";
}

/* ======================================================================
 * LSM hook: file_mprotect
 *
 * The refusals of mmap_file for a protection change to executable; a VMA
 * with VM_WRITE or VM_MAYWRITE counts as writable. A shared anonymous mapping
 * carries a shmem file here, a private /dev/zero mapping its file without
 * vm_ops; both take the anonymous refusals.
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

	if (!(prot & LOTA_PROT_EXEC))
		return 0;

	mode = get_mode();

	/* a direct read keeps vm_file trusted for the fs-verity kfunc */
	file = vma->vm_file;

	if (!file || !BPF_CORE_READ(vma, vm_ops) || is_shared_anon_file(file))
		return anon_exec_refused(NULL, mode, 1) ? -EPERM : 0;

	inc_stat(STAT_MMAP_EXECS);
	vm_flags = BPF_CORE_READ(vma, vm_flags);

	/* mprotect(PROT_EXEC) maps code too */
	remember_mapped_exec(file);
	remember_protected_exec(file);

	if (is_anon_memory_file(file) && anon_exec_refused(file, mode, 1))
		return -EPERM;

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
		note_refusal(file, 0);
		return -EPERM;
	}

	return 0;
}

/* ======================================================================
 * Who reached a process of an instance
 *
 * instance_actors records, per instance, every process that reached one of
 * its processes on a road the gate lets through:
 *
 *   - a process outside the instance that connects to, or sends to, a unix
 *     socket a process of the instance created, bound or listens on: a
 *     process of the instance can act on a request that came that way;
 *   - a process of the instance that ptrace-accesses another one, or
 *     signals it: what the wineserver does to the processes it hosts, and
 *     what the gate allows inside an instance and refuses from outside;
 *   - a process of the instance that makes anonymous memory executable, which
 *     leaves no object behind for the list of objects to name.
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
		inc_stat(STAT_INSTANCE_ACTORS_LOST);
		return;
	}
	if (owner->tgid)
		return;

	owner->id = id;
	bpf_get_current_comm(owner->comm, sizeof(owner->comm));
	owner->tgid = BPF_CORE_READ(task, tgid);
}

/* @other was reached from the current task; counted when from outside */
static __always_inline void record_instance_actor(struct sock *other, u32 kind)
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

	note_instance_actor(task, &owner->id, owner->tgid, owner->comm, kind);
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
	note_instance_actor(task, root, BPF_CORE_READ(target, tgid),
			    target_comm, kind);
}

/* ======================================================================
 * LSM hook: ptrace_access_check
 *
 * procfs asks it too, for a read of another process's /proc. Past the agent's
 * own reads, refuses in every mode an access to the agent and to a protected
 * process from outside its instance; in enforce mode with block_ptrace, any
 * attach.
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

	if (ret != 0)
		return -EPERM;

	inc_stat(STAT_PTRACE_ATTEMPTS);

	lota_mode = get_mode();

	child_pid = BPF_CORE_READ(child, pid);

	if (lota_ptrace_agent_read_exempt(mode, is_current_lota_agent_task()))
		return 0;

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
				LOTA_INSTANCE_ACTOR_PTRACE_ATTACH :
				LOTA_INSTANCE_ACTOR_PTRACE_READ);

	return 0;
}

/* records a signal at the agent or a protected task; label is 8 bytes */
static __always_inline void report_signal(int event_type, int blocked, int sig,
					  u32 target_tgid, const char *label)
{
	struct lota_exec_event *event = NULL;
	u64 pid_tgid = bpf_get_current_pid_tgid();
	int emit_event;

	emit_event = should_emit_event(get_mode(), blocked, event_type);
	if (emit_event)
		event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (event) {
		__builtin_memset(event, 0, sizeof(*event));
		event->timestamp_ns = bpf_ktime_get_ns();
		event->event_type = (u32)event_type;
		event->tgid = (u32)(pid_tgid >> 32);
		event->pid = (u32)pid_tgid;
		event->uid = (u32)(bpf_get_current_uid_gid() & 0xFFFFFFFF);
		event->target_pid = target_tgid;
		event->signal = (u32)sig;

		bpf_get_current_comm(event->comm, sizeof(event->comm));
		__builtin_memcpy(event->filename, label, 8);

		bpf_ringbuf_submit(event, 0);
		inc_stat(STAT_EVENTS_SENT);
	} else if (emit_event) {
		inc_stat(STAT_RINGBUF_DROPS);
	}
}

/* ======================================================================
 * LSM hook: task_kill
 *
 * The verdict of lota_signal_denied() for a signal at the agent or a
 * protected process. A signal within one thread group, from the agent or
 * the admin identity, or the parent-death signal of an exiting parent
 * passes unrecorded.
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
	int target_is_agent;
	int target_is_protected = 0;
	int sender_inside = 0;
	int blocked;
	int event_type;

	(void)cred;

	if (!p)
		return 0;

	target_is_agent = is_lota_agent_task(p);
	if (!target_is_agent)
		target_is_protected = task_instance(p, &target_id);

	if (!target_is_agent && !target_is_protected)
		return 0;

	sender_tgid = (u32)(bpf_get_current_pid_tgid() >> 32);
	target_tgid = BPF_CORE_READ(p, tgid);

	if (sender_tgid == target_tgid)
		return 0;

	current = (struct task_struct *)bpf_get_current_task_btf();
	if (!current)
		return 0;

	if (is_lota_agent_task(current) || is_bpf_admin_task())
		return 0;

	/*
	 * The signal the target asked for when its parent exits. The verifier
	 * holds info non-NULL, and an exiting task sends no other signal that
	 * reaches this hook.
	 */
	if ((BPF_CORE_READ(current, flags) & PF_EXITING) &&
	    sig == BPF_CORE_READ(p, pdeath_signal))
		return 0;

	if (target_is_protected)
		sender_inside = lota_inside_instance(
			task_instance(current, &sender_id), sender_id.root_tgid,
			sender_id.root_start_ticks, 1, target_id.root_tgid,
			target_id.root_start_ticks);

	/* a signal between two processes of one instance is in its record */
	if (sig && sender_inside)
		record_instance_access(p, &target_id,
				       LOTA_INSTANCE_ACTOR_SIGNAL);

	blocked = lota_signal_denied(sig, target_is_agent, sender_inside);

	/* report every signal but a permitted probe, which is only counted */
	event_type = lota_signal_event(sig, blocked);
	if (!event_type) {
		inc_stat(STAT_KILL_PROBES);
		return 0;
	}

	report_signal(event_type, blocked, sig, target_tgid, "(kill)\0");

	if (blocked)
		return -EPERM;

	return 0;
}

/* ======================================================================
 * LSM hook: file_send_sigiotask
 *
 * F_SETOWN and F_SETSIG aim any signal at a task past lota_task_kill. The write
 * raising it can run in softirq, where current says nothing about who aimed it,
 * so the sender counts as outside the instance.
 * ====================================================================== */
SEC("lsm/file_send_sigiotask")
int BPF_PROG(lota_file_send_sigiotask, struct task_struct *tsk,
	     struct fown_struct *fown, int sig)
{
	struct lota_instance_entry id = {};
	int target_is_agent;

	(void)fown;

	target_is_agent = is_lota_agent_task(tsk);
	if (!target_is_agent && !task_instance(tsk, &id))
		return 0;

	if (!lota_sigio_denied(sig, target_is_agent))
		return 0;

	report_signal(LOTA_EVENT_KILL_BLOCKED, 1, sig, BPF_CORE_READ(tsk, tgid),
		      "(sigio)");
	return -EPERM;
}

/* ======================================================================
 * LSM hook: task_setrlimit
 *
 * RLIMIT_CPU has the kernel itself raise SIGXCPU and SIGKILL at the task, which
 * no signal verdict sees, and RLIMIT_CORE widens what a dump writes. Another
 * process's limits are refused from outside its instance.
 * ====================================================================== */
SEC("lsm/task_setrlimit")
int BPF_PROG(lota_task_setrlimit, struct task_struct *p, unsigned int resource,
	     struct rlimit *new_rlim)
{
	struct lota_instance_entry target_id = {};
	struct lota_instance_entry sender_id = {};
	struct task_struct *current;
	u32 target_tgid;
	int target_is_agent;

	(void)new_rlim;
	(void)resource;

	target_is_agent = is_lota_agent_task(p);
	if (!target_is_agent && !task_instance(p, &target_id))
		return 0;

	target_tgid = BPF_CORE_READ(p, tgid);
	if ((u32)(bpf_get_current_pid_tgid() >> 32) == target_tgid)
		return 0;

	current = (struct task_struct *)bpf_get_current_task_btf();
	if (is_lota_agent_task(current) || is_bpf_admin_task())
		return 0;

	if (!target_is_agent &&
	    lota_inside_instance(
		    task_instance(current, &sender_id), sender_id.root_tgid,
		    sender_id.root_start_ticks, 1, target_id.root_tgid,
		    target_id.root_start_ticks))
		return 0;

	report_signal(LOTA_EVENT_KILL_BLOCKED, 1, 0, target_tgid, "(rlimit)");
	return -EPERM;
}

/* ======================================================================
 * Unix sockets of an instance: the sockets carry it, a reach from outside
 * is counted (record_instance_actor())
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
	record_instance_actor(other, LOTA_INSTANCE_ACTOR_CONNECT);
	return 0;
}

SEC("lsm/unix_may_send")
int BPF_PROG(lota_unix_may_send, struct socket *sock, struct socket *other,
	     int ret)
{
	if (ret || !other)
		return ret;
	record_instance_actor(other->sk, LOTA_INSTANCE_ACTOR_SEND);
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
 * The agent's exit: nothing it protects outlives it
 *
 * The agent is what a report rests on, and the programs end with it. Its links
 * close in exit_files(), after this tracepoint, so the signal goes out with
 * every hook still on, whatever ended the agent. A process forking meanwhile
 * adds its child behind the walk, or is refused the fork once signalled.
 * Threads are walked, not leaders: a leader that exited takes no signal, and
 * its group can be running.
 * ====================================================================== */
#define LOTA_TASK_ITER_ALL_THREADS 1

/* where preemption is off the kill goes through a per-CPU slot: -EBUSY, once */
#define LOTA_KILL_TRIES 64
#define LOTA_EBUSY 16

static __always_inline void kill_group(struct task_struct *t)
{
	int i;

	for (i = 0; i < LOTA_KILL_TRIES; i++) {
		if (bpf_send_signal_task(t, LOTA_SIG_KILL, PIDTYPE_TGID, 0) !=
		    -LOTA_EBUSY)
			break;
	}
}

/* end every protected group, and the agent with @with_agent */
static __always_inline void kill_instances(int with_agent)
{
	struct lota_instance_entry id = {};
	struct task_struct *held;
	struct task_struct *t;

	bpf_rcu_read_lock();
	bpf_for_each(task, t, NULL, LOTA_TASK_ITER_ALL_THREADS)
	{
		if (!task_instance_rcu(t, &id) &&
		    !(with_agent && is_lota_agent_task(t)))
			continue;
		held = bpf_task_acquire(t);
		if (!held)
			continue;
		kill_group(held);
		bpf_task_release(held);
	}
	bpf_rcu_read_unlock();
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(lota_agent_exit, struct task_struct *task, bool group_dead)
{
	if (!group_dead || !is_lota_agent_task(task))
		return 0;

	kill_instances(0);
	return 0;
}

/* ======================================================================
 * Tracepoint: signal_deliver
 *
 * A core file is a read of the memory the hooks guard, and a terminal's ^\ or
 * a process's own crash raises the signal with no hook asked. The group's
 * SIGKILL goes out here, before the kernel acts on the default: a group already
 * exiting takes no dump. A signal with a handler is the process's own business.
 * ====================================================================== */
SEC("tp_btf/signal_deliver")
int BPF_PROG(lota_no_core, int sig, struct kernel_siginfo *info,
	     struct k_sigaction *ka)
{
	struct lota_instance_entry id = {};
	struct task_struct *current;

	(void)info;

	if (!lota_signal_dumps(sig) || BPF_CORE_READ(ka, sa.sa_handler))
		return 0;

	current = bpf_get_current_task_btf();
	if (!task_instance(current, &id))
		return 0;

	report_signal(LOTA_EVENT_KILL_BLOCKED, 1, sig,
		      BPF_CORE_READ(current, tgid), "(dump)\0");
	kill_group(current);
	return 0;
}

/* ======================================================================
 * LSM hook: task_free
 *
 * A freed group leader takes its protected_pids entry with it.
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
 * LSM hook: bprm_committed_creds
 *
 * The old image is gone and the new one is not mapped yet, so every object of
 * the new image passes through the history.
 * ====================================================================== */
SEC("lsm/bprm_committed_creds")
int BPF_PROG(lota_bprm_committed_creds, const struct linux_binprm *bprm)
{
	struct task_struct *task;
	u32 *born;

	task = bpf_get_current_task_btf();
	if (!is_protected_task(task))
		return 0;

	born = bpf_task_storage_get(&born_protected, task, 0,
				    BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!born)
		return 0;
	*born = 1;

	/* withdrawn meanwhile: the agent's delete may have run before the create */
	if (!is_protected_task(task))
		bpf_task_storage_delete(&born_protected, task);
	return 0;
}

/* ======================================================================
 * LSM hook: task_fix_setuid
 *
 * Reports a change of the real UID in every mode and refuses none.
 * ====================================================================== */
SEC("lsm/task_fix_setuid")
int BPF_PROG(lota_task_fix_setuid, struct cred *new, const struct cred *old,
	     int flags, int ret)
{
	struct lota_exec_event *event;
	u32 old_uid, new_uid;

	if (ret != 0)
		return -EPERM;

	old_uid = BPF_CORE_READ(old, uid.val);
	new_uid = BPF_CORE_READ(new, uid.val);

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

	return 0;
}

/* ======================================================================
 * LSM hook: bpf_map
 *
 * With lock_bpf, refuses a descriptor of a map is_lota_managed_map() names,
 * in any mode of access, to all but the admin identity.
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
 * With lock_bpf, refuses BPF_LINK_DETACH to all but the admin identity.
 * It names its link by a descriptor the caller can swap after this hook
 * read it, so one link cannot be told from another here.
 * ====================================================================== */
SEC("lsm/bpf")
int BPF_PROG(lota_bpf, int cmd, union bpf_attr *attr, unsigned int size,
	     bool kernel, int ret)
{
	(void)size;
	(void)attr;
	(void)kernel;

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
 * fentry: cgroup_attach_task
 *
 * Moving a task between cgroups has no security hook, and a cgroup frozen
 * before the move freezes what enters it, in either hierarchy: no file guard
 * can stop that. The agent has no reason to move, so a move ends it the way
 * its death does, before the move takes effect. Not the cgroup_attach_task
 * tracepoint: it fires under a spinlock, where one kill per CPU gets out.
 * ===================================================================== */
SEC("fentry/cgroup_attach_task")
int BPF_PROG(lota_agent_moved, struct cgroup *dst_cgrp,
	     struct task_struct *leader, bool threadgroup)
{
	struct lota_exec_event *event;
	const char *name;

	(void)threadgroup;

	if (!is_lota_agent_task(leader))
		return 0;

	event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (event) {
		__builtin_memset(event, 0, sizeof(*event));
		event->timestamp_ns = bpf_ktime_get_ns();
		event->event_type = LOTA_EVENT_AGENT_MOVED;
		event->tgid = bpf_get_current_pid_tgid() >> 32;
		event->pid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
		event->uid = (u32)(bpf_get_current_uid_gid() & 0xFFFFFFFF);
		event->target_pid = BPF_CORE_READ(leader, tgid);
		bpf_get_current_comm(event->comm, sizeof(event->comm));
		name = BPF_CORE_READ(dst_cgrp, kn, name);
		if (name)
			bpf_probe_read_kernel_str(
				event->filename, sizeof(event->filename), name);
		bpf_ringbuf_submit(event, 0);
		inc_stat(STAT_EVENTS_SENT);
	} else {
		inc_stat(STAT_RINGBUF_DROPS);
	}

	kill_instances(1);
	return 0;
}

/* =====================================================================
 * STOPPED TIME
 *
 * A frozen cgroup, a job-control stop and a ptrace stop all pass through
 * these two, in the thread that stands. An unfrozen thread passing through
 * cgroup_leave_frozen() is what ends a stop: leaving with the freeze still on
 * re-arms the trap and the thread stays frozen.
 * ===================================================================== */
static __always_inline struct task_struct *
instance_root_acquire(struct task_struct *task)
{
	struct lota_instance_entry id = {};
	struct task_struct *root;

	if (!task_instance(task, &id))
		return NULL;

	root = bpf_task_from_pid(id.root_tgid);
	if (!root)
		return NULL;
	if (get_task_start_ticks(root) != id.root_start_ticks) {
		bpf_task_release(root);
		return NULL;
	}
	return root;
}

SEC("fentry/cgroup_enter_frozen")
int BPF_PROG(lota_stop_enter)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct lota_instance_stops *stops;
	struct task_struct *root;
	u64 now;

	if (BPF_CORE_READ_BITFIELD_PROBED(task, frozen))
		return 0;

	root = instance_root_acquire(task);
	if (!root)
		return 0;

	stops = bpf_task_storage_get(&instance_stops, root, 0,
				     BPF_LOCAL_STORAGE_GET_F_CREATE);
	if (!stops) {
		inc_stat(STAT_INSTANCE_STOPS_LOST);
		goto out;
	}

	now = bpf_ktime_get_ns();
	bpf_spin_lock(&stops->lock);
	if (stops->stopped_threads++ == 0)
		stops->since_ns = now;
	bpf_spin_unlock(&stops->lock);
out:
	bpf_task_release(root);
	return 0;
}

SEC("fexit/cgroup_leave_frozen")
int BPF_PROG(lota_stop_leave, bool always_leave)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct lota_instance_stops *stops;
	struct task_struct *root;
	u64 now;

	(void)always_leave;

	if (BPF_CORE_READ_BITFIELD_PROBED(task, frozen))
		return 0;

	root = instance_root_acquire(task);
	if (!root)
		return 0;

	stops = bpf_task_storage_get(&instance_stops, root, 0, 0);
	if (!stops)
		goto out;

	now = bpf_ktime_get_ns();
	bpf_spin_lock(&stops->lock);
	if (stops->stopped_threads > 0 && --stops->stopped_threads == 0)
		stops->total_ns = lota_stopped_ns(stops->total_ns, 1,
						  stops->since_ns, now);
	bpf_spin_unlock(&stops->lock);
out:
	bpf_task_release(root);
	return 0;
}
