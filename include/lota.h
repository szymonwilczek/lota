/* SPDX-License-Identifier: MIT */
/*
 * LOTA definitions shared by user space and BPF.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_H
#define LOTA_H

/* A BPF object takes its types from vmlinux.h, included before this header. */
#ifndef __BPF_PROGRAM__
#include <linux/types.h>
#include <stdbool.h>
#endif

/*
 * Attestation report wire version. The verifier accepts exactly one, so agents
 * and verifiers cross a layout change together.
 * See Documentation/operator/protocol-versions.rst.
 */
#define LOTA_REPORT_VERSION_MAJOR 1
#define LOTA_REPORT_VERSION_MINOR 0
#define LOTA_REPORT_VERSION_PATCH 0
#define LOTA_REPORT_VERSION                  \
	((LOTA_REPORT_VERSION_MAJOR << 16) | \
	 (LOTA_REPORT_VERSION_MINOR << 8) | LOTA_REPORT_VERSION_PATCH)

/* "LOTA" in little-endian */
#define LOTA_MAGIC 0x41544F4C

#define LOTA_HASH_SIZE 32 /* SHA-256 */
#define LOTA_NONCE_SIZE 32
#define LOTA_MAX_SIG_SIZE 512 /* RSA-4096 */
#define LOTA_MAX_AIK_PUB_SIZE 512 /* DER SPKI */
#define LOTA_MAX_AIK_CERT_SIZE 2048 /* DER X.509 */
#define LOTA_HARDWARE_ID_SIZE 32 /* SHA-256 */

#define LOTA_PCR_COUNT 24

#define LOTA_RINGBUF_SIZE (256 * 1024)
#define LOTA_MAX_PATH_LEN 256
#define LOTA_MAX_COMM_LEN 16

enum lota_event_type {
	LOTA_EVENT_EXEC = 1, /* Binary execution */
	LOTA_EVENT_EXEC_BLOCKED, /* Execution blocked by policy */
	LOTA_EVENT_MODULE_LOAD, /* Kernel module load */
	LOTA_EVENT_MODULE_BLOCKED, /* Module load blocked by policy */
	LOTA_EVENT_MMAP_EXEC, /* Executable mmap (library load) */
	LOTA_EVENT_MMAP_BLOCKED, /* Executable mmap blocked by policy */
	LOTA_EVENT_PTRACE, /* ptrace access attempt */
	LOTA_EVENT_PTRACE_BLOCKED, /* ptrace access blocked by policy */
	/* refused signal or setrlimit, or a dump signal ending the process */
	LOTA_EVENT_KILL_BLOCKED,
	LOTA_EVENT_SETUID, /* Privilege escalation (setuid) */
	LOTA_EVENT_ANON_EXEC, /* Anonymous executable mmap (JIT, shellcode) */
	LOTA_EVENT_ANON_EXEC_BLOCKED, /* Anonymous executable mmap blocked */
	LOTA_EVENT_KILL, /* signal delivery to protected task observed */
	LOTA_EVENT_MOUNT_BLOCKED, /* mount that would shadow a trusted file */
	LOTA_EVENT_KILL_GUARD_BLOCKED, /* write that kills a guarded task */
	LOTA_EVENT_MAPPED_WRITE_BLOCKED, /* write to a pinned mapped library */
	LOTA_EVENT_AGENT_MOVED, /* the agent was moved to another cgroup */
};

/* One past the last event type, so a per-type array covers every one */
#define LOTA_EVENT_TYPE_COUNT (LOTA_EVENT_AGENT_MOVED + 1)

/*
 * struct lota_exec_event.flags.
 *
 * PROTECTED: executable mapping by a protected task; the agent re-measures it.
 * INSIDE_INSTANCE: ptrace access between processes of one instance, recorded.
 */
enum lota_event_flag {
	LOTA_EVENT_FLAG_PROTECTED = (1U << 0),
	LOTA_EVENT_FLAG_INSIDE_INSTANCE = (1U << 1),
};

/* Whether policy refuses or only logs. Integrity rules hold in every mode. */
enum lota_mode {
	LOTA_MODE_MONITOR = 0, /* Log what policy would refuse */
	LOTA_MODE_ENFORCE = 1, /* Refuse what policy refuses */
};

/* Config map keys */
#define LOTA_CFG_MODE 0 /* enum lota_mode */
#define LOTA_CFG_STRICT_MMAP 1 /* 1 = block mmap from untrusted paths */
#define LOTA_CFG_BLOCK_PTRACE 2 /* 1 = block ptrace attach */
#define LOTA_CFG_BLOCK_ANON_EXEC 3 /* 1 = block anonymous mmap(PROT_EXEC) */
#define LOTA_CFG_STRICT_EXEC 4 /* 1 = block exec from untrusted paths */
#define LOTA_CFG_STRICT_MODULES 5 /* 1 = enforce verified modules/firmware */
#define LOTA_CFG_LOCK_BPF 6 /* 1 = block non-agent writes to LOTA BPF maps */
#define LOTA_CFG_MAX_ENTRIES 9

/*
 * enum kernel_read_file_id and enum kernel_load_data_id, generated from one
 * list in include/linux/kernel_read_file.h and sharing their numbering.
 *
 * Mirrored so the gate's rules can be tested here, whichever kernel generated
 * vmlinux.h.
 */
#define LOTA_KREAD_UNKNOWN 0
#define LOTA_KREAD_FIRMWARE 1
#define LOTA_KREAD_MODULE 2
#define LOTA_KREAD_KEXEC_IMAGE 3
#define LOTA_KREAD_KEXEC_INITRAMFS 4
#define LOTA_KREAD_POLICY 5
#define LOTA_KREAD_X509_CERTIFICATE 6
#define LOTA_KREAD_MODULE_COMPRESSED 7
#define LOTA_KREAD_MAX_KNOWN LOTA_KREAD_MODULE_COMPRESSED

/**
 * lota_kread_is_module() - Whether a purpose names a kernel module.
 * @id: enum kernel_read_file_id, as LOTA_KREAD_*.
 *
 * finit_module(MODULE_INIT_COMPRESSED_FILE) reads under the compressed purpose,
 * any other module read under the plain one.
 *
 * Return: 1 for a module purpose, 0 otherwise.
 */
static inline int lota_kread_is_module(unsigned int id)
{
	return id == LOTA_KREAD_MODULE || id == LOTA_KREAD_MODULE_COMPRESSED;
}

/**
 * lota_kread_is_known() - Whether a purpose is on the list above.
 * @id: as for lota_kread_is_module().
 *
 * One above the list comes from a newer kernel and may be a module load, so
 * lota_kread_denied() refuses it under strict module loading.
 *
 * Return: 1 up to LOTA_KREAD_MAX_KNOWN, 0 above it.
 */
static inline int lota_kread_is_known(unsigned int id)
{
	return id <= LOTA_KREAD_MAX_KNOWN;
}

/**
 * lota_kread_is_watched() - Whether the gate rules on a purpose.
 * @id:        as for lota_kread_is_module().
 * @from_file: kernel_read_file, else kernel_load_data. A certificate is watched
 *             only in the second.
 *
 * Return: 1 when the gate rules on @id, 0 when it passes unjudged.
 */
static inline int lota_kread_is_watched(unsigned int id, int from_file)
{
	if (lota_kread_is_module(id))
		return 1;

	switch (id) {
	case LOTA_KREAD_FIRMWARE:
	case LOTA_KREAD_KEXEC_IMAGE:
	case LOTA_KREAD_KEXEC_INITRAMFS:
	case LOTA_KREAD_POLICY:
		return 1;
	case LOTA_KREAD_X509_CERTIFICATE:
		return !from_file;
	}
	return 0;
}

/**
 * lota_kread_denied() - Verdict on what the kernel takes in on its own behalf.
 * @id:             as for lota_kread_is_module().
 * @from_file:      kernel_read_file, else kernel_load_data.
 * @policy_on:      The mode is enforce.
 * @strict_modules: The strict_modules setting.
 * @baseline_ok:    Module signature enforcement and lockdown are both on.
 * @verity_allowed: The file's fs-verity digest is on the allow_verity list.
 * @foreign_userns: The caller is outside the initial user namespace.
 *
 * Integrity holds in every mode:
 *
 *   - kexec replaces the measured kernel, and is refused;
 *   - a user namespace other than the initial one takes in nothing watched;
 *   - a module or firmware load needs module signature enforcement and
 *     lockdown.
 *
 * strict_modules is policy and applies in enforce only:
 *
 *   - a module or firmware read from a file needs an allow_verity digest;
 *   - one handed over from memory has no file to check, and is refused;
 *   - a purpose not on the list is refused.
 *
 * An IMA policy read from a file is always allowed.
 *
 * Return: 1 to deny, 0 to allow.
 */
static inline int lota_kread_denied(unsigned int id, int from_file,
				    int policy_on, int strict_modules,
				    int baseline_ok, int verity_allowed,
				    int foreign_userns)
{
	int strict = policy_on && strict_modules;
	int payload = lota_kread_is_module(id) || id == LOTA_KREAD_FIRMWARE;

	if (!lota_kread_is_known(id))
		return strict;

	if (!lota_kread_is_watched(id, from_file))
		return 0;

	if (from_file && id == LOTA_KREAD_POLICY)
		return 0;

	if (id == LOTA_KREAD_KEXEC_IMAGE || id == LOTA_KREAD_KEXEC_INITRAMFS)
		return 1;

	if (foreign_userns)
		return 1;

	if (payload && !baseline_ok)
		return 1;

	if (payload && strict)
		return from_file ? !verity_allowed : 1;

	return 0;
}

/* From include/linux/ptrace.h; vmlinux.h carries no macros. */
#define LOTA_PTRACE_MODE_READ 0x01
#define LOTA_PTRACE_MODE_ATTACH 0x02

/**
 * lota_ptrace_is_attach() - Whether an access asks to trace the target.
 * @ptrace_mode: PTRACE_MODE_* bits the hook was given.
 *
 * Return: 1 when @ptrace_mode carries PTRACE_MODE_ATTACH, 0 otherwise.
 */
static inline int lota_ptrace_is_attach(unsigned int ptrace_mode)
{
	return (ptrace_mode & LOTA_PTRACE_MODE_ATTACH) != 0;
}

/**
 * lota_ptrace_agent_read_exempt() - Whether an access is the agent's own read.
 * @ptrace_mode:    as for lota_ptrace_is_attach().
 * @actor_is_agent: The caller is the agent.
 *
 * procfs checks the agent's reads of /proc/<pid>/exe and maps with
 * PTRACE_MODE_READ. Refused, they leave a protected process unmeasured.
 *
 * Return: 1 for a read by the agent, 0 otherwise.
 */
static inline int lota_ptrace_agent_read_exempt(unsigned int ptrace_mode,
						int actor_is_agent)
{
	return actor_is_agent && !lota_ptrace_is_attach(ptrace_mode);
}

/**
 * lota_ptrace_denied() - Verdict on a ptrace access.
 * @ptrace_mode:         as for lota_ptrace_is_attach().
 * @lota_mode:           LOTA_MODE_*.
 * @block_ptrace:        The block_ptrace setting.
 * @target_is_agent:     The target is the agent.
 * @target_is_protected: Protected, and the actor is outside its instance.
 *
 * The caller has settled the agent's read exemption.
 *
 * The agent and a protected process refuse both access modes in every
 * enforcement mode: a token speaks for an isolated process measured by an
 * intact agent.
 *
 * block_ptrace is policy over any other access: enforce only, and attach only.
 * A read stays with the kernel's permission model, as tools such as lsof read
 * other processes' /proc.
 *
 * Return: 1 to deny, 0 to allow.
 */
static inline int lota_ptrace_denied(unsigned int ptrace_mode,
				     unsigned int lota_mode, int block_ptrace,
				     int target_is_agent,
				     int target_is_protected)
{
	if (target_is_agent || target_is_protected)
		return 1;

	if (lota_mode == LOTA_MODE_ENFORCE && block_ptrace &&
	    lota_ptrace_is_attach(ptrace_mode))
		return 1;

	return 0;
}

/* longest /proc entry name lota_proc_entry_reads_mm() names, plus one */
#define LOTA_PROC_NAME_MAX 16

static inline int lota_name_is(const char *name, unsigned int len,
			       const char *want)
{
	unsigned int i;

	for (i = 0; i < LOTA_PROC_NAME_MAX; i++) {
		if (want[i] == '\0')
			return i == len;
		if (i >= len || name[i] != want[i])
			return 0;
	}
	return 0;
}

/**
 * lota_proc_entry_reads_mm() - Whether a /proc/<pid> entry reads memory.
 * @name: entry name, need not be NUL-terminated.
 * @len:  bytes in @name.
 *
 * mm_access() admits CAP_PERFMON past a refused READ ptrace check, so these
 * opens are refused on their own, by the rules of the ptrace verdict. Entries
 * that only name the process stay open.
 *
 * Return: 1 for an entry that reads memory, 0 otherwise.
 */
static inline int lota_proc_entry_reads_mm(const char *name, unsigned int len)
{
	return lota_name_is(name, len, "maps") ||
	       lota_name_is(name, len, "smaps") ||
	       lota_name_is(name, len, "smaps_rollup") ||
	       lota_name_is(name, len, "numa_maps") ||
	       lota_name_is(name, len, "pagemap") ||
	       lota_name_is(name, len, "environ") ||
	       lota_name_is(name, len, "auxv") ||
	       lota_name_is(name, len, "map_files");
}

/* CLONE_THREAD from <linux/sched.h>, mirrored like the above */
#define LOTA_CLONE_THREAD 0x00010000

/**
 * lota_clone_inherits_protection() - Whether a new task becomes protected.
 * @clone_flags:       flags of the clone.
 * @creator_protected: The creating task is protected.
 *
 * The child is marked before it first runs and stays marked across execve. A
 * thread belongs to its leader and takes no mark of its own.
 *
 * Return: 1 when the child takes the mark, 0 otherwise.
 */
static inline int lota_clone_inherits_protection(unsigned long clone_flags,
						 int creator_protected)
{
	return creator_protected && !(clone_flags & LOTA_CLONE_THREAD);
}

/**
 * lota_clone_refused() - Whether a traced protected process may not clone.
 * @creator_protected: The creating task is protected.
 * @creator_traced:    The creating task has a tracer.
 * @tracer_protected:  The tracer is inside the creator's instance.
 *
 * A tracer attached before the process was protected stays attached, and
 * ptrace_init_task() links it to every child it asked for with no LSM hook.
 *
 * Return: 1 to refuse the clone, 0 to allow it.
 */
static inline int lota_clone_refused(int creator_protected, int creator_traced,
				     int tracer_protected)
{
	return creator_protected && creator_traced && !tracer_protected;
}

/**
 * lota_inside_instance() - Whether an access stays inside one instance.
 * @actor_protected:  The actor is protected.
 * @actor_root:       tgid of the root of the actor's instance.
 * @actor_ticks:      start time of that root.
 * @target_protected: The target is protected.
 * @target_root:      tgid of the root of the target's instance.
 * @target_ticks:     start time of that root.
 *
 * An instance is the tree one protected process started, named by that root's
 * tgid and start time, so a recycled tgid names another instance. The
 * wineserver ptraces processes it hosts, so being protected refuses no ptrace
 * inside an instance: it is recorded, and only block_ptrace can refuse an
 * attach.
 *
 * Return: 1 when both are protected under the same root, 0 otherwise.
 */
static inline int
lota_inside_instance(int actor_protected, unsigned int actor_root,
		     unsigned long long actor_ticks, int target_protected,
		     unsigned int target_root, unsigned long long target_ticks)
{
	return actor_protected && target_protected &&
	       actor_root == target_root && actor_ticks == target_ticks;
}

/* Signal numbers of the architectures LOTA builds for. */
#define LOTA_SIG_HUP 1
#define LOTA_SIG_KILL 9
#define LOTA_SIG_IO 29

/* what stops a task, and what makes the kernel write its memory to a core */
#define LOTA_SIG_FREEZES \
	((1ULL << 19) | (1ULL << 20) | (1ULL << 21) | (1ULL << 22))
#define LOTA_SIG_DUMPS                                                         \
	((1ULL << 3) | (1ULL << 4) | (1ULL << 5) | (1ULL << 6) | (1ULL << 7) | \
	 (1ULL << 8) | (1ULL << 11) | (1ULL << 24) | (1ULL << 25) |            \
	 (1ULL << 31))

/* a signal whose default action writes a core file */
static inline int lota_signal_dumps(int sig)
{
	return sig > 0 && sig <= 31 && !!(LOTA_SIG_DUMPS & (1ULL << sig));
}

/**
 * lota_signal_denied() - Verdict on a signal.
 * @sender_inside: The sender is in the target's instance.
 *
 * Self-signals, the agent, the admin identity and kernel-generated signals
 * never reach this.
 *
 * Only a probe (sig 0) and SIGHUP, its reload, reach the agent. It stops with
 * lota-agent --shutdown.
 *
 * A protected process can be ended. From outside its instance it takes no
 * stopping signal, nor one whose default writes its memory to a core file.
 * Inside it everything passes: the wineserver drives the processes it hosts
 * with signals.
 *
 * The mode does not change the verdict: a killed agent stops measuring without
 * a trace.
 *
 * Return: 1 to refuse, 0 to deliver.
 */
static inline int lota_signal_denied(int sig, int target_is_agent,
				     int sender_inside)
{
	if (target_is_agent)
		return sig != 0 && sig != LOTA_SIG_HUP;

	if (sender_inside || sig <= 0 || sig > 31)
		return 0;

	return lota_signal_dumps(sig) || !!(LOTA_SIG_FREEZES & (1ULL << sig));
}

/**
 * lota_sigio_denied() - Verdict on a signal aimed through F_SETOWN.
 * @sig:             signal number, 0 for the default SIGIO.
 * @target_is_agent: The target is the agent.
 *
 * The sender is unknown and counts as outside.
 *
 * Return: as for lota_signal_denied().
 */
static inline int lota_sigio_denied(int sig, int target_is_agent)
{
	return lota_signal_denied(sig ? sig : LOTA_SIG_IO, target_is_agent, 0);
}

/**
 * lota_signal_event() - Event for a signal aimed at a protected target.
 * @sig:    signal number, 0 for a probe.
 * @denied: The answer of lota_signal_denied().
 *
 * A permitted probe (sig 0) is not recorded: launchers poll several times a
 * second.
 *
 * Return: An enum lota_event_type, or 0 for none.
 */
static inline int lota_signal_event(int sig, int denied)
{
	if (denied)
		return LOTA_EVENT_KILL_BLOCKED;

	if (sig == 0)
		return 0;

	return LOTA_EVENT_KILL;
}

/**
 * lota_kill_guard_denied() - Verdict on opening a guarded cgroup file.
 * @write_open:    The open is for writing.
 * @guarded:       The file is a guarded one.
 * @opener_exempt: The opener is the agent or the admin identity.
 *
 * A write to it ends or stops tasks past the signal hook, so in every mode only
 * the agent and the admin identity may open it for writing.
 *
 * Return: 1 to refuse, 0 to allow.
 */
static inline int lota_kill_guard_denied(int write_open, int guarded,
					 int opener_exempt)
{
	return write_open && guarded && !opener_exempt;
}

/* fs-verity digest sizes policy enforcement accepts. */
#define LOTA_VERITY_DIGEST_SHA256_SIZE 32
#define LOTA_VERITY_DIGEST_SHA512_SIZE 64
#define LOTA_VERITY_DIGEST_MAX_SIZE LOTA_VERITY_DIGEST_SHA512_SIZE

/*
 * fs-verity allowlist key. len is one of the sizes above and the bytes past it
 * are zero, so both sizes share one map.
 */
struct lota_verity_digest_key {
	__u32 len;
	__u8 digest[LOTA_VERITY_DIGEST_MAX_SIZE];
};

/* whether a measured digest length is one LOTA policy enforcement takes */
#define LOTA_VERITY_DIGEST_LEN_SUPPORTED(len)       \
	((len) == LOTA_VERITY_DIGEST_SHA256_SIZE || \
	 (len) == LOTA_VERITY_DIGEST_SHA512_SIZE)

_Static_assert(LOTA_VERITY_DIGEST_MAX_SIZE == LOTA_VERITY_DIGEST_SHA512_SIZE,
	       "fs-verity key width must remain SHA-512 sized");
_Static_assert(sizeof(((struct lota_verity_digest_key *)0)->digest) ==
		       LOTA_VERITY_DIGEST_SHA512_SIZE,
	       "fs-verity map key digest must support 64-byte SHA-512");

/*
 * bpf_get_fsverity_digest() writes a struct fsverity_digest, this header then
 * the digest, and reports success as 0, not as a length.
 */
struct lota_fsverity_digest_hdr {
	__u16 digest_algorithm;
	__u16 digest_size;
};

#define LOTA_FSVERITY_DIGEST_HDR_SIZE 4u
#define LOTA_FSVERITY_DIGEST_BUF_SIZE \
	(LOTA_FSVERITY_DIGEST_HDR_SIZE + LOTA_VERITY_DIGEST_MAX_SIZE)

_Static_assert(sizeof(struct lota_fsverity_digest_hdr) ==
		       LOTA_FSVERITY_DIGEST_HDR_SIZE,
	       "fs-verity digest header must stay four bytes");

/**
 * lota_verity_key_from_digest_buf() - Build an allowlist key from that buffer.
 * @buf: At least LOTA_FSVERITY_DIGEST_BUF_SIZE wide and aligned for the header.
 * @out: filled on success, untouched on failure.
 *
 * Return: 0 on success, -1 when the reported size is not one policy enforces.
 */
static inline int
lota_verity_key_from_digest_buf(const void *buf,
				struct lota_verity_digest_key *out)
{
	const struct lota_fsverity_digest_hdr *hdr = buf;
	const __u8 *digest = (const __u8 *)buf + LOTA_FSVERITY_DIGEST_HDR_SIZE;
	__u16 size;

	if (!buf || !out)
		return -1;

	size = hdr->digest_size;
	if (!LOTA_VERITY_DIGEST_LEN_SUPPORTED(size))
		return -1;

	__builtin_memset(out, 0, sizeof(*out));

	/*
	 * Constant-size copies: clang refuses a variable-length memcpy for
	 * BPF, and the two supported sizes are the whole set.
	 */
	if (size == LOTA_VERITY_DIGEST_SHA256_SIZE)
		__builtin_memcpy(out->digest, digest,
				 LOTA_VERITY_DIGEST_SHA256_SIZE);
	else
		__builtin_memcpy(out->digest, digest,
				 LOTA_VERITY_DIGEST_SHA512_SIZE);

	out->len = size;
	return 0;
}

/*
 * Ring buffer event. Every type sets timestamp_ns, pid, tgid, uid and comm; uid
 * is 0 on the module types. Beyond those:
 *   EXEC:           filename, hash
 *   MODULE_LOAD:    filename
 *   MMAP_EXEC:      filename, flags
 *   ANON_EXEC:      filename (a fixed label)
 *   PTRACE:         target_pid, filename (the target's), flags
 *   KILL:           target_pid, signal, filename (a fixed label)
 *   SETUID:         target_uid (new uid)
 *   AGENT_MOVED:    target_pid, filename (the cgroup)
 *   PTRACE_BLOCKED on a /proc open: target_pid, filename (the /proc entry)
 *   MOUNT_BLOCKED, KILL_GUARD_BLOCKED, MAPPED_WRITE_BLOCKED: filename
 *   other *_BLOCKED: same as base type
 */
struct lota_exec_event {
	__u64 timestamp_ns;
	__u32 event_type; /* enum lota_event_type */
	__u32 pid;
	__u32 tgid;
	__u32 uid;
	union {
		__u32 target_pid;
		__u32 target_uid;
	};
	__u32 flags; /* LOTA_EVENT_FLAG_* */
	__u32 signal; /* kill */
	__u8 hash[LOTA_HASH_SIZE]; /* start of the fs-verity digest, if any */
	char comm[LOTA_MAX_COMM_LEN];
	char filename[LOTA_MAX_PATH_LEN];
} __attribute__((packed));

#define LOTA_MAX_PROTECTED_PIDS 1024

#define LOTA_MAX_TRUSTED_LIBS 512

/*
 * Files whose write kills or stops a protected task past every signal hook:
 * cgroup.kill and cgroup.freeze of the agent's cgroup and its ancestors,
 * two per level of a cgroup depth.
 */
#define LOTA_MAX_GUARDED_FILES 64

/*
 * Agent threads with a kernel hash outstanding at once;
 * each asks about one object at a time.
 */
#define LOTA_MAX_EXE_HASH_SLOTS 64

#define LOTA_EXE_HASH_IDLE 0 /* nothing asked */
#define LOTA_EXE_HASH_ASKED 1 /* the next open is hashed */
#define LOTA_EXE_HASH_ANSWERED 2 /* err set; the rest per question */
#define LOTA_EXE_HASH_ASKED_PIN 3 /* the next open is pinned, not read */

/* Is the pinned file the one mapped? Anything but OK leaves it uncovered */
#define LOTA_EXE_MAP_SEEN_OK 0
#define LOTA_EXE_MAP_SEEN_MISSING 1 /* never recorded, or evicted */
#define LOTA_EXE_MAP_SEEN_CHANGED 2 /* written since it was mapped */

/* <linux/hash_info.h> ids; the algorithm fixes the digest length */
#define LOTA_EXE_HASH_ALGO_SHA256 4
#define LOTA_EXE_HASH_ALGO_SHA512 6

/* One agent thread's kernel hash request, keyed by its tid */
struct lota_exe_hash_slot {
	__u32 state; /* LOTA_EXE_HASH_* */
	__u32 algo; /* LOTA_EXE_HASH_ALGO_*, 0 on failure */
	__u32 err; /* positive errno, 0 on success */
	__u32 guard; /* already pinned by the agent */
	__u64 dev; /* kernel's key for the file, not stat's st_dev */
	__u64 ino;
	__u32 seen; /* LOTA_EXE_MAP_SEEN_* */
	__u32 writers; /* write opens granted; a pin cannot recall them */
	__u8 digest[LOTA_VERITY_DIGEST_MAX_SIZE]; /* read during the open */
};

/* guarded_files value: why the file is guarded */
#define LOTA_GUARD_CGROUP_KILL 1
#define LOTA_GUARD_CGROUP_FREEZE 2

/*
 * Libraries the agent pins against writes while measuring a process.
 * Only the agent writes the map, so the protected set bounds it.
 */
#define LOTA_MAX_MAPPED_EXEC_GUARDS 16384

/*
 * Size and ctime of a file as mapped executable, to catch one swapped before
 * the pin; utimensat cannot set ctime. Evictable: a loss costs a measurement.
 */
struct lota_mapped_seen {
	__u64 size;
	__u64 ctime_sec;
	__u32 ctime_nsec;
	__u32 pad;
};

#define LOTA_MAX_MAPPED_SEEN 65536

/*
 * Every file a protected process mapped or mprotected executable, refused
 * attempts included: an unmapped object leaves no trace in /proc.
 * Keyed by the process and its start time, so a reused PID starts empty.
 * Only the agent deletes, and only entries of a process that is gone.
 */
#define LOTA_EXEC_HISTORY_NAME_MAX 128
#define LOTA_MAX_EXEC_HISTORY 65536

struct lota_exec_history_key {
	__u32 tgid;
	__u32 pad;
	__u64 start_ticks;
	__u64 dev; /* s_dev, kernel encoding */
	__u64 ino;
};

/*
 * another file could write the code: open for write, mapped shared writable,
 * or memory with no name and no write seal, which any fd holder can write
 */
#define LOTA_EXEC_HISTORY_WRITABLE (1U << 0)
/* the code lives in memory only: memfd, shm, tmpfs or hugetlbfs */
#define LOTA_EXEC_HISTORY_MEMORY (1U << 1)

struct lota_exec_history_val {
	__u64 size;
	__u32 flags; /* LOTA_EXEC_HISTORY_*, of every attempt */
	__u32 pad;
	char name[LOTA_EXEC_HISTORY_NAME_MAX];
};

/*
 * Every process that reached a process of an instance by a path the gate
 * lets through: from outside, through a unix socket of the instance, by
 * connecting to it or sending to it; from inside, by a ptrace access or a
 * signal to another process of the instance. A process of the instance is
 * listed for itself when it makes anonymous memory executable.
 * Keyed by the instance root and its start time, the actor and its start
 * time, the process of the instance it reached and how.
 * Only the agent deletes, and only entries of a root that is gone.
 */
#define LOTA_MAX_INSTANCE_ACTORS 4096

enum lota_instance_actor_kind {
	LOTA_INSTANCE_ACTOR_CONNECT = 1, /* stream or seqpacket connect */
	LOTA_INSTANCE_ACTOR_SEND = 2, /* datagram sent */
	LOTA_INSTANCE_ACTOR_PTRACE_READ = 3, /* read-mode access, inside */
	LOTA_INSTANCE_ACTOR_PTRACE_ATTACH = 4, /* attach-mode access, inside */
	LOTA_INSTANCE_ACTOR_SIGNAL = 5, /* signal sent, inside */
	LOTA_INSTANCE_ACTOR_ANON_EXEC = 6, /* own anonymous memory executable */
};

struct lota_instance_actor_key {
	__u64 root_start_ticks;
	__u64 actor_start_ticks;
	__u32 root_tgid;
	__u32 actor_tgid;
	__u32 owner_tgid; /* process of the instance it reached */
	__u32 kind; /* enum lota_instance_actor_kind */
};

struct lota_instance_actor_val {
	__u64 count; /* times it did so */
	__u64 exe_dev; /* s_dev of the actor's executable, kernel encoding */
	__u64 exe_ino;
	__u32 uid; /* actor's real uid at its first reach */
	__u32 pad;
	char comm[LOTA_MAX_COMM_LEN];
	char owner_comm[LOTA_MAX_COMM_LEN];
};

/*
 * Kernel integrity baseline, read by the agent at startup. module.sig_enforce
 * is enable-only and the lockdown level never falls, so it does not go stale.
 */
struct integrity_data {
	__u32 sig_enforce; /* 1 when module signatures are enforced */
	__u32 lockdown; /* 1 when lockdown is integrity or above */
};

/*
 * Stopped time of an instance at @now: what ended periods add up to, plus the
 * open one while a thread still stands.
 */
static inline __u64 lota_stopped_ns(__u64 total_ns, __u32 stopped_threads,
				    __u64 since_ns, __u64 now)
{
	if (stopped_threads && now > since_ns)
		return total_ns + (now - since_ns);
	return total_ns;
}

#endif /* LOTA_H */
