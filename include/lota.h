/* SPDX-License-Identifier: MIT */
/*
 * LOTA - Linux Open Trusted Attestation
 * Common definitions shared between user-space and BPF
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_H
#define LOTA_H

/*
 * For BPF programs, types come from vmlinux.h
 * For user-space, include linux/types.h
 * BPF programs should include vmlinux.h before this header!!!
 */
#ifndef __BPF_PROGRAM__
#include <linux/types.h>
#include <stdbool.h>
#endif

/*
 * Attestation report wire version.
 * Major changes on breaking report layout change, which is a flag-day:
 * the verifier accepts exactly one version, so agents and verifiers cross
 * the boundary together.
 *
 * The components are laid out as the verifier renders them, one byte each
 * below the major, so both halves read the same number the same way.
 * See Documentation/operator/protocol-versions.rst
 */
#define LOTA_REPORT_VERSION_MAJOR 1
#define LOTA_REPORT_VERSION_MINOR 0
#define LOTA_REPORT_VERSION_PATCH 0
#define LOTA_REPORT_VERSION                  \
	((LOTA_REPORT_VERSION_MAJOR << 16) | \
	 (LOTA_REPORT_VERSION_MINOR << 8) | LOTA_REPORT_VERSION_PATCH)

/* Magic number: "LOTA" in little-endian */
#define LOTA_MAGIC 0x41544F4C

/* Cryptographic constants */
#define LOTA_HASH_SIZE 32 /* SHA-256 digest size */
#define LOTA_NONCE_SIZE 32 /* Challenge nonce size */
#define LOTA_MAX_SIG_SIZE 512 /* Max TPM signature size (RSA-4096) */
#define LOTA_MAX_AIK_PUB_SIZE 512 /* Max AIK public key (DER SPKI format) */
#define LOTA_MAX_AIK_CERT_SIZE 2048 /* Max AIK certificate size (DER X.509) */
#define LOTA_HARDWARE_ID_SIZE 32 /* SHA-256 of EK public key */

/* Number of PCRs to include in attestation */
#define LOTA_PCR_COUNT 24

/* Ring buffer constants */
#define LOTA_RINGBUF_SIZE (256 * 1024) /* 256 KB */
#define LOTA_MAX_PATH_LEN 256
#define LOTA_MAX_COMM_LEN 16

/* Event types for ring buffer */
enum lota_event_type {
	LOTA_EVENT_EXEC = 1, /* Binary execution */
	LOTA_EVENT_EXEC_BLOCKED, /* Execution blocked by policy */
	LOTA_EVENT_MODULE_LOAD, /* Kernel module load */
	LOTA_EVENT_MODULE_BLOCKED, /* Module load blocked by policy */
	LOTA_EVENT_MMAP_EXEC, /* Executable mmap (library load) */
	LOTA_EVENT_MMAP_BLOCKED, /* Executable mmap blocked by policy */
	LOTA_EVENT_PTRACE, /* ptrace access attempt */
	LOTA_EVENT_PTRACE_BLOCKED, /* ptrace access blocked by policy */
	LOTA_EVENT_KILL_BLOCKED, /* signal delivery to protected task blocked */
	LOTA_EVENT_SETUID, /* Privilege escalation (setuid) */
	LOTA_EVENT_ANON_EXEC, /* Anonymous executable mmap (JIT, shellcode) */
	LOTA_EVENT_ANON_EXEC_BLOCKED, /* Anonymous executable mmap blocked */
	LOTA_EVENT_KILL, /* signal delivery to protected task observed */
	LOTA_EVENT_MOUNT_BLOCKED, /* mount that would shadow a trusted file */
	LOTA_EVENT_KILL_GUARD_BLOCKED, /* write that would kill a guarded task */
	LOTA_EVENT_MAPPED_WRITE_BLOCKED, /* write to a pinned mapped library */
};

/* One past the last event type, so a per-type array covers every one */
#define LOTA_EVENT_TYPE_COUNT (LOTA_EVENT_MAPPED_WRITE_BLOCKED + 1)

/*
 * Event flags (struct lota_exec_event.flags).
 *
 * PROTECTED marks an executable-mapping event whose task is in the
 * protected set, so the agent can trigger an event-driven re-measurement
 * of that process instead of waiting for the next periodic heartbeat.
 *
 * INSIDE_INSTANCE marks a ptrace access one process of an instance made
 * to another of the same instance: allowed, and recorded.
 */
enum lota_event_flag {
	LOTA_EVENT_FLAG_PROTECTED = (1U << 0),
	LOTA_EVENT_FLAG_INSIDE_INSTANCE = (1U << 1),
};

/*
 * LOTA enforcement modes
 * Controls whether LSM hooks block or just monitor
 */
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
 * The purpose the kernel gives when it reads a file or a buffer on its own
 * behalf: enum kernel_read_file_id and enum kernel_load_data_id.
 * The two enums are generated from one list in include/linux/kernel_read_file.h
 * and share their numbering, so one set of values answers for both hooks.
 *
 * Mirrored, so that what the gate asks about a purpose can be stated and tested
 * here instead of only in the hook, and so that it does not depend on which
 * kernel generated that header.
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

/*
 * Whether a purpose names a kernel module
 *
 * A module reaches the kernel in one of two forms and the kernel reports which:
 * the image itself, from insmod of a plain .ko, or the compressed file handed
 * to finit_module(MODULE_INIT_COMPRESSED_FILE) for the kernel to expand.
 * The second is what modprobe produces on every distribution that compresses its
 * modules, so on a stock host every module load carries the compressed purpose
 * and none carries the plain one.
 */
static inline int lota_kread_is_module(unsigned int id)
{
	return id == LOTA_KREAD_MODULE || id == LOTA_KREAD_MODULE_COMPRESSED;
}

/*
 * Whether this object has heard of the purpose at all.
 *
 * A purpose above the list is one a later kernel added, and while strict module
 * loading is armed the gate has to treat it as a load it cannot classify.
 * The kernel can ask about a module in a form this object has no rule for,
 * and the absence of a rule must not read as consent.
 *
 * The refusal is bounded by the configuration key, so a host that did not ask
 * for strict module loading keeps whatever the kernel does today.
 */
static inline int lota_kread_is_known(unsigned int id)
{
	return id <= LOTA_KREAD_MAX_KNOWN;
}

/*
 * Whether the gate rules on a purpose at all.
 * @from_file: kernel_read_file rather than kernel_load_data, which also sees
 * certificates handed to the keyring from memory.
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

/*
 * The verdict on code or data the kernel takes in on its own behalf, shared
 * by kernel_read_file and kernel_load_data and stated here for the tests.
 * Returns 1 to deny, 0 to allow.
 *
 * Integrity of the running kernel is not policy and holds in every mode:
 *
 *   - kexec replaces the measured kernel, and is refused;
 *   - a user namespace other than the initial one takes nothing in;
 *   - a module or firmware load needs module signature enforcement and
 *     lockdown, the baseline the token reports.
 *
 * strict_modules is policy and applies in enforce only (@policy_on):
 *
 *   - a module or firmware read from a file needs an allow_verity digest;
 *   - one handed over from memory has no file to check, and is refused;
 *   - a purpose this object has no rule for is refused.
 *
 * An IMA policy read from a file is always allowed.
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

/*
 * PTRACE_MODE_ATTACH from include/linux/ptrace.h.
 *
 * Mirrored: the enforcement object builds against vmlinux.h, which carries types
 * and not the uapi-adjacent flag definitions.
 */
#define LOTA_PTRACE_MODE_ATTACH 0x02

/* Whether an access asks to trace the target rather than only to read it */
static inline int lota_ptrace_is_attach(unsigned int ptrace_mode)
{
	return (ptrace_mode & LOTA_PTRACE_MODE_ATTACH) != 0;
}

/*
 * The agent measures a protected process's live code from the kernel side,
 * and procfs charges that read a PTRACE_MODE_READ check: reading /proc/<pid>/exe
 * or /proc/<pid>/maps goes through this hook.
 *
 * Denying it to the agent makes protecting a process and issuing a token for it
 * mutually exclusive -- the measurement cannot be taken, and a measurement that
 * is missing must never be issued as a trusted one, so GET_TOKEN fails closed.
 *
 * Read access only. PTRACE_MODE_ATTACH stays denied to everyone including
 * the agent, so nothing here opens a debugger onto a protected task.
 * The caller identifies the agent by the task auth flag the rest of
 * the enforcement object trusts, not by a pid a caller could claim.
 */
static inline int lota_ptrace_agent_read_exempt(unsigned int ptrace_mode,
						int actor_is_agent)
{
	return actor_is_agent && !lota_ptrace_is_attach(ptrace_mode);
}

/*
 * The ptrace access verdict, stated here so the enforcement object and the tests
 * answer it the same way.
 * Returns 1 to deny, 0 to allow; the caller has already settled the agent read
 * exemption above.
 *
 * Three rules, in the order they are asked:
 *
 *   - the agent itself is never a ptrace target;
 *   - a protected process refuses both modes to anything outside its
 *     instance (lota_inside_instance());
 *   - block_ptrace covers every other task, in enforce, and for an attach
 *     only.
 *
 * The first two hold in every enforcement mode: a token speaks for an isolated
 * process measured by an intact agent, and no mode makes that true without
 * the gate. The mode switches policy, and block_ptrace is policy.
 *
 * The third rule is a global over every task on the machine, so the access modes
 * part company there. An attach is what the key is named for and what it refuses.
 * A read is left to the kernel's own permission model, which already answers it:
 * reading another process's /proc is what lsof, ps, a profiler and a crash
 * handler do, same-uid access to it is ordinary, and yama's ptrace_scope covers
 * the attach case without reaching this far.
 * Refusing it for everyone breaks the desktop the agent runs on and protects
 * nothing -- the target the operator meant to protect is the second rule,
 * which is a set they opt into and which still refuses both.
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

/* CLONE_THREAD from <linux/sched.h>, mirrored like the above */
#define LOTA_CLONE_THREAD 0x00010000

/*
 * Whether a task made by clone(2) joins its creator's protected set.
 *
 * A protected process is protected with everything it starts. The child is
 * marked before it first runs, so nothing reaches it unprotected, and the
 * mark stays across execve as the process does. A thread belongs to its
 * leader and takes no mark of its own.
 */
static inline int lota_clone_inherits_protection(unsigned long clone_flags,
						 int creator_protected)
{
	return creator_protected && !(clone_flags & LOTA_CLONE_THREAD);
}

/*
 * Whether a protected process may not create anything because a tracer
 * outside its instance holds it. A tracer attached before the process
 * was protected stays attached, and the kernel hands it every child a
 * PTRACE_O_TRACEFORK tracer asks for without asking the LSM.
 */
static inline int lota_clone_refused(int creator_protected, int creator_traced,
				     int tracer_protected)
{
	return creator_protected && creator_traced && !tracer_protected;
}

/*
 * Whether an access stays inside one instance: the tree one protected process
 * started, named by that root's tgid and start time, so a recycled tgid names
 * another instance. Wine's server reads and writes the memory of every process
 * it hosts, so inside an instance ptrace is recorded, not refused; nothing
 * outside it reaches in.
 */
static inline int
lota_inside_instance(int actor_protected, unsigned int actor_root,
		     unsigned long long actor_ticks, int target_protected,
		     unsigned int target_root, unsigned long long target_ticks)
{
	return actor_protected && target_protected &&
	       actor_root == target_root && actor_ticks == target_ticks;
}

/*
 * SIGHUP, shared by every Linux architecture LOTA builds for.
 *
 * Mirrored for the same reason as the ptrace flag above:
 * the enforcement object builds against vmlinux.h, which carries types
 * and not the uapi signal numbers.
 */
#define LOTA_SIG_HUP 1

/*
 * The signal-delivery verdict, stated here so the enforcement object
 * and the tests answer it the same way.
 * Returns 1 to refuse the signal, 0 to deliver it.
 *
 * The caller has already settled who the sender is: a task signalling itself,
 * the agent, a task holding CAP_SYS_ADMIN over BPF, and a kernel-generated
 * signal all reach delivery without asking this.
 *
 * Only the agent is guarded, so a local root cannot kill it and swap a
 * tampered binary in before the next attestation. A probe (sig 0) and SIGHUP,
 * its reload, are delivered, since neither ends it. It stops with
 * lota-agent --shutdown.
 *
 * A protected process is not guarded: a signal runs its own handler or ends
 * or stops it, and none of that puts foreign code into it. Every signal at it
 * is still recorded.
 *
 * The verdict does not depend on the enforcement mode: an agent that can be
 * killed in monitor is an agent whose measurements stop without a trace,
 * and the mode switches policy, not the integrity of the measurement.
 */
static inline int lota_signal_denied(int sig, int target_is_agent)
{
	if (!target_is_agent)
		return 0;

	return sig != 0 && sig != LOTA_SIG_HUP;
}

/*
 * Event for a signal aimed at a protected target, shared with the tests like
 * the verdict above. @denied is lota_signal_denied()'s answer; a refusal is
 * recorded for any signal, a permitted probe (sig 0) never: launchers poll
 * several times a second.
 * Returns an enum lota_event_type, or 0 for none.
 */
static inline int lota_signal_event(int sig, int denied)
{
	if (denied)
		return LOTA_EVENT_KILL_BLOCKED;

	if (sig == 0)
		return 0;

	return LOTA_EVENT_KILL;
}

/*
 * The cgroup.kill verdict, shared with the tests like the signal verdict.
 * A write to a guarded cgroup.kill ends every task in the cgroup without
 * passing the signal hook, so it is refused on the same terms as SIGKILL:
 * in every mode, to everyone but the agent and the admin identity.
 * A read ends nobody.
 */
static inline int lota_kill_guard_denied(int write_open, int guarded,
					 int opener_exempt)
{
	return write_open && guarded && !opener_exempt;
}

/*
 * fs-verity digest sizes LOTA policy enforcement accepts.
 *
 * SHA-256 is what fsverity-utils, the RPM fs-verity plugin and composefs produce
 * by default, so it is the size a distribution-signed object carries;
 * SHA-512 is the stronger option an operator may choose.
 * Key always states its own length, and the map key stays SHA-512 wide with
 * the unused tail zeroed, so both sizes share one map.
 */
#define LOTA_VERITY_DIGEST_SHA256_SIZE 32
#define LOTA_VERITY_DIGEST_SHA512_SIZE 64
#define LOTA_VERITY_DIGEST_MAX_SIZE LOTA_VERITY_DIGEST_SHA512_SIZE

/*
 * fs-verity allowlist key used by BPF map and user-space loader.
 *
 * len must be one of the sizes above;
 * the bytes past len are zero, so key built from either algorithm compares
 * and hashes as one map key.
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
 * What bpf_get_fsverity_digest() writes into the caller's buffer.
 *
 * The kernel fills a struct fsverity_digest -- a two-field header,
 * then the digest bytes -- and reports success as 0, not as a length.
 * Both halves matter to a caller building a map key: the digest starts after
 * the header, and its size is read out of the header.
 *
 * Declared here so the same parse serves the enforcement object and the tests
 * that hold it to this layout.
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

/*
 * Build an allowlist key from that buffer.
 *
 * @buf must be at least LOTA_FSVERITY_DIGEST_BUF_SIZE wide and aligned for
 * the header, which a BPF map value and a userspace object both are.
 * Returns 0 on success, -1 when the reported size is not one policy enforces.
 *
 * The tail past len is zeroed so a SHA-256 key and a SHA-512 key hash as one
 * map key, which is the invariant the struct comment above states.
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
	 * Constant-size copies: a variable length here is what the BPF
	 * verifier refuses, and the two supported sizes are the whole set.
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
 * Execution event - sent from eBPF to user-space via ring buffer.
 * Packed to ensure consistent layout across architectures.
 *
 * Fields used per event type:
 *   EXEC:           pid, uid, comm, filename, hash
 *   MODULE_LOAD:    pid, comm, filename
 *   MMAP_EXEC:      pid, uid, comm, filename, target_pid (=0)
 *   PTRACE:         pid, uid, comm, target_pid
 *   KILL:           pid, uid, comm, target_pid, signal
 *   SETUID:         pid, uid, comm, target_uid (new uid)
 *   *_BLOCKED:      same as base type
 */
struct lota_exec_event {
	__u64 timestamp_ns; /* ktime_get_ns() */
	__u32 event_type; /* enum lota_event_type */
	__u32 pid;
	__u32 tgid;
	__u32 uid;
	union {
		__u32 target_pid; /* ptrace: target process PID */
		__u32 target_uid; /* setuid: new UID after transition */
	};
	__u32 flags; /* LOTA_EVENT_FLAG_* */
	__u32 signal; /* kill: the signal number, which says what arrived */
	__u8 hash[LOTA_HASH_SIZE]; /* inode metadata fingerprint (BPF) */
	char comm[LOTA_MAX_COMM_LEN]; /* Process name */
	char filename[LOTA_MAX_PATH_LEN]; /* Binary path / library path */
} __attribute__((packed));

/*
 * Protected PID map maximum entries.
 * Processes can be added to this map to receive extra protection:
 *   - ptrace on these PIDs is blocked in ENFORCE mode
 *   - mmap(PROT_EXEC) by these PIDs is logged with higher priority
 */
#define LOTA_MAX_PROTECTED_PIDS 1024

/*
 * Trusted library whitelist maximum entries.
 * Specific library paths (for example game-specific .so files) that
 * are allowed in ENFORCE mode even if not in standard paths.
 */
#define LOTA_MAX_TRUSTED_LIBS 512

/*
 * Files whose write kills a protected task past every signal hook:
 * cgroup.kill of the agent's cgroup and its ancestors, so a cgroup depth.
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
	__u32 writers; /* write opens already granted; a pin cannot recall them */
	__u8 digest[LOTA_VERITY_DIGEST_MAX_SIZE]; /* read during the open */
};

/* guarded_files value: why the file is guarded */
#define LOTA_GUARD_CGROUP_KILL 1

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

struct lota_exec_history_val {
	__u64 size;
	char name[LOTA_EXEC_HISTORY_NAME_MAX];
};

/*
 * Every process outside an instance that reached a unix socket of the
 * instance, by connecting to it or sending to it.
 * Keyed by the instance root and its start time, the peer and its start
 * time, the process that owns the socket and how it was reached.
 * Only the agent deletes, and only entries of a root that is gone.
 */
#define LOTA_MAX_INSTANCE_PEERS 4096

enum lota_instance_peer_kind {
	LOTA_INSTANCE_PEER_CONNECT = 1, /* stream or seqpacket connect */
	LOTA_INSTANCE_PEER_SEND = 2, /* datagram sent */
};

struct lota_instance_peer_key {
	__u64 root_start_ticks;
	__u64 peer_start_ticks;
	__u32 root_tgid;
	__u32 peer_tgid;
	__u32 owner_tgid; /* process of the instance that made the socket */
	__u32 kind; /* enum lota_instance_peer_kind */
};

struct lota_instance_peer_val {
	__u64 count; /* connects or datagrams */
	__u64 exe_dev; /* s_dev of the peer's executable, kernel encoding */
	__u64 exe_ino;
	__u32 uid; /* peer's real uid at its first reach */
	__u32 pad;
	char comm[LOTA_MAX_COMM_LEN];
	char owner_comm[LOTA_MAX_COMM_LEN];
};

/*
 * Kernel integrity baseline, as the agent's startup hardening gate read it.
 *
 * The gate refuses to start the agent unless the kernel enforces module
 * signatures and sits at lockdown integrity or above. Both properties are
 * raise-only in the kernel -- module.sig_enforce is an enable-only parameter
 * and the lockdown level never falls -- so the verdict cannot go stale while
 * the agent runs, and the hook reads it here.
 */
struct integrity_data {
	__u32 sig_enforce; /* 1 when module signatures are enforced */
	__u32 lockdown; /* 1 when lockdown is integrity or above */
};

#endif /* LOTA_H */
