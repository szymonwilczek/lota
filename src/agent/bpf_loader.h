/* SPDX-License-Identifier: MIT */
/*
 * LOTA - BPF Program Loader
 * Loads and manages eBPF enforcement programs using libbpf
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_BPF_LOADER_H
#define LOTA_BPF_LOADER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../../include/lota.h"
#include "mapped_pins.h"

struct bpf_object;
struct ring_buffer;
struct bpf_link;

#define BPF_MAX_LSM_LINKS 32

struct bpf_loader_ctx {
	struct bpf_object *obj;
	struct ring_buffer *ringbuf;
	struct bpf_link
		*links[BPF_MAX_LSM_LINKS]; /* attached BPF program links */
	int link_count;
	int ringbuf_fd;
	int stats_fd;
	int config_fd;
	int integrity_fd;
	int task_auth_fd;
	int trusted_libs_fd;
	int guarded_files_fd;
	int protected_pids_fd;
	int instance_fd;
	int instance_stops_fd;
	int born_protected_fd;
	int allow_verity_digest_fd;
	int exe_hash_slots_fd;
	int mapped_exec_fd;
	int exec_history_fd;
	int instance_actors_fd;
	struct mapped_exec_pin *pins; /* what this agent has pinned */
	size_t pin_count;
	size_t pin_cap;
	uint64_t pin_round; /* the round bpf_loader_pin_round_begin() opened */
	bool loaded; /* object in the kernel, maps resolved */
	bool attached; /* programs attached to their hooks */
};

/**
 * bpf_loader_allow_verity_digest() - Add a digest to the fs-verity allowlist.
 * @ctx: Loaded context.
 * @key: Digest length and bytes.
 *
 * Return: 0, -ENOTSUP without the map, or another negative errno.
 */
int bpf_loader_allow_verity_digest(struct bpf_loader_ctx *ctx,
				   const struct lota_verity_digest_key *key);

/**
 * bpf_loader_disallow_verity_digest() - Remove a digest from the allowlist.
 * @ctx: Loaded context.
 * @key: Digest length and bytes.
 *
 * Return: 0, -ENOTSUP without the map, or another negative errno.
 */
int bpf_loader_disallow_verity_digest(struct bpf_loader_ctx *ctx,
				      const struct lota_verity_digest_key *key);

/**
 * bpf_loader_measure_verity_digest() - Read the fs-verity digest of a file.
 * @path: Absolute path to a regular file, with no symlink along it.
 * @out: Digest length and bytes.
 *
 * Return: 0 or a negative errno.
 */
int bpf_loader_measure_verity_digest(const char *path,
				     struct lota_verity_digest_key *out);

/**
 * bpf_loader_hash_file() - Kernel hash of a file, taken during its open.
 * @ctx: Loaded context.
 * @path: /proc magic link to open.
 * @expect_dev: st_dev the open must resolve to.
 * @expect_ino: st_ino the open must resolve to.
 * @out: Digest length and bytes.
 *
 * Return: 0, -ENOSYS without the exe_hash_slots map, -ESTALE when the open
 * resolved to another object, -ENXIO when no program answered, -EPROTO for an
 * unknown algorithm, or another negative errno.
 */
int bpf_loader_hash_file(struct bpf_loader_ctx *ctx, const char *path,
			 uint64_t expect_dev, uint64_t expect_ino,
			 struct lota_verity_digest_key *out);

/**
 * bpf_loader_pin_mapped_object() - Pin a mapped library against writes.
 * @ctx: Loaded context.
 * @path: Path to open, as for bpf_loader_hash_file().
 * @expect_dev: st_dev the open must resolve to.
 * @expect_ino: st_ino the open must resolve to.
 * @guarded: Set to 1 when the file is pinned and may be measured, 0 otherwise.
 *
 * Pins the inode of this open. A file with no mapping record, changed since it
 * was mapped, or open for writing leaves @guarded 0: no pin is set, and one an
 * earlier round set stays. Held until a bpf_loader_pin_sweep() misses it.
 *
 * Return: 0 or a negative errno.
 */
int bpf_loader_pin_mapped_object(struct bpf_loader_ctx *ctx, const char *path,
				 uint64_t expect_dev, uint64_t expect_ino,
				 int *guarded);

/**
 * bpf_loader_pin_round_begin() - Start a round of pinning.
 * @ctx: Loaded context.
 */
void bpf_loader_pin_round_begin(struct bpf_loader_ctx *ctx);

/**
 * bpf_loader_pin_sweep() - Release the pins this round did not reach.
 * @ctx: Loaded context.
 * @released: Optional, set to the number of inodes unpinned.
 *
 * Return: 0 or a negative errno. A pin that could not be released is tried
 * again by the next sweep.
 */
int bpf_loader_pin_sweep(struct bpf_loader_ctx *ctx, size_t *released);

/**
 * bpf_loader_exec_history() - Read the exec history, dropping the dead.
 * @ctx: Loaded context.
 * @alive: Says whether process @tgid started at @start_ticks still runs.
 * @keys: Receives the live entries' keys, to free().
 * @vals: Receives their values, parallel to @keys, to free().
 * @n: Receives the number of entries.
 *
 * Entries of a process @alive denies are deleted from the map.
 *
 * Return: 0, -ENOENT without the map, or another negative errno.
 */
int bpf_loader_exec_history(struct bpf_loader_ctx *ctx,
			    int (*alive)(uint32_t tgid, uint64_t start_ticks),
			    struct lota_exec_history_key **keys,
			    struct lota_exec_history_val **vals, size_t *n);

/**
 * bpf_loader_instance_actors() - Read an instance's actors, dropping the dead.
 * @ctx: Loaded context.
 * @alive: Says whether the instance root @tgid started at @start_ticks runs.
 * @keys: Receives the live entries' keys, to free().
 * @vals: Receives their values, parallel to @keys, to free().
 * @n: Receives the number of entries.
 *
 * Entries of an instance whose root @alive denies are deleted from the map.
 *
 * Return: 0, -ENOENT without the map, or another negative errno.
 */
int bpf_loader_instance_actors(struct bpf_loader_ctx *ctx,
			       int (*alive)(uint32_t tgid,
					    uint64_t start_ticks),
			       struct lota_instance_actor_key **keys,
			       struct lota_instance_actor_val **vals,
			       size_t *n);

typedef int (*bpf_event_handler_t)(void *ctx, void *data, size_t len);

/**
 * bpf_loader_init() - Initialize a loader context.
 * @ctx: Context to initialize.
 *
 * Return: 0, or -EINVAL when @ctx is NULL.
 */
int bpf_loader_init(struct bpf_loader_ctx *ctx);

/**
 * bpf_loader_verify_object() - Would bpf_loader_load() refuse this object?
 * @bpf_obj_path: Compiled BPF object file.
 * @bpf_pubkey_pem_path: PEM Ed25519 public key for the detached signature at
 *	<bpf_obj_path>.sig.
 *
 * Reads the three files and loads nothing, so main refuses a mis-signed object
 * before the boot commitment is spent. bpf_loader_load() verifies again.
 *
 * Return: 0 when the signature verifies, -EINVAL when no object path or public
 * key is configured, or another negative errno.
 */
int bpf_loader_verify_object(const char *bpf_obj_path,
			     const char *bpf_pubkey_pem_path);

/**
 * bpf_loader_load() - Load the BPF object into the kernel, unattached.
 * @ctx: Initialized context.
 * @bpf_obj_path: Compiled BPF object file.
 * @bpf_pubkey_pem_path: PEM Ed25519 public key for the detached signature at
 *	<bpf_obj_path>.sig.
 *
 * Verifies the signature, loads the verified bytes, resolves the map fds with
 * FD_CLOEXEC set, and writes lota_task_auth, the early LOCK_BPF, integrity_cfg
 * and guarded_files. bpf_loader_attach() attaches the programs.
 *
 * Return: 0, -EALREADY when already loaded, or another negative errno.
 */
int bpf_loader_load(struct bpf_loader_ctx *ctx, const char *bpf_obj_path,
		    const char *bpf_pubkey_pem_path);

/**
 * bpf_loader_attach() - Attach the loaded LSM and tracing programs.
 * @ctx: Context after a successful bpf_loader_load().
 *
 * Call once the enforcement policy is in lota_config: a hook attached earlier
 * reads a policy not yet written. Detaches them all on failure.
 *
 * Return: 0, -ENOENT when a program the agent requires did not attach, -E2BIG
 * past BPF_MAX_LSM_LINKS, -EALREADY when already attached, or another negative
 * errno.
 */
int bpf_loader_attach(struct bpf_loader_ctx *ctx);

/**
 * bpf_loader_setup_ringbuf() - Set up the ring buffer for events.
 * @ctx: Loaded context.
 * @handler: Callback for processing events.
 * @handler_ctx: User context passed to @handler.
 *
 * Return: 0, -EALREADY when already set up, or another negative errno.
 */
int bpf_loader_setup_ringbuf(struct bpf_loader_ctx *ctx,
			     bpf_event_handler_t handler, void *handler_ctx);

/**
 * bpf_loader_get_event_fd() - Get the epoll fd of the ring buffer.
 * @ctx: Context.
 *
 * Return: file descriptor or a negative errno.
 */
int bpf_loader_get_event_fd(struct bpf_loader_ctx *ctx);

/**
 * bpf_loader_consume() - Consume available events without blocking.
 * @ctx: Context.
 *
 * Return: number of events processed or a negative errno.
 */
int bpf_loader_consume(struct bpf_loader_ctx *ctx);

/**
 * bpf_loader_set_mode() - Set the enforcement mode.
 * @ctx: Loaded context.
 * @mode: enum lota_mode value.
 *
 * Return: 0 or a negative errno.
 */
int bpf_loader_set_mode(struct bpf_loader_ctx *ctx, uint32_t mode);

/**
 * bpf_loader_get_mode() - Get the enforcement mode.
 * @ctx: Loaded context.
 * @mode: Set to the current mode.
 *
 * Return: 0 or a negative errno.
 */
int bpf_loader_get_mode(struct bpf_loader_ctx *ctx, uint32_t *mode);

/**
 * bpf_loader_set_config() - Set a runtime configuration value.
 * @ctx: Loaded context.
 * @key: LOTA_CFG_* key.
 * @value: Value for @key.
 *
 * Return: 0 or a negative errno.
 */
int bpf_loader_set_config(struct bpf_loader_ctx *ctx, uint32_t key,
			  uint32_t value);

/**
 * bpf_loader_verify_integrity_config() - Compare integrity_cfg with the kernel.
 * @ctx: Loaded context.
 *
 * Return: 0 when the map holds what the kernel publishes now, -ENOTSUP without
 * the map, -EPERM on a mismatch, or another negative errno.
 */
int bpf_loader_verify_integrity_config(struct bpf_loader_ctx *ctx);

/* Where the kernel publishes the two properties the module gate stands on */
#define LOTA_MODULE_SIG_ENFORCE_PATH "/sys/module/module/parameters/sig_enforce"
#define LOTA_KERNEL_LOCKDOWN_PATH "/sys/kernel/security/lockdown"

/**
 * bpf_loader_kernel_module_sig_enforced() - Are module signatures enforced?
 * @sig_enforce_path: sysfs file carrying the module.sig_enforce parameter.
 *
 * Return: 0 when enforced, a negative errno otherwise.
 */
int bpf_loader_kernel_module_sig_enforced(const char *sig_enforce_path);

/**
 * bpf_loader_kernel_lockdown_restrictive() - Is lockdown on?
 * @lockdown_path: securityfs file carrying the lockdown state.
 *
 * Return: 0 in integrity or confidentiality mode, a negative errno otherwise.
 */
int bpf_loader_kernel_lockdown_restrictive(const char *lockdown_path);

/**
 * bpf_loader_build_integrity_config() - Fill the value the module gate reads.
 * @cfg: Value written into the integrity_cfg map.
 * @sig_enforce_path: sysfs file carrying the module.sig_enforce parameter.
 * @lockdown_path: securityfs file carrying the lockdown state.
 *
 * Runs the two readers the hardening gate runs. A reader that fails leaves its
 * field 0.
 *
 * Return: 0, or -EINVAL when @cfg is NULL.
 */
int bpf_loader_build_integrity_config(struct integrity_data *cfg,
				      const char *sig_enforce_path,
				      const char *lockdown_path);

/**
 * bpf_loader_object_integrity_layout() - The integrity map an object carries.
 * @bpf_obj_path: Enforcement object on disk.
 * @key_size: Set to the map's key size.
 * @value_size: Set to the map's value size.
 *
 * Return: 0, -EIO when the object cannot be opened, -ENOENT when it carries no
 * integrity map, or -EINVAL on a NULL argument.
 */
int bpf_loader_object_integrity_layout(const char *bpf_obj_path,
				       uint32_t *key_size,
				       uint32_t *value_size);

/**
 * bpf_loader_check_object_integrity_layout() - Can this agent read that map?
 * @bpf_obj_path: Enforcement object on disk.
 *
 * The kernel copies the map's own value_size to and from the caller's buffer,
 * so its layout has to match struct integrity_data. Reads the file alone, so
 * main refuses a mismatch before the boot commitment is spent.
 *
 * Return: 0 when the sizes match, -ENOTSUP when they do not, or another
 * negative errno.
 */
int bpf_loader_check_object_integrity_layout(const char *bpf_obj_path);

/**
 * bpf_loader_integrity_config_satisfied() - Does @cfg meet the module baseline?
 * @cfg: Value written into the integrity_cfg map.
 *
 * The userspace mirror of integrity_baseline_ok() in the BPF program.
 *
 * Return: true when both module signatures and lockdown are set in @cfg.
 */
bool bpf_loader_integrity_config_satisfied(const struct integrity_data *cfg);

/**
 * bpf_loader_ima_appraisal_active() - Do mode and policy appraise exec?
 * @cmdline_path: Kernel cmdline carrying ima_appraise=, the mode.
 * @policy_path: Loaded IMA policy carrying the func= rules, the scope.
 * @secureboot: Non-zero when this host booted with Secure Boot on. The kernel
 *	then keeps its built-in mode, enforce, and @cmdline_path is not read.
 *
 * Return: 0 when the mode is enforce and a rule reaches an executable,
 * -ENOENT when no rule does, -EACCES when the policy could not be read, or
 * another negative errno. Callers report anything but 0 as not appraised.
 */
int bpf_loader_ima_appraisal_active(const char *cmdline_path,
				    const char *policy_path, int secureboot);

/**
 * bpf_loader_secure_boot_enabled() - Check the UEFI Secure Boot state.
 *
 * Return: 0 when efivarfs shows SecureBoot=1, a negative errno otherwise.
 */
int bpf_loader_secure_boot_enabled(void);

/**
 * bpf_loader_kernel_appraises_exec() - Does this host appraise executables?
 *
 * bpf_loader_ima_appraisal_active() on the booted cmdline, the loaded policy
 * and this host's Secure Boot state.
 *
 * Return: as for bpf_loader_ima_appraisal_active().
 */
int bpf_loader_kernel_appraises_exec(void);

/**
 * bpf_loader_verify_kernel_runtime_hardening() - Check the kernel floor.
 * @allow_mutable_rootfs: Let the checks named below pass with a warning.
 *
 * Refuses unless lockdown is restrictive and module signatures are enforced.
 *
 * Refuses when no executable is appraised, unless the agent binary has
 * fs-verity or @allow_mutable_rootfs is set; an IMA policy that could not be
 * read passes either way, with a warning.
 *
 * Unless @allow_mutable_rootfs is set, refuses a TPM device without the
 * lota_tpm_device_t label and an agent binary with neither fs-verity nor a
 * signature-type security.ima.
 *
 * Return: 0 or a negative errno.
 */
int bpf_loader_verify_kernel_runtime_hardening(bool allow_mutable_rootfs);

/**
 * bpf_loader_protect_pid() - Add a PID to the protected set.
 * @ctx: Loaded context.
 * @pid: Process ID to protect.
 *
 * The entry carries the start time from /proc/<pid>/stat, which a process that
 * reuses @pid does not match.
 *
 * Return: 0, -ENOTSUP without the map or outside the initial PID namespace,
 * or another negative errno.
 */
int bpf_loader_protect_pid(struct bpf_loader_ctx *ctx, uint32_t pid);

/**
 * bpf_loader_adopt_instance_member() - Name an instance member in the set.
 * @ctx: Loaded context.
 * @pid: Process ID to ask about.
 *
 * A process created by a protected one carries its creator's instance in
 * lota_instance. When @pid does, it is added to protected_pids under its start
 * time. The membership is read through a pidfd before and after the start time,
 * so a PID reused in between is not taken.
 *
 * Return: 1 when added, 0 when @pid is not a member, or a negative errno.
 */
int bpf_loader_adopt_instance_member(struct bpf_loader_ctx *ctx, uint32_t pid);

/**
 * bpf_loader_instance_stopped_ms() - How long @pid's instance stood stopped.
 * @ctx: Loaded context.
 * @pid: Process ID to ask about.
 * @ms: Set to the milliseconds any thread of the instance stood stopped.
 *
 * Read from the root of the instance, so the value covers every member.
 * @ms is 0 when the root has gone or no stop was recorded.
 *
 * Return: 0 or a negative errno.
 */
int bpf_loader_instance_stopped_ms(struct bpf_loader_ctx *ctx, uint32_t pid,
				   uint64_t *ms);

/**
 * bpf_loader_born_protected() - Was @pid's image executed under protection?
 * @ctx: Loaded context.
 * @pid: Process ID to ask about.
 * @start_ticks: Start time the answer has to belong to.
 *
 * A process that forked from a protected one and never executed was not.
 *
 * Return: 1 when it was, 0 when not or unknown, or a negative errno.
 */
int bpf_loader_born_protected(struct bpf_loader_ctx *ctx, uint32_t pid,
			      uint64_t start_ticks);

/**
 * bpf_loader_probe_protect_pid() - Could this PID be protected?
 * @pid: Process ID a startup policy names.
 *
 * Makes the read bpf_loader_protect_pid() makes and needs no loaded context,
 * so main refuses a startup policy before the boot commitment is spent.
 *
 * Return: 0 when the PID can be protected, -ENOENT when no process runs under
 * it, or another negative errno.
 */
int bpf_loader_probe_protect_pid(uint32_t pid);

/**
 * bpf_loader_protected_pids() - Read the protected set.
 * @ctx: Loaded context.
 * @pid: Receives up to @max PIDs.
 * @start: Receives each PID's start time in clock ticks.
 * @max: Capacity of both arrays.
 *
 * Return: the number of entries read or a negative errno.
 */
int bpf_loader_protected_pids(const struct bpf_loader_ctx *ctx, uint32_t *pid,
			      uint64_t *start, size_t max);

/**
 * bpf_loader_unprotect_pid() - Remove a PID from the protected set.
 * @ctx: Loaded context.
 * @pid: Process ID to unprotect.
 *
 * Return: 0 or a negative errno.
 */
int bpf_loader_unprotect_pid(struct bpf_loader_ctx *ctx, uint32_t pid);

/**
 * bpf_loader_trust_lib() - Add a library to the trusted set.
 * @ctx: Loaded context.
 * @path: Absolute path to a regular file, with no symlink along it.
 *
 * Keyed by superblock device and inode. A trusted library passes the strict
 * mmap check on executable mappings.
 *
 * Return: 0, -ENOTSUP without the map, or another negative errno.
 */
int bpf_loader_trust_lib(struct bpf_loader_ctx *ctx, const char *path);

/**
 * bpf_loader_probe_trusted_lib() - Could this path be trusted?
 * @path: As for bpf_loader_trust_lib().
 *
 * Resolves @path as bpf_loader_trust_lib() does and needs no loaded context,
 * so main refuses a startup policy before the boot commitment is spent.
 *
 * Return: 0 when the path resolves or a negative errno.
 */
int bpf_loader_probe_trusted_lib(const char *path);

/**
 * bpf_loader_untrust_lib() - Remove a library from the trusted set.
 * @ctx: Loaded context.
 * @path: As for bpf_loader_trust_lib().
 *
 * Return: 0, also when @path was not in the set, -ENOTSUP without the map,
 * or another negative errno.
 */
int bpf_loader_untrust_lib(struct bpf_loader_ctx *ctx, const char *path);

struct bpf_extended_stats {
	uint64_t total_execs;
	uint64_t events_sent;
	uint64_t drops;
	uint64_t modules_blocked;
	uint64_t mmap_execs;
	uint64_t mmap_blocked;
	uint64_t ptrace_attempts;
	uint64_t ptrace_blocked;
	uint64_t setuid_events;
	uint64_t bpf_syscall_blocked;
	uint64_t mounts_blocked;
	uint64_t kill_guard_blocked;
	uint64_t events_yielded; /* dropped to leave ring room */
	uint64_t blocked_suppressed; /* refused events past their budget */
	uint64_t kill_probes; /* signal-0 probes at a protected task */
	uint64_t mapped_write_blocked; /* writes refused to a pinned library */
	uint64_t mapped_pin_refused; /* mapped objects left unpinned */
	uint64_t exec_history_lost; /* exec mappings left unrecorded */
	uint64_t instance_actors_lost; /* instance socket reaches unrecorded */
	uint64_t instance_stops_lost; /* instance thread stops unrecorded */
};

/**
 * bpf_loader_get_extended_stats() - Read the statistics.
 * @ctx: Loaded context.
 * @stats: Receives the counters; one that cannot be read is 0.
 *
 * Return: 0, or -EINVAL without a loaded context or the stats map.
 */
int bpf_loader_get_extended_stats(struct bpf_loader_ctx *ctx,
				  struct bpf_extended_stats *stats);

/**
 * bpf_loader_cleanup() - Release the object and reset the context.
 * @ctx: Context to clean up.
 *
 * The links stay open, so the attached programs run until this process exits.
 */
void bpf_loader_cleanup(struct bpf_loader_ctx *ctx);

#endif /* LOTA_BPF_LOADER_H */
