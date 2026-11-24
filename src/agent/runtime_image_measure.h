/* SPDX-License-Identifier: MIT */
/*
 * Kernel-anchored runtime image measurement of a live process.
 *
 * Enumerates the file-backed executable mappings of a target PID from
 * /proc/<pid>/maps (kernel-maintained, so the target cannot forge it) and,
 * for each backing object, folds the kernel-computed fs-verity digest into
 * the canonical per-process image digest defined in
 * include/lota_runtime_image_measure.h.
 *
 * Measurement is performed by the privileged agent, never by the measured
 * process.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_AGENT_RUNTIME_IMAGE_MEASURE_H
#define LOTA_AGENT_RUNTIME_IMAGE_MEASURE_H

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "lota_runtime_image_measure.h"
#include "lota.h"

/* longest mapping path kept; the parser refuses a longer one */
#define LOTA_RT_MAP_PATH_MAX (LOTA_RUNTIME_IMAGE_SONAME_MAX + 64)

/* What a failing object is to the process that mapped it */
enum lota_rt_object_role {
	LOTA_RT_ROLE_UNKNOWN = 0, /* mapping would not open */
	LOTA_RT_ROLE_EXECUTABLE, /* no digest refuses the token */
	LOTA_RT_ROLE_MAPPED_OBJECT, /* no digest marks coverage partial */
};

/*
 * One file-backed executable mapping selected for measurement.
 * - start/end are the mapping's virtual address range (used to build the
 * authoritative /proc/<pid>/map_files key)
 * - dev/ino identify the backing inode
 * - soname is the basename the image digest folds
 * - path is the mapped file, for the operator
 */
struct lota_rt_map_entry {
	unsigned long start;
	unsigned long end;
	unsigned int dev_major;
	unsigned int dev_minor;
	unsigned long long ino;
	char soname[LOTA_RUNTIME_IMAGE_SONAME_MAX];
	char path[LOTA_RT_MAP_PATH_MAX];
};

/*
 * Parse one /proc/<pid>/maps line.
 *
 * Returns 1 and fills *out when the line is a file-backed executable
 * mapping worth measuring, 0 when the line should be skipped (non-executable,
 * anonymous, or a special region such as [vdso] / [stack]), or a negative
 * errno when the line is malformed.
 */
int lota_rt_parse_maps_line(const char *line, struct lota_rt_map_entry *out);

/*
 * Identity of an opened mapping, as stat() reports it.
 *
 * Kept apart from the numbers in /proc/<pid>/maps:
 * this one is comparable with a stat() of /proc/<pid>/exe,
 * and that one is not.
 */
struct lota_rt_open_identity {
	dev_t dev;
	ino_t ino;
	unsigned long fs_magic; /* fstatfs() f_type of the fd, 0 if unread */
	int fs_magic_err; /* fstatfs() errno, 0 if fs_magic was read */
	uint64_t size; /* with mtime, tells a replaced file from a cached one */
	int64_t mtime_sec;
	int64_t mtime_nsec;
	/* 0 once nothing links it anywhere */
	unsigned long nlink;
	int seals; /* F_GET_SEALS of the fd, negative where it has none */
};

/*
 * How an object's digest may be produced. fs-verity wins wherever present;
 * a content hash is sound only for what cannot be written: the running
 * executable or a write-guarded library.
 */
enum lota_rt_identity_road {
	LOTA_RT_ROAD_NONE = 0, /* no digest may be produced for this object */
	LOTA_RT_ROAD_VERITY, /* the kernel holds an fs-verity digest */
	LOTA_RT_ROAD_CONTENT_HASH, /* the kernel hashes the content on demand */
};

/*
 * Whether an object is memory with no file behind it: an unlinked tmpfs or
 * hugetlbfs object, such as a memfd. No road may answer for it;
 * it is a coverage gap. An unlinked file on disk is still a file.
 */
int lota_rt_object_has_no_file(unsigned long fs_magic, unsigned long nlink);

/*
 * The LOTA_EXEC_HISTORY_* an open object carries by what it is, for a mapping
 * older than protection, which the kernel never saw. With no name and no seal
 * against writes, any holder of an fd can write it. A writer of anything else
 * shows only at the mapping itself.
 */
uint32_t lota_rt_object_memory_flags(unsigned long fs_magic,
				     unsigned long nlink, int seals);

/*
 * Which road may measure one object of a live process. role is an enum
 * lota_rt_object_role; a filesystem off the fs_magic allowlist gets no
 * content hash; write_guarded: the agent pinned it against writes.
 */
enum lota_rt_identity_road lota_rt_identity_road(int role, int verity_present,
						 unsigned long fs_magic,
						 int write_guarded);

/*
 * Kernel hash of the content behind one mapping: path is its /proc magic
 * link, dev/ino the identity the open must resolve to.
 * Returns 0 or a negative errno. With none installed, only fs-verity measures.
 */
typedef int (*lota_rt_content_hasher_fn)(const char *path, uint64_t dev,
					 uint64_t ino,
					 struct lota_verity_digest_key *out);

void lota_rt_set_content_hasher(lota_rt_content_hasher_fn fn);

/*
 * Pin the file behind one mapping against writes; arguments as for the
 * hasher. 0 and pinned set, or a negative errno. Unset: no library hashed.
 */
typedef int (*lota_rt_pin_object_fn)(const char *path, uint64_t dev,
				     uint64_t ino, int *pinned);

/* Pin rounds: the sweep unpins what its round did not reach */
typedef void (*lota_rt_pin_round_fn)(void);
typedef int (*lota_rt_pin_sweep_fn)(size_t *released);

void lota_rt_set_pin_object(lota_rt_pin_object_fn pin,
			    lota_rt_pin_round_fn round_begin,
			    lota_rt_pin_sweep_fn sweep);

/*
 * Bracket one measurement of the whole protected set,
 * so a library two processes map stays pinned for both.
 */
void lota_rt_measure_round_begin(void);
int lota_rt_measure_round_end(size_t *released);

/*
 * Does the opened mapping still describe the one that was enumerated?
 *
 * enumerated and observed are both read from /proc/<pid>/maps -- the second
 * after the handle was opened -- so their device numbers are the same quantity
 * and can be compared.
 *
 * opened_ino is the inode of the handle itself, which is what ties the file
 * that will be measured to the range that was enumerated.
 *
 * A device from stat() is deliberately not one of the inputs: a filesystem
 * that reports one device per subvolume, as btrfs does, answers stat()
 * and maps differently for the same live mapping, and comparing the two refuses
 * every mapping on such a host.
 *
 * Returns 1 when the mapping is unchanged, 0 otherwise -- including for a NULL
 * argument, so the caller fails closed.
 */
int lota_rt_mapping_identity_ok(const struct lota_rt_map_entry *enumerated,
				const struct lota_rt_map_entry *observed,
				unsigned long long opened_ino);

/*
 * Collect the deduplicated set of file-backed executable mappings of a live
 * process (one entry per backing inode) into entries[].
 *
 * Returns 0, the entry count via *n_out and the number of mappings that did
 * not fit via *past_limit, or a negative errno. Mappings past max are counted
 * and not deduplicated: telling their inodes apart would take the list the
 * limit bounds.
 */
int lota_rt_collect_exec_maps(pid_t pid, struct lota_rt_map_entry *entries,
			      size_t max, size_t *n_out, uint32_t *past_limit);

/*
 * Why a runtime image measurement failed, so the caller can name the object
 * instead of printing a bare errno.
 *
 * soname is the basename of the object that stopped the measurement
 * and is empty when the measurement failed before any object was reached.
 *
 * path is where that object was mapped from; a basename is ambiguous.
 *
 * role is enum lota_rt_object_role.
 *
 * reported_len is the digest length the kernel returned for that object:
 * zero when it carries no fs-verity digest at all, otherwise a length LOTA
 * does not take.
 */
struct lota_runtime_measure_failure {
	char soname[LOTA_RUNTIME_IMAGE_SONAME_MAX];
	char path[LOTA_RT_MAP_PATH_MAX];
	uint32_t reported_len;
	int role;
	int err;
	int road_err; /* content road's refusal, 0 if that road was closed */
	int no_file; /* memory with no file behind it */
	uint32_t past_limit; /* mappings past the limit, once all were walked */
};

/*
 * Whether err says the agent ran out of something, and nothing about the
 * process it walked.
 */
static inline int lota_rt_err_is_agent_failure(int err)
{
	return err == -ENOMEM || err == -EMFILE || err == -ENFILE;
}

#define LOTA_RT_REASON_MAX 512 /* longest lota_rt_failure_reason() sentence */

/*
 * Render a failure into buf as one sentence: object path, its role in the
 * process, and the reason. Always NUL-terminates.
 * Safe with a NULL failure, which renders the errno alone.
 */
void lota_rt_failure_reason(const struct lota_runtime_measure_failure *fail,
			    int err, char *buf, size_t buflen);

/*
 * How much of a process's mapped code the measurement could account for.
 *
 * measured counts the objects folded into the image digest;
 * unmeasurable counts those the kernel holds no fs-verity digest for.
 *
 * Distinction is the relying party's to act on: machine that cannot measure
 * distribution's libc is not a machine that hid something, and a publisher who
 * wants full coverage asks for the flag that says so.
 */
struct lota_runtime_measure_coverage {
	uint32_t measured;
	uint32_t unmeasurable;
	uint32_t content_hashed; /* of measured: content hash, not fs-verity */
	uint32_t past_limit; /* of unmeasurable: past the object limit */
};

/*
 * Coverage of a process's mapped code, without folding a digest.
 *
 * Same enumeration and the same per-object read as the measurement,
 * minus the hash: it answers "how much of this process could be measured"
 * for a caller that needs the answer rather than the value
 * -- the status word, which has to agree with the token the same connection
 * later fetches.
 * Returns 0 and fills cov, or a negative errno.
 */
int lota_runtime_coverage_pid(pid_t pid,
			      struct lota_runtime_measure_coverage *cov);

/*
 * Whether a measurement round may be issued at all.
 *
 * Full coverage is a publisher's policy question, but two properties are the host's
 * and are not negotiable: something has to have been measured, and the process's
 * own executable -- the code the title itself ships, which whoever ships it can
 * make measurable -- has to be one of the objects measured.
 *
 * Returns 0 when the digest may be issued, -ENODATA otherwise.
 */
int lota_rt_coverage_verdict(const struct lota_runtime_measure_coverage *cov,
			     int exe_measured);

/*
 * Open the file behind one enumerated mapping through <dirfd>/<range>, dirfd
 * being /proc/<pid>/map_files: a kernel magic symlink, so no path the process
 * controls is followed.
 *
 * Returns the fd and fills st, or a negative errno; -ESTALE when the range no
 * longer holds a regular file.
 */
int lota_rt_open_mapping(int dirfd, const struct lota_rt_map_entry *entry,
			 struct stat *st);

/*
 * Compute the kernel-anchored runtime image digest of a live process.
 *
 * Enumerates the process's file-backed executable mappings, opens them all,
 * reads the maps once more to tie every handle to its range, folds the kernel
 * fs-verity digest of every object that carries one into the canonical image
 * digest, and writes the 32-byte result.
 *
 * Objects with no digest, mappings that will not open or no longer resolve to
 * the inode enumerated, and mappings past LOTA_RUNTIME_IMAGE_MAX_MODULES, are
 * counted, not guessed at:
 * they are absent from the fold and reported through cov, so partial measurement
 * can never be read as a complete one.
 * cov->past_limit is set also when the measurement fails after the enumeration.
 *
 * Fails closed (negative errno) when lota_rt_coverage_verdict() refuses the round,
 * when the own executable fails, with the errno of a read that failed, and
 * when the agent runs out of memory or descriptors.
 *
 * cov and fail may be NULL.
 * When fail is non-NULL it receives the object that stopped the measurement,
 * for lota_rt_failure_reason().
 *
 * Returns 0 on success.
 */
int lota_runtime_measure_pid(pid_t pid,
			     uint8_t out_digest[LOTA_RUNTIME_IMAGE_DIGEST_SIZE],
			     struct lota_runtime_measure_coverage *cov,
			     struct lota_runtime_measure_failure *fail);

/*
 * One mapping a measurement found, for the registry.
 *
 * digest.len is 0 for an object absent from the fold; content_hashed says
 * the digest is a kernel content hash rather than an fs-verity one.
 * size is 0 when the object would not open.
 */
struct lota_rt_object_record {
	struct lota_rt_map_entry entry;
	struct lota_verity_digest_key digest;
	uint64_t size;
	int content_hashed;
	int unmapped; /* only in the exec history, no longer in the maps */
	uint32_t history_flags; /* LOTA_EXEC_HISTORY_*, by the walk and the kernel */
};

/*
 * lota_runtime_measure_pid(), plus every enumerated mapping in objs.
 *
 * objs holds LOTA_RUNTIME_IMAGE_MAX_MODULES records, or is NULL.
 * *n_objs receives how many were filled, also when the measurement fails
 * after the enumeration, so a failed process still names what it mapped.
 */
int lota_runtime_measure_pid_objects(
	pid_t pid, uint8_t out_digest[LOTA_RUNTIME_IMAGE_DIGEST_SIZE],
	struct lota_runtime_measure_coverage *cov,
	struct lota_runtime_measure_failure *fail,
	struct lota_rt_object_record *objs, size_t *n_objs);

#endif /* LOTA_AGENT_RUNTIME_IMAGE_MEASURE_H */
