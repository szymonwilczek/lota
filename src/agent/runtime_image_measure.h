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

#include <stddef.h>
#include <stdint.h>
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
	uint64_t size; /* with mtime, tells a replaced file from a cached one */
	int64_t mtime_sec;
	int64_t mtime_nsec;
};

/*
 * How an object's digest may be produced. fs-verity wins wherever present;
 * a content hash is sound only for the process's own executable, which
 * cannot be written while it runs.
 */
enum lota_rt_identity_road {
	LOTA_RT_ROAD_NONE = 0, /* no digest may be produced for this object */
	LOTA_RT_ROAD_VERITY, /* the kernel holds an fs-verity digest */
	LOTA_RT_ROAD_CONTENT_HASH, /* the kernel hashes the content on demand */
};

/*
 * Which road may measure one object of a live process.
 * role is an enum lota_rt_object_role; fs_magic is matched against an allowlist,
 * so an unlisted filesystem gets no content hash.
 */
enum lota_rt_identity_road lota_rt_identity_road(int role, int verity_present,
						 unsigned long fs_magic);

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
 * Read the current /proc/<pid>/maps entry covering exactly [start, end).
 *
 * Returns 1 and fills *out when the range is still a file-backed executable
 * mapping, 0 when no such range exists any more, or a negative errno.
 * *out is zeroed on anything but a hit.
 */
int lota_rt_lookup_map_entry(pid_t pid, unsigned long start, unsigned long end,
			     struct lota_rt_map_entry *out);

/*
 * Collect the deduplicated set of file-backed executable mappings of a live
 * process (one entry per backing inode) into entries[].
 *
 * Returns 0 and the entry count via *n_out, or a negative errno. -E2BIG is
 * returned (fail closed) if the process has more measurable objects than the
 * caller-provided capacity.
 */
int lota_rt_collect_exec_maps(pid_t pid, struct lota_rt_map_entry *entries,
			      size_t max, size_t *n_out);

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
	unsigned long long ino;
	uint32_t reported_len;
	int role;
	int err;
};

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
 * Measure the kernel fs-verity digest of one enumerated mapping.
 *
 * Opens the exact backing inode through /proc/<pid>/map_files/<range> (a
 * kernel magic symlink, so no attacker-controlled path is followed),
 * confirms it still resolves to the dev/inode recorded during enumeration,
 * and reads the kernel-computed fs-verity measurement.
 * Fails closed if the object lacks fs-verity.
 *
 * When reported_len is non-NULL it receives the digest length the kernel reported,
 * so caller can say what was wrong with a length LOTA does not take.
 *
 * Returns 0 on success, negative errno otherwise.
 */
int lota_rt_measure_entry_verity(pid_t pid,
				 const struct lota_rt_map_entry *entry,
				 struct lota_verity_digest_key *out,
				 uint32_t *reported_len,
				 struct lota_rt_open_identity *opened);

/*
 * Compute the kernel-anchored runtime image digest of a live process.
 *
 * Enumerates the process's file-backed executable mappings, folds the
 * kernel fs-verity digest of every object that carries one into the
 * canonical image digest, and writes the 32-byte result.
 *
 * Objects the kernel holds no digest for are counted, not guessed at:
 * they are absent from the fold and reported through cov, so partial measurement
 * can never be read as a complete one.
 *
 * Fails closed (negative errno) when lota_rt_coverage_verdict() refuses the round,
 * and on any error that is not an unmeasurable object -- mapping that cannot
 * be opened or no longer resolves to the inode enumerated is a failure,
 * not a coverage gap.
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

#endif /* LOTA_AGENT_RUNTIME_IMAGE_MEASURE_H */
