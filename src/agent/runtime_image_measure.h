/* SPDX-License-Identifier: MIT */
/*
 * Kernel-anchored runtime image measurement of a live process: the
 * file-backed executable mappings folded into the image digest of
 * include/lota_runtime_image_measure.h.
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

/* the parser refuses a longer mapping path */
#define LOTA_RT_MAP_PATH_MAX (LOTA_RUNTIME_IMAGE_SONAME_MAX + 64)

/**
 * enum lota_rt_object_role - What an object is to the process that mapped it.
 * @LOTA_RT_ROLE_UNKNOWN: not opened, or no longer the mapping enumerated.
 * @LOTA_RT_ROLE_EXECUTABLE: the process's own executable; a failure fails
 *	the measurement.
 * @LOTA_RT_ROLE_MAPPED_OBJECT: anything else; a failure is counted as
 *	unmeasurable.
 */
enum lota_rt_object_role {
	LOTA_RT_ROLE_UNKNOWN = 0,
	LOTA_RT_ROLE_EXECUTABLE,
	LOTA_RT_ROLE_MAPPED_OBJECT,
};

/**
 * struct lota_rt_map_entry - One file-backed executable mapping.
 * @start: start of the address range, which names it in map_files.
 * @end: end of the address range.
 * @dev_major: device major, as maps reports it.
 * @dev_minor: device minor, as maps reports it.
 * @ino: inode of the backing file.
 * @soname: basename the image digest folds.
 * @path: mapped path, " (deleted)" stripped.
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

/**
 * lota_rt_parse_maps_line() - Parse one /proc/<pid>/maps line.
 * @line: the line.
 * @out: the mapping.
 *
 * Return: 1 and @out filled for a file-backed executable mapping, 0 for a
 * line to skip (not executable, anonymous, or a region such as [vdso]),
 * -ENAMETOOLONG for a path that does not fit, -EINVAL otherwise.
 */
int lota_rt_parse_maps_line(const char *line, struct lota_rt_map_entry *out);

/**
 * struct lota_rt_open_identity - An opened mapping, as fstat() reports it.
 * @dev: device; comparable with a stat() of /proc/<pid>/exe, unlike the
 *	maps device.
 * @ino: inode.
 * @fs_magic: fstatfs() f_type of the fd, 0 if unread.
 * @fs_magic_err: fstatfs() errno, 0 if @fs_magic was read.
 * @size: size; with dev, ino and mtime, the digest cache key.
 * @mtime_sec: mtime seconds.
 * @mtime_nsec: mtime nanoseconds.
 * @nlink: link count; 0 once nothing links it.
 * @seals: F_GET_SEALS of the fd, negative where it has none.
 */
struct lota_rt_open_identity {
	dev_t dev;
	ino_t ino;
	unsigned long fs_magic;
	int fs_magic_err;
	uint64_t size;
	int64_t mtime_sec;
	int64_t mtime_nsec;
	unsigned long nlink;
	int seals;
};

/**
 * enum lota_rt_identity_road - How an object's digest may be produced.
 * @LOTA_RT_ROAD_NONE: no digest may be produced.
 * @LOTA_RT_ROAD_VERITY: the kernel holds an fs-verity digest.
 * @LOTA_RT_ROAD_CONTENT_HASH: the kernel hashes the content on demand.
 */
enum lota_rt_identity_road {
	LOTA_RT_ROAD_NONE = 0,
	LOTA_RT_ROAD_VERITY,
	LOTA_RT_ROAD_CONTENT_HASH,
};

/**
 * lota_rt_object_has_no_file() - Whether an object is memory with no file.
 * @fs_magic: f_type of its filesystem.
 * @nlink: its link count.
 *
 * Return: 1 for an unlinked tmpfs or hugetlbfs object, such as a memfd,
 * 0 otherwise; an unlinked file on disk is still a file.
 */
int lota_rt_object_has_no_file(unsigned long fs_magic, unsigned long nlink);

/**
 * lota_rt_object_memory_flags() - LOTA_EXEC_HISTORY_* of an open object.
 * @fs_magic: f_type of its filesystem.
 * @nlink: its link count.
 * @seals: its F_GET_SEALS, negative where it has none.
 *
 * Return: 0 off tmpfs and hugetlbfs, else LOTA_EXEC_HISTORY_MEMORY, plus
 * LOTA_EXEC_HISTORY_WRITABLE when unlinked and not sealed against writes.
 */
uint32_t lota_rt_object_memory_flags(unsigned long fs_magic,
				     unsigned long nlink, int seals);

/**
 * lota_rt_identity_road() - Which road may measure one object.
 * @role: enum lota_rt_object_role.
 * @verity_present: the kernel holds an fs-verity digest for it.
 * @fs_magic: f_type of its filesystem.
 * @write_guarded: bpf_loader_pin_mapped_object() set its @guarded.
 *
 * fs-verity wins whatever the role. A content hash is taken only for the
 * executable or a write-guarded mapped object, on a filesystem in the
 * allowlist.
 *
 * Return: the road, LOTA_RT_ROAD_NONE when none may.
 */
enum lota_rt_identity_road lota_rt_identity_road(int role, int verity_present,
						 unsigned long fs_magic,
						 int write_guarded);

/**
 * typedef lota_rt_content_hasher_fn - Kernel hash of the content of a mapping.
 * @path: its map_files link.
 * @dev: device the open must resolve to.
 * @ino: inode the open must resolve to.
 * @out: the digest.
 *
 * With none installed, only fs-verity measures.
 *
 * Return: 0 or a negative errno.
 */
typedef int (*lota_rt_content_hasher_fn)(const char *path, uint64_t dev,
					 uint64_t ino,
					 struct lota_verity_digest_key *out);

void lota_rt_set_content_hasher(lota_rt_content_hasher_fn fn);

/**
 * typedef lota_rt_pin_object_fn - Pin the file of a mapping against writes.
 * @path: its map_files link.
 * @dev: device the open must resolve to.
 * @ino: inode the open must resolve to.
 * @pinned: set when the file is pinned.
 *
 * With none installed, no mapped object is content hashed.
 *
 * Return: 0 or a negative errno.
 */
typedef int (*lota_rt_pin_object_fn)(const char *path, uint64_t dev,
				     uint64_t ino, int *pinned);

/* a round's sweep unpins what the round did not reach */
typedef void (*lota_rt_pin_round_fn)(void);
typedef int (*lota_rt_pin_sweep_fn)(size_t *released);

void lota_rt_set_pin_object(lota_rt_pin_object_fn pin,
			    lota_rt_pin_round_fn round_begin,
			    lota_rt_pin_sweep_fn sweep);

/*
 * Bracket one measurement of the whole protected set. round_end() returns
 * the sweep's result, 0 with *released 0 when no sweep is installed.
 */
void lota_rt_measure_round_begin(void);
int lota_rt_measure_round_end(size_t *released);

/**
 * lota_rt_mapping_identity_ok() - Whether an opened mapping is the one
 * enumerated.
 * @enumerated: the mapping from the first maps read.
 * @observed: the same range from the maps read after the open.
 * @opened_ino: inode of the opened handle.
 *
 * Both devices come from maps: a filesystem with a device per subvolume,
 * such as btrfs, reports another one to stat().
 *
 * Return: 1 when device and inode match, 0 otherwise or for a NULL argument.
 */
int lota_rt_mapping_identity_ok(const struct lota_rt_map_entry *enumerated,
				const struct lota_rt_map_entry *observed,
				unsigned long long opened_ino);

/**
 * lota_rt_collect_exec_maps() - File-backed executable mappings of a process.
 * @pid: the process.
 * @entries: one entry per backing inode.
 * @max: capacity of @entries.
 * @n_out: entries filled.
 * @past_limit: mappings that did not fit.
 *
 * A mapping past @max whose inode is in @entries is skipped; the others are
 * counted, each mapping of one inode again.
 *
 * Return: 0, or a negative errno with @n_out and @past_limit untouched.
 */
int lota_rt_collect_exec_maps(pid_t pid, struct lota_rt_map_entry *entries,
			      size_t max, size_t *n_out, uint32_t *past_limit);

/**
 * struct lota_runtime_measure_failure - The object a measurement failed on.
 * @soname: its basename; empty when no mapping was reached.
 * @path: where it was mapped from.
 * @reported_len: fs-verity digest length the kernel returned; nonzero only
 *	for a length LOTA does not take.
 * @role: enum lota_rt_object_role.
 * @err: negative errno of its measurement.
 * @road_err: why the content road refused, 0 if it was not tried.
 * @no_file: memory with no file behind it.
 * @past_limit: mappings past the limit, set once all were walked.
 */
struct lota_runtime_measure_failure {
	char soname[LOTA_RUNTIME_IMAGE_SONAME_MAX];
	char path[LOTA_RT_MAP_PATH_MAX];
	uint32_t reported_len;
	int role;
	int err;
	int road_err;
	int no_file;
	uint32_t past_limit;
};

/* the agent ran out of something; nothing about the process walked */
static inline int lota_rt_err_is_agent_failure(int err)
{
	return err == -ENOMEM || err == -EMFILE || err == -ENFILE;
}

#define LOTA_RT_REASON_MAX 512

/**
 * lota_rt_failure_reason() - Render a failure as one sentence.
 * @fail: the failure, or NULL for @err alone.
 * @err: errno of the measurement, either sign.
 * @buf: the sentence, NUL-terminated and truncated to @buflen.
 * @buflen: size of @buf.
 *
 * Mappings past the limit win over the object; -ENODATA names the cause
 * kept in @fail.
 */
void lota_rt_failure_reason(const struct lota_runtime_measure_failure *fail,
			    int err, char *buf, size_t buflen);

/**
 * struct lota_runtime_measure_coverage - How much mapped code was measured.
 * @measured: objects folded into the image digest.
 * @unmeasurable: objects left out of it.
 * @content_hashed: of @measured, those content hashed, not fs-verity.
 * @past_limit: of @unmeasurable, those past the object limit.
 */
struct lota_runtime_measure_coverage {
	uint32_t measured;
	uint32_t unmeasurable;
	uint32_t content_hashed;
	uint32_t past_limit;
};

/**
 * lota_runtime_coverage_pid() - Coverage of a process, without the digest.
 * @pid: the process.
 * @cov: the coverage.
 *
 * Same roads as lota_runtime_measure_pid(), but a failing executable is only
 * counted; when /proc/<pid>/exe does not stat, every object is a mapped one.
 *
 * Return: 0 and @cov filled, or a negative errno from the enumeration or an
 * agent failure.
 */
int lota_runtime_coverage_pid(pid_t pid,
			      struct lota_runtime_measure_coverage *cov);

/**
 * lota_rt_coverage_verdict() - Whether a measurement may be issued.
 * @cov: the coverage.
 * @exe_measured: the process's own executable was measured.
 *
 * Return: 0 when something and the executable were measured, -ENODATA
 * otherwise, -EINVAL for a NULL @cov.
 */
int lota_rt_coverage_verdict(const struct lota_runtime_measure_coverage *cov,
			     int exe_measured);

/**
 * lota_rt_open_mapping() - Open the file behind one enumerated mapping.
 * @dirfd: /proc/<pid>/map_files.
 * @entry: the mapping, opened by its range, never by its maps path.
 * @st: fstat() of the fd.
 *
 * Return: the fd, -EINVAL for a bad range, -ESTALE when the range no longer
 * holds a regular file, or another negative errno.
 */
int lota_rt_open_mapping(int dirfd, const struct lota_rt_map_entry *entry,
			 struct stat *st);

/**
 * lota_runtime_measure_pid() - Runtime image digest of a live process.
 * @pid: the process.
 * @out_digest: the digest.
 * @cov: the coverage, or NULL; on failure only @cov->past_limit, once the
 *	enumeration ran.
 * @fail: the object that stopped the measurement, or NULL.
 *
 * Opens every mapping, ties each handle to its range with a second maps read,
 * and folds the digest of every object measured. A mapped object that fails,
 * and a mapping past LOTA_RUNTIME_IMAGE_MAX_MODULES, is left out and counted
 * in @cov.
 *
 * Return: 0, -ENOENT with no mapping, -ENODATA when the executable carries no
 * digest or lota_rt_coverage_verdict() refuses, or another negative errno:
 * the executable's, an unopened mapping's on a refused verdict, or an agent
 * failure.
 */
int lota_runtime_measure_pid(pid_t pid,
			     uint8_t out_digest[LOTA_RUNTIME_IMAGE_DIGEST_SIZE],
			     struct lota_runtime_measure_coverage *cov,
			     struct lota_runtime_measure_failure *fail);

/**
 * struct lota_rt_object_record - One mapping a measurement found.
 * @entry: the mapping.
 * @digest: its digest; len 0 when left out of the fold.
 * @size: its size; 0 when not opened.
 * @content_hashed: @digest is a content hash, not fs-verity.
 * @unmapped: only in the exec history, no longer in the maps.
 * @history_flags: LOTA_EXEC_HISTORY_*, from the walk and the exec history.
 */
struct lota_rt_object_record {
	struct lota_rt_map_entry entry;
	struct lota_verity_digest_key digest;
	uint64_t size;
	int content_hashed;
	int unmapped;
	uint32_t history_flags;
};

/**
 * lota_runtime_measure_pid_objects() - lota_runtime_measure_pid(), plus
 * every enumerated mapping.
 * @pid: the process.
 * @out_digest: the digest.
 * @cov: the coverage, or NULL.
 * @fail: the object that stopped the measurement, or NULL.
 * @objs: LOTA_RUNTIME_IMAGE_MAX_MODULES records, or NULL.
 * @n_objs: records filled, also when the measurement fails after the
 *	enumeration; required with @objs.
 *
 * Return: as lota_runtime_measure_pid(); -EINVAL for a NULL @out_digest.
 */
int lota_runtime_measure_pid_objects(
	pid_t pid, uint8_t out_digest[LOTA_RUNTIME_IMAGE_DIGEST_SIZE],
	struct lota_runtime_measure_coverage *cov,
	struct lota_runtime_measure_failure *fail,
	struct lota_rt_object_record *objs, size_t *n_objs);

#endif /* LOTA_AGENT_RUNTIME_IMAGE_MEASURE_H */
