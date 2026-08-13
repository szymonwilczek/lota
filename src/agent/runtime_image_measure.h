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

/*
 * One file-backed executable mapping selected for measurement.
 * - start/end are the mapping's virtual address range (used to build the
 * authoritative /proc/<pid>/map_files key)
 * - dev/ino identify the backing inode
 * - soname is the file basename
 */
struct lota_rt_map_entry {
	unsigned long start;
	unsigned long end;
	unsigned int dev_major;
	unsigned int dev_minor;
	unsigned long long ino;
	char soname[LOTA_RUNTIME_IMAGE_SONAME_MAX];
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
 * reported_len is the digest length the kernel returned for that object:
 * zero when it carries no fs-verity digest at all, otherwise a length LOTA
 * does not take.
 */
struct lota_runtime_measure_failure {
	char soname[LOTA_RUNTIME_IMAGE_SONAME_MAX];
	unsigned long long ino;
	uint32_t reported_len;
	int err;
};

/*
 * Render a failure as one operator-readable sentence naming
 * the object and the reason, into buf.
 * Always NUL-terminates.
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
				 uint32_t *reported_len);

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
