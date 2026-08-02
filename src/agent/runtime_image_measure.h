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
 * Measure the kernel fs-verity digest of one enumerated mapping.
 *
 * Opens the exact backing inode through /proc/<pid>/map_files/<range> (a
 * kernel magic symlink, so no attacker-controlled path is followed),
 * confirms it still resolves to the dev/inode recorded during enumeration,
 * and reads the kernel-computed fs-verity measurement. Fails closed if the
 * object lacks fs-verity. Returns 0 on success, negative errno otherwise.
 */
int lota_rt_measure_entry_verity(pid_t pid,
				 const struct lota_rt_map_entry *entry,
				 struct lota_verity_digest_key *out);

/*
 * Compute the kernel-anchored runtime image digest of a live process.
 *
 * Enumerates the process's file-backed executable mappings, folds the
 * kernel fs-verity digest of each backing object into the canonical image
 * digest, and writes the 32-byte result. Fails closed (negative errno) if
 * the process has no measurable executable object or if any object lacks
 * fs-verity, so a missing measurement can never be mistaken for a trusted
 * one. Returns 0 on success.
 */
int lota_runtime_measure_pid(
	pid_t pid, uint8_t out_digest[LOTA_RUNTIME_IMAGE_DIGEST_SIZE]);

#endif /* LOTA_AGENT_RUNTIME_IMAGE_MEASURE_H */
