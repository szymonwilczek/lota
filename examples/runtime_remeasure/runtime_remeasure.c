/* SPDX-License-Identifier: MIT */
/*
 * LOTA runtime re-measurement demonstrator.
 *
 * A standalone, TPM-free reference for the runtime measurement that the
 * anti-cheat heartbeat binds into every beat. It needs no agent, no
 * verifier and no TPM, so it runs unmodified inside a plain VM.
 *
 * It shows three things:
 *
 *   1. The live measurement of the running image (the bytes mapped into
 *      this process) equals the measurement derived from the on-disk ELF.
 *      This is the invariant a verifier relies on: it can precompute the
 *      expected value from the binary and still recognise an honest
 *      producer's live measurement.
 *
 *   2. A one-byte change inside an executable segment flips the digest
 *      (--patch-demo). That is exactly the on-disk-vs-live drift runtime
 *      re-measurements closes: a runtime patch the session-start file
 *      hash never saw.
 *
 *   3. Re-measuring a steady process repeatedly yields a stable digest
 *      (--watch), which is what the heartbeat does on every interval.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>

#include "lota_anticheat.h"

static void print_digest(const char *label,
			 const uint8_t d[LOTA_AC_RUNTIME_MEASURE_SIZE])
{
	printf("%-22s ", label);
	for (int i = 0; i < LOTA_AC_RUNTIME_MEASURE_SIZE; i++)
		printf("%02x", d[i]);
	printf("\n");
}

/* Sleep helper that tolerates signal interruption. */
static void sleep_seconds(unsigned seconds)
{
	struct timespec ts = { .tv_sec = (time_t)seconds, .tv_nsec = 0 };
	while (nanosleep(&ts, &ts) != 0 && errno == EINTR)
		;
}

/*
 * File offset of the last byte of the first executable (PF_X) PT_LOAD
 * segment, or (off_t)-1 on failure. The last byte is always code and
 * never overlaps the ELF header, so patching it exercises detection
 * instead of corrupting the parse.
 */
static off_t first_exec_seg_last_byte(const char *path)
{
	Elf64_Ehdr ehdr;
	Elf64_Phdr ph;
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	off_t ret = (off_t)-1;

	if (fd < 0)
		return ret;
	if (pread(fd, &ehdr, sizeof(ehdr), 0) != (ssize_t)sizeof(ehdr))
		goto done;
	if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0)
		goto done;

	for (size_t i = 0; i < ehdr.e_phnum; i++) {
		off_t off = (off_t)ehdr.e_phoff + (off_t)(i * ehdr.e_phentsize);
		if (pread(fd, &ph, sizeof(ph), off) != (ssize_t)sizeof(ph))
			goto done;
		if (ph.p_type == PT_LOAD && (ph.p_flags & PF_X) &&
		    ph.p_filesz > 0) {
			ret = (off_t)(ph.p_offset + ph.p_filesz - 1);
			goto done;
		}
	}

done:
	close(fd);
	return ret;
}

static int copy_file(const char *src, const char *dst)
{
	uint8_t buf[8192];
	int in = open(src, O_RDONLY | O_CLOEXEC);
	int out = -1;
	int ret = -1;

	if (in < 0)
		goto done;
	out = open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0700);
	if (out < 0)
		goto done;

	for (;;) {
		ssize_t n = read(in, buf, sizeof(buf));
		if (n < 0) {
			if (errno == EINTR)
				continue;
			goto done;
		}
		if (n == 0)
			break;
		if (write(out, buf, (size_t)n) != n)
			goto done;
	}
	ret = 0;

done:
	if (in >= 0)
		close(in);
	if (out >= 0)
		close(out);
	return ret;
}

/* Collect the enumerated runtime object paths into a fixed table. */
#define RM_MAX_OBJS 512
struct obj_table {
	char (*paths)[LOTA_AC_RUNTIME_PATH_MAX];
	size_t count;
	int overflow;
};

static int obj_collect_cb(const char *path, void *user)
{
	struct obj_table *t = user;
	if (t->count >= RM_MAX_OBJS) {
		t->overflow = 1;
		return 1;
	}
	strncpy(t->paths[t->count], path, LOTA_AC_RUNTIME_PATH_MAX - 1);
	t->paths[t->count][LOTA_AC_RUNTIME_PATH_MAX - 1] = '\0';
	t->count++;
	return 0;
}

/*
 * Default mode: prove the live mapped image (all loaded objects) equals
 * the set measure reproduced from the same objects' on-disk files.
 * This is the producer/verifier invariant runtime re-measurements relies on.
 */
static int run_default(void)
{
	uint8_t live[LOTA_AC_RUNTIME_MEASURE_SIZE];
	uint8_t set[LOTA_AC_RUNTIME_MEASURE_SIZE];
	struct obj_table t = { 0 };
	const char **vec = NULL;
	int rc;
	int ret = 1;

	t.paths = calloc(RM_MAX_OBJS, LOTA_AC_RUNTIME_PATH_MAX);
	if (!t.paths) {
		fprintf(stderr, "out of memory\n");
		return 1;
	}

	rc = lota_ac_list_runtime_objects(obj_collect_cb, &t);
	if (rc < 0 || t.overflow || t.count == 0) {
		fprintf(stderr, "object enumeration failed (%s)\n",
			t.overflow ? "too many objects" :
				     strerror(rc ? -rc : 0));
		goto out;
	}

	vec = calloc(t.count, sizeof(*vec));
	if (!vec) {
		fprintf(stderr, "out of memory\n");
		goto out;
	}
	for (size_t i = 0; i < t.count; i++)
		vec[i] = t.paths[i];

	rc = lota_ac_compute_runtime_measure(live);
	if (rc < 0) {
		fprintf(stderr, "live measurement failed: %s\n", strerror(-rc));
		goto out;
	}
	rc = lota_ac_compute_expected_runtime_measure_set(vec, t.count, set);
	if (rc < 0) {
		fprintf(stderr, "set measurement failed: %s\n", strerror(-rc));
		goto out;
	}

	printf("measured objects:     %zu\n", t.count);
	print_digest("live (mapped image):", live);
	print_digest("set (on-disk files):", set);

	if (memcmp(live, set, sizeof(live)) != 0) {
		printf("RESULT: MISMATCH - live image differs from on-disk "
		       "objects\n");
		goto out;
	}
	printf("RESULT: MATCH - live image matches its on-disk objects\n");
	ret = 0;
out:
	free(vec);
	free(t.paths);
	return ret;
}

static int print_path_cb(const char *path, void *user)
{
	(void)user;
	printf("%s\n", path);
	return 0;
}

/* --list-objects: print the trusted runtime manifest, one path per line. */
static int run_list_objects(void)
{
	int rc = lota_ac_list_runtime_objects(print_path_cb, NULL);
	if (rc < 0) {
		fprintf(stderr, "object enumeration failed: %s\n",
			strerror(-rc));
		return 1;
	}
	return 0;
}

/*
 * --manifest FILE: read a manifest (one ELF path per line, '#' comments
 * and blank lines ignored), compute the set measure, and compare it to
 * the live image. This is the verifier-side reproduction path.
 */
static int run_manifest(const char *manifest)
{
	uint8_t live[LOTA_AC_RUNTIME_MEASURE_SIZE];
	uint8_t set[LOTA_AC_RUNTIME_MEASURE_SIZE];
	char line[LOTA_AC_RUNTIME_PATH_MAX];
	char (*paths)[LOTA_AC_RUNTIME_PATH_MAX] = NULL;
	const char **vec = NULL;
	size_t count = 0;
	FILE *f;
	int rc;
	int ret = 1;

	f = fopen(manifest, "re");
	if (!f) {
		fprintf(stderr, "cannot open manifest %s: %s\n", manifest,
			strerror(errno));
		return 1;
	}
	paths = calloc(RM_MAX_OBJS, LOTA_AC_RUNTIME_PATH_MAX);
	if (!paths) {
		fclose(f);
		fprintf(stderr, "out of memory\n");
		return 1;
	}

	while (fgets(line, sizeof(line), f)) {
		char *s = line;
		size_t n;
		while (*s == ' ' || *s == '\t')
			s++;
		n = strlen(s);
		while (n > 0 && (s[n - 1] == '\n' || s[n - 1] == ' ' ||
				 s[n - 1] == '\t'))
			s[--n] = '\0';
		if (n == 0 || s[0] == '#')
			continue;
		if (count >= RM_MAX_OBJS) {
			fprintf(stderr, "manifest has too many entries\n");
			goto out;
		}
		snprintf(paths[count], LOTA_AC_RUNTIME_PATH_MAX, "%s", s);
		count++;
	}
	if (count == 0) {
		fprintf(stderr, "manifest %s has no paths\n", manifest);
		goto out;
	}

	vec = calloc(count, sizeof(*vec));
	if (!vec) {
		fprintf(stderr, "out of memory\n");
		goto out;
	}
	for (size_t i = 0; i < count; i++)
		vec[i] = paths[i];

	rc = lota_ac_compute_runtime_measure(live);
	if (rc < 0) {
		fprintf(stderr, "live measurement failed: %s\n", strerror(-rc));
		goto out;
	}
	rc = lota_ac_compute_expected_runtime_measure_set(vec, count, set);
	if (rc < 0) {
		fprintf(stderr, "manifest measurement failed: %s\n",
			strerror(-rc));
		goto out;
	}

	print_digest("live (mapped image):", live);
	print_digest("set (manifest files):", set);
	if (memcmp(live, set, sizeof(live)) != 0) {
		printf("RESULT: MISMATCH - live image differs from manifest\n");
		goto out;
	}
	printf("RESULT: MATCH - live image matches the manifest\n");
	ret = 0;
out:
	free(vec);
	free(paths);
	fclose(f);
	return ret;
}

/* --patch-demo: a one-byte code patch must flip the digest. */
static int run_patch_demo(const char *exe_path)
{
	char tmp[] = "/tmp/lota_remeasure_XXXXXX";
	uint8_t before[LOTA_AC_RUNTIME_MEASURE_SIZE];
	uint8_t after[LOTA_AC_RUNTIME_MEASURE_SIZE];
	off_t off;
	uint8_t byte;
	int fd;
	int ret = 1;

	fd = mkstemp(tmp);
	if (fd < 0) {
		perror("mkstemp");
		return 1;
	}
	close(fd);

	if (copy_file(exe_path, tmp) != 0) {
		fprintf(stderr, "copy %s -> %s failed\n", exe_path, tmp);
		goto done;
	}
	if (lota_ac_compute_expected_runtime_measure(tmp, before) < 0) {
		fprintf(stderr, "measure before failed\n");
		goto done;
	}

	off = first_exec_seg_last_byte(tmp);
	if (off < 0) {
		fprintf(stderr, "could not locate an executable segment\n");
		goto done;
	}

	fd = open(tmp, O_RDWR | O_CLOEXEC);
	if (fd < 0 || pread(fd, &byte, 1, off) != 1) {
		perror("open/read patch site");
		if (fd >= 0)
			close(fd);
		goto done;
	}
	byte ^= 0xFF;
	if (pwrite(fd, &byte, 1, off) != 1) {
		perror("write patch");
		close(fd);
		goto done;
	}
	close(fd);

	if (lota_ac_compute_expected_runtime_measure(tmp, after) < 0) {
		fprintf(stderr, "measure after failed\n");
		goto done;
	}

	print_digest("before patch:", before);
	print_digest("after 1-byte patch:", after);

	if (memcmp(before, after, sizeof(before)) == 0) {
		printf("RESULT: UNDETECTED - patch did not change the digest\n");
		goto done;
	}
	printf("RESULT: DETECTED - code patch flipped the runtime digest\n");
	ret = 0;

done:
	unlink(tmp);
	return ret;
}

/* --watch: re-measure repeatedly; a steady process stays stable. */
static int run_watch(unsigned interval, unsigned count)
{
	uint8_t baseline[LOTA_AC_RUNTIME_MEASURE_SIZE];
	int rc = lota_ac_compute_runtime_measure(baseline);

	if (rc < 0) {
		fprintf(stderr, "live measurement failed: %s\n", strerror(-rc));
		return 1;
	}
	print_digest("baseline:", baseline);

	for (unsigned i = 1; i <= count; i++) {
		uint8_t now[LOTA_AC_RUNTIME_MEASURE_SIZE];

		sleep_seconds(interval);
		rc = lota_ac_compute_runtime_measure(now);
		if (rc < 0) {
			fprintf(stderr, "live measurement failed: %s\n",
				strerror(-rc));
			return 1;
		}
		if (memcmp(now, baseline, sizeof(now)) != 0) {
			printf("tick %u: CHANGED - live code pages drifted\n",
			       i);
			print_digest("  now:", now);
			return 1;
		}
		printf("tick %u: stable\n", i);
	}
	printf("RESULT: STABLE - %u re-measurements matched the baseline\n",
	       count);
	return 0;
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s [--list-objects | --manifest FILE | --patch-demo |\n"
		"           --watch SEC] [--count N] [--exe PATH]\n"
		"\n"
		"  (no flags)       prove the live image (all loaded objects)\n"
		"                   matches the set measure of its on-disk "
		"files\n"
		"  --list-objects   print the trusted runtime manifest, one "
		"path\n"
		"                   per line (main binary + shared libraries)\n"
		"  --manifest FILE  reproduce the set measure from FILE and "
		"compare\n"
		"                   it to the live image (verifier side)\n"
		"  --patch-demo     show a 1-byte code patch flips an object "
		"digest\n"
		"  --watch SEC      re-measure this image every SEC seconds\n"
		"  --count N        number of --watch ticks (default 5)\n"
		"  --exe PATH       ELF copied for --patch-demo (default "
		"/proc/self/exe)\n",
		prog);
}

int main(int argc, char **argv)
{
	const char *exe_path = "/proc/self/exe";
	const char *manifest = NULL;
	int list_objects = 0;
	int patch_demo = 0;
	long watch = -1;
	unsigned count = 5;

	int i = 1;
	while (i < argc) {
		const char *arg = argv[i];

		if (strcmp(arg, "--list-objects") == 0) {
			list_objects = 1;
			i += 1;
		} else if (strcmp(arg, "--manifest") == 0 && i + 1 < argc) {
			manifest = argv[i + 1];
			i += 2;
		} else if (strcmp(arg, "--patch-demo") == 0) {
			patch_demo = 1;
			i += 1;
		} else if (strcmp(arg, "--watch") == 0 && i + 1 < argc) {
			watch = strtol(argv[i + 1], NULL, 10);
			if (watch < 0) {
				usage(argv[0]);
				return 2;
			}
			i += 2;
		} else if (strcmp(arg, "--count") == 0 && i + 1 < argc) {
			long c = strtol(argv[i + 1], NULL, 10);
			if (c <= 0) {
				usage(argv[0]);
				return 2;
			}
			count = (unsigned)c;
			i += 2;
		} else if (strcmp(arg, "--exe") == 0 && i + 1 < argc) {
			exe_path = argv[i + 1];
			i += 2;
		} else if (strcmp(arg, "--help") == 0 ||
			   strcmp(arg, "-h") == 0) {
			usage(argv[0]);
			return 0;
		} else {
			usage(argv[0]);
			return 2;
		}
	}

	if (list_objects)
		return run_list_objects();
	if (manifest)
		return run_manifest(manifest);
	if (patch_demo)
		return run_patch_demo(exe_path);
	if (watch >= 0)
		return run_watch((unsigned)watch, count);
	return run_default();
}
