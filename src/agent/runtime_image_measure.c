/* SPDX-License-Identifier: MIT */
/*
 * Kernel-anchored runtime image measurement of a live process.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <errno.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <linux/fsverity.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include "runtime_image_measure.h"
#include "rt_verity_cache.h"

/*
 * Digests already read from the kernel this boot.
 *
 * One instance for the daemon, which runs a single event-loop thread
 * (see agent_globals_lock())
 * It holds no secret, only public file properties.
 */
static struct lota_rt_verity_cache rt_digest_cache;

static const char *rt_basename(const char *path)
{
	const char *slash = strrchr(path, '/');
	return slash ? slash + 1 : path;
}

/* drop the kernel's " (deleted)" suffix from a mapped pathname in place */
static void rt_strip_deleted_suffix(char *path)
{
	static const char suffix[] = " (deleted)";
	size_t len = strlen(path);
	size_t slen = sizeof(suffix) - 1;

	if (len >= slen && strcmp(path + len - slen, suffix) == 0)
		path[len - slen] = '\0';
}

static int rt_map_files_leaf_is_safe(const char *leaf)
{
	int saw_dash = 0;
	size_t left = 0;
	size_t right = 0;

	if (!leaf)
		return 0;

	for (const char *p = leaf; *p; p++) {
		if (*p == '-') {
			if (saw_dash || left == 0)
				return 0;
			saw_dash = 1;
			continue;
		}
		if ((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f')) {
			if (saw_dash)
				right++;
			else
				left++;
			continue;
		}
		return 0;
	}

	return saw_dash && right > 0;
}

int lota_rt_parse_maps_line(const char *line, struct lota_rt_map_entry *out)
{
	unsigned long start, end, off;
	unsigned int maj, min;
	unsigned long long ino;
	char perms[5] = { 0 };
	char path[LOTA_RUNTIME_IMAGE_SONAME_MAX + 64];
	const char *p;
	const char *soname;
	int pos = 0;
	int n;

	if (!line || !out)
		return -EINVAL;

	n = sscanf(line, "%lx-%lx %4s %lx %x:%x %llu %n", &start, &end, perms,
		   &off, &maj, &min, &ino, &pos);
	if (n < 7 || pos <= 0)
		return -EINVAL;
	if (strlen(perms) != 4)
		return -EINVAL;

	/* only file-backed executable mappings are measured */
	if (perms[2] != 'x' || ino == 0)
		return 0;

	p = line + pos;
	if (*p == '\0' || *p == '\n')
		return 0; /* anonymous executable mapping */
	if (*p == '[')
		return 0; /* special region: [vdso], [stack], ... */

	if (strlen(p) >= sizeof(path))
		return -ENAMETOOLONG;
	snprintf(path, sizeof(path), "%s", p);
	path[strcspn(path, "\n")] = '\0';
	rt_strip_deleted_suffix(path);

	soname = rt_basename(path);
	if (soname[0] == '\0' ||
	    strlen(soname) >= LOTA_RUNTIME_IMAGE_SONAME_MAX)
		return -ENAMETOOLONG;

	memset(out, 0, sizeof(*out));
	out->start = start;
	out->end = end;
	out->dev_major = maj;
	out->dev_minor = min;
	out->ino = ino;
	snprintf(out->soname, sizeof(out->soname), "%s", soname);
	return 1;
}

static int rt_entry_seen(const struct lota_rt_map_entry *entries, size_t n,
			 const struct lota_rt_map_entry *cand)
{
	for (size_t i = 0; i < n; i++) {
		if (entries[i].dev_major == cand->dev_major &&
		    entries[i].dev_minor == cand->dev_minor &&
		    entries[i].ino == cand->ino)
			return 1;
	}
	return 0;
}

int lota_rt_collect_exec_maps(pid_t pid, struct lota_rt_map_entry *entries,
			      size_t max, size_t *n_out)
{
	char maps_path[64];
	char *line = NULL;
	size_t line_cap = 0;
	size_t count = 0;
	FILE *f;
	int ret = 0;

	if (!entries || !n_out || max == 0)
		return -EINVAL;

	snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", (int)pid);
	f = fopen(maps_path, "re");
	if (!f)
		return -errno;

	while (getline(&line, &line_cap, f) != -1) {
		struct lota_rt_map_entry e;
		int rc = lota_rt_parse_maps_line(line, &e);

		if (rc < 0) {
			ret = rc;
			goto out;
		}
		if (rc == 0)
			continue;
		if (rt_entry_seen(entries, count, &e))
			continue;
		if (count >= max) {
			ret = -E2BIG;
			goto out;
		}
		entries[count++] = e;
	}

	*n_out = count;
out:
	free(line);
	fclose(f);
	return ret;
}

int lota_rt_measure_entry_verity(pid_t pid,
				 const struct lota_rt_map_entry *entry,
				 struct lota_verity_digest_key *out,
				 uint32_t *reported_len)
{
	char map_files_dir[64];
	char map_files_leaf[40];
	struct stat st = { 0 };
	int dirfd = -1;
	int fd = -1;
	int ret = 0;
	int n;

	if (reported_len)
		*reported_len = 0;

	if (!entry || !out)
		return -EINVAL;
	if (entry->start >= entry->end)
		return -EINVAL;

	/*
	 * keep the untrusted /proc/<pid>/maps pathname out of the file access:
	 * map_files is keyed only by the numeric range, under a trusted procfs
	 * directory, and the range leaf cannot contain path separators
	 */
	n = snprintf(map_files_dir, sizeof(map_files_dir), "/proc/%d/map_files",
		     (int)pid);
	if (n < 0 || (size_t)n >= sizeof(map_files_dir))
		return -ENAMETOOLONG;
	n = snprintf(map_files_leaf, sizeof(map_files_leaf), "%lx-%lx",
		     entry->start, entry->end);
	if (n < 0 || (size_t)n >= sizeof(map_files_leaf) ||
	    !rt_map_files_leaf_is_safe(map_files_leaf))
		return -EINVAL;

	dirfd = open(map_files_dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (dirfd < 0)
		return -errno;

	fd = openat(dirfd, map_files_leaf, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		ret = -errno;
		goto out;
	}

	if (fstat(fd, &st) != 0) {
		ret = -errno;
		goto out;
	}

	/* mapping must still resolve to the inode seen during enumeration */
	if (!S_ISREG(st.st_mode) || major(st.st_dev) != entry->dev_major ||
	    minor(st.st_dev) != entry->dev_minor ||
	    (unsigned long long)st.st_ino != entry->ino) {
		ret = -ESTALE;
		goto out;
	}

	{
		union {
			uint8_t buf[sizeof(struct fsverity_digest) +
				    LOTA_VERITY_DIGEST_MAX_SIZE];
			struct fsverity_digest hdr;
		} d;
		struct lota_rt_verity_key ckey;

		/*
		 * fs-verity fixes inode's contents, so digest already read from
		 * this exact inode -- same device, size and mtime -- cannot have
		 * changed.
		 * Anything else is a miss and re-reads.
		 */
		lota_rt_verity_key_from_stat(&st, &ckey);
		if (lota_rt_verity_cache_get(&rt_digest_cache, &ckey, out)) {
			if (reported_len)
				*reported_len = out->len;
			goto out;
		}

		memset(&d, 0, sizeof(d));
		d.hdr.digest_size = (uint16_t)LOTA_VERITY_DIGEST_MAX_SIZE;

		if (ioctl(fd, FS_IOC_MEASURE_VERITY, &d) != 0) {
			ret = -errno;
			goto out;
		}
		if (reported_len)
			*reported_len = d.hdr.digest_size;
		if (!LOTA_VERITY_DIGEST_LEN_SUPPORTED(d.hdr.digest_size)) {
			ret = -EINVAL;
			goto out;
		}

		memset(out, 0, sizeof(*out));
		out->len = d.hdr.digest_size;
		memcpy(out->digest, d.hdr.digest, (size_t)out->len);
		lota_rt_verity_cache_put(&rt_digest_cache, &ckey, out);
	}

out:
	if (fd >= 0)
		close(fd);
	close(dirfd);
	return ret;
}

void lota_rt_failure_reason(const struct lota_runtime_measure_failure *fail,
			    int err, char *buf, size_t buflen)
{
	const char *soname;

	if (!buf || buflen == 0)
		return;

	if (err < 0)
		err = -err;

	if (!fail || fail->soname[0] == '\0') {
		snprintf(buf, buflen, "%s", strerror(err));
		return;
	}

	soname = fail->soname;

	/*
	 * two measurable-object cases are what integrator hits,
	 * so both name the object and the action that fixes it;
	 * anything else is ordinary errno against a named object.
	 */
	if (err == ENODATA) {
		snprintf(buf, buflen,
			 "%s carries no fs-verity digest (enable fs-verity on "
			 "it, or drop the process from the protected set)",
			 soname);
		return;
	}

	if (err == EINVAL && fail->reported_len != 0) {
		snprintf(buf, buflen,
			 "%s carries a %u-byte fs-verity digest; LOTA takes "
			 "SHA-256 (%d) or SHA-512 (%d)",
			 soname, fail->reported_len,
			 LOTA_VERITY_DIGEST_SHA256_SIZE,
			 LOTA_VERITY_DIGEST_SHA512_SIZE);
		return;
	}

	snprintf(buf, buflen, "%s: %s", soname, strerror(err));
}

/* qsort comparator over the canonical module order */
static int rt_module_qsort_cmp(const void *a, const void *b)
{
	return lota__runtime_image_module_cmp(a, b);
}

int lota_rt_coverage_verdict(const struct lota_runtime_measure_coverage *cov,
			     int exe_measured)
{
	if (!cov)
		return -EINVAL;

	/* nothing measured is not a partial measurement, it is none */
	if (cov->measured == 0)
		return -ENODATA;

	/*
	 * Title's own code is the object its publisher controls,
	 * so an unmeasurable executable is a packaging decision on their side,
	 * not a property of the machine the player runs.
	 */
	if (!exe_measured)
		return -ENODATA;

	return 0;
}

/*
 * Object at /proc/<pid>/exe, so the measurement can tell the process's own
 * executable apart from the libraries it loaded.
 * Returns 0 and fills dev/ino, or a negative errno.
 */
static int rt_exe_identity(pid_t pid, dev_t *dev, ino_t *ino)
{
	char exe_path[64];
	struct stat st;

	snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", (int)pid);
	if (stat(exe_path, &st) != 0)
		return -errno;

	*dev = st.st_dev;
	*ino = st.st_ino;
	return 0;
}

/* object the kernel holds no usable fs-verity digest for */
static int rt_err_is_unmeasurable(int err)
{
	return err == -ENODATA || err == -EOPNOTSUPP || err == -EINVAL;
}

int lota_runtime_coverage_pid(pid_t pid,
			      struct lota_runtime_measure_coverage *cov)
{
	struct lota_rt_map_entry *entries = NULL;
	size_t n = 0;
	int ret;

	if (!cov)
		return -EINVAL;
	memset(cov, 0, sizeof(*cov));

	entries = calloc(LOTA_RUNTIME_IMAGE_MAX_MODULES, sizeof(*entries));
	if (!entries)
		return -ENOMEM;

	ret = lota_rt_collect_exec_maps(pid, entries,
					LOTA_RUNTIME_IMAGE_MAX_MODULES, &n);
	if (ret != 0)
		goto out;

	for (size_t i = 0; i < n; i++) {
		struct lota_verity_digest_key key;

		ret = lota_rt_measure_entry_verity(pid, &entries[i], &key,
						   NULL);
		if (ret == 0) {
			cov->measured++;
			continue;
		}
		if (!rt_err_is_unmeasurable(ret))
			goto out;
		cov->unmeasurable++;
	}
	ret = 0;
out:
	free(entries);
	return ret;
}

int lota_runtime_measure_pid(pid_t pid,
			     uint8_t out_digest[LOTA_RUNTIME_IMAGE_DIGEST_SIZE],
			     struct lota_runtime_measure_coverage *cov,
			     struct lota_runtime_measure_failure *fail)
{
	struct lota_rt_map_entry *entries = NULL;
	struct lota_runtime_image_module *mods = NULL;
	struct lota_runtime_measure_coverage local_cov = { 0 };
	int exe_measured = 0;
	dev_t exe_dev = 0;
	ino_t exe_ino = 0;
	size_t n = 0;
	size_t i, unique;
	int ret;

	if (fail)
		memset(fail, 0, sizeof(*fail));
	if (cov)
		memset(cov, 0, sizeof(*cov));

	if (!out_digest)
		return -EINVAL;

	entries = calloc(LOTA_RUNTIME_IMAGE_MAX_MODULES, sizeof(*entries));
	mods = calloc(LOTA_RUNTIME_IMAGE_MAX_MODULES, sizeof(*mods));
	if (!entries || !mods) {
		ret = -ENOMEM;
		goto out;
	}

	ret = lota_rt_collect_exec_maps(pid, entries,
					LOTA_RUNTIME_IMAGE_MAX_MODULES, &n);
	if (ret != 0)
		goto out;
	if (n == 0) {
		/* live process always maps at least its own executable */
		ret = -ENOENT;
		goto out;
	}

	ret = rt_exe_identity(pid, &exe_dev, &exe_ino);
	if (ret != 0)
		goto out;

	for (i = 0; i < n; i++) {
		struct lota_runtime_image_module *slot =
			&mods[local_cov.measured];
		uint32_t reported = 0;
		int is_exe = major(exe_dev) == entries[i].dev_major &&
			     minor(exe_dev) == entries[i].dev_minor &&
			     (unsigned long long)exe_ino == entries[i].ino;

		snprintf(slot->soname, sizeof(slot->soname), "%s",
			 entries[i].soname);

		ret = lota_rt_measure_entry_verity(pid, &entries[i],
						   &slot->verity, &reported);
		if (ret != 0) {
			if (fail) {
				snprintf(fail->soname, sizeof(fail->soname),
					 "%s", entries[i].soname);
				fail->ino = entries[i].ino;
				fail->reported_len = reported;
				fail->err = ret;
			}
			/*
			 * object with no digest is coverage the relying party
			 * judges; anything else -- a mapping that will not open,
			 * or one that no longer resolves to the inode enumerated
			 * -- is this measurement failing.
			 */
			if (!rt_err_is_unmeasurable(ret))
				goto out;
			if (is_exe) {
				ret = -ENODATA;
				goto out;
			}
			local_cov.unmeasurable++;
			memset(slot, 0, sizeof(*slot));
			continue;
		}

		if (is_exe)
			exe_measured = 1;
		local_cov.measured++;
	}

	ret = lota_rt_coverage_verdict(&local_cov, exe_measured);
	if (ret != 0)
		goto out;

	n = local_cov.measured;
	qsort(mods, n, sizeof(*mods), rt_module_qsort_cmp);

	/*
	 * Two distinct inodes can share an soname and content digest (the same
	 * library mounted at two paths); collapse such exact duplicates so the
	 * strictly increasing canonical-order contract still holds
	 */
	unique = 1;
	for (i = 1; i < n; i++) {
		if (lota__runtime_image_module_cmp(&mods[unique - 1],
						   &mods[i]) != 0)
			mods[unique++] = mods[i];
	}

	ret = lota_compute_runtime_image_digest(mods, (uint32_t)unique,
						out_digest);
	if (ret == 0 && cov)
		*cov = local_cov;
out:
	free(entries);
	if (mods)
		OPENSSL_cleanse(mods,
				LOTA_RUNTIME_IMAGE_MAX_MODULES * sizeof(*mods));
	free(mods);
	return ret;
}
