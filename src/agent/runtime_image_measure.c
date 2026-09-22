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
#include <sys/vfs.h>
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

/*
 * Content hashes, kept apart so a hit never serves one road's digest for the
 * other's. Same key; only running executables, which are unwritable, land here.
 */
static struct lota_rt_verity_cache rt_content_cache;

/* installed by whoever loaded the BPF object */
static lota_rt_content_hasher_fn rt_content_hasher;

static lota_rt_pin_object_fn rt_pin_object;
static lota_rt_pin_round_fn rt_pin_round_begin;
static lota_rt_pin_sweep_fn rt_pin_sweep;

void lota_rt_set_pin_object(lota_rt_pin_object_fn pin,
			    lota_rt_pin_round_fn round_begin,
			    lota_rt_pin_sweep_fn sweep)
{
	rt_pin_object = pin;
	rt_pin_round_begin = round_begin;
	rt_pin_sweep = sweep;
}

void lota_rt_measure_round_begin(void)
{
	if (rt_pin_round_begin)
		rt_pin_round_begin();
}

int lota_rt_measure_round_end(size_t *released)
{
	if (released)
		*released = 0;
	if (!rt_pin_sweep)
		return 0;
	return rt_pin_sweep(released);
}

void lota_rt_set_content_hasher(lota_rt_content_hasher_fn fn)
{
	rt_content_hasher = fn;
	lota_rt_verity_cache_clear(&rt_content_cache);
}

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
	char path[LOTA_RT_MAP_PATH_MAX];
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
	snprintf(out->path, sizeof(out->path), "%s", path);
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

int lota_rt_mapping_identity_ok(const struct lota_rt_map_entry *enumerated,
				const struct lota_rt_map_entry *observed,
				unsigned long long opened_ino)
{
	if (!enumerated || !observed)
		return 0;

	/*
	 * Both devices come from /proc/<pid>/maps, so they are the same quantity.
	 * Taking one of them from stat() would compare a subvolume's anonymous
	 * device against the filesystem's on any filesystem that distinguishes
	 * them.
	 */
	if (observed->dev_major != enumerated->dev_major ||
	    observed->dev_minor != enumerated->dev_minor)
		return 0;
	if (observed->ino != enumerated->ino)
		return 0;

	/* and the handle that was opened is that same inode */
	if (opened_ino != enumerated->ino)
		return 0;

	return 1;
}

int lota_rt_lookup_map_entry(pid_t pid, unsigned long start, unsigned long end,
			     struct lota_rt_map_entry *out)
{
	char maps_path[64];
	char *line = NULL;
	size_t line_cap = 0;
	FILE *f;
	int ret = 0;

	if (!out)
		return -EINVAL;

	memset(out, 0, sizeof(*out));

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
		if (e.start == start && e.end == end) {
			*out = e;
			ret = 1;
			goto out;
		}
	}

out:
	free(line);
	fclose(f);
	return ret;
}

int lota_rt_measure_entry_verity(pid_t pid,
				 const struct lota_rt_map_entry *entry,
				 struct lota_verity_digest_key *out,
				 uint32_t *reported_len,
				 struct lota_rt_open_identity *opened)
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
	if (opened)
		memset(opened, 0, sizeof(*opened));

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

	/*
	 * The mapping must still resolve to what was enumerated.
	 * The range is re-read from the same /proc/<pid>/maps the enumeration
	 * used, so the two device numbers are comparable; the opened handle's
	 * inode is what ties the file about to be measured to that range.
	 */
	if (!S_ISREG(st.st_mode)) {
		ret = -ESTALE;
		goto out;
	}
	{
		struct lota_rt_map_entry observed;
		int found = lota_rt_lookup_map_entry(pid, entry->start,
						     entry->end, &observed);

		if (found < 0) {
			ret = found;
			goto out;
		}
		if (found == 0 ||
		    !lota_rt_mapping_identity_ok(
			    entry, &observed, (unsigned long long)st.st_ino)) {
			ret = -ESTALE;
			goto out;
		}

		/*
		 * Report the handle's own identity so the caller can tell
		 * which mapping is the executable without comparing a stat()
		 * device against a maps one -- the comparison this block
		 * exists to avoid.
		 */
		if (opened) {
			struct statfs sfs;

			opened->dev = st.st_dev;
			opened->ino = st.st_ino;
			opened->size = (uint64_t)st.st_size;
			opened->mtime_sec = (int64_t)st.st_mtim.tv_sec;
			opened->mtime_nsec = (int64_t)st.st_mtim.tv_nsec;
			/* off the fd: the path may have moved since open */
			if (fstatfs(fd, &sfs) == 0)
				opened->fs_magic = (unsigned long)sfs.f_type;
		}
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
	char subject[LOTA_RT_REASON_MAX];
	const char *object;
	const char *tail;

	if (!buf || buflen == 0)
		return;

	if (err < 0)
		err = -err;

	if (!fail || (fail->soname[0] == '\0' && fail->path[0] == '\0')) {
		snprintf(buf, buflen, "%s", strerror(err));
		return;
	}

	/* basename only when the mapping was never parsed */
	object = fail->path[0] ? fail->path : fail->soname;

	/* role is unknown when the mapping would not open */
	switch (fail->role) {
	case LOTA_RT_ROLE_EXECUTABLE:
		snprintf(subject, sizeof(subject),
			 "the process's own executable %s", object);
		tail = "";
		break;
	case LOTA_RT_ROLE_MAPPED_OBJECT:
		snprintf(subject, sizeof(subject),
			 "%s, an object the process has mapped", object);
		tail = ",";
		break;
	default:
		snprintf(subject, sizeof(subject), "%s", object);
		tail = "";
		break;
	}

	/*
	 * two measurable-object cases are what integrator hits,
	 * so both name the object and the action that fixes it;
	 * anything else is ordinary errno against a named object.
	 */
	if (err == ENODATA && fail->road_err != 0) {
		/* content road refused too: name its error, not fs-verity */
		snprintf(buf, buflen,
			 "%s%s carries no fs-verity digest and the kernel "
			 "would not hash its content either: %s",
			 subject, tail,
			 strerror(fail->road_err < 0 ? -fail->road_err :
						       fail->road_err));
		return;
	}

	if (err == ENODATA) {
		snprintf(buf, buflen,
			 "%s%s carries no fs-verity digest (enable fs-verity "
			 "on it, or drop the process from the protected set)",
			 subject, tail);
		return;
	}

	if (err == EINVAL && fail->reported_len != 0) {
		snprintf(buf, buflen,
			 "%s%s carries a %u-byte fs-verity digest; LOTA takes "
			 "SHA-256 (%d) or SHA-512 (%d)",
			 subject, tail, fail->reported_len,
			 LOTA_VERITY_DIGEST_SHA256_SIZE,
			 LOTA_VERITY_DIGEST_SHA512_SIZE);
		return;
	}

	snprintf(buf, buflen, "%s: %s", subject, strerror(err));
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

/*
 * Allowlist of filesystems whose content this host serves itself.
 * One served by userspace or a peer may hand the hasher and the page fault
 * different bytes, and an untested one is not assumed safe.
 */
#define LOTA_RT_MAGIC_BTRFS 0x9123683EUL
#define LOTA_RT_MAGIC_EXT4 0xEF53UL
#define LOTA_RT_MAGIC_XFS 0x58465342UL
#define LOTA_RT_MAGIC_OVERLAYFS 0x794C7630UL
#define LOTA_RT_MAGIC_TMPFS 0x01021994UL

static int rt_fs_may_be_content_hashed(unsigned long fs_magic)
{
	switch (fs_magic) {
	case LOTA_RT_MAGIC_BTRFS:
	case LOTA_RT_MAGIC_EXT4:
	case LOTA_RT_MAGIC_XFS:
	case LOTA_RT_MAGIC_OVERLAYFS:
	case LOTA_RT_MAGIC_TMPFS:
		return 1;
	default:
		return 0;
	}
}

enum lota_rt_identity_road lota_rt_identity_road(int role, int verity_present,
						 unsigned long fs_magic,
						 int write_guarded)
{
	/* a kernel-enforced digest wins, whatever the role */
	if (verity_present)
		return LOTA_RT_ROAD_VERITY;

	/* a running executable is unwritable; a library only while guarded */
	if (role != LOTA_RT_ROLE_EXECUTABLE &&
	    !(role == LOTA_RT_ROLE_MAPPED_OBJECT && write_guarded))
		return LOTA_RT_ROAD_NONE;

	if (!rt_fs_may_be_content_hashed(fs_magic))
		return LOTA_RT_ROAD_NONE;

	return LOTA_RT_ROAD_CONTENT_HASH;
}

/* What one mapping of a live process measured to */
struct rt_object_measure {
	struct lota_verity_digest_key digest;
	struct lota_rt_open_identity opened;
	uint32_t reported_len;
	int role;
	int is_exe;
	int content_hashed; /* digest is a content hash, not fs-verity */
	int road_err; /* why the content road refused, 0 if it was not open */
};

/* Kernel hash of one mapping, cached by the identity the verity read took */
static int rt_content_hash_entry(pid_t pid,
				 const struct lota_rt_map_entry *entry,
				 const struct lota_rt_open_identity *opened,
				 struct lota_verity_digest_key *out)
{
	struct lota_rt_verity_key ckey = { 0 };
	char path[96];
	int ret;
	int n;

	if (!rt_content_hasher)
		return -ENOTSUP;

	ckey.dev = (uint64_t)opened->dev;
	ckey.ino = (uint64_t)opened->ino;
	ckey.size = opened->size;
	ckey.mtime_sec = opened->mtime_sec;
	ckey.mtime_nsec = opened->mtime_nsec;
	if (lota_rt_verity_cache_get(&rt_content_cache, &ckey, out))
		return 0;

	n = snprintf(path, sizeof(path), "/proc/%d/map_files/%lx-%lx", (int)pid,
		     entry->start, entry->end);
	if (n < 0 || (size_t)n >= sizeof(path))
		return -ENAMETOOLONG;

	ret = rt_content_hasher(path, (uint64_t)opened->dev,
				(uint64_t)opened->ino, out);
	if (ret != 0)
		return ret;
	if (!LOTA_VERITY_DIGEST_LEN_SUPPORTED(out->len))
		return -EINVAL;

	lota_rt_verity_cache_put(&rt_content_cache, &ckey, out);
	return 0;
}

/* no pinner or no answer: unpinned, so unmeasured */
static int rt_entry_pinned(pid_t pid, const struct lota_rt_map_entry *entry,
			   const struct lota_rt_open_identity *opened)
{
	char path[96];
	int pinned = 0;
	int n;

	if (!rt_pin_object)
		return 0;

	n = snprintf(path, sizeof(path), "/proc/%d/map_files/%lx-%lx", (int)pid,
		     entry->start, entry->end);
	if (n < 0 || (size_t)n >= sizeof(path))
		return 0;

	if (rt_pin_object(path, (uint64_t)opened->dev, (uint64_t)opened->ino,
			  &pinned) != 0)
		return 0;

	return pinned ? 1 : 0;
}

/*
 * Measure one mapping by whichever road may. Returns 0 or the verity read's
 * errno, so the caller still tells a coverage gap from a failure.
 */
static int rt_measure_object(pid_t pid, const struct lota_rt_map_entry *entry,
			     dev_t exe_dev, ino_t exe_ino,
			     struct rt_object_measure *m)
{
	enum lota_rt_identity_road road;
	int ret;

	memset(m, 0, sizeof(*m));

	ret = lota_rt_measure_entry_verity(pid, entry, &m->digest,
					   &m->reported_len, &m->opened);

	/*
	 * Both from stat(): a maps device never matches one on a filesystem
	 * with a device per subvolume.
	 */
	m->is_exe = m->opened.ino != 0 && m->opened.dev == exe_dev &&
		    m->opened.ino == exe_ino;

	/* not opened: is_exe is unknown, not false */
	if (m->opened.ino == 0)
		m->role = LOTA_RT_ROLE_UNKNOWN;
	else
		m->role = m->is_exe ? LOTA_RT_ROLE_EXECUTABLE :
				      LOTA_RT_ROLE_MAPPED_OBJECT;

	if (ret == 0)
		return 0;
	if (!rt_err_is_unmeasurable(ret))
		return ret;

	/* a running executable is unwritable already */
	road = lota_rt_identity_road(m->role, 0, m->opened.fs_magic,
				     m->role == LOTA_RT_ROLE_MAPPED_OBJECT ?
					     rt_entry_pinned(pid, entry,
							     &m->opened) :
					     0);
	if (road != LOTA_RT_ROAD_CONTENT_HASH)
		return ret;

	m->road_err = rt_content_hash_entry(pid, entry, &m->opened, &m->digest);
	if (m->road_err != 0)
		return ret;

	m->content_hashed = 1;
	return 0;
}

int lota_runtime_coverage_pid(pid_t pid,
			      struct lota_runtime_measure_coverage *cov)
{
	struct lota_rt_map_entry *entries = NULL;
	dev_t exe_dev = 0;
	ino_t exe_ino = 0;
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

	/* same roads as the token; unknown executable: fs-verity only */
	if (rt_exe_identity(pid, &exe_dev, &exe_ino) != 0) {
		exe_dev = 0;
		exe_ino = 0;
	}

	for (size_t i = 0; i < n; i++) {
		struct rt_object_measure m;

		ret = rt_measure_object(pid, &entries[i], exe_dev, exe_ino, &m);
		if (ret == 0) {
			cov->measured++;
			if (m.content_hashed)
				cov->content_hashed++;
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
		struct rt_object_measure m;

		snprintf(slot->soname, sizeof(slot->soname), "%s",
			 entries[i].soname);

		ret = rt_measure_object(pid, &entries[i], exe_dev, exe_ino, &m);
		if (ret != 0) {
			if (fail) {
				snprintf(fail->soname, sizeof(fail->soname),
					 "%s", entries[i].soname);
				snprintf(fail->path, sizeof(fail->path), "%s",
					 entries[i].path);
				fail->ino = entries[i].ino;
				fail->reported_len = m.reported_len;
				fail->role = m.role;
				fail->err = ret;
				fail->road_err = m.road_err;
			}
			/*
			 * object with no digest is coverage the relying party
			 * judges; anything else -- a mapping that will not open,
			 * or one that no longer resolves to the inode enumerated
			 * -- is this measurement failing.
			 */
			if (!rt_err_is_unmeasurable(ret))
				goto out;
			if (m.is_exe) {
				ret = -ENODATA;
				goto out;
			}
			local_cov.unmeasurable++;
			memset(slot, 0, sizeof(*slot));
			continue;
		}

		slot->verity = m.digest;
		if (m.is_exe)
			exe_measured = 1;
		if (m.content_hashed)
			local_cov.content_hashed++;
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
