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
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <unistd.h>

#include "runtime_image_measure.h"
#include "rt_verity_cache.h"

/* fs-verity digests read this boot; unlocked, only the event loop measures */
static struct lota_rt_verity_cache rt_digest_cache;

/* content hashes, kept apart so a hit never serves the other road's digest */
static struct lota_rt_verity_cache rt_content_cache;

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

/* length of the first @len bytes of @path without a " (deleted)" mark */
static size_t rt_deleted_suffix_len(const char *path, size_t len)
{
	static const char suffix[] = " (deleted)";
	size_t slen = sizeof(suffix) - 1;

	if (len >= slen && memcmp(path + len - slen, suffix, slen) == 0)
		return len - slen;
	return len;
}

static void rt_path_keep_tail(const char *path, size_t len, char *out,
			      size_t cap)
{
	size_t keep;

	if (!out || cap == 0)
		return;
	out[0] = '\0';
	if (!path)
		return;

	if (len < cap) {
		memcpy(out, path, len);
		out[len] = '\0';
		return;
	}
	if (cap < sizeof(LOTA_RT_PATH_CUT) + 1)
		return;

	keep = cap - sizeof(LOTA_RT_PATH_CUT);
	memcpy(out, LOTA_RT_PATH_CUT, sizeof(LOTA_RT_PATH_CUT) - 1);
	memcpy(out + sizeof(LOTA_RT_PATH_CUT) - 1, path + len - keep, keep);
	out[cap - 1] = '\0';
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
	const char *p;
	const char *soname;
	size_t len, slen;
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

	if (perms[2] != 'x' || ino == 0)
		return 0;

	p = line + pos;
	if (*p == '\0' || *p == '\n')
		return 0;
	if (*p == '[')
		return 0;

	len = rt_deleted_suffix_len(p, strcspn(p, "\n"));
	soname = memrchr(p, '/', len);
	soname = soname ? soname + 1 : p;
	slen = len - (size_t)(soname - p);
	if (slen == 0 || slen >= LOTA_RUNTIME_IMAGE_SONAME_MAX)
		return -ENAMETOOLONG;

	memset(out, 0, sizeof(*out));
	out->start = start;
	out->end = end;
	out->dev_major = maj;
	out->dev_minor = min;
	out->ino = ino;
	memcpy(out->soname, soname, slen);
	rt_path_keep_tail(p, len, out->path, sizeof(out->path));
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
			      size_t max, size_t *n_out, uint32_t *past_limit)
{
	char maps_path[64];
	char *line = NULL;
	size_t line_cap = 0;
	size_t count = 0;
	uint32_t past = 0;
	FILE *f;
	int ret = 0;

	if (!entries || !n_out || !past_limit || max == 0)
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
			past++;
			continue;
		}
		entries[count++] = e;
	}

	*n_out = count;
	*past_limit = past;
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

	if (observed->dev_major != enumerated->dev_major ||
	    observed->dev_minor != enumerated->dev_minor)
		return 0;
	if (observed->ino != enumerated->ino)
		return 0;
	if (opened_ino != enumerated->ino)
		return 0;

	return 1;
}

int lota_rt_open_mapping(int dirfd, const struct lota_rt_map_entry *entry,
			 struct stat *st)
{
	char leaf[40];
	int fd;
	int n;

	if (!entry || !st || entry->start >= entry->end)
		return -EINVAL;

	n = snprintf(leaf, sizeof(leaf), "%lx-%lx", entry->start, entry->end);
	if (n < 0 || (size_t)n >= sizeof(leaf) ||
	    !rt_map_files_leaf_is_safe(leaf))
		return -EINVAL;

	fd = openat(dirfd, leaf, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;

	if (fstat(fd, st) != 0) {
		int err = -errno;

		close(fd);
		return err;
	}
	if (!S_ISREG(st->st_mode)) {
		close(fd);
		return -ESTALE;
	}
	return fd;
}

/* One enumerated mapping, held open from before its check until measured */
struct rt_mapping {
	int fd;
	int err; /* why fd cannot be measured, 0 if it can */
	int checked;
	struct stat st;
};

/* Tie every open handle to its enumerated range, from a single maps read */
static void rt_check_mappings(pid_t pid,
			      const struct lota_rt_map_entry *entries,
			      struct rt_mapping *maps, size_t n)
{
	char maps_path[64];
	char *line = NULL;
	size_t line_cap = 0;
	FILE *f;
	int ret = 0;

	snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", (int)pid);
	f = fopen(maps_path, "re");
	if (!f) {
		ret = -errno;
		goto out;
	}

	while (getline(&line, &line_cap, f) != -1) {
		struct lota_rt_map_entry e;
		int rc = lota_rt_parse_maps_line(line, &e);

		if (rc < 0) {
			ret = rc;
			break;
		}
		if (rc == 0)
			continue;
		for (size_t i = 0; i < n; i++) {
			if (entries[i].start != e.start ||
			    entries[i].end != e.end)
				continue;
			maps[i].checked = lota_rt_mapping_identity_ok(
				&entries[i], &e,
				(unsigned long long)maps[i].st.st_ino);
			break;
		}
	}
	free(line);
	fclose(f);
out:
	for (size_t i = 0; i < n; i++) {
		if (maps[i].err != 0)
			continue;
		if (ret != 0)
			maps[i].err = ret;
		else if (!maps[i].checked)
			maps[i].err = -ESTALE;
	}
}

static void rt_close_mappings(struct rt_mapping *maps, size_t n)
{
	for (size_t i = 0; i < n; i++) {
		if (maps[i].fd >= 0)
			close(maps[i].fd);
	}
	free(maps);
}

/*
 * Open all, then check all with one maps read. A mapping that fails keeps its
 * errno. NULL when out of memory.
 */
static struct rt_mapping *
rt_open_mappings(pid_t pid, const struct lota_rt_map_entry *entries, size_t n)
{
	char dir[64];
	struct rt_mapping *maps;
	int dirfd;
	int dir_err;

	maps = calloc(n, sizeof(*maps));
	if (!maps)
		return NULL;

	snprintf(dir, sizeof(dir), "/proc/%d/map_files", (int)pid);
	dirfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	dir_err = dirfd < 0 ? -errno : 0;

	for (size_t i = 0; i < n; i++) {
		int fd = dir_err ? dir_err :
				   lota_rt_open_mapping(dirfd, &entries[i],
							&maps[i].st);

		maps[i].fd = fd < 0 ? -1 : fd;
		maps[i].err = fd < 0 ? fd : 0;
	}
	if (dirfd >= 0)
		close(dirfd);

	rt_check_mappings(pid, entries, maps, n);
	return maps;
}

static void rt_fill_open_identity(const struct rt_mapping *map,
				  struct lota_rt_open_identity *opened)
{
	struct statfs sfs;

	opened->dev = map->st.st_dev;
	opened->ino = map->st.st_ino;
	opened->size = (uint64_t)map->st.st_size;
	opened->mtime_sec = (int64_t)map->st.st_mtim.tv_sec;
	opened->mtime_nsec = (int64_t)map->st.st_mtim.tv_nsec;
	opened->nlink = (unsigned long)map->st.st_nlink;
	/* off the fd: the path may have moved since open */
	if (fstatfs(map->fd, &sfs) == 0)
		opened->fs_magic = (unsigned long)sfs.f_type;
	else
		opened->fs_magic_err = errno;
	opened->seals = fcntl(map->fd, F_GET_SEALS);
}

static int rt_read_verity(const struct rt_mapping *map,
			  struct lota_verity_digest_key *out,
			  uint32_t *reported_len)
{
	union {
		uint8_t buf[sizeof(struct fsverity_digest) +
			    LOTA_VERITY_DIGEST_MAX_SIZE];
		struct fsverity_digest hdr;
	} d;
	struct lota_rt_verity_key ckey;

	/* fs-verity fixes an inode's content, so the digest of a key holds */
	lota_rt_verity_key_from_stat(&map->st, &ckey);
	if (lota_rt_verity_cache_get(&rt_digest_cache, &ckey, out)) {
		*reported_len = out->len;
		return 0;
	}

	memset(&d, 0, sizeof(d));
	d.hdr.digest_size = (uint16_t)LOTA_VERITY_DIGEST_MAX_SIZE;

	if (ioctl(map->fd, FS_IOC_MEASURE_VERITY, &d) != 0)
		return -errno;

	*reported_len = d.hdr.digest_size;
	if (!LOTA_VERITY_DIGEST_LEN_SUPPORTED(d.hdr.digest_size))
		return -EINVAL;

	memset(out, 0, sizeof(*out));
	out->len = d.hdr.digest_size;
	memcpy(out->digest, d.hdr.digest, (size_t)out->len);
	lota_rt_verity_cache_put(&rt_digest_cache, &ckey, out);
	return 0;
}

void lota_rt_path_keep_tail(const char *path, char *out, size_t cap)
{
	rt_path_keep_tail(path, path ? strlen(path) : 0, out, cap);
}

/*
 * The link reads where the file behind it may not be reached; a longer link
 * keeps its tail, marked.
 */
static void rt_name_exe_failure(pid_t pid, int err,
				struct lota_runtime_measure_failure *fail)
{
	char exe_path[64];
	char link[PATH_MAX];
	ssize_t len;

	snprintf(exe_path, sizeof(exe_path), "/proc/%d/exe", (int)pid);
	len = readlink(exe_path, link, sizeof(link) - 1);
	if (len <= 0)
		return;

	link[len] = '\0';
	lota_rt_path_keep_tail(link, fail->path, sizeof(fail->path));
	fail->role = LOTA_RT_ROLE_EXECUTABLE;
	fail->err = err;
}

/* object the kernel holds no usable fs-verity digest for */
static int rt_err_is_unmeasurable(int err)
{
	return err == -ENODATA || err == -EOPNOTSUPP || err == -EINVAL ||
	       err == -ENOTTY;
}

#define RT_REASON_MAPPED ", an object the process has mapped"
#define RT_REASON_NO_HASH                                    \
	" carries no fs-verity digest and the kernel would " \
	"not hash its content either: "
#define RT_REASON_NO_DIGEST                                         \
	" carries no fs-verity digest (enable fs-verity on it, or " \
	"drop the process from the protected set)"
/* room for a strerror() text */
#define RT_REASON_ERRNO_ROOM 64

/* the longest reasons: a mapped object's path and the longest texts */
_Static_assert(LOTA_RT_REASON_MAX >=
		       LOTA_RT_MAP_PATH_MAX + sizeof(RT_REASON_MAPPED) +
			       sizeof(RT_REASON_NO_HASH) + RT_REASON_ERRNO_ROOM,
	       "a reason naming the longest path is cut");
_Static_assert(LOTA_RT_REASON_MAX >= LOTA_RT_MAP_PATH_MAX +
					     sizeof(RT_REASON_MAPPED) +
					     sizeof(RT_REASON_NO_DIGEST),
	       "a reason naming the longest path is cut");

void lota_rt_failure_reason(const struct lota_runtime_measure_failure *fail,
			    int err, char *buf, size_t buflen)
{
	char subject[LOTA_RT_REASON_MAX];
	const char *object;
	const char *tail;
	int no_digest;

	if (!buf || buflen == 0)
		return;

	if (fail && fail->past_limit > 0) {
		snprintf(buf, buflen,
			 "the process has %u executable mappings past the %d "
			 "objects LOTA measures",
			 fail->past_limit, LOTA_RUNTIME_IMAGE_MAX_MODULES);
		return;
	}

	if (err < 0)
		err = -err;

	/* an executable answered ENODATA; its cause is kept in fail */
	if (err == ENODATA && fail && fail->err != 0)
		err = fail->err < 0 ? -fail->err : fail->err;

	if (!fail || (fail->soname[0] == '\0' && fail->path[0] == '\0')) {
		snprintf(buf, buflen, "%s", strerror(err));
		return;
	}

	object = fail->path[0] ? fail->path : fail->soname;

	switch (fail->role) {
	case LOTA_RT_ROLE_EXECUTABLE:
		snprintf(subject, sizeof(subject),
			 "the process's own executable %s", object);
		tail = "";
		break;
	case LOTA_RT_ROLE_MAPPED_OBJECT:
		snprintf(subject, sizeof(subject), "%s" RT_REASON_MAPPED,
			 object);
		tail = ",";
		break;
	default:
		snprintf(subject, sizeof(subject), "%s", object);
		tail = "";
		break;
	}

	if (err == ENODATA && fail->no_file) {
		snprintf(buf, buflen,
			 "%s%s is memory with no file behind it, so nothing "
			 "can carry a digest for it",
			 subject, tail);
		return;
	}

	no_digest = rt_err_is_unmeasurable(-err) &&
		    !(err == EINVAL && fail->reported_len != 0);

	if (no_digest && fail->road_err != 0) {
		/* content road refused too: name its error, not fs-verity */
		snprintf(buf, buflen, "%s%s" RT_REASON_NO_HASH "%s", subject,
			 tail,
			 strerror(fail->road_err < 0 ? -fail->road_err :
						       fail->road_err));
		return;
	}

	if (no_digest && err != ENODATA) {
		snprintf(buf, buflen,
			 "%s%s is on a filesystem without fs-verity", subject,
			 tail);
		return;
	}

	if (no_digest) {
		snprintf(buf, buflen, "%s%s" RT_REASON_NO_DIGEST, subject,
			 tail);
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

static int rt_module_qsort_cmp(const void *a, const void *b)
{
	return lota__runtime_image_module_cmp(a, b);
}

int lota_rt_coverage_verdict(const struct lota_runtime_measure_coverage *cov,
			     int exe_measured)
{
	if (!cov)
		return -EINVAL;

	if (cov->measured == 0)
		return -ENODATA;
	if (!exe_measured)
		return -ENODATA;

	return 0;
}

/* stat() of /proc/<pid>/exe, to tell the executable from what it mapped */
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

/*
 * Only a filesystem this host serves itself may be content hashed: one served
 * by userspace or a peer may hand the hasher and the page fault different
 * bytes.
 */
#define LOTA_RT_MAGIC_BTRFS 0x9123683EUL
#define LOTA_RT_MAGIC_EXT4 0xEF53UL
#define LOTA_RT_MAGIC_XFS 0x58465342UL
#define LOTA_RT_MAGIC_OVERLAYFS 0x794C7630UL
#define LOTA_RT_MAGIC_TMPFS 0x01021994UL
#define LOTA_RT_MAGIC_HUGETLBFS 0x958458F6UL

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

int lota_rt_object_has_no_file(unsigned long fs_magic, unsigned long nlink)
{
	if (nlink != 0)
		return 0;

	return fs_magic == LOTA_RT_MAGIC_TMPFS ||
	       fs_magic == LOTA_RT_MAGIC_HUGETLBFS;
}

uint32_t lota_rt_object_memory_flags(unsigned long fs_magic,
				     unsigned long nlink, int seals)
{
	uint32_t flags = LOTA_EXEC_HISTORY_MEMORY;

	if (fs_magic != LOTA_RT_MAGIC_TMPFS &&
	    fs_magic != LOTA_RT_MAGIC_HUGETLBFS)
		return 0;

	if (nlink == 0 &&
	    (seals < 0 || !(seals & (F_SEAL_WRITE | F_SEAL_FUTURE_WRITE))))
		flags |= LOTA_EXEC_HISTORY_WRITABLE;

	return flags;
}

enum lota_rt_identity_road lota_rt_identity_road(int role, int verity_present,
						 unsigned long fs_magic,
						 int write_guarded)
{
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
	int road_err; /* why the content road refused, 0 if not tried */
	int no_file; /* memory with no file behind it */
};

/* Kernel hash of one mapping, cached under its fstat() identity */
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

/* no pinner or an error reads as unpinned */
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
 * Measure one mapping by whichever road may. Returns 0, the open's, the
 * mapping check's or the verity read's errno, or -ENODATA for memory with
 * no file.
 */
static int rt_measure_object(pid_t pid, const struct lota_rt_map_entry *entry,
			     const struct rt_mapping *map, dev_t exe_dev,
			     ino_t exe_ino, struct rt_object_measure *m)
{
	enum lota_rt_identity_road road;
	int ret = map->err;

	memset(m, 0, sizeof(*m));

	if (ret == 0) {
		rt_fill_open_identity(map, &m->opened);
		ret = rt_read_verity(map, &m->digest, &m->reported_len);
	}

	/* both from stat(): maps reports another device per subvolume */
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

	/* memory with no file has no road */
	if (m->opened.ino != 0 &&
	    lota_rt_object_has_no_file(m->opened.fs_magic, m->opened.nlink)) {
		m->no_file = 1;
		return -ENODATA;
	}
	if (!rt_err_is_unmeasurable(ret))
		return ret;

	/* no filesystem type, no road: say why, the verity refusal hides it */
	if (m->opened.fs_magic_err != 0) {
		m->road_err = -m->opened.fs_magic_err;
		return ret;
	}

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
	struct rt_mapping *maps = NULL;
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
					LOTA_RUNTIME_IMAGE_MAX_MODULES, &n,
					&cov->past_limit);
	if (ret != 0 || n == 0)
		goto out;

	/* unknown executable: every opened object is a mapped one */
	if (rt_exe_identity(pid, &exe_dev, &exe_ino) != 0) {
		exe_dev = 0;
		exe_ino = 0;
	}

	maps = rt_open_mappings(pid, entries, n);
	if (!maps) {
		ret = -ENOMEM;
		goto out;
	}

	for (size_t i = 0; i < n; i++) {
		struct rt_object_measure m;

		ret = rt_measure_object(pid, &entries[i], &maps[i], exe_dev,
					exe_ino, &m);
		if (ret == 0) {
			cov->measured++;
			if (m.content_hashed)
				cov->content_hashed++;
			continue;
		}
		if (lota_rt_err_is_agent_failure(ret))
			goto out;
		cov->unmeasurable++;
	}
	cov->unmeasurable += cov->past_limit;
	ret = 0;
out:
	if (maps)
		rt_close_mappings(maps, n);
	free(entries);
	return ret;
}

int lota_runtime_measure_pid_objects(
	pid_t pid, uint8_t out_digest[LOTA_RUNTIME_IMAGE_DIGEST_SIZE],
	struct lota_runtime_measure_coverage *cov,
	struct lota_runtime_measure_failure *fail,
	struct lota_rt_object_record *objs, size_t *n_objs)
{
	struct lota_rt_map_entry *entries = NULL;
	struct rt_mapping *maps = NULL;
	struct lota_runtime_image_module *mods = NULL;
	struct lota_runtime_measure_coverage local_cov = { 0 };
	int exe_measured = 0;
	dev_t exe_dev = 0;
	ino_t exe_ino = 0;
	size_t n = 0;
	size_t i, unique;
	int unopened = 0;
	int ret;

	if (fail)
		memset(fail, 0, sizeof(*fail));
	if (cov)
		memset(cov, 0, sizeof(*cov));
	if (n_objs)
		*n_objs = 0;

	if (!out_digest || (objs && !n_objs))
		return -EINVAL;

	entries = calloc(LOTA_RUNTIME_IMAGE_MAX_MODULES, sizeof(*entries));
	mods = calloc(LOTA_RUNTIME_IMAGE_MAX_MODULES, sizeof(*mods));
	if (!entries || !mods) {
		ret = -ENOMEM;
		goto out;
	}

	ret = lota_rt_collect_exec_maps(pid, entries,
					LOTA_RUNTIME_IMAGE_MAX_MODULES, &n,
					&local_cov.past_limit);
	if (ret != 0)
		goto out;
	if (cov)
		cov->past_limit = local_cov.past_limit;
	if (n == 0) {
		/* live process always maps at least its own executable */
		ret = -ENOENT;
		goto out;
	}

	/* every mapping is listed, measured or not */
	if (objs) {
		for (i = 0; i < n; i++) {
			memset(&objs[i], 0, sizeof(objs[i]));
			objs[i].entry = entries[i];
		}
		*n_objs = n;
	}

	ret = rt_exe_identity(pid, &exe_dev, &exe_ino);
	if (ret != 0) {
		if (fail)
			rt_name_exe_failure(pid, ret, fail);
		goto out;
	}

	maps = rt_open_mappings(pid, entries, n);
	if (!maps) {
		ret = -ENOMEM;
		goto out;
	}

	for (i = 0; i < n; i++) {
		struct lota_runtime_image_module *slot =
			&mods[local_cov.measured];
		struct rt_object_measure m;

		snprintf(slot->soname, sizeof(slot->soname), "%s",
			 entries[i].soname);

		ret = rt_measure_object(pid, &entries[i], &maps[i], exe_dev,
					exe_ino, &m);
		if (objs) {
			objs[i].size = m.opened.size;
			objs[i].history_flags = lota_rt_object_memory_flags(
				m.opened.fs_magic, m.opened.nlink,
				m.opened.seals);
			if (ret == 0) {
				objs[i].digest = m.digest;
				objs[i].content_hashed = m.content_hashed;
			}
		}
		if (ret != 0) {
			int agent_failure = lota_rt_err_is_agent_failure(ret);

			if (fail && (!unopened || m.is_exe || agent_failure)) {
				snprintf(fail->soname, sizeof(fail->soname),
					 "%s", entries[i].soname);
				snprintf(fail->path, sizeof(fail->path), "%s",
					 entries[i].path);
				fail->reported_len = m.reported_len;
				fail->role = m.role;
				fail->err = ret;
				fail->road_err = m.road_err;
				fail->no_file = m.no_file;
			}
			if (m.role == LOTA_RT_ROLE_UNKNOWN && !unopened)
				unopened = ret;
			if (agent_failure)
				goto out;
			if (m.is_exe) {
				if (rt_err_is_unmeasurable(ret))
					ret = -ENODATA;
				goto out;
			}
			/* a gap the relying party judges, whatever the cause */
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

	local_cov.unmeasurable += local_cov.past_limit;
	if (fail)
		fail->past_limit = local_cov.past_limit;

	ret = lota_rt_coverage_verdict(&local_cov, exe_measured);
	if (ret != 0) {
		/* a mapping that would not open may be the executable */
		if (unopened)
			ret = unopened;
		goto out;
	}

	qsort(mods, local_cov.measured, sizeof(*mods), rt_module_qsort_cmp);

	/*
	 * Two inodes can share soname and digest (one library at two paths):
	 * drop the repeat so the canonical order stays strictly increasing.
	 */
	unique = 1;
	for (i = 1; i < local_cov.measured; i++) {
		if (lota__runtime_image_module_cmp(&mods[unique - 1],
						   &mods[i]) != 0)
			mods[unique++] = mods[i];
	}

	ret = lota_compute_runtime_image_digest(mods, (uint32_t)unique,
						out_digest);
	if (ret == 0 && cov)
		*cov = local_cov;
out:
	if (maps)
		rt_close_mappings(maps, n);
	free(entries);
	if (mods)
		OPENSSL_cleanse(mods,
				LOTA_RUNTIME_IMAGE_MAX_MODULES * sizeof(*mods));
	free(mods);
	return ret;
}

int lota_runtime_measure_pid(pid_t pid,
			     uint8_t out_digest[LOTA_RUNTIME_IMAGE_DIGEST_SIZE],
			     struct lota_runtime_measure_coverage *cov,
			     struct lota_runtime_measure_failure *fail)
{
	return lota_runtime_measure_pid_objects(pid, out_digest, cov, fail,
						NULL, NULL);
}
