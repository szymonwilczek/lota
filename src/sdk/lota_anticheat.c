/* SPDX-License-Identifier: MIT */
/*
 * LOTA Anti-Cheat Compatibility Layer
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>
#include <unistd.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/types.h>
#include <stdint.h>
#include <sys/types.h>

#include "lota.h"
#include "lota_anticheat.h"
#include "lota_endian.h"
#include "lota_gaming.h"
#include "lota_server.h"
#include "lota_snapshot.h"

_Static_assert(sizeof(struct lota_ac_heartbeat_wire) == LOTA_AC_HEADER_SIZE,
	       "heartbeat wire header size must match LOTA_AC_HEADER_SIZE");

#define LOTA_AC_MAX_HEARTBEAT_AGE_SEC 120ULL

/*
 * Frozen string pairs selected by LOTA_AC_DOMAIN_VERSION_*. Adding a new
 * version means appending a new row, never editing an existing one.
 */
struct lota_ac_domain_strings {
	uint32_t version;
	const char *game_binding;
	const char *heartbeat_nonce;
	int bind_runtime; /* V2+: nonce also binds the runtime measurement */
};

static const struct lota_ac_domain_strings lota_ac_domain_table[] = {
	{ LOTA_AC_DOMAIN_VERSION_V1, "lota-ac-game-binding:v2",
	  "lota-ac-heartbeat:v1", 0 },
	{ LOTA_AC_DOMAIN_VERSION_V2, "lota-ac-game-binding:v2",
	  "lota-ac-heartbeat:v2", 1 },
};

static const struct lota_ac_domain_strings *
lota_ac_domain_lookup(uint32_t version)
{
	size_t i;
	for (i = 0;
	     i < sizeof(lota_ac_domain_table) / sizeof(lota_ac_domain_table[0]);
	     i++) {
		if (lota_ac_domain_table[i].version == version)
			return &lota_ac_domain_table[i];
	}
	return NULL;
}

static int compute_heartbeat_nonce(
	uint8_t out_nonce[LOTA_NONCE_SIZE],
	const uint8_t session_id[LOTA_AC_SESSION_ID_SIZE], uint8_t provider,
	uint32_t sequence, uint32_t lota_flags, uint64_t timestamp,
	const uint8_t game_id_hash[LOTA_AC_GAME_HASH_SIZE],
	const uint8_t runtime_measure[LOTA_AC_RUNTIME_MEASURE_SIZE],
	uint32_t domain_version);

static ssize_t read_file_buf(const char *path, void *buf, size_t buflen);

static int hash_file_sha256(const char *path,
			    uint8_t out[LOTA_AC_GAME_HASH_SIZE]);

struct lota_ac_session {
	enum lota_ac_provider provider;
	enum lota_ac_state state;

	uint8_t session_id[LOTA_AC_SESSION_ID_SIZE];
	char game_id[LOTA_AC_MAX_GAME_ID];
	uint8_t game_id_hash[LOTA_AC_GAME_HASH_SIZE];

	uint64_t session_start;
	uint64_t last_heartbeat;
	uint32_t heartbeat_seq;
	uint32_t heartbeat_interval;
	uint32_t required_flags;
	uint32_t lota_flags;

	/* direct SDK mode */
	int direct;
	struct lota_client *client;

	/* file mode */
	char token_dir[256];
	char status_path[512];
	char token_path[512];
	char snapshot_path[512];
	int snapshot_warned;

	/* cached token (wire format) */
	uint8_t token_buf[LOTA_AC_MAX_TOKEN];
	size_t token_len;
};

static uint16_t read_le16_u(const uint8_t *p)
{
	return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t read_le32_u(const uint8_t *p)
{
	return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
	       ((uint32_t)p[3] << 24);
}

static uint64_t read_le64_u(const uint8_t *p)
{
	return (uint64_t)read_le32_u(p) | ((uint64_t)read_le32_u(p + 4) << 32);
}

static int read_snapshot(struct lota_ac_session *session)
{
	uint8_t buf[LOTA_SNAPSHOT_HEADER_SIZE + LOTA_AC_MAX_TOKEN] = { 0 };
	ssize_t n = read_file_buf(session->snapshot_path, buf, sizeof(buf));
	if (n < 0)
		return (int)n;
	if (n < LOTA_SNAPSHOT_HEADER_SIZE)
		return -EIO;

	if (read_le32_u(buf + 0) != LOTA_SNAPSHOT_MAGIC)
		return -EIO;
	if (read_le16_u(buf + 4) != (uint16_t)LOTA_SNAPSHOT_VERSION)
		return -EIO;
	if (read_le16_u(buf + 6) != 0)
		return -EIO;

	uint32_t flags = read_le32_u(buf + 8);
	uint32_t token_size = read_le32_u(buf + 12);
	if (token_size == 0 || token_size > LOTA_AC_MAX_TOKEN)
		return -EIO;
	if ((size_t)n < LOTA_SNAPSHOT_HEADER_SIZE + (size_t)token_size)
		return -EIO;

	session->lota_flags = flags;
	memcpy(session->token_buf, buf + LOTA_SNAPSHOT_HEADER_SIZE, token_size);
	session->token_len = (size_t)token_size;
	return 0;
}

int lota_ac_compute_game_binding_hash(const char *game_id, const char *exe_path,
				      uint8_t out[LOTA_AC_GAME_HASH_SIZE])
{
	const struct lota_ac_domain_strings *dom;
	uint8_t exe_digest[LOTA_AC_GAME_HASH_SIZE];
	EVP_MD_CTX *ctx;
	unsigned int out_len = LOTA_AC_GAME_HASH_SIZE;
	int ok;

	if (!game_id || !exe_path || !out)
		return -EINVAL;
	if (game_id[0] == '\0')
		return -EINVAL;

	dom = lota_ac_domain_lookup(LOTA_AC_DOMAIN_VERSION_CURRENT);
	if (!dom)
		return -EINVAL;

	if (hash_file_sha256(exe_path, exe_digest) < 0)
		return -EIO;

	ctx = EVP_MD_CTX_new();
	if (!ctx)
		return -ENOMEM;

	ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) &&
	     EVP_DigestUpdate(ctx, dom->game_binding,
			      strlen(dom->game_binding) + 1) &&
	     EVP_DigestUpdate(ctx, game_id, strlen(game_id)) &&
	     EVP_DigestUpdate(ctx, exe_digest, sizeof(exe_digest)) &&
	     EVP_DigestFinal_ex(ctx, out, &out_len);

	EVP_MD_CTX_free(ctx);
	return ok ? 0 : -EIO;
}

static int compute_game_id_hash(const char *game_id,
				uint8_t out[LOTA_AC_GAME_HASH_SIZE])
{
	return lota_ac_compute_game_binding_hash(game_id, "/proc/self/exe",
						 out);
}

/*
 * Runtime re-measurement.
 *
 * Measures every file-backed loaded object (main executable + shared
 * libraries, excluding the vDSO). Each object yields a content-only
 * digest over its executable PT_LOAD segments; the combined image digest
 * folds those, keyed by soname (file basename) and sorted, so neither
 * load order nor search path matters. Computed either from the live
 * mapping (producer) or from a set of ELF files (verifier).
 *
 * See lota_anticheat.h for the canonical layout.
 */
#define LOTA_AC_RUNTIME_MEASURE_DOMAIN "lota-ac-runtime-measure:v2"
#define LOTA_AC_RUNTIME_OBJECT_DOMAIN "lota-ac-runtime-object:v1"
#define LOTA_AC_RUNTIME_MAX_SEGS 16
#define LOTA_AC_RUNTIME_MAX_OBJS 256
#define LOTA_AC_SONAME_MAX 256

/* One measured object: its soname (file basename) and content digest. */
struct rt_object {
	char soname[LOTA_AC_SONAME_MAX];
	uint8_t digest[LOTA_AC_RUNTIME_MEASURE_SIZE];
};

static const char *rt_basename(const char *path)
{
	const char *slash = strrchr(path, '/');
	return slash ? slash + 1 : path;
}

static int rt_starts_with(const char *s, const char *prefix)
{
	return strncmp(s, prefix, strlen(prefix)) == 0;
}

static int runtime_measure_update_seg_hdr(EVP_MD_CTX *md, uint64_t vaddr,
					  uint64_t offset, uint64_t filesz)
{
	uint8_t le[8];

	lota__write_le64(le, vaddr);
	if (EVP_DigestUpdate(md, le, sizeof(le)) != 1)
		return -EIO;
	lota__write_le64(le, offset);
	if (EVP_DigestUpdate(md, le, sizeof(le)) != 1)
		return -EIO;
	lota__write_le64(le, filesz);
	if (EVP_DigestUpdate(md, le, sizeof(le)) != 1)
		return -EIO;
	return 0;
}

/* Begin a per-object digest with its domain and executable segment count. */
static int rt_object_digest_begin(EVP_MD_CTX *md, uint32_t seg_count)
{
	static const char domain[] = LOTA_AC_RUNTIME_OBJECT_DOMAIN;
	uint8_t le[4];

	if (EVP_DigestInit_ex(md, EVP_sha256(), NULL) != 1 ||
	    EVP_DigestUpdate(md, domain, sizeof(domain)) != 1)
		return -EIO;
	lota__write_le32(le, seg_count);
	if (EVP_DigestUpdate(md, le, sizeof(le)) != 1)
		return -EIO;
	return 0;
}

/*
 * Per-object digest of the live mapping. Fills out on success and sets
 * *has_exec. An object with no executable PT_LOAD segment is valid and
 * simply contributes nothing (*has_exec = 0).
 */
static int rt_live_object_digest(struct dl_phdr_info *info, uint8_t out[32],
				 int *has_exec)
{
	const ElfW(Phdr) * segs[LOTA_AC_RUNTIME_MAX_SEGS];
	uint32_t n = 0;
	EVP_MD_CTX *md;
	unsigned int out_len = LOTA_AC_RUNTIME_MEASURE_SIZE;
	int ret = -EIO;

	*has_exec = 0;

	for (size_t i = 0; i < info->dlpi_phnum; i++) {
		const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
		if (ph->p_type != PT_LOAD || !(ph->p_flags & PF_X) ||
		    ph->p_filesz == 0)
			continue;
		if (n >= LOTA_AC_RUNTIME_MAX_SEGS)
			return -E2BIG;
		segs[n++] = ph;
	}
	if (n == 0)
		return 0; /* no executable code: skip this object */

	for (uint32_t k = 1; k < n; k++) {
		const ElfW(Phdr) *key = segs[k];
		uint32_t j = k;
		while (j > 0 && segs[j - 1]->p_vaddr > key->p_vaddr) {
			segs[j] = segs[j - 1];
			j--;
		}
		segs[j] = key;
	}

	md = EVP_MD_CTX_new();
	if (!md)
		return -ENOMEM;
	if (rt_object_digest_begin(md, n) < 0)
		goto out;

	for (uint32_t k = 0; k < n; k++) {
		const ElfW(Phdr) *ph = segs[k];
		const uint8_t *bytes =
			(const uint8_t *)(info->dlpi_addr + ph->p_vaddr);

		if (runtime_measure_update_seg_hdr(
			    md, ph->p_vaddr, ph->p_offset, ph->p_filesz) < 0)
			goto out;
		if (EVP_DigestUpdate(md, bytes, ph->p_filesz) != 1)
			goto out;
	}

	if (EVP_DigestFinal_ex(md, out, &out_len) != 1)
		goto out;
	*has_exec = 1;
	ret = 0;
out:
	EVP_MD_CTX_free(md);
	return ret;
}

/* qsort comparator: order objects by soname, then digest as a tiebreak. */
static int rt_object_cmp(const void *a, const void *b)
{
	const struct rt_object *oa = a;
	const struct rt_object *ob = b;
	int c = strcmp(oa->soname, ob->soname);
	if (c != 0)
		return c;
	return memcmp(oa->digest, ob->digest, LOTA_AC_RUNTIME_MEASURE_SIZE);
}

/* Fold the sorted object set into the combined image digest. */
static int rt_finalize_combined(struct rt_object *objs, size_t count,
				uint8_t out[LOTA_AC_RUNTIME_MEASURE_SIZE])
{
	static const char domain[] = LOTA_AC_RUNTIME_MEASURE_DOMAIN;
	EVP_MD_CTX *md;
	unsigned int out_len = LOTA_AC_RUNTIME_MEASURE_SIZE;
	uint8_t le[4];
	int ret = -EIO;

	if (count == 0)
		return -ENOENT;

	qsort(objs, count, sizeof(*objs), rt_object_cmp);

	md = EVP_MD_CTX_new();
	if (!md)
		return -ENOMEM;
	if (EVP_DigestInit_ex(md, EVP_sha256(), NULL) != 1 ||
	    EVP_DigestUpdate(md, domain, sizeof(domain)) != 1)
		goto out;
	lota__write_le32(le, (uint32_t)count);
	if (EVP_DigestUpdate(md, le, sizeof(le)) != 1)
		goto out;

	for (size_t i = 0; i < count; i++) {
		uint32_t slen = (uint32_t)strlen(objs[i].soname);
		lota__write_le32(le, slen);
		if (EVP_DigestUpdate(md, le, sizeof(le)) != 1)
			goto out;
		if (EVP_DigestUpdate(md, objs[i].soname, slen) != 1)
			goto out;
		if (EVP_DigestUpdate(md, objs[i].digest,
				     LOTA_AC_RUNTIME_MEASURE_SIZE) != 1)
			goto out;
	}

	if (EVP_DigestFinal_ex(md, out, &out_len) != 1)
		goto out;
	ret = 0;
out:
	EVP_MD_CTX_free(md);
	return ret;
}

static int rt_add_object(struct rt_object *objs, size_t *count,
			 const char *soname, const uint8_t digest[32])
{
	if (*count >= LOTA_AC_RUNTIME_MAX_OBJS)
		return -E2BIG;
	if (strlen(soname) >= LOTA_AC_SONAME_MAX)
		return -ENAMETOOLONG;
	memset(&objs[*count], 0, sizeof(objs[*count]));
	strncpy(objs[*count].soname, soname, LOTA_AC_SONAME_MAX - 1);
	memcpy(objs[*count].digest, digest, LOTA_AC_RUNTIME_MEASURE_SIZE);
	(*count)++;
	return 0;
}

static int rt_resolve_self_exe(char *buf, size_t len)
{
	ssize_t n = readlink("/proc/self/exe", buf, len - 1);
	if (n < 0)
		return -errno;
	buf[n] = '\0';
	return 0;
}

/*
 * Decide whether a dl_iterate_phdr object is measured, and resolve its
 * on-disk path and soname. index 0 is always the main executable.
 * Returns 1 to include, 0 to skip (vDSO / unnamed auxiliary objects).
 */
static int rt_object_identity(struct dl_phdr_info *info, unsigned index,
			      const char *self_exe, const char **path_out,
			      const char **soname_out)
{
	if (index == 0) {
		*path_out = self_exe;
		*soname_out = rt_basename(self_exe);
		return 1;
	}
	if (!info->dlpi_name || info->dlpi_name[0] == '\0')
		return 0; /* anonymous auxiliary object (e.g. vDSO) */

	const char *base = rt_basename(info->dlpi_name);
	if (rt_starts_with(base, "linux-vdso") ||
	    rt_starts_with(base, "linux-gate"))
		return 0;

	*path_out = info->dlpi_name;
	*soname_out = base;
	return 1;
}

struct rt_collect_ctx {
	struct rt_object *objs;
	size_t count;
	unsigned index;
	const char *self_exe;
	int err;
};

static int rt_collect_cb(struct dl_phdr_info *info, size_t size, void *data)
{
	struct rt_collect_ctx *ctx = data;
	const char *path = NULL;
	const char *soname = NULL;
	uint8_t digest[LOTA_AC_RUNTIME_MEASURE_SIZE];
	int has_exec = 0;
	int rc;
	unsigned index = ctx->index++;

	(void)size;

	if (!rt_object_identity(info, index, ctx->self_exe, &path, &soname))
		return 0;

	rc = rt_live_object_digest(info, digest, &has_exec);
	if (rc < 0) {
		ctx->err = rc;
		return 1;
	}
	if (!has_exec)
		return 0;

	rc = rt_add_object(ctx->objs, &ctx->count, soname, digest);
	if (rc < 0) {
		ctx->err = rc;
		return 1;
	}
	return 0;
}

int lota_ac_compute_runtime_measure(uint8_t out[LOTA_AC_RUNTIME_MEASURE_SIZE])
{
	struct rt_collect_ctx ctx;
	char self_exe[LOTA_AC_RUNTIME_PATH_MAX];
	int ret;

	if (!out)
		return -EINVAL;

	ret = rt_resolve_self_exe(self_exe, sizeof(self_exe));
	if (ret < 0)
		return ret;

	memset(&ctx, 0, sizeof(ctx));
	ctx.objs = calloc(LOTA_AC_RUNTIME_MAX_OBJS, sizeof(*ctx.objs));
	if (!ctx.objs)
		return -ENOMEM;
	ctx.self_exe = self_exe;

	dl_iterate_phdr(rt_collect_cb, &ctx);
	if (ctx.err) {
		ret = ctx.err;
		goto out;
	}

	ret = rt_finalize_combined(ctx.objs, ctx.count, out);
out:
	free(ctx.objs);
	return ret;
}

struct rt_list_ctx {
	lota_ac_runtime_object_fn fn;
	void *user;
	unsigned index;
	const char *self_exe;
	int stop;
};

static int rt_list_cb(struct dl_phdr_info *info, size_t size, void *data)
{
	struct rt_list_ctx *ctx = data;
	const char *path = NULL;
	const char *soname = NULL;
	unsigned index = ctx->index++;

	(void)size;

	if (ctx->stop)
		return 1;
	if (!rt_object_identity(info, index, ctx->self_exe, &path, &soname))
		return 0;

	if (ctx->fn(path, ctx->user) != 0) {
		ctx->stop = 1;
		return 1;
	}
	return 0;
}

int lota_ac_list_runtime_objects(lota_ac_runtime_object_fn fn, void *user)
{
	struct rt_list_ctx ctx;
	char self_exe[LOTA_AC_RUNTIME_PATH_MAX];
	int ret;

	if (!fn)
		return -EINVAL;

	ret = rt_resolve_self_exe(self_exe, sizeof(self_exe));
	if (ret < 0)
		return ret;

	memset(&ctx, 0, sizeof(ctx));
	ctx.fn = fn;
	ctx.user = user;
	ctx.self_exe = self_exe;

	dl_iterate_phdr(rt_list_cb, &ctx);
	return 0;
}

static int pread_full(int fd, void *buf, size_t len, off_t off)
{
	uint8_t *p = buf;

	while (len > 0) {
		ssize_t n = pread(fd, p, len, off);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (n == 0)
			return -EIO; /* truncated file */
		p += n;
		off += n;
		len -= (size_t)n;
	}
	return 0;
}

static int runtime_measure_update_file_seg(EVP_MD_CTX *md, int fd,
					   uint64_t offset, uint64_t filesz)
{
	uint8_t buf[4096];
	uint64_t remaining = filesz;
	off_t cur = (off_t)offset;

	while (remaining > 0) {
		size_t want = remaining < sizeof(buf) ? (size_t)remaining :
							sizeof(buf);
		int rc = pread_full(fd, buf, want, cur);
		if (rc < 0)
			return rc;
		if (EVP_DigestUpdate(md, buf, want) != 1)
			return -EIO;
		cur += (off_t)want;
		remaining -= want;
	}
	return 0;
}

/*
 * Per-object digest from an ELF file on disk. Mirrors
 * rt_live_object_digest(). Fills out and sets *has_exec on success; a
 * file with no executable PT_LOAD segment is valid (*has_exec = 0).
 * Returns a negative error for a malformed or unreadable file.
 */
static int rt_file_object_digest(const char *path, uint8_t out[32],
				 int *has_exec)
{
	Elf64_Ehdr ehdr;
	Elf64_Phdr *phdrs = NULL;
	const Elf64_Phdr *segs[LOTA_AC_RUNTIME_MAX_SEGS];
	EVP_MD_CTX *md = NULL;
	unsigned int out_len = LOTA_AC_RUNTIME_MEASURE_SIZE;
	uint32_t n = 0;
	size_t phsz;
	int fd = -1;
	int ret = -EIO;

	*has_exec = 0;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		ret = -errno;
		goto out;
	}

	ret = pread_full(fd, &ehdr, sizeof(ehdr), 0);
	if (ret < 0)
		goto out;
	if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
		ret = -EINVAL;
		goto out;
	}
	if (ehdr.e_ident[EI_CLASS] != ELFCLASS64 ||
	    ehdr.e_ident[EI_DATA] != ELFDATA2LSB) {
		ret = -ENOTSUP;
		goto out;
	}
	if (ehdr.e_phentsize != sizeof(Elf64_Phdr)) {
		ret = -EINVAL;
		goto out;
	}
	if (ehdr.e_phnum == 0 || ehdr.e_phnum >= PN_XNUM) {
		ret = -EINVAL;
		goto out;
	}

	phsz = (size_t)ehdr.e_phnum * sizeof(Elf64_Phdr);
	phdrs = malloc(phsz);
	if (!phdrs) {
		ret = -ENOMEM;
		goto out;
	}
	ret = pread_full(fd, phdrs, phsz, (off_t)ehdr.e_phoff);
	if (ret < 0)
		goto out;

	for (size_t i = 0; i < ehdr.e_phnum; i++) {
		const Elf64_Phdr *ph = &phdrs[i];
		if (ph->p_type != PT_LOAD || !(ph->p_flags & PF_X) ||
		    ph->p_filesz == 0)
			continue;
		if (n >= LOTA_AC_RUNTIME_MAX_SEGS) {
			ret = -E2BIG;
			goto out;
		}
		segs[n++] = ph;
	}

	if (n == 0) {
		ret = 0; /* no executable code: caller skips this object */
		goto out;
	}

	for (uint32_t k = 1; k < n; k++) {
		const Elf64_Phdr *key = segs[k];
		uint32_t j = k;
		while (j > 0 && segs[j - 1]->p_vaddr > key->p_vaddr) {
			segs[j] = segs[j - 1];
			j--;
		}
		segs[j] = key;
	}

	md = EVP_MD_CTX_new();
	if (!md) {
		ret = -ENOMEM;
		goto out;
	}
	if (rt_object_digest_begin(md, n) < 0) {
		ret = -EIO;
		goto out;
	}

	for (uint32_t k = 0; k < n; k++) {
		const Elf64_Phdr *ph = segs[k];
		if (runtime_measure_update_seg_hdr(
			    md, ph->p_vaddr, ph->p_offset, ph->p_filesz) < 0) {
			ret = -EIO;
			goto out;
		}
		ret = runtime_measure_update_file_seg(md, fd, ph->p_offset,
						      ph->p_filesz);
		if (ret < 0)
			goto out;
	}

	if (EVP_DigestFinal_ex(md, out, &out_len) != 1) {
		ret = -EIO;
		goto out;
	}
	*has_exec = 1;
	ret = 0;
out:
	if (md)
		EVP_MD_CTX_free(md);
	free(phdrs);
	if (fd >= 0)
		close(fd);
	return ret;
}

int lota_ac_compute_expected_runtime_measure_set(
	const char *const *paths, size_t count,
	uint8_t out[LOTA_AC_RUNTIME_MEASURE_SIZE])
{
	struct rt_object *objs;
	size_t nobj = 0;
	int ret;

	if (!paths || !out)
		return -EINVAL;

	objs = calloc(LOTA_AC_RUNTIME_MAX_OBJS, sizeof(*objs));
	if (!objs)
		return -ENOMEM;

	for (size_t i = 0; i < count; i++) {
		uint8_t digest[LOTA_AC_RUNTIME_MEASURE_SIZE];
		int has_exec = 0;

		if (!paths[i]) {
			ret = -EINVAL;
			goto out;
		}
		ret = rt_file_object_digest(paths[i], digest, &has_exec);
		if (ret < 0)
			goto out;
		if (!has_exec)
			continue;
		ret = rt_add_object(objs, &nobj, rt_basename(paths[i]), digest);
		if (ret < 0)
			goto out;
	}

	ret = rt_finalize_combined(objs, nobj, out);
out:
	free(objs);
	return ret;
}

int lota_ac_compute_expected_runtime_measure(
	const char *exe_path, uint8_t out[LOTA_AC_RUNTIME_MEASURE_SIZE])
{
	if (!exe_path || !out)
		return -EINVAL;
	return lota_ac_compute_expected_runtime_measure_set(&exe_path, 1, out);
}

static int compute_heartbeat_nonce(
	uint8_t out_nonce[LOTA_NONCE_SIZE],
	const uint8_t session_id[LOTA_AC_SESSION_ID_SIZE], uint8_t provider,
	uint32_t sequence, uint32_t lota_flags, uint64_t timestamp,
	const uint8_t game_id_hash[LOTA_AC_GAME_HASH_SIZE],
	const uint8_t runtime_measure[LOTA_AC_RUNTIME_MEASURE_SIZE],
	uint32_t domain_version)
{
	const struct lota_ac_domain_strings *dom;
	uint8_t le32[4];
	uint8_t flags_le[4];
	uint8_t le64[8];
	uint8_t ver_le[4];
	EVP_MD_CTX *ctx;
	unsigned int out_len = LOTA_NONCE_SIZE;
	int ok;

	if (!out_nonce || !session_id || !game_id_hash)
		return -EINVAL;

	dom = lota_ac_domain_lookup(domain_version);
	if (!dom)
		return -EINVAL;

	/* runtime-binding domains (V2+) require the measurement */
	if (dom->bind_runtime && !runtime_measure)
		return -EINVAL;

	ctx = EVP_MD_CTX_new();
	if (!ctx)
		return -ENOMEM;

	lota__write_le32(le32, sequence);
	lota__write_le32(flags_le, lota_flags);
	lota__write_le64(le64, timestamp);
	lota__write_le32(ver_le, domain_version);

	ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) &&
	     EVP_DigestUpdate(ctx, dom->heartbeat_nonce,
			      strlen(dom->heartbeat_nonce) + 1) &&
	     EVP_DigestUpdate(ctx, session_id, LOTA_AC_SESSION_ID_SIZE) &&
	     EVP_DigestUpdate(ctx, &provider, sizeof(provider)) &&
	     EVP_DigestUpdate(ctx, le32, sizeof(le32)) &&
	     EVP_DigestUpdate(ctx, flags_le, sizeof(flags_le)) &&
	     EVP_DigestUpdate(ctx, le64, sizeof(le64)) &&
	     EVP_DigestUpdate(ctx, game_id_hash, LOTA_AC_GAME_HASH_SIZE) &&
	     EVP_DigestUpdate(ctx, ver_le, sizeof(ver_le));

	/*
	 * runtime measurement is appended only for domains that bind it,
	 * so V1 nonces stay byte-for-byte identical to their frozen layout
	 */
	if (ok && dom->bind_runtime)
		ok = EVP_DigestUpdate(ctx, runtime_measure,
				      LOTA_AC_RUNTIME_MEASURE_SIZE);

	ok = ok && EVP_DigestFinal_ex(ctx, out_nonce, &out_len);

	EVP_MD_CTX_free(ctx);
	return ok ? 0 : -EIO;
}

static int generate_session_id(uint8_t id[LOTA_AC_SESSION_ID_SIZE])
{
	ssize_t n = getrandom(id, LOTA_AC_SESSION_ID_SIZE, 0);
	if (n != LOTA_AC_SESSION_ID_SIZE)
		return -errno;
	return 0;
}

static ssize_t read_file_buf(const char *path, void *buf, size_t buflen)
{
	int fd = open(path, O_RDONLY);
	if (fd < 0)
		return -errno;

	ssize_t total = 0;
	while ((size_t)total < buflen) {
		ssize_t n = read(fd, (uint8_t *)buf + total,
				 buflen - (size_t)total);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			int err = errno;
			close(fd);
			return -err;
		}
		if (n == 0)
			break;
		total += n;
	}

	close(fd);
	return total;
}

static int hash_file_sha256(const char *path,
			    uint8_t out[LOTA_AC_GAME_HASH_SIZE])
{
	uint8_t buf[4096];
	EVP_MD_CTX *ctx = NULL;
	unsigned int out_len = LOTA_AC_GAME_HASH_SIZE;
	int fd = -1;
	int ret = -EIO;

	if (!path || !out)
		return -EINVAL;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;

	ctx = EVP_MD_CTX_new();
	if (!ctx) {
		ret = -ENOMEM;
		goto out;
	}

	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
		ret = -EIO;
		goto out;
	}

	for (;;) {
		ssize_t n = read(fd, buf, sizeof(buf));
		if (n == 0)
			break;
		if (n < 0) {
			if (errno == EINTR)
				continue;
			ret = -errno;
			goto out;
		}
		if (EVP_DigestUpdate(ctx, buf, (size_t)n) != 1) {
			ret = -EIO;
			goto out;
		}
	}

	if (EVP_DigestFinal_ex(ctx, out, &out_len) != 1) {
		ret = -EIO;
		goto out;
	}

	ret = 0;

out:
	if (ctx)
		EVP_MD_CTX_free(ctx);
	if (fd >= 0)
		close(fd);
	return ret;
}

/*
 * Resolve token directory for file mode.
 * Priority: cfg->token_dir > $LOTA_HOOK_TOKEN_DIR > $XDG_RUNTIME_DIR/lota
 */
static int resolve_token_dir(const struct lota_ac_config *cfg, char *out,
			     size_t outlen)
{
	const char *dir = cfg->token_dir;
	if (!dir)
		dir = getenv("LOTA_HOOK_TOKEN_DIR");

	if (!dir) {
		const char *xdg = getenv("XDG_RUNTIME_DIR");
		if (xdg) {
			int ret = snprintf(out, outlen, "%s/lota", xdg);
			if (ret < 0 || (size_t)ret >= outlen)
				return -ENAMETOOLONG;
			return 0;
		}
		return -ENOENT;
	}

	if (strlen(dir) >= outlen)
		return -ENAMETOOLONG;
	strncpy(out, dir, outlen - 1);
	out[outlen - 1] = '\0';
	return 0;
}

static int is_trusted(uint32_t flags, uint32_t required)
{
	if (required)
		return (flags & required) == required;
	return flags != 0;
}

struct lota_ac_session *lota_ac_init(const struct lota_ac_config *cfg)
{
	if (!cfg)
		return NULL;
	if (!cfg->game_id || cfg->game_id[0] == '\0')
		return NULL;
	if (strlen(cfg->game_id) >= LOTA_AC_MAX_GAME_ID)
		return NULL;
	if (cfg->provider != LOTA_AC_PROVIDER_EAC &&
	    cfg->provider != LOTA_AC_PROVIDER_BATTLEYE)
		return NULL;

	struct lota_ac_session *s = calloc(1, sizeof(*s));
	if (!s)
		return NULL;

	s->provider = cfg->provider;
	s->state = LOTA_AC_STATE_IDLE;
	strncpy(s->game_id, cfg->game_id, LOTA_AC_MAX_GAME_ID - 1);
	s->heartbeat_interval = cfg->heartbeat_interval_sec ?
					cfg->heartbeat_interval_sec :
					LOTA_AC_DEFAULT_HEARTBEAT_SEC;
	s->required_flags = cfg->required_flags;
	s->direct = cfg->direct;

	if (generate_session_id(s->session_id) < 0) {
		free(s);
		return NULL;
	}
	if (compute_game_id_hash(s->game_id, s->game_id_hash) < 0) {
		free(s);
		return NULL;
	}

	s->session_start = (uint64_t)time(NULL);

	if (cfg->direct) {
		if (cfg->socket_path) {
			struct lota_connect_opts opts = { 0 };
			opts.socket_path = cfg->socket_path;
			opts.timeout_ms = 5000;
			s->client = lota_connect_opts(&opts);
		} else {
			s->client = lota_connect();
		}
		if (!s->client)
			s->state = LOTA_AC_STATE_ERROR;
		else
			s->state = LOTA_AC_STATE_RUNNING;
	} else {
		if (resolve_token_dir(cfg, s->token_dir, sizeof(s->token_dir)) <
		    0) {
			s->state = LOTA_AC_STATE_ERROR;
		} else {
			snprintf(s->status_path, sizeof(s->status_path),
				 "%s/lota-status", s->token_dir);
			snprintf(s->token_path, sizeof(s->token_path),
				 "%s/lota-token.bin", s->token_dir);
			snprintf(s->snapshot_path, sizeof(s->snapshot_path),
				 "%s/%s", s->token_dir,
				 LOTA_SNAPSHOT_FILE_NAME);
			s->state = LOTA_AC_STATE_RUNNING;
		}
	}

	/* initial tick to populate state */
	if (s->state == LOTA_AC_STATE_RUNNING)
		lota_ac_tick(s);

	return s;
}

void lota_ac_shutdown(struct lota_ac_session *session)
{
	if (!session)
		return;

	if (session->client) {
		lota_disconnect(session->client);
		session->client = NULL;
	}

	session->state = LOTA_AC_STATE_IDLE;
	free(session);
}

enum lota_ac_state lota_ac_get_state(const struct lota_ac_session *session)
{
	if (!session)
		return LOTA_AC_STATE_IDLE;
	return session->state;
}

int lota_ac_get_info(const struct lota_ac_session *session,
		     struct lota_ac_info *info)
{
	if (!session || !info)
		return -EINVAL;

	info->provider = session->provider;
	info->state = (session->state == LOTA_AC_STATE_ERROR) ?
			      LOTA_AC_STATE_ERROR :
			      LOTA_AC_STATE_RUNNING;
	memcpy(info->session_id, session->session_id, LOTA_AC_SESSION_ID_SIZE);
	info->session_start = session->session_start;
	info->last_heartbeat = session->last_heartbeat;
	info->heartbeat_seq = session->heartbeat_seq;
	info->lota_flags = session->lota_flags;
	info->trusted = 0;

	return 0;
}

int lota_ac_tick(struct lota_ac_session *session)
{
	if (!session)
		return -EINVAL;
	if (session->state == LOTA_AC_STATE_IDLE)
		return -EINVAL;

	if (session->direct) {
		/* direct SDK mode */
		if (!session->client) {
			session->state = LOTA_AC_STATE_ERROR;
			return -ENOTCONN;
		}

		struct lota_status status;
		int ret = lota_get_status(session->client, &status);
		if (ret != LOTA_OK) {
			session->state = LOTA_AC_STATE_ERROR;
			return -EIO;
		}
		session->lota_flags = status.flags;

		struct lota_token token;
		ret = lota_get_token(session->client, NULL, &token);
		if (ret == LOTA_OK) {
			size_t sz = lota_token_serialized_size(&token);
			if (sz <= LOTA_AC_MAX_TOKEN)
				lota_token_serialize(&token, session->token_buf,
						     LOTA_AC_MAX_TOKEN,
						     &session->token_len);
			lota_token_free(&token);
		} else {
			session->token_len = 0;
		}
	} else {
		int sret = read_snapshot(session);
		if (sret < 0) {
			if (!session->snapshot_warned) {
				fprintf(stderr,
					"lota-ac: snapshot read failed (%s): %s\n",
					session->snapshot_path,
					strerror(-sret));
				session->snapshot_warned = 1;
			}
			session->lota_flags = 0;
			session->token_len = 0;
		}
	}

	/* update state machine */
	if (session->token_len > 0 || session->lota_flags != 0)
		session->state = is_trusted(session->lota_flags,
					    session->required_flags) ?
					 LOTA_AC_STATE_TRUSTED :
					 LOTA_AC_STATE_UNTRUSTED;
	else
		session->state = LOTA_AC_STATE_ERROR;

	return 0;
}

int lota_ac_heartbeat(struct lota_ac_session *session, uint8_t *buf,
		      size_t buflen, size_t *written)
{
	uint64_t timestamp;
	uint32_t sequence;
	uint8_t heartbeat_nonce[LOTA_NONCE_SIZE];
	uint8_t runtime_measure[LOTA_AC_RUNTIME_MEASURE_SIZE];

	if (!session || !buf || !written)
		return -EINVAL;

	/*
	 * Replay-safe heartbeat requires nonce-bound token acquisition.
	 * File mode uses pre-generated snapshot tokens and cannot safely bind
	 * current sequence/timestamp challenge into TPM-signed nonce.
	 */
	if (!session->direct)
		return -EOPNOTSUPP;

	/*
	 * Refresh integrity flags for the nonce binding with GET_STATUS only. A
	 * heartbeat needs exactly one TPM quote (the nonce-bound GET_TOKEN
	 * below); routing through lota_ac_tick() would issue a second,
	 * immediately overwritten GET_TOKEN and burn an extra slot of the
	 * agent's per-UID GET_TOKEN rate limit (ipc.c), halving the sustainable
	 * heartbeat rate.
	 */
	if (!session->client)
		return -ENOTCONN;

	struct lota_status status;
	int ret = lota_get_status(session->client, &status);
	if (ret != LOTA_OK) {
		session->state = LOTA_AC_STATE_ERROR;
		return -EIO;
	}
	session->lota_flags = status.flags;

	timestamp = (uint64_t)time(NULL);
	sequence = session->heartbeat_seq;

	/*
	 * Re-measure the live executable image for this beat.
	 * Binding the fresh measurement into the nonce ties it to the
	 * TPM-signed token and closes the TOCTOU window left by the
	 * session-start on-disk hash
	 */
	ret = lota_ac_compute_runtime_measure(runtime_measure);
	if (ret < 0)
		return ret;

	ret = compute_heartbeat_nonce(heartbeat_nonce, session->session_id,
				      (uint8_t)session->provider, sequence,
				      session->lota_flags, timestamp,
				      session->game_id_hash, runtime_measure,
				      LOTA_AC_DOMAIN_VERSION_CURRENT);
	if (ret < 0)
		return ret;

	{
		struct lota_token token;
		size_t tok_written = 0;

		memset(&token, 0, sizeof(token));
		ret = lota_get_token(session->client, heartbeat_nonce, &token);
		if (ret != LOTA_OK) {
			if (ret == LOTA_ERR_NOT_ATTESTED)
				return -ENODATA;
			return -EIO;
		}

		if (memcmp(token.nonce, heartbeat_nonce, LOTA_NONCE_SIZE) !=
		    0) {
			lota_token_free(&token);
			return -EPROTO;
		}

		session->lota_flags = token.flags;
		session->state = is_trusted(session->lota_flags,
					    session->required_flags) ?
					 LOTA_AC_STATE_TRUSTED :
					 LOTA_AC_STATE_UNTRUSTED;

		ret = lota_token_serialize(&token, session->token_buf,
					   LOTA_AC_MAX_TOKEN, &tok_written);
		lota_token_free(&token);
		if (ret != LOTA_OK)
			return -EIO;

		session->token_len = tok_written;
	}

	if (session->token_len == 0)
		return -ENODATA;

	size_t total = LOTA_AC_HEADER_SIZE + session->token_len;
	if (buflen < total)
		return -ENOSPC;

	lota__write_le32(buf + 0, (uint32_t)LOTA_AC_MAGIC);
	buf[4] = (uint8_t)LOTA_AC_VERSION;
	buf[5] = (uint8_t)session->provider;
	lota__write_le16(buf + 6, (uint16_t)total);
	memcpy(buf + 8, session->session_id, LOTA_AC_SESSION_ID_SIZE);
	lota__write_le32(buf + 24, session->heartbeat_seq);
	lota__write_le32(buf + 28, session->lota_flags);
	lota__write_le64(buf + 32, timestamp);
	memcpy(buf + 40, session->game_id_hash, LOTA_AC_GAME_HASH_SIZE);
	lota__write_le16(buf + 72, (uint16_t)session->token_len);
	lota__write_le32(buf + 74, LOTA_AC_DOMAIN_VERSION_CURRENT);
	memcpy(buf + 78, runtime_measure, LOTA_AC_RUNTIME_MEASURE_SIZE);

	memcpy(buf + LOTA_AC_HEADER_SIZE, session->token_buf,
	       session->token_len);

	session->heartbeat_seq++;
	session->last_heartbeat = timestamp;

	*written = total;
	return 0;
}

int lota_ac_verify_heartbeat(
	const uint8_t *data, size_t len, const uint8_t *aik_pub_der,
	size_t aik_pub_len,
	const uint8_t expected_game_id_hash[LOTA_AC_GAME_HASH_SIZE],
	const uint8_t expected_runtime_measure[LOTA_AC_RUNTIME_MEASURE_SIZE],
	struct lota_ac_info *info)
{
	if (!data || !expected_game_id_hash || !expected_runtime_measure ||
	    !info)
		return LOTA_SERVER_ERR_INVALID_ARG;

	if (len < LOTA_AC_HEADER_SIZE)
		return LOTA_SERVER_ERR_BAD_TOKEN;

	uint32_t magic = read_le32_u(data + 0);
	uint8_t version = data[4];
	uint8_t provider = data[5];
	uint16_t total_size = read_le16_u(data + 6);
	uint32_t sequence = read_le32_u(data + 24);
	uint32_t heartbeat_lota_flags = read_le32_u(data + 28);
	uint64_t timestamp = read_le64_u(data + 32);
	uint16_t token_size = read_le16_u(data + 72);
	uint32_t domain_version = read_le32_u(data + 74);
	uint64_t now = (uint64_t)time(NULL);
	uint8_t expected_nonce[LOTA_NONCE_SIZE];
	int ret = LOTA_SERVER_OK;

	if (magic != LOTA_AC_MAGIC)
		return LOTA_SERVER_ERR_BAD_TOKEN;
	if (version != LOTA_AC_VERSION)
		return LOTA_SERVER_ERR_BAD_VERSION;
	if ((size_t)total_size > len)
		return LOTA_SERVER_ERR_BAD_TOKEN;
	if ((size_t)total_size != LOTA_AC_HEADER_SIZE + (size_t)token_size)
		return LOTA_SERVER_ERR_BAD_TOKEN;
	if (token_size == 0 || token_size > LOTA_AC_MAX_TOKEN)
		return LOTA_SERVER_ERR_BAD_TOKEN;
	if (provider != LOTA_AC_PROVIDER_EAC &&
	    provider != LOTA_AC_PROVIDER_BATTLEYE)
		return LOTA_SERVER_ERR_BAD_TOKEN;

	if (!lota_ac_domain_lookup(domain_version))
		return LOTA_SERVER_ERR_BAD_VERSION;

	if (CRYPTO_memcmp(data + 40, expected_game_id_hash,
			  LOTA_AC_GAME_HASH_SIZE) != 0)
		return LOTA_SERVER_ERR_BAD_TOKEN;

	/*
	 * Runtime measurement must match the value an honest producer of this
	 * image reports.
	 * Reject before signature work, then bind the same bytes into the
	 * expected nonce so a TPM-signed token cannot smuggle a different
	 * measurement past this check
	 */
	if (CRYPTO_memcmp(data + 78, expected_runtime_measure,
			  LOTA_AC_RUNTIME_MEASURE_SIZE) != 0)
		return LOTA_SERVER_ERR_BAD_TOKEN;

	if (timestamp > now + LOTA_AC_MAX_HEARTBEAT_AGE_SEC)
		return LOTA_SERVER_ERR_BAD_TOKEN;
	if (timestamp + LOTA_AC_MAX_HEARTBEAT_AGE_SEC < now)
		return LOTA_SERVER_ERR_BAD_TOKEN;

	ret = compute_heartbeat_nonce(expected_nonce, data + 8, provider,
				      sequence, heartbeat_lota_flags, timestamp,
				      data + 40, data + 78, domain_version);
	if (ret < 0)
		return LOTA_SERVER_ERR_CRYPTO;

	const uint8_t *token = data + LOTA_AC_HEADER_SIZE;

	struct lota_server_claims claims;

	if (!aik_pub_der || aik_pub_len == 0)
		return LOTA_SERVER_ERR_INVALID_ARG;

	ret = lota_server_verify_token(token, token_size, aik_pub_der,
				       aik_pub_len, expected_nonce, &claims);

	if (ret != LOTA_SERVER_OK)
		return ret;

	if (memcmp(claims.nonce, expected_nonce, LOTA_NONCE_SIZE) != 0)
		return LOTA_SERVER_ERR_NONCE_FAIL;

	/*
	 * lota_flags in heartbeat header are plaintext transport metadata only.
	 * Trust token claims (nonce-bound and signature-verified when AIK is
	 * set) and fail closed if header/token disagree
	 */
	if (heartbeat_lota_flags != claims.flags)
		return LOTA_SERVER_ERR_BAD_TOKEN;

	info->provider = (enum lota_ac_provider)provider;
	memcpy(info->session_id, data + 8, LOTA_AC_SESSION_ID_SIZE);
	info->session_start = 0; /* not available from a single heartbeat */
	info->last_heartbeat = timestamp;
	info->heartbeat_seq = sequence;
	info->lota_flags = claims.flags;
	memcpy(info->game_id_hash, data + 40, LOTA_AC_GAME_HASH_SIZE);
	info->trusted = (claims.flags != 0);
	info->state = info->trusted ? LOTA_AC_STATE_TRUSTED :
				      LOTA_AC_STATE_UNTRUSTED;

	return 0;
}

const char *lota_ac_state_str(enum lota_ac_state state)
{
	switch (state) {
	case LOTA_AC_STATE_IDLE:
		return "idle";
	case LOTA_AC_STATE_RUNNING:
		return "running";
	case LOTA_AC_STATE_TRUSTED:
		return "trusted";
	case LOTA_AC_STATE_UNTRUSTED:
		return "untrusted";
	case LOTA_AC_STATE_ERROR:
		return "error";
	}
	return "unknown";
}

const char *lota_ac_provider_str(enum lota_ac_provider provider)
{
	switch (provider) {
	case LOTA_AC_PROVIDER_EAC:
		return "EAC";
	case LOTA_AC_PROVIDER_BATTLEYE:
		return "BattlEye";
	}
	return "unknown";
}
