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
#include <sys/auxv.h>
#include <sys/random.h>
#include <sys/stat.h>
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
#include "lota_wine_hook.h"
#include "lota_snapshot.h"
#include "lota_token.h"

_Static_assert(LOTA_AC_MAX_TOKEN == LOTA_TOKEN_MAX_SIZE,
	       "LOTA_AC_MAX_TOKEN must match LOTA_TOKEN_MAX_SIZE");

_Static_assert(sizeof(struct lota_ac_heartbeat_wire) == LOTA_AC_HEADER_SIZE,
	       "heartbeat wire header size must match LOTA_AC_HEADER_SIZE");

/*
 * The library hands out LOTA_AC_ERR_* and negative errno: a caller reads a
 * number and has to know which of them it is.
 */
_Static_assert(LOTA_AC_ERR_BASE < -255,
	       "LOTA_AC_ERR_BASE must sit past any errno value");

#define LOTA_AC_MAX_HEARTBEAT_AGE_SEC 120ULL

_Static_assert(sizeof(struct lota_ac_heartbeat_wire) == 110,
	       "heartbeat wire header is frozen");

/* String pairs selected by LOTA_AC_DOMAIN_VERSION_*. */
struct lota_ac_domain_strings {
	uint32_t version;
	const char *game_binding;
	const char *heartbeat_nonce;
};

static const struct lota_ac_domain_strings lota_ac_domain_table[] = {
	{ LOTA_AC_DOMAIN_VERSION_V1, "lota-ac-game-binding:v1",
	  "lota-ac-heartbeat:v1" },
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

/* per thread, as lota_ac_last_error() reads it */
static _Thread_local int g_ac_error = LOTA_AC_ERR_OK;

int lota_ac_last_error(void)
{
	return g_ac_error;
}

/* record @ret for lota_ac_last_error() and return it */
static int ac_ret(int ret)
{
	g_ac_error = ret;
	return ret;
}

/* ac_ret() for call sites that return their own value */
static int ac_fail(int err)
{
	return ac_ret(err);
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
	uint32_t required_flags;
	uint32_t lota_flags;

	/* direct SDK mode */
	int direct;
	struct lota_client *client;
	int connect_error; /* why client is NULL */

	/* file mode */
	char token_dir[256];
	char status_path[512];
	char token_path[512];
	char snapshot_path[512];
	char evidence_path[512];
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
		return ac_ret(-EINVAL);
	if (game_id[0] == '\0')
		return ac_ret(-EINVAL);

	dom = lota_ac_domain_lookup(LOTA_AC_DOMAIN_VERSION_CURRENT);
	if (!dom)
		return ac_ret(-EINVAL);

	if (hash_file_sha256(exe_path, exe_digest) < 0)
		return ac_ret(-EIO);

	ctx = EVP_MD_CTX_new();
	if (!ctx)
		return ac_ret(-ENOMEM);

	ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) &&
	     EVP_DigestUpdate(ctx, dom->game_binding,
			      strlen(dom->game_binding) + 1) &&
	     EVP_DigestUpdate(ctx, game_id, strlen(game_id)) &&
	     EVP_DigestUpdate(ctx, exe_digest, sizeof(exe_digest)) &&
	     EVP_DigestFinal_ex(ctx, out, &out_len);

	EVP_MD_CTX_free(ctx);
	return ac_ret(ok ? 0 : -EIO);
}

static int compute_game_id_hash(const char *game_id,
				uint8_t out[LOTA_AC_GAME_HASH_SIZE])
{
	return lota_ac_compute_game_binding_hash(game_id, "/proc/self/exe",
						 out);
}

/*
 * Runtime measurement.
 *
 * Covers each object dl_iterate_phdr() lists, less the vDSO, matched by name.
 * Each object yields a digest over its executable PT_LOAD segments; the
 * combined digest folds those, keyed by file basename and sorted, so neither
 * load order nor directory matters. Computed from the live mapping (producer)
 * or from a set of ELF files (verifier). The two differ on an object with
 * DT_TEXTREL and on a program run through ld.so explicitly.
 *
 * See lota_anticheat.h for the canonical layout.
 */
#define LOTA_AC_RUNTIME_MEASURE_DOMAIN "lota-ac-runtime-measure:v1"
#define LOTA_AC_RUNTIME_OBJECT_DOMAIN "lota-ac-runtime-object:v1"
#define LOTA_AC_RUNTIME_MAX_SEGS 16
#define LOTA_AC_RUNTIME_MAX_OBJS 256
#define LOTA_AC_SONAME_MAX 256

/* @soname is the file's basename, not DT_SONAME. */
struct rt_object {
	char soname[LOTA_AC_SONAME_MAX];
	uint8_t digest[LOTA_AC_RUNTIME_MEASURE_SIZE];
};

static const char *rt_basename(const char *path)
{
	const char *slash = strrchr(path, '/');
	return slash ? slash + 1 : path;
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
 * An object with no executable PT_LOAD segment is valid and contributes
 * nothing (*has_exec = 0).
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
		return 0;

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

/* the digest breaks a tie between objects of one name */
static int rt_object_cmp(const void *a, const void *b)
{
	const struct rt_object *oa = a;
	const struct rt_object *ob = b;
	int c = strcmp(oa->soname, ob->soname);
	if (c != 0)
		return c;
	return memcmp(oa->digest, ob->digest, LOTA_AC_RUNTIME_MEASURE_SIZE);
}

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

/* the loader points the vDSO's program headers into the kernel's image */
static int rt_is_vdso(const struct dl_phdr_info *info)
{
	unsigned long ehdr = getauxval(AT_SYSINFO_EHDR);
	const ElfW(Ehdr) *eh = (const ElfW(Ehdr) *)ehdr;

	return eh && (const void *)info->dlpi_phdr ==
			     (const void *)(ehdr + eh->e_phoff);
}

/*
 * The kernel hands a dynamic executable its interpreter's base. Run as
 * "ld.so program", the kernel ran the loader and /proc/self/exe names it.
 */
static int rt_started_by_loader(const struct dl_phdr_info *info)
{
	for (ElfW(Half) i = 0; i < info->dlpi_phnum; i++) {
		if (info->dlpi_phdr[i].p_type == PT_INTERP)
			return getauxval(AT_BASE) == 0;
	}
	return 0;
}

/*
 * Index 0 is the main executable, which glibc lists unnamed.
 * Return: 1 to measure, 0 to skip, -ENOTSUP if its file is unknown.
 */
static int rt_object_identity(struct dl_phdr_info *info, unsigned index,
			      const char *self_exe, const char **path_out,
			      const char **soname_out)
{
	if (index == 0) {
		if (rt_started_by_loader(info))
			return -ENOTSUP;
		*path_out = self_exe;
		*soname_out = rt_basename(self_exe);
		return 1;
	}
	if (!info->dlpi_name || info->dlpi_name[0] == '\0' || rt_is_vdso(info))
		return 0;

	const char *base = rt_basename(info->dlpi_name);

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

	rc = rt_object_identity(info, index, ctx->self_exe, &path, &soname);
	if (rc < 0) {
		ctx->err = rc;
		return 1;
	}
	if (!rc)
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
		return ac_ret(-EINVAL);

	ret = rt_resolve_self_exe(self_exe, sizeof(self_exe));
	if (ret < 0)
		return ac_ret(ret);

	memset(&ctx, 0, sizeof(ctx));
	ctx.objs = calloc(LOTA_AC_RUNTIME_MAX_OBJS, sizeof(*ctx.objs));
	if (!ctx.objs)
		return ac_ret(-ENOMEM);
	ctx.self_exe = self_exe;

	dl_iterate_phdr(rt_collect_cb, &ctx);
	if (ctx.err) {
		ret = ctx.err;
		goto out;
	}

	ret = rt_finalize_combined(ctx.objs, ctx.count, out);
out:
	free(ctx.objs);
	return ac_ret(ret);
}

struct rt_list_ctx {
	lota_ac_runtime_object_fn fn;
	void *user;
	unsigned index;
	const char *self_exe;
	int stop;
	int err;
};

static int rt_list_cb(struct dl_phdr_info *info, size_t size, void *data)
{
	struct rt_list_ctx *ctx = data;
	const char *path = NULL;
	const char *soname = NULL;
	unsigned index = ctx->index++;
	int rc;

	(void)size;

	if (ctx->stop)
		return 1;
	rc = rt_object_identity(info, index, ctx->self_exe, &path, &soname);
	if (rc < 0) {
		ctx->err = rc;
		return 1;
	}
	if (!rc)
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
		return ac_ret(-EINVAL);

	ret = rt_resolve_self_exe(self_exe, sizeof(self_exe));
	if (ret < 0)
		return ac_ret(ret);

	memset(&ctx, 0, sizeof(ctx));
	ctx.fn = fn;
	ctx.user = user;
	ctx.self_exe = self_exe;

	dl_iterate_phdr(rt_list_cb, &ctx);
	return ac_ret(ctx.err);
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
 * rt_live_object_digest() from an ELF file on disk.
 * Return: 0 on success, negative errno for a malformed or unreadable file.
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
		ret = 0;
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
		return ac_ret(-EINVAL);

	objs = calloc(LOTA_AC_RUNTIME_MAX_OBJS, sizeof(*objs));
	if (!objs)
		return ac_ret(-ENOMEM);

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
	return ac_ret(ret);
}

int lota_ac_compute_expected_runtime_measure(
	const char *exe_path, uint8_t out[LOTA_AC_RUNTIME_MEASURE_SIZE])
{
	if (!exe_path || !out)
		return ac_ret(-EINVAL);
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

	if (!out_nonce || !session_id || !game_id_hash || !runtime_measure)
		return -EINVAL;

	dom = lota_ac_domain_lookup(domain_version);
	if (!dom)
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
	     EVP_DigestUpdate(ctx, ver_le, sizeof(ver_le)) &&
	     EVP_DigestUpdate(ctx, runtime_measure,
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
	int fd;
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
	close(fd);
	return ret;
}

/*
 * Priority: cfg->token_dir > $LOTA_HOOK_TOKEN_DIR >
 *           $XDG_RUNTIME_DIR/lota-hook > /tmp/lota-<uid>
 *
 * The producer's order (src/sdk/lota_wine_hook.c) below cfg->token_dir.
 * The producer skips an empty or unusable $LOTA_HOOK_TOKEN_DIR and sets it
 * to the directory it chose; here any non-empty value wins. An empty
 * cfg->token_dir skips $LOTA_HOOK_TOKEN_DIR too. The last two count only
 * if the directory exists.
 * $XDG_RUNTIME_DIR/lota is the agent's: it holds the container socket at
 * root:lota 0750.
 */
static int resolve_token_dir(const struct lota_ac_config *cfg, char *out,
			     size_t outlen)
{
	const char *dir = cfg->token_dir;
	const char *xdg;
	struct stat st;
	int ret;

	if (!dir)
		dir = getenv("LOTA_HOOK_TOKEN_DIR");

	if (dir && dir[0]) {
		if (strlen(dir) >= outlen)
			return -ENAMETOOLONG;
		strncpy(out, dir, outlen - 1);
		out[outlen - 1] = '\0';
		return 0;
	}

	xdg = getenv("XDG_RUNTIME_DIR");
	if (xdg && xdg[0]) {
		ret = snprintf(out, outlen, "%s/%s", xdg,
			       LOTA_HOOK_TOKEN_DIR_NAME);
		if (ret < 0 || (size_t)ret >= outlen)
			return -ENAMETOOLONG;
		if (stat(out, &st) == 0 && S_ISDIR(st.st_mode))
			return 0;
	}

	ret = snprintf(out, outlen, "/tmp/lota-%u", (unsigned)getuid());
	if (ret < 0 || (size_t)ret >= outlen)
		return -ENAMETOOLONG;
	if (stat(out, &st) == 0 && S_ISDIR(st.st_mode))
		return 0;

	/* neither exists: the snapshot error names the default */
	if (!xdg || !xdg[0])
		return -ENOENT;
	ret = snprintf(out, outlen, "%s/%s", xdg, LOTA_HOOK_TOKEN_DIR_NAME);
	if (ret < 0 || (size_t)ret >= outlen)
		return -ENAMETOOLONG;
	return 0;
}

/*
 * @required adds to LOTA_FLAG_ATTESTED. A non-zero word proves nothing:
 * the agent sets TPM_OK on opening the TPM.
 */
static int is_trusted(uint32_t flags, uint32_t required)
{
	uint32_t need = required | LOTA_FLAG_ATTESTED;

	return (flags & need) == need;
}

const char *lota_ac_strerror(int err)
{
	switch (err) {
	case LOTA_AC_ERR_OK:
		return "no error";
	case LOTA_AC_ERR_INVALID_ARG:
		return "invalid argument";
	case LOTA_AC_ERR_MALFORMED:
		return "malformed heartbeat";
	case LOTA_AC_ERR_VERSION:
		return "heartbeat version not supported";
	case LOTA_AC_ERR_SIG_FAIL:
		return "heartbeat signature verification failed";
	case LOTA_AC_ERR_NONCE_FAIL:
		return "heartbeat nonce does not match";
	case LOTA_AC_ERR_EXPIRED:
		return "heartbeat is outside its freshness window";
	case LOTA_AC_ERR_CRYPTO:
		return "cryptographic operation failed";
	case LOTA_AC_ERR_CONFIG_SIZE:
		return "config struct_size is unset or too small";
	case LOTA_AC_ERR_GAME_ID:
		return "game_id is missing, empty or too long";
	case LOTA_AC_ERR_PROVIDER:
		return "provider is neither EAC nor BattlEye";
	case LOTA_AC_ERR_NO_MEMORY:
		return "out of memory";
	case LOTA_AC_ERR_INTERNAL:
		return "internal error building the session";
	case LOTA_AC_ERR_NO_AGENT:
		return "no LOTA agent is answering on this machine";
	case LOTA_AC_ERR_CONSENT_REQUIRED:
		return "nobody at this machine has agreed to this publisher";
	case LOTA_AC_ERR_UNKNOWN_PROFILE:
		return "this machine is not enrolled with that publisher";
	case LOTA_AC_ERR_NO_KEY_SLOT:
		return "this machine has no attestation-key slot left for that publisher";
	case LOTA_AC_ERR_TPM_LOCKOUT:
		return "the TPM on this machine is locked out and signs nothing until it is cleared";
	case LOTA_AC_ERR_ACCESS_DENIED:
		return "the agent refused this caller";
	case LOTA_AC_ERR_TOKEN_DIR:
		return "no hook output directory for file mode";
	case LOTA_AC_ERR_NOT_ATTESTED:
		return "this machine holds no attestation verdict yet";
	case LOTA_AC_ERR_RATE_LIMITED:
		return "beating faster than the agent issues tokens";
	case LOTA_AC_ERR_STATUS:
		return "the agent would not report its state";
	case LOTA_AC_ERR_TOKEN:
		return "the agent would not issue a token";
	case LOTA_AC_ERR_MEASURE:
		return "this process could not be measured";
	case LOTA_AC_ERR_SERIALIZE:
		return "the token could not be serialised";
	case LOTA_AC_ERR_RUNTIME_IMAGE:
		return "the runtime measurement is not the expected one";
	case LOTA_AC_ERR_NO_EVIDENCE:
		return "the agent would not hand over boot evidence";
	case LOTA_AC_ERR_BAD_EVIDENCE:
		return "the boot evidence is not the boot the heartbeat quotes";
	}

	/* not one of ours: the measure helpers return negative errno */
	if (err < 0 && err > LOTA_AC_ERR_BASE) {
		const char *desc = strerrordesc_np(-err);

		if (desc)
			return desc;
	}

	return "unknown error";
}

/* A refusal without a code of its own here reads as no agent. */
static int ac_error_from_connect(int connect_err)
{
	switch (connect_err) {
	case LOTA_ERR_CONSENT_REQUIRED:
		return LOTA_AC_ERR_CONSENT_REQUIRED;
	case LOTA_ERR_UNKNOWN_PROFILE:
		return LOTA_AC_ERR_UNKNOWN_PROFILE;
	case LOTA_ERR_NO_KEY_SLOT:
		return LOTA_AC_ERR_NO_KEY_SLOT;
	case LOTA_ERR_ACCESS_DENIED:
		return LOTA_AC_ERR_ACCESS_DENIED;
	case LOTA_ERR_RATE_LIMITED:
		return LOTA_AC_ERR_RATE_LIMITED;
	case LOTA_ERR_INVALID_ARG:
		return LOTA_AC_ERR_INVALID_ARG;
	default:
		return LOTA_AC_ERR_NO_AGENT;
	}
}

struct lota_ac_session *lota_ac_init(const struct lota_ac_config *cfg)
{
	g_ac_error = LOTA_AC_ERR_OK;

	if (!cfg) {
		ac_fail(LOTA_AC_ERR_INVALID_ARG);
		return NULL;
	}
	/* the caller says how big its configuration is; see the header */
	if (cfg->struct_size < LOTA_AC_CONFIG_SIZE_MIN) {
		ac_fail(LOTA_AC_ERR_CONFIG_SIZE);
		return NULL;
	}
	if (!cfg->game_id || cfg->game_id[0] == '\0' ||
	    strlen(cfg->game_id) >= LOTA_AC_MAX_GAME_ID) {
		ac_fail(LOTA_AC_ERR_GAME_ID);
		return NULL;
	}
	if (cfg->provider != LOTA_AC_PROVIDER_EAC &&
	    cfg->provider != LOTA_AC_PROVIDER_BATTLEYE) {
		ac_fail(LOTA_AC_ERR_PROVIDER);
		return NULL;
	}

	struct lota_ac_session *s = calloc(1, sizeof(*s));
	if (!s) {
		ac_fail(LOTA_AC_ERR_NO_MEMORY);
		return NULL;
	}

	s->provider = cfg->provider;
	s->state = LOTA_AC_STATE_IDLE;
	strncpy(s->game_id, cfg->game_id, LOTA_AC_MAX_GAME_ID - 1);
	s->required_flags = cfg->required_flags;
	s->direct = cfg->direct;

	if (generate_session_id(s->session_id) < 0) {
		free(s);
		ac_fail(LOTA_AC_ERR_INTERNAL);
		return NULL;
	}
	if (compute_game_id_hash(s->game_id, s->game_id_hash) < 0) {
		free(s);
		ac_fail(LOTA_AC_ERR_INTERNAL);
		return NULL;
	}

	s->session_start = (uint64_t)time(NULL);

	if (cfg->direct) {
		if (cfg->socket_path || cfg->publisher_profile) {
			struct lota_connect_opts opts = { 0 };

			opts.struct_size = sizeof(opts);
			opts.socket_path = cfg->socket_path;
			opts.timeout_ms = 5000;
			opts.publisher_profile = cfg->publisher_profile;
			s->client = lota_connect_opts(&opts);
		} else {
			s->client = lota_connect();
		}

		/*
		 * A session whose agent is not there is handed back, so the
		 * title has something to show the player. It never connects
		 * later: a host that gets ready takes a new session.
		 */
		if (!s->client) {
			s->state = LOTA_AC_STATE_ERROR;
			s->connect_error = ac_error_from_connect(
				lota_connect_last_error());
			ac_fail(s->connect_error);
		} else {
			s->state = LOTA_AC_STATE_RUNNING;
		}
	} else {
		if (resolve_token_dir(cfg, s->token_dir, sizeof(s->token_dir)) <
		    0) {
			s->state = LOTA_AC_STATE_ERROR;
			ac_fail(LOTA_AC_ERR_TOKEN_DIR);
		} else {
			snprintf(s->status_path, sizeof(s->status_path),
				 "%s/lota-status", s->token_dir);
			snprintf(s->token_path, sizeof(s->token_path),
				 "%s/lota-token.bin", s->token_dir);
			snprintf(s->snapshot_path, sizeof(s->snapshot_path),
				 "%s/%s", s->token_dir,
				 LOTA_SNAPSHOT_FILE_NAME);
			snprintf(s->evidence_path, sizeof(s->evidence_path),
				 "%s/%s", s->token_dir,
				 LOTA_HOOK_BOOT_EVIDENCE_FILE);
			s->state = LOTA_AC_STATE_RUNNING;
		}
	}

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
		return ac_ret(-EINVAL);

	info->provider = session->provider;
	info->state = session->state;
	memcpy(info->session_id, session->session_id, LOTA_AC_SESSION_ID_SIZE);
	info->session_start = session->session_start;
	info->last_heartbeat = session->last_heartbeat;
	info->heartbeat_seq = session->heartbeat_seq;
	info->lota_flags = session->lota_flags;
	info->trusted = session->state == LOTA_AC_STATE_TRUSTED;
	/* only a verified heartbeat says which boot it quotes */
	info->pcr_mask = 0;
	memset(info->pcr_digest, 0, sizeof(info->pcr_digest));

	return ac_ret(0);
}

int lota_ac_tick(struct lota_ac_session *session)
{
	if (!session)
		return ac_ret(-EINVAL);
	if (session->state == LOTA_AC_STATE_IDLE)
		return ac_ret(-EINVAL);

	if (session->direct) {
		if (!session->client) {
			session->state = LOTA_AC_STATE_ERROR;
			ac_fail(session->connect_error ?
					session->connect_error :
					LOTA_AC_ERR_NO_AGENT);
			return -ENOTCONN;
		}

		struct lota_status status;
		int ret = lota_get_status(session->client, &status);
		if (ret != LOTA_OK) {
			session->state = LOTA_AC_STATE_ERROR;
			ac_fail(ret == LOTA_ERR_CONNECTION_FAILED ?
					LOTA_AC_ERR_NO_AGENT :
					LOTA_AC_ERR_STATUS);
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
			session->state = LOTA_AC_STATE_ERROR;
			ac_fail(sret == -ENOENT ? LOTA_AC_ERR_NO_AGENT :
						  LOTA_AC_ERR_MALFORMED);
			return sret;
		}
	}

	if (session->token_len > 0 || session->lota_flags != 0)
		session->state = is_trusted(session->lota_flags,
					    session->required_flags) ?
					 LOTA_AC_STATE_TRUSTED :
					 LOTA_AC_STATE_UNTRUSTED;
	else
		session->state = LOTA_AC_STATE_ERROR;

	return ac_ret(0);
}

int lota_ac_heartbeat(struct lota_ac_session *session, uint8_t *buf,
		      size_t buflen, size_t *written)
{
	uint64_t timestamp;
	uint32_t sequence;
	uint8_t heartbeat_nonce[LOTA_NONCE_SIZE];
	uint8_t runtime_measure[LOTA_AC_RUNTIME_MEASURE_SIZE];

	g_ac_error = LOTA_AC_ERR_OK;

	if (!session || !buf || !written) {
		ac_fail(LOTA_AC_ERR_INVALID_ARG);
		return -EINVAL;
	}

	/*
	 * A heartbeat binds its sequence and timestamp into the token's nonce.
	 * File mode holds the hook's token, requested with no nonce.
	 */
	if (!session->direct) {
		ac_fail(LOTA_AC_ERR_INVALID_ARG);
		return -EOPNOTSUPP;
	}

	/*
	 * GET_STATUS only: lota_ac_tick() also fetches a token, which takes a
	 * second slot of the agent's GET_TOKEN rate limit (ipc.c) on every beat.
	 */
	if (!session->client) {
		ac_fail(session->connect_error ? session->connect_error :
						 LOTA_AC_ERR_NO_AGENT);
		return -ENOTCONN;
	}

	struct lota_status status;
	int ret = lota_get_status(session->client, &status);
	if (ret != LOTA_OK) {
		session->state = LOTA_AC_STATE_ERROR;
		ac_fail(ret == LOTA_ERR_CONNECTION_FAILED ?
				LOTA_AC_ERR_NO_AGENT :
				LOTA_AC_ERR_STATUS);
		return -EIO;
	}
	session->lota_flags = status.flags;

	timestamp = (uint64_t)time(NULL);
	sequence = session->heartbeat_seq;

	/*
	 * Measured at each beat. The nonce binds the value into the signed
	 * token, so it cannot change on the way to a server.
	 */
	ret = lota_ac_compute_runtime_measure(runtime_measure);
	if (ret < 0) {
		ac_fail(LOTA_AC_ERR_MEASURE);
		return ret;
	}

	ret = compute_heartbeat_nonce(heartbeat_nonce, session->session_id,
				      (uint8_t)session->provider, sequence,
				      session->lota_flags, timestamp,
				      session->game_id_hash, runtime_measure,
				      LOTA_AC_DOMAIN_VERSION_CURRENT);
	if (ret < 0) {
		ac_fail(LOTA_AC_ERR_INTERNAL);
		return ret;
	}

	{
		struct lota_token token;
		size_t tok_written = 0;

		memset(&token, 0, sizeof(token));
		ret = lota_get_token(session->client, heartbeat_nonce, &token);
		if (ret != LOTA_OK) {
			if (ret == LOTA_ERR_NOT_ATTESTED) {
				ac_fail(LOTA_AC_ERR_NOT_ATTESTED);
				return -ENODATA;
			}

			if (ret == LOTA_ERR_TPM_LOCKED) {
				ac_fail(LOTA_AC_ERR_TPM_LOCKOUT);
				return -EIO;
			}

			/* an integrator fixes this one by beating slower */
			ac_fail(ret == LOTA_ERR_RATE_LIMITED ?
					LOTA_AC_ERR_RATE_LIMITED :
				ret == LOTA_ERR_CONNECTION_FAILED ?
					LOTA_AC_ERR_NO_AGENT :
					LOTA_AC_ERR_TOKEN);
			return -EIO;
		}

		if (CRYPTO_memcmp(token.nonce, heartbeat_nonce,
				  LOTA_NONCE_SIZE) != 0) {
			lota_token_free(&token);
			ac_fail(LOTA_AC_ERR_NONCE_FAIL);
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
		if (ret != LOTA_OK) {
			ac_fail(LOTA_AC_ERR_SERIALIZE);
			return -EIO;
		}

		session->token_len = tok_written;
	}

	if (session->token_len == 0) {
		ac_fail(LOTA_AC_ERR_NOT_ATTESTED);
		return -ENODATA;
	}

	size_t total = LOTA_AC_HEADER_SIZE + session->token_len;
	if (buflen < total) {
		ac_fail(LOTA_AC_ERR_INVALID_ARG);
		return -ENOSPC;
	}

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

static int boot_evidence_from_agent(struct lota_ac_session *session,
				    uint8_t *buf, size_t buflen,
				    size_t *written)
{
	int ret;

	if (!session->client) {
		ac_fail(session->connect_error ? session->connect_error :
						 LOTA_AC_ERR_NO_AGENT);
		return -ENOTCONN;
	}

	ret = lota_get_boot_evidence(session->client, buf, buflen, written);
	switch (ret) {
	case LOTA_OK:
		return 0;
	case LOTA_ERR_BUFFER_TOO_SMALL:
		ac_fail(LOTA_AC_ERR_INVALID_ARG);
		return -ENOSPC;
	case LOTA_ERR_NO_TPM:
		ac_fail(LOTA_AC_ERR_NO_EVIDENCE);
		return -ENODATA;
	case LOTA_ERR_RATE_LIMITED:
		ac_fail(LOTA_AC_ERR_RATE_LIMITED);
		return -EIO;
	case LOTA_ERR_CONNECTION_FAILED:
		ac_fail(LOTA_AC_ERR_NO_AGENT);
		return -EIO;
	default:
		ac_fail(LOTA_AC_ERR_NO_EVIDENCE);
		return -EIO;
	}
}

/* the hook writes it only when the agent gave it */
static int boot_evidence_from_file(struct lota_ac_session *session,
				   uint8_t *buf, size_t buflen, size_t *written)
{
	uint8_t file[LOTA_BOOT_EVIDENCE_MAX_SIZE + 1];
	ssize_t n = read_file_buf(session->evidence_path, file, sizeof(file));

	if (n == -ENOENT || n == 0) {
		ac_fail(LOTA_AC_ERR_NO_EVIDENCE);
		return -ENODATA;
	}
	if (n < 0 || (size_t)n > LOTA_BOOT_EVIDENCE_MAX_SIZE) {
		ac_fail(LOTA_AC_ERR_NO_EVIDENCE);
		return n < 0 ? (int)n : -EIO;
	}
	if ((size_t)n > buflen) {
		ac_fail(LOTA_AC_ERR_INVALID_ARG);
		return -ENOSPC;
	}

	memcpy(buf, file, (size_t)n);
	*written = (size_t)n;
	return 0;
}

int lota_ac_boot_evidence(struct lota_ac_session *session, uint8_t *buf,
			  size_t buflen, size_t *written)
{
	g_ac_error = LOTA_AC_ERR_OK;

	if (!session || !buf || !written) {
		ac_fail(LOTA_AC_ERR_INVALID_ARG);
		return -EINVAL;
	}

	if (session->direct)
		return boot_evidence_from_agent(session, buf, buflen, written);
	return boot_evidence_from_file(session, buf, buflen, written);
}

/*
 * The verifiers here return only LOTA_AC_ERR_*.
 * Anything without its own code is MALFORMED.
 */
static int ac_error_from_server(int server_err)
{
	switch (server_err) {
	case LOTA_SERVER_OK:
		return LOTA_AC_ERR_OK;
	case LOTA_SERVER_ERR_INVALID_ARG:
		return LOTA_AC_ERR_INVALID_ARG;
	case LOTA_SERVER_ERR_BAD_VERSION:
		return LOTA_AC_ERR_VERSION;
	case LOTA_SERVER_ERR_SIG_FAIL:
		return LOTA_AC_ERR_SIG_FAIL;
	case LOTA_SERVER_ERR_NONCE_FAIL:
		return LOTA_AC_ERR_NONCE_FAIL;
	case LOTA_SERVER_ERR_EXPIRED:
	case LOTA_SERVER_ERR_FUTURE:
		return LOTA_AC_ERR_EXPIRED;
	case LOTA_SERVER_ERR_CRYPTO:
		return LOTA_AC_ERR_CRYPTO;
	case LOTA_SERVER_ERR_RUNTIME_IMAGE:
		return LOTA_AC_ERR_RUNTIME_IMAGE;
	case LOTA_SERVER_ERR_BAD_EVIDENCE:
		return LOTA_AC_ERR_BAD_EVIDENCE;
	case LOTA_SERVER_ERR_BAD_TOKEN:
	case LOTA_SERVER_ERR_ATTEST_PARSE:
	case LOTA_SERVER_ERR_BUFFER:
	default:
		return LOTA_AC_ERR_MALFORMED;
	}
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
		return ac_ret(LOTA_AC_ERR_INVALID_ARG);

	if (len < LOTA_AC_HEADER_SIZE)
		return ac_ret(LOTA_AC_ERR_MALFORMED);

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
		return ac_ret(LOTA_AC_ERR_MALFORMED);
	if (version != LOTA_AC_VERSION)
		return ac_ret(LOTA_AC_ERR_VERSION);
	if ((size_t)total_size > len)
		return ac_ret(LOTA_AC_ERR_MALFORMED);
	if ((size_t)total_size != LOTA_AC_HEADER_SIZE + (size_t)token_size)
		return ac_ret(LOTA_AC_ERR_MALFORMED);
	if (token_size == 0 || token_size > LOTA_AC_MAX_TOKEN)
		return ac_ret(LOTA_AC_ERR_MALFORMED);
	if (provider != LOTA_AC_PROVIDER_EAC &&
	    provider != LOTA_AC_PROVIDER_BATTLEYE)
		return ac_ret(LOTA_AC_ERR_MALFORMED);

	if (!lota_ac_domain_lookup(domain_version))
		return ac_ret(LOTA_AC_ERR_VERSION);

	if (CRYPTO_memcmp(data + 40, expected_game_id_hash,
			  LOTA_AC_GAME_HASH_SIZE) != 0)
		return ac_ret(LOTA_AC_ERR_MALFORMED);

	/*
	 * Rejected before signature work. The expected nonce binds the same
	 * bytes, so a signed token cannot carry a different measurement.
	 */
	if (CRYPTO_memcmp(data + 78, expected_runtime_measure,
			  LOTA_AC_RUNTIME_MEASURE_SIZE) != 0)
		return ac_ret(LOTA_AC_ERR_RUNTIME_IMAGE);

	if (timestamp > now + LOTA_AC_MAX_HEARTBEAT_AGE_SEC)
		return ac_ret(LOTA_AC_ERR_MALFORMED);
	if (timestamp + LOTA_AC_MAX_HEARTBEAT_AGE_SEC < now)
		return ac_ret(LOTA_AC_ERR_MALFORMED);

	ret = compute_heartbeat_nonce(expected_nonce, data + 8, provider,
				      sequence, heartbeat_lota_flags, timestamp,
				      data + 40, data + 78, domain_version);
	if (ret < 0)
		return ac_ret(LOTA_AC_ERR_CRYPTO);

	const uint8_t *token = data + LOTA_AC_HEADER_SIZE;

	struct lota_server_claims claims;

	if (!aik_pub_der || aik_pub_len == 0)
		return ac_ret(LOTA_AC_ERR_INVALID_ARG);

	ret = lota_server_verify_token(token, token_size, aik_pub_der,
				       aik_pub_len, expected_nonce, &claims);

	if (ret != LOTA_SERVER_OK)
		return ac_ret(ac_error_from_server(ret));

	if (CRYPTO_memcmp(claims.nonce, expected_nonce, LOTA_NONCE_SIZE) != 0)
		return ac_ret(LOTA_AC_ERR_NONCE_FAIL);

	/* the nonce covers the header's flags: they must equal the token's */
	if (heartbeat_lota_flags != claims.flags)
		return ac_ret(LOTA_AC_ERR_MALFORMED);

	info->provider = (enum lota_ac_provider)provider;
	memcpy(info->session_id, data + 8, LOTA_AC_SESSION_ID_SIZE);
	info->session_start = 0; /* not available from a single heartbeat */
	info->last_heartbeat = timestamp;
	info->heartbeat_seq = sequence;
	info->lota_flags = claims.flags;
	memcpy(info->game_id_hash, data + 40, LOTA_AC_GAME_HASH_SIZE);
	info->trusted = is_trusted(claims.flags, 0);
	info->state = info->trusted ? LOTA_AC_STATE_TRUSTED :
				      LOTA_AC_STATE_UNTRUSTED;
	info->pcr_mask = claims.pcr_mask;
	memset(info->pcr_digest, 0, sizeof(info->pcr_digest));
	if (claims.pcr_digest_len == sizeof(info->pcr_digest))
		memcpy(info->pcr_digest, claims.pcr_digest,
		       sizeof(info->pcr_digest));

	return ac_ret(0);
}

int lota_ac_verify_boot_evidence(const struct lota_ac_info *info,
				 const uint8_t *evidence, size_t len,
				 int *secure_boot)
{
	struct lota_server_claims claims;

	if (!info || !evidence || !secure_boot)
		return ac_ret(LOTA_AC_ERR_INVALID_ARG);

	memset(&claims, 0, sizeof(claims));
	claims.pcr_mask = info->pcr_mask;
	memcpy(claims.pcr_digest, info->pcr_digest, sizeof(info->pcr_digest));
	claims.pcr_digest_len = sizeof(info->pcr_digest);

	return ac_ret(ac_error_from_server(lota_server_verify_boot_evidence(
		&claims, evidence, len, secure_boot)));
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
