/* SPDX-License-Identifier: MIT */
/*
 * LOTA Anti-Cheat Compatibility Layer — Unit Tests
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <link.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/types.h>
#include <stdint.h>
#include <sys/types.h>

#include "test.h"
#include "lota_anticheat.h"
#include "lota_gaming.h"
#include "lota_ipc.h"
#include "lota_snapshot.h"
#include "lota_server.h"
#include "lota_token.h"
#include "lota_wine_hook.h"
#include "token_forge.h"

#ifndef LOTA_SDK_LIB_PATH
#define LOTA_SDK_LIB_PATH "build/liblotagaming.so"
#endif

static char test_dir[256];

static void setup_test_dir(void)
{
	snprintf(test_dir, sizeof(test_dir), "/tmp/lota_test_ac_XXXXXX");
	if (!mkdtemp(test_dir)) {
		perror("mkdtemp");
		exit(1);
	}
}

static void cleanup_test_dir(void)
{
	char cmd[512];
	snprintf(cmd, sizeof(cmd), "rm -rf %s", test_dir);
	int rc = system(cmd);
	(void)rc; /* best effort cleanup */
}

static void write_test_file(const char *dir, const char *name, const void *data,
			    size_t len)
{
	char path[512];
	snprintf(path, sizeof(path), "%s/%s", dir, name);

	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
	if (fd < 0) {
		perror("write_test_file open");
		return;
	}
	if (write(fd, data, len) != (ssize_t)len)
		perror("write_test_file write");
	close(fd);
}

static size_t build_mock_token(uint8_t *buf, size_t buflen, uint32_t flags,
			       const uint8_t nonce[32]);

static void write_le16(uint8_t *p, uint16_t v)
{
	p[0] = (uint8_t)(v & 0xFF);
	p[1] = (uint8_t)((v >> 8) & 0xFF);
}

static void write_le32(uint8_t *p, uint32_t v)
{
	p[0] = (uint8_t)(v & 0xFF);
	p[1] = (uint8_t)((v >> 8) & 0xFF);
	p[2] = (uint8_t)((v >> 16) & 0xFF);
	p[3] = (uint8_t)((v >> 24) & 0xFF);
}

static void write_mock_snapshot(const char *dir, uint32_t flags)
{
	uint8_t tok[2048];
	size_t tok_len = build_mock_token(tok, sizeof(tok), flags, NULL);
	if (tok_len == 0)
		return;

	uint8_t buf[16 + 2048];
	write_le32(buf + 0, LOTA_SNAPSHOT_MAGIC);
	write_le16(buf + 4, (uint16_t)LOTA_SNAPSHOT_VERSION);
	write_le16(buf + 6, 0);
	write_le32(buf + 8, flags);
	write_le32(buf + 12, (uint32_t)tok_len);
	memcpy(buf + 16, tok, tok_len);

	write_test_file(dir, LOTA_SNAPSHOT_FILE_NAME, buf, 16 + tok_len);
}

/*
 * minimal valid LOTA token wire blob using the gaming SDK
 * attest/sig data is fabricated (not cryptographically valid),
 * but the header satisfies lota_server_parse_token()
 */
static size_t build_mock_token(uint8_t *buf, size_t buflen, uint32_t flags,
			       const uint8_t nonce[32])
{
	struct lota_token tok = { 0 };
	tok.valid_until = (uint64_t)time(NULL) + 3600;
	tok.flags = flags;
	if (nonce)
		memcpy(tok.nonce, nonce, 32);
	tok.sig_alg = 0x0014;
	tok.hash_alg = 0x000B;
	tok.pcr_mask = 0x4001;
	tok.runtime_protect_version = LOTA_RUNTIME_PROTECT_V1;

	uint8_t attest[16] = { 0xAA };
	uint8_t sig[8] = { 0xCC };
	tok.attest_data = attest;
	tok.attest_size = sizeof(attest);
	tok.signature = sig;
	tok.signature_len = sizeof(sig);

	size_t written = 0;
	if (lota_token_serialize(&tok, buf, buflen, &written) != LOTA_OK)
		return 0;
	return written;
}

static int compute_game_id_hash_test(const char *game_id, uint8_t out[32])
{
	return lota_ac_compute_game_binding_hash(game_id, "/proc/self/exe",
						 out);
}

static int compute_hb_nonce_test(uint8_t out[32], const uint8_t session_id[16],
				 uint8_t provider, uint32_t sequence,
				 uint64_t timestamp,
				 const uint8_t game_hash[32],
				 const uint8_t runtime_measure[32],
				 uint32_t domain_version)
{
	static const char domain[] = "lota-ac-heartbeat:v1";
	uint8_t seq_le[4], ts_le[8], ver_le[4];
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	unsigned int out_len = 32;
	int ok;

	if (!ctx)
		return -ENOMEM;

	write_le32(seq_le, sequence);
	write_le32(ver_le, domain_version);
	for (int i = 0; i < 8; i++)
		ts_le[i] = (uint8_t)((timestamp >> (8 * i)) & 0xFF);

	ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) &&
	     EVP_DigestUpdate(ctx, domain, sizeof(domain)) &&
	     EVP_DigestUpdate(ctx, session_id, 16) &&
	     EVP_DigestUpdate(ctx, &provider, 1) &&
	     EVP_DigestUpdate(ctx, seq_le, sizeof(seq_le)) &&
	     EVP_DigestUpdate(ctx, ts_le, sizeof(ts_le)) &&
	     EVP_DigestUpdate(ctx, game_hash, 32) &&
	     EVP_DigestUpdate(ctx, ver_le, sizeof(ver_le)) &&
	     EVP_DigestUpdate(ctx, runtime_measure, 32) &&
	     EVP_DigestFinal_ex(ctx, out, &out_len);

	EVP_MD_CTX_free(ctx);
	return ok ? 0 : -EIO;
}

/*
 * Runtime measurement the test producer image must report.
 * Producer measures every loaded object, so the expected value is the set
 * measure over the objects the runtime enumerator reports, exactly as a
 * verifier reproduces it from the trusted runtime manifest.
 */
#define EXPECTED_RT_MAX_OBJS 128
struct rt_path_collect {
	char (*paths)[LOTA_AC_RUNTIME_PATH_MAX];
	size_t max;
	size_t count;
	int overflow;
};

static int rt_path_collect_cb(const char *path, void *user)
{
	struct rt_path_collect *c = user;
	if (c->count >= c->max) {
		c->overflow = 1;
		return 1;
	}
	strncpy(c->paths[c->count], path, LOTA_AC_RUNTIME_PATH_MAX - 1);
	c->paths[c->count][LOTA_AC_RUNTIME_PATH_MAX - 1] = '\0';
	c->count++;
	return 0;
}

static int expected_runtime_measure_test(uint8_t out[32])
{
	struct rt_path_collect c = {};
	const char **vec;
	int ret;

	c.paths = calloc(EXPECTED_RT_MAX_OBJS, LOTA_AC_RUNTIME_PATH_MAX);
	if (!c.paths)
		return -ENOMEM;
	c.max = EXPECTED_RT_MAX_OBJS;

	if (lota_ac_list_runtime_objects(rt_path_collect_cb, &c) != 0 ||
	    c.overflow || c.count == 0) {
		free(c.paths);
		return -EIO;
	}

	vec = calloc(c.count, sizeof(*vec));
	if (!vec) {
		free(c.paths);
		return -ENOMEM;
	}
	for (size_t i = 0; i < c.count; i++)
		vec[i] = c.paths[i];

	ret = lota_ac_compute_expected_runtime_measure_set(vec, c.count, out);
	free(vec);
	free(c.paths);
	return ret;
}

/* an object is the vDSO by its address, not by a name a file can carry */
static void test_runtime_measure_counts_a_vdso_named_object(void)
{
	char path[512];
	char cmd[1024];
	uint8_t before[LOTA_AC_RUNTIME_MEASURE_SIZE];
	uint8_t after[LOTA_AC_RUNTIME_MEASURE_SIZE];
	struct rt_path_collect c = {};
	int listed = 0, vdso = 0;
	void *h;

	TEST("runtime measure: an object named linux-vdso* is measured");

	snprintf(path, sizeof(path), "%s/linux-vdso-test.so", test_dir);
	snprintf(cmd, sizeof(cmd), "cp %s %s", LOTA_SDK_LIB_PATH, path);
	if (system(cmd) != 0 || lota_ac_compute_runtime_measure(before) != 0) {
		FAIL("setup");
		return;
	}
	h = dlopen(path, RTLD_NOW | RTLD_LOCAL);
	if (!h) {
		FAIL(dlerror());
		return;
	}

	c.paths = calloc(EXPECTED_RT_MAX_OBJS, LOTA_AC_RUNTIME_PATH_MAX);
	c.max = EXPECTED_RT_MAX_OBJS;
	if (c.paths &&
	    lota_ac_list_runtime_objects(rt_path_collect_cb, &c) == 0)
		for (size_t i = 0; i < c.count; i++) {
			listed |= strcmp(c.paths[i], path) == 0;
			vdso |= strcmp(c.paths[i], "linux-vdso.so.1") == 0;
		}
	free(c.paths);

	if (lota_ac_compute_runtime_measure(after) != 0) {
		FAIL("measure failed");
	} else if (!listed) {
		FAIL("the object is not listed");
	} else if (vdso) {
		FAIL("the vDSO is listed");
	} else if (memcmp(before, after, sizeof(before)) == 0) {
		FAIL("the object left the measure unchanged");
	} else {
		PASS();
	}
	dlclose(h);
}

#define LOADER_CHILD_ENV "LOTA_TEST_LOADER_CHILD"

/* the child: 0 if both refuse with -ENOTSUP, 10 if both measure */
__attribute__((constructor)) static void loader_child(void)
{
	uint8_t m[LOTA_AC_RUNTIME_MEASURE_SIZE];
	struct rt_path_collect c = { .max = EXPECTED_RT_MAX_OBJS };
	int mret, lret;

	if (!getenv(LOADER_CHILD_ENV))
		return;
	c.paths = calloc(EXPECTED_RT_MAX_OBJS, LOTA_AC_RUNTIME_PATH_MAX);
	if (!c.paths)
		_exit(1);
	mret = lota_ac_compute_runtime_measure(m);
	lret = lota_ac_list_runtime_objects(rt_path_collect_cb, &c);
	if (mret == -ENOTSUP && lret == -ENOTSUP && c.count == 0)
		_exit(0);
	_exit(mret == 0 && lret == 0 && c.count > 0 ? 10 : 1);
}

static int interp_cb(struct dl_phdr_info *info, size_t size, void *data)
{
	(void)size;
	for (ElfW(Half) i = 0; i < info->dlpi_phnum; i++) {
		if (info->dlpi_phdr[i].p_type == PT_INTERP) {
			*(const char **)data =
				(const char *)(info->dlpi_addr +
					       info->dlpi_phdr[i].p_vaddr);
			break;
		}
	}
	return 1;
}

static int run_loader_child(const char *loader, const char *self)
{
	int status;
	pid_t pid = fork();

	if (pid < 0)
		return -1;
	if (pid == 0) {
		setenv(LOADER_CHILD_ENV, "1", 1);
		if (loader)
			execl(loader, loader, self, (char *)NULL);
		else
			execl(self, self, (char *)NULL);
		_exit(127);
	}
	if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status))
		return -1;
	return WEXITSTATUS(status);
}

/* run as "ld.so program", /proc/self/exe names the loader, not the title */
static void test_runtime_measure_refuses_a_loader_start(void)
{
	const char *loader = NULL;
	char self[LOTA_AC_RUNTIME_PATH_MAX];
	ssize_t n;
	int direct, through;

	TEST("runtime measure: a start through ld.so is refused");

	dl_iterate_phdr(interp_cb, &loader);
	n = readlink("/proc/self/exe", self, sizeof(self) - 1);
	if (!loader || n < 0) {
		FAIL("setup");
		return;
	}
	self[n] = '\0';

	direct = run_loader_child(NULL, self);
	through = run_loader_child(loader, self);
	if (direct != 10)
		FAIL("a direct start was not measured");
	else if (through != 0)
		FAIL("a start through ld.so was not refused");
	else
		PASS();
}

static int build_bound_heartbeat_packet(uint8_t *out, size_t out_cap,
					size_t *out_len, uint8_t provider,
					const char *game_id, uint32_t flags,
					uint32_t sequence)
{
	uint8_t session_id[LOTA_AC_SESSION_ID_SIZE];
	uint8_t game_hash[LOTA_AC_GAME_HASH_SIZE];
	uint8_t runtime_measure[LOTA_AC_RUNTIME_MEASURE_SIZE];
	uint8_t nonce[32];
	uint8_t token[2048];
	uint64_t timestamp = (uint64_t)time(NULL);
	size_t token_len;
	size_t total;

	for (int i = 0; i < (int)sizeof(session_id); i++)
		session_id[i] = (uint8_t)(0xA0 + i);

	if (compute_game_id_hash_test(game_id, game_hash) != 0)
		return -EIO;
	/*
	 * Measure the live image, exactly as the SDK producer does.
	 *
	 * It must equal the file-derived value the verifier precomputes.
	 */
	if (lota_ac_compute_runtime_measure(runtime_measure) != 0)
		return -EIO;
	if (compute_hb_nonce_test(nonce, session_id, provider, sequence,
				  timestamp, game_hash, runtime_measure,
				  LOTA_AC_DOMAIN_VERSION_CURRENT) != 0)
		return -EIO;

	token_len = build_mock_token(token, sizeof(token), flags, nonce);
	if (token_len == 0)
		return -EIO;

	total = LOTA_AC_HEADER_SIZE + token_len;
	if (total > out_cap)
		return -ENOSPC;

	write_le32(out + 0, LOTA_AC_MAGIC);
	out[4] = LOTA_AC_VERSION;
	out[5] = provider;
	write_le16(out + 6, (uint16_t)total);
	memcpy(out + 8, session_id, sizeof(session_id));
	write_le32(out + 24, sequence);
	write_le32(out + 28, flags);
	for (int i = 0; i < 8; i++)
		out[32 + i] = (uint8_t)((timestamp >> (8 * i)) & 0xFF);
	memcpy(out + 40, game_hash, sizeof(game_hash));
	write_le16(out + 72, (uint16_t)token_len);
	write_le32(out + 74, LOTA_AC_DOMAIN_VERSION_CURRENT);
	memcpy(out + 78, runtime_measure, sizeof(runtime_measure));
	memcpy(out + LOTA_AC_HEADER_SIZE, token, token_len);

	*out_len = total;
	return 0;
}

static void test_init_null_config(void)
{
	TEST("init(NULL) -> NULL");
	struct lota_ac_session *s = lota_ac_init(NULL);
	if (s) {
		FAIL("returned non-NULL");
		lota_ac_shutdown(s);
	} else {
		PASS();
	}
}

/*
 * struct_size is what lets this structure grow without second entry point,
 * so caller that does not set it has to be refused: reading members it never
 * wrote is exactly what the field exists to prevent.
 */
static void test_init_struct_size(void)
{
	TEST("init: unset struct_size -> NULL");
	struct lota_ac_config zero = {
		.provider = LOTA_AC_PROVIDER_EAC,
		.game_id = "test-game",
	};
	struct lota_ac_session *s = lota_ac_init(&zero);
	if (s) {
		FAIL("a config that never set struct_size was accepted");
		lota_ac_shutdown(s);
	} else {
		PASS();
	}

	TEST("init: undersized struct_size -> NULL");
	struct lota_ac_config small = {
		.struct_size = LOTA_AC_CONFIG_SIZE_MIN - 1,
		.provider = LOTA_AC_PROVIDER_EAC,
		.game_id = "test-game",
	};
	s = lota_ac_init(&small);
	if (s) {
		FAIL("a config smaller than the 1.0 surface was accepted");
		lota_ac_shutdown(s);
	} else {
		PASS();
	}

	TEST("init: struct_size from a newer caller is accepted");
	struct lota_ac_config bigger = {
		.struct_size = sizeof(bigger) + 64,
		.provider = LOTA_AC_PROVIDER_EAC,
		.game_id = "test-game",
	};
	s = lota_ac_init(&bigger);
	if (!s) {
		FAIL("a caller built against a newer header was refused");
	} else {
		PASS();
		lota_ac_shutdown(s);
	}
}

static void test_init_empty_game_id(void)
{
	TEST("init: empty game_id -> NULL");
	struct lota_ac_config cfg = {
		.struct_size = sizeof(cfg),
		.provider = LOTA_AC_PROVIDER_EAC,
		.game_id = "",
	};
	struct lota_ac_session *s = lota_ac_init(&cfg);
	if (s) {
		FAIL("returned non-NULL");
		lota_ac_shutdown(s);
	} else {
		PASS();
	}
}

static void test_init_null_game_id(void)
{
	TEST("init: NULL game_id -> NULL");
	struct lota_ac_config cfg = {
		.struct_size = sizeof(cfg),
		.provider = LOTA_AC_PROVIDER_EAC,
		.game_id = NULL,
	};
	struct lota_ac_session *s = lota_ac_init(&cfg);
	if (s) {
		FAIL("returned non-NULL");
		lota_ac_shutdown(s);
	} else {
		PASS();
	}
}

static void test_init_game_id_too_long(void)
{
	TEST("init: game_id >= 64 chars -> NULL");
	char long_id[128];
	memset(long_id, 'A', sizeof(long_id) - 1);
	long_id[sizeof(long_id) - 1] = '\0';
	struct lota_ac_config cfg = {
		.struct_size = sizeof(cfg),
		.provider = LOTA_AC_PROVIDER_EAC,
		.game_id = long_id,
	};
	struct lota_ac_session *s = lota_ac_init(&cfg);
	if (s) {
		FAIL("returned non-NULL");
		lota_ac_shutdown(s);
	} else {
		PASS();
	}
}

static void test_init_invalid_provider(void)
{
	TEST("init: provider=99 -> NULL");
	struct lota_ac_config cfg = {
		.struct_size = sizeof(cfg),
		.provider = 99,
		.game_id = "test-game",
		.token_dir = test_dir,
	};
	struct lota_ac_session *s = lota_ac_init(&cfg);
	if (s) {
		FAIL("returned non-NULL");
		lota_ac_shutdown(s);
	} else {
		PASS();
	}
}

static void test_init_eac_file_mode(void)
{
	TEST("init: EAC file mode with valid mock data");
	write_mock_snapshot(test_dir, 0x07);

	struct lota_ac_config cfg = {
		.struct_size = sizeof(cfg),
		.provider = LOTA_AC_PROVIDER_EAC,
		.game_id = "test-game-eac",
		.token_dir = test_dir,
	};
	struct lota_ac_session *s = lota_ac_init(&cfg);
	if (!s) {
		FAIL("returned NULL");
		return;
	}
	enum lota_ac_state state = lota_ac_get_state(s);
	if (state != LOTA_AC_STATE_TRUSTED) {
		FAIL("expected TRUSTED");
		lota_ac_shutdown(s);
		return;
	}
	lota_ac_shutdown(s);
	PASS();
}

static void test_init_eac_file_mode_snapshot_only(void)
{
	TEST("init: EAC file mode snapshot-only (atomic)");

	write_mock_snapshot(test_dir, 0x07);

	struct lota_ac_config cfg = {
		.struct_size = sizeof(cfg),
		.provider = LOTA_AC_PROVIDER_EAC,
		.game_id = "test-game-eac-snap",
		.token_dir = test_dir,
	};
	struct lota_ac_session *s = lota_ac_init(&cfg);
	if (!s) {
		FAIL("returned NULL");
		return;
	}
	enum lota_ac_state state = lota_ac_get_state(s);
	if (state != LOTA_AC_STATE_TRUSTED) {
		FAIL("expected TRUSTED");
		lota_ac_shutdown(s);
		return;
	}
	lota_ac_shutdown(s);
	PASS();
}

static void test_init_battleye_file_mode(void)
{
	TEST("init: BattlEye file mode with valid mock data");
	write_mock_snapshot(test_dir, 0x07);

	struct lota_ac_config cfg = {
		.struct_size = sizeof(cfg),
		.provider = LOTA_AC_PROVIDER_BATTLEYE,
		.game_id = "test-game-be",
		.token_dir = test_dir,
	};
	struct lota_ac_session *s = lota_ac_init(&cfg);
	if (!s) {
		FAIL("returned NULL");
		return;
	}
	if (lota_ac_get_state(s) != LOTA_AC_STATE_TRUSTED) {
		FAIL("expected TRUSTED");
		lota_ac_shutdown(s);
		return;
	}
	lota_ac_shutdown(s);
	PASS();
}

static void test_shutdown_null(void)
{
	TEST("shutdown(NULL) does not crash");
	lota_ac_shutdown(NULL);
	PASS();
}

static void test_get_state_null(void)
{
	TEST("get_state(NULL) -> IDLE");
	if (lota_ac_get_state(NULL) != LOTA_AC_STATE_IDLE) {
		FAIL("expected IDLE");
		return;
	}
	PASS();
}

static void test_get_info_null(void)
{
	TEST("get_info(NULL, ...) -> -EINVAL");
	struct lota_ac_info info;
	if (lota_ac_get_info(NULL, &info) != -EINVAL) {
		FAIL("expected -EINVAL");
		return;
	}
	PASS();
}

static void test_get_info_null_info(void)
{
	TEST("get_info(session, NULL) -> -EINVAL");
	write_mock_snapshot(test_dir, 0x07);

	struct lota_ac_config cfg = {
		.struct_size = sizeof(cfg),
		.provider = LOTA_AC_PROVIDER_EAC,
		.game_id = "test-game",
		.token_dir = test_dir,
	};
	struct lota_ac_session *s = lota_ac_init(&cfg);
	if (!s) {
		FAIL("init failed");
		return;
	}
	if (lota_ac_get_info(s, NULL) != -EINVAL) {
		FAIL("expected -EINVAL");
		lota_ac_shutdown(s);
		return;
	}
	lota_ac_shutdown(s);
	PASS();
}

static void test_get_info_fields(void)
{
	TEST("get_info returns the session's own telemetry");
	write_mock_snapshot(test_dir, 0x07);

	struct lota_ac_config cfg = {
		.struct_size = sizeof(cfg),
		.provider = LOTA_AC_PROVIDER_EAC,
		.game_id = "test-game-info",
		.token_dir = test_dir,
	};
	struct lota_ac_session *s = lota_ac_init(&cfg);
	if (!s) {
		FAIL("init failed");
		return;
	}

	struct lota_ac_info info;
	if (lota_ac_get_info(s, &info) != 0) {
		FAIL("get_info failed");
		lota_ac_shutdown(s);
		return;
	}
	int ok = 1;
	if (info.provider != LOTA_AC_PROVIDER_EAC) {
		ok = 0;
		printf("(provider) ");
	}
	/* 0x07 carries ATTESTED, so the session is trusted and says so */
	if (info.state != LOTA_AC_STATE_TRUSTED) {
		ok = 0;
		printf("(state) ");
	}
	if (info.session_start == 0) {
		ok = 0;
		printf("(start) ");
	}
	if (info.lota_flags != 0x07) {
		ok = 0;
		printf("(flags) ");
	}
	if (info.trusted != 1) {
		ok = 0;
		printf("(trusted) ");
	}
	if (info.heartbeat_seq != 0) {
		ok = 0;
		printf("(seq) ");
	}

	lota_ac_shutdown(s);
	if (ok)
		PASS();
	else
		FAIL("field mismatch");
}

static void test_state_untrusted_zero_flags(void)
{
	TEST("state: zero flags -> UNTRUSTED");
	write_mock_snapshot(test_dir, 0x00);

	struct lota_ac_config cfg = {
		.struct_size = sizeof(cfg),
		.provider = LOTA_AC_PROVIDER_EAC,
		.game_id = "test-untrusted",
		.token_dir = test_dir,
	};
	struct lota_ac_session *s = lota_ac_init(&cfg);
	if (!s) {
		FAIL("init failed");
		return;
	}
	/* flags = 0 but token present -> UNTRUSTED */
	if (lota_ac_get_state(s) != LOTA_AC_STATE_UNTRUSTED) {
		FAIL("expected UNTRUSTED");
		lota_ac_shutdown(s);
		return;
	}
	lota_ac_shutdown(s);
	PASS();
}

static void test_state_required_flags(void)
{
	TEST("state: missing required flags -> UNTRUSTED");
	write_mock_snapshot(test_dir,
			    0x03); /* ATTESTED + TPM_OK but no IOMMU */

	struct lota_ac_config cfg = {
		.struct_size = sizeof(cfg),
		.provider = LOTA_AC_PROVIDER_BATTLEYE,
		.game_id = "test-required",
		.token_dir = test_dir,
		.required_flags = 0x07, /* need ATTESTED + TPM + IOMMU */
	};
	struct lota_ac_session *s = lota_ac_init(&cfg);
	if (!s) {
		FAIL("init failed");
		return;
	}
	if (lota_ac_get_state(s) != LOTA_AC_STATE_UNTRUSTED) {
		FAIL("expected UNTRUSTED");
		lota_ac_shutdown(s);
		return;
	}
	lota_ac_shutdown(s);
	PASS();
}

static void test_state_required_flags_met(void)
{
	TEST("state: required flags met -> TRUSTED");
	write_mock_snapshot(test_dir, 0x07);

	struct lota_ac_config cfg = {
		.struct_size = sizeof(cfg),
		.provider = LOTA_AC_PROVIDER_EAC,
		.game_id = "test-met",
		.token_dir = test_dir,
		.required_flags = 0x07,
	};
	struct lota_ac_session *s = lota_ac_init(&cfg);
	if (!s) {
		FAIL("init failed");
		return;
	}
	if (lota_ac_get_state(s) != LOTA_AC_STATE_TRUSTED) {
		FAIL("expected TRUSTED");
		lota_ac_shutdown(s);
		return;
	}
	lota_ac_shutdown(s);
	PASS();
}

static void test_state_no_files(void)
{
	TEST("state: missing files -> ERROR");
	/* use a fresh empty dir */
	char empty_dir[512];
	snprintf(empty_dir, sizeof(empty_dir), "%s/empty", test_dir);
	mkdir(empty_dir, 0700);

	struct lota_ac_config cfg = {
		.struct_size = sizeof(cfg),
		.provider = LOTA_AC_PROVIDER_EAC,
		.game_id = "test-nofiles",
		.token_dir = empty_dir,
	};
	struct lota_ac_session *s = lota_ac_init(&cfg);
	if (!s) {
		FAIL("init failed");
		return;
	}
	if (lota_ac_get_state(s) != LOTA_AC_STATE_ERROR) {
		FAIL("expected ERROR");
		lota_ac_shutdown(s);
		return;
	}
	if (lota_ac_last_error() != LOTA_AC_ERR_NO_AGENT) {
		FAIL("expected LOTA_AC_ERR_NO_AGENT");
		lota_ac_shutdown(s);
		return;
	}
	if (lota_ac_tick(s) != -ENOENT) {
		FAIL("tick did not return -ENOENT");
		lota_ac_shutdown(s);
		return;
	}
	lota_ac_shutdown(s);
	PASS();
}

static void test_state_malformed_snapshot(void)
{
	static const char junk[] = "not a snapshot";
	char dir[512], path[600];
	int fd;

	TEST("state: unreadable snapshot -> ERROR, MALFORMED");
	snprintf(dir, sizeof(dir), "%s/garbled", test_dir);
	mkdir(dir, 0700);
	snprintf(path, sizeof(path), "%s/%s", dir, LOTA_SNAPSHOT_FILE_NAME);
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0 ||
	    write(fd, junk, sizeof(junk) - 1) != (ssize_t)(sizeof(junk) - 1)) {
		if (fd >= 0)
			close(fd);
		FAIL("cannot write the snapshot");
		return;
	}
	close(fd);

	struct lota_ac_config cfg = {
		.struct_size = sizeof(cfg),
		.provider = LOTA_AC_PROVIDER_EAC,
		.game_id = "test-garbled",
		.token_dir = dir,
	};
	struct lota_ac_session *s = lota_ac_init(&cfg);
	if (!s) {
		FAIL("init failed");
		return;
	}
	if (lota_ac_get_state(s) != LOTA_AC_STATE_ERROR ||
	    lota_ac_last_error() != LOTA_AC_ERR_MALFORMED) {
		FAIL("expected ERROR with LOTA_AC_ERR_MALFORMED");
		lota_ac_shutdown(s);
		return;
	}
	if (lota_ac_tick(s) != -EIO) {
		FAIL("tick did not return -EIO");
		lota_ac_shutdown(s);
		return;
	}
	lota_ac_shutdown(s);
	PASS();
}

/* the token's valid_until, rewritten in place */
static int age_snapshot_token(const char *dir, uint64_t valid_until)
{
	char path[600];
	uint8_t le[8];
	FILE *f;
	int ok;

	snprintf(path, sizeof(path), "%s/%s", dir, LOTA_SNAPSHOT_FILE_NAME);
	for (int i = 0; i < 8; i++)
		le[i] = (uint8_t)(valid_until >> (8 * i));
	f = fopen(path, "r+");
	if (!f)
		return -1;
	ok = fseek(f, LOTA_SNAPSHOT_HEADER_SIZE + 8, SEEK_SET) == 0 &&
	     fwrite(le, sizeof(le), 1, f) == 1;
	return fclose(f) == 0 && ok ? 0 : -1;
}

/*
 * A snapshot stays on disk after the agent stops. Its token says how long
 * the verdict holds; past that the file is no verdict at all.
 */
static void test_state_expired_snapshot(void)
{
	char dir[512];

	TEST("state: snapshot whose token expired -> ERROR, NO_AGENT");
	snprintf(dir, sizeof(dir), "%s/expired", test_dir);
	mkdir(dir, 0700);
	write_mock_snapshot(dir, 0x07);
	if (age_snapshot_token(dir, (uint64_t)time(NULL) - 1) < 0) {
		FAIL("cannot age the snapshot");
		return;
	}

	struct lota_ac_config cfg = {
		.struct_size = sizeof(cfg),
		.provider = LOTA_AC_PROVIDER_EAC,
		.game_id = "test-expired",
		.token_dir = dir,
	};
	struct lota_ac_session *s = lota_ac_init(&cfg);
	if (!s) {
		FAIL("init failed");
		return;
	}
	if (lota_ac_get_state(s) != LOTA_AC_STATE_ERROR ||
	    lota_ac_last_error() != LOTA_AC_ERR_NO_AGENT) {
		FAIL("expected ERROR with LOTA_AC_ERR_NO_AGENT");
		lota_ac_shutdown(s);
		return;
	}
	if (lota_ac_tick(s) != -ESTALE) {
		FAIL("tick did not return -ESTALE");
		lota_ac_shutdown(s);
		return;
	}

	write_mock_snapshot(dir, 0x07);
	if (lota_ac_tick(s) != 0 ||
	    lota_ac_get_state(s) != LOTA_AC_STATE_TRUSTED) {
		FAIL("a renewed snapshot did not read TRUSTED");
		lota_ac_shutdown(s);
		return;
	}
	lota_ac_shutdown(s);
	PASS();
}

/* Ticks @s with stderr in @path; returns the tick's result. */
static int tick_capturing_stderr(struct lota_ac_session *s, const char *path)
{
	int saved, fd, ret;

	fflush(stderr);
	saved = dup(STDERR_FILENO);
	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (saved < 0 || fd < 0)
		return -EIO;
	dup2(fd, STDERR_FILENO);
	close(fd);
	ret = lota_ac_tick(s);
	fflush(stderr);
	dup2(saved, STDERR_FILENO);
	close(saved);
	return ret;
}

static bool file_contains(const char *path, const char *what)
{
	char buf[1024] = { 0 };
	FILE *f = fopen(path, "r");
	size_t n;

	if (!f)
		return false;
	n = fread(buf, 1, sizeof(buf) - 1, f);
	fclose(f);
	buf[n] = '\0';
	return strstr(buf, what) != NULL;
}

/*
 * One warning per failure, not per session: a title that started before
 * the hook wrote a snapshot still hears that the token later expired.
 */
static void test_state_each_snapshot_failure_warns_once(void)
{
	char dir[512], log[600];

	TEST("state: a new snapshot failure warns once");
	snprintf(dir, sizeof(dir), "%s/warn", test_dir);
	snprintf(log, sizeof(log), "%s/warn.log", test_dir);
	mkdir(dir, 0700);

	struct lota_ac_config cfg = {
		.struct_size = sizeof(cfg),
		.provider = LOTA_AC_PROVIDER_EAC,
		.game_id = "test-warn",
		.token_dir = dir,
	};
	struct lota_ac_session *s = lota_ac_init(&cfg);
	if (!s) {
		FAIL("init failed");
		return;
	}

	write_mock_snapshot(dir, 0x07);
	if (age_snapshot_token(dir, (uint64_t)time(NULL) - 1) < 0) {
		FAIL("cannot age the snapshot");
		lota_ac_shutdown(s);
		return;
	}
	if (tick_capturing_stderr(s, log) != -ESTALE ||
	    !file_contains(log, "its token has expired")) {
		FAIL("an expiry after a missing file was not warned of");
		lota_ac_shutdown(s);
		return;
	}
	if (tick_capturing_stderr(s, log) != -ESTALE ||
	    file_contains(log, "snapshot read failed")) {
		FAIL("the same failure was warned of twice");
		lota_ac_shutdown(s);
		return;
	}
	lota_ac_shutdown(s);
	PASS();
}

static int test_sha256(const void *data, size_t len, uint8_t out[32])
{
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	if (!ctx)
		return -ENOMEM;

	unsigned int out_len = 32;
	int ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) &&
		 EVP_DigestUpdate(ctx, data, len) &&
		 EVP_DigestFinal_ex(ctx, out, &out_len);

	EVP_MD_CTX_free(ctx);
	return ok ? 0 : -EIO;
}

static void test_heartbeat_game_id_hash_domain_separated(void)
{
	TEST("heartbeat: game_id_hash is domain-separated");
	uint8_t hdr_hash[LOTA_AC_GAME_HASH_SIZE];
	uint8_t legacy_hash[LOTA_AC_GAME_HASH_SIZE];
	if (compute_game_id_hash_test("game-alpha", hdr_hash) != 0) {
		FAIL("domain hash compute failed");
		return;
	}
	if (test_sha256("game-alpha", strlen("game-alpha"), legacy_hash) != 0) {
		FAIL("legacy hash compute failed");
		return;
	}

	if (memcmp(hdr_hash, legacy_hash, LOTA_AC_GAME_HASH_SIZE) == 0) {
		FAIL("hash matches legacy SHA-256(game_id)");
		return;
	}

	PASS();
}

static void test_heartbeat_buf_too_small(void)
{
	TEST("heartbeat: file mode returns -EOPNOTSUPP before size checks");
	write_mock_snapshot(test_dir, 0x07);

	struct lota_ac_config cfg = {
		.struct_size = sizeof(cfg),
		.provider = LOTA_AC_PROVIDER_EAC,
		.game_id = "test-small",
		.token_dir = test_dir,
	};
	struct lota_ac_session *s = lota_ac_init(&cfg);
	if (!s) {
		FAIL("init failed");
		return;
	}

	uint8_t buf[16]; /* way too small */
	size_t written;
	int ret = lota_ac_heartbeat(s, buf, sizeof(buf), &written);
	lota_ac_shutdown(s);

	if (ret == -EOPNOTSUPP)
		PASS();
	else
		FAIL("expected -EOPNOTSUPP");
}

static void test_heartbeat_null_args(void)
{
	TEST("heartbeat: NULL arguments -> -EINVAL");
	uint8_t buf[64];
	size_t written;
	int ok = 1;
	if (lota_ac_heartbeat(NULL, buf, sizeof(buf), &written) != -EINVAL)
		ok = 0;

	write_mock_snapshot(test_dir, 0x07);
	struct lota_ac_config cfg = {
		.struct_size = sizeof(cfg),
		.provider = LOTA_AC_PROVIDER_EAC,
		.game_id = "test-null",
		.token_dir = test_dir,
	};
	struct lota_ac_session *s = lota_ac_init(&cfg);
	if (s) {
		if (lota_ac_heartbeat(s, NULL, 100, &written) != -EINVAL)
			ok = 0;
		if (lota_ac_heartbeat(s, buf, sizeof(buf), NULL) != -EINVAL)
			ok = 0;
		lota_ac_shutdown(s);
	}
	if (ok)
		PASS();
	else
		FAIL("did not return -EINVAL");
}

static void test_verify_roundtrip(void)
{
	TEST("verify: nonce-bound heartbeat requires AIK key");
	uint8_t buf[LOTA_AC_MAX_HEARTBEAT];
	uint8_t expected_game_hash[LOTA_AC_GAME_HASH_SIZE];
	size_t written = 0;
	int ret = build_bound_heartbeat_packet(buf, sizeof(buf), &written,
					       LOTA_AC_PROVIDER_EAC,
					       "test-verify", 0x07, 0);
	if (ret != 0) {
		FAIL("packet build failed");
		return;
	}
	if (compute_game_id_hash_test("test-verify", expected_game_hash) != 0) {
		FAIL("expected game hash compute failed");
		return;
	}
	uint8_t expected_rm[LOTA_AC_RUNTIME_MEASURE_SIZE];
	if (expected_runtime_measure_test(expected_rm) != 0) {
		FAIL("expected runtime measure compute failed");
		return;
	}

	/* fail closed: cryptographic verification key is mandatory */
	struct lota_ac_info verified;
	ret = lota_ac_verify_heartbeat(buf, written, NULL, 0,
				       expected_game_hash, expected_rm,
				       &verified);
	if (ret != LOTA_AC_ERR_INVALID_ARG) {
		FAIL("expected LOTA_AC_ERR_INVALID_ARG");
		return;
	}

	PASS();
}

static void test_verify_battleye_roundtrip(void)
{
	TEST("verify: BattlEye heartbeat requires AIK key");
	uint8_t buf[LOTA_AC_MAX_HEARTBEAT];
	uint8_t expected_game_hash[LOTA_AC_GAME_HASH_SIZE];
	size_t written = 0;
	if (build_bound_heartbeat_packet(buf, sizeof(buf), &written,
					 LOTA_AC_PROVIDER_BATTLEYE,
					 "test-be-verify", 0x1F, 42) != 0) {
		FAIL("packet build failed");
		return;
	}
	if (compute_game_id_hash_test("test-be-verify", expected_game_hash) !=
	    0) {
		FAIL("expected game hash compute failed");
		return;
	}
	uint8_t expected_rm[LOTA_AC_RUNTIME_MEASURE_SIZE];
	if (expected_runtime_measure_test(expected_rm) != 0) {
		FAIL("expected runtime measure compute failed");
		return;
	}

	struct lota_ac_info info;
	int ret = lota_ac_verify_heartbeat(
		buf, written, NULL, 0, expected_game_hash, expected_rm, &info);
	if (ret != LOTA_AC_ERR_INVALID_ARG) {
		FAIL("expected LOTA_AC_ERR_INVALID_ARG");
		return;
	}
	PASS();
}

static void test_verify_rejects_game_hash_mismatch(void)
{
	TEST("verify: wrong expected game hash -> MALFORMED");
	uint8_t buf[LOTA_AC_MAX_HEARTBEAT];
	uint8_t wrong_hash[LOTA_AC_GAME_HASH_SIZE] = { 0 };
	size_t written = 0;

	if (build_bound_heartbeat_packet(
		    buf, sizeof(buf), &written, LOTA_AC_PROVIDER_EAC,
		    "test-verify-mismatch", 0x07, 0) != 0) {
		FAIL("packet build failed");
		return;
	}

	uint8_t any_rm[LOTA_AC_RUNTIME_MEASURE_SIZE] = { 0 };
	struct lota_ac_info info;
	int ret = lota_ac_verify_heartbeat(buf, written, NULL, 0, wrong_hash,
					   any_rm, &info);
	if (ret != LOTA_AC_ERR_MALFORMED) {
		FAIL("expected LOTA_AC_ERR_MALFORMED");
		return;
	}

	PASS();
}

static void test_verify_null_data(void)
{
	TEST("verify: NULL data -> INVALID_ARG");
	uint8_t expected_game_hash[LOTA_AC_GAME_HASH_SIZE] = { 0 };
	uint8_t any_rm[LOTA_AC_RUNTIME_MEASURE_SIZE] = { 0 };
	struct lota_ac_info info;
	if (lota_ac_verify_heartbeat(NULL, 100, NULL, 0, expected_game_hash,
				     any_rm,
				     &info) != LOTA_AC_ERR_INVALID_ARG) {
		FAIL("expected LOTA_AC_ERR_INVALID_ARG");
		return;
	}
	PASS();
}

static void test_verify_null_info(void)
{
	TEST("verify: NULL info -> INVALID_ARG");
	uint8_t data[128] = { 0 };
	uint8_t expected_game_hash[LOTA_AC_GAME_HASH_SIZE] = { 0 };
	uint8_t any_rm[LOTA_AC_RUNTIME_MEASURE_SIZE] = { 0 };
	if (lota_ac_verify_heartbeat(data, sizeof(data), NULL, 0,
				     expected_game_hash, any_rm,
				     NULL) != LOTA_AC_ERR_INVALID_ARG) {
		FAIL("expected LOTA_AC_ERR_INVALID_ARG");
		return;
	}
	PASS();
}

static void test_verify_truncated(void)
{
	TEST("verify: truncated data -> MALFORMED");
	uint8_t data[32] = { 0 };
	uint8_t expected_game_hash[LOTA_AC_GAME_HASH_SIZE] = { 0 };
	uint8_t any_rm[LOTA_AC_RUNTIME_MEASURE_SIZE] = { 0 };
	struct lota_ac_info info;
	if (lota_ac_verify_heartbeat(data, sizeof(data), NULL, 0,
				     expected_game_hash, any_rm,
				     &info) != LOTA_AC_ERR_MALFORMED) {
		FAIL("expected LOTA_AC_ERR_MALFORMED");
		return;
	}
	PASS();
}

static void test_verify_bad_magic(void)
{
	TEST("verify: bad magic -> MALFORMED");
	uint8_t data[LOTA_AC_HEADER_SIZE + 96];
	memset(data, 0, sizeof(data));

	struct lota_ac_heartbeat_wire *hdr =
		(struct lota_ac_heartbeat_wire *)data;
	hdr->magic = 0xDEADBEEF;
	hdr->version = LOTA_AC_VERSION;
	hdr->provider = LOTA_AC_PROVIDER_EAC;
	hdr->total_size = sizeof(data);
	hdr->token_size = sizeof(data) - LOTA_AC_HEADER_SIZE;

	uint8_t expected_game_hash[LOTA_AC_GAME_HASH_SIZE] = { 0 };
	uint8_t any_rm[LOTA_AC_RUNTIME_MEASURE_SIZE] = { 0 };
	struct lota_ac_info info;
	if (lota_ac_verify_heartbeat(data, sizeof(data), NULL, 0,
				     expected_game_hash, any_rm,
				     &info) != LOTA_AC_ERR_MALFORMED) {
		FAIL("expected LOTA_AC_ERR_MALFORMED");
		return;
	}
	PASS();
}

static void test_verify_bad_version(void)
{
	TEST("verify: bad version -> VERSION");
	uint8_t data[LOTA_AC_HEADER_SIZE + 96];
	memset(data, 0, sizeof(data));

	struct lota_ac_heartbeat_wire *hdr =
		(struct lota_ac_heartbeat_wire *)data;
	hdr->magic = LOTA_AC_MAGIC;
	hdr->version = 99;
	hdr->provider = LOTA_AC_PROVIDER_EAC;
	hdr->total_size = sizeof(data);
	hdr->token_size = sizeof(data) - LOTA_AC_HEADER_SIZE;

	uint8_t expected_game_hash[LOTA_AC_GAME_HASH_SIZE] = { 0 };
	uint8_t any_rm[LOTA_AC_RUNTIME_MEASURE_SIZE] = { 0 };
	struct lota_ac_info info;
	if (lota_ac_verify_heartbeat(data, sizeof(data), NULL, 0,
				     expected_game_hash, any_rm,
				     &info) != LOTA_AC_ERR_VERSION) {
		FAIL("expected LOTA_AC_ERR_VERSION");
		return;
	}
	PASS();
}

static void test_verify_bad_provider(void)
{
	TEST("verify: bad provider -> MALFORMED");
	uint8_t data[LOTA_AC_HEADER_SIZE + 96];
	memset(data, 0, sizeof(data));

	struct lota_ac_heartbeat_wire *hdr =
		(struct lota_ac_heartbeat_wire *)data;
	hdr->magic = LOTA_AC_MAGIC;
	hdr->version = LOTA_AC_VERSION;
	hdr->provider = 42;
	hdr->total_size = sizeof(data);
	hdr->token_size = sizeof(data) - LOTA_AC_HEADER_SIZE;

	uint8_t expected_game_hash[LOTA_AC_GAME_HASH_SIZE] = { 0 };
	uint8_t any_rm[LOTA_AC_RUNTIME_MEASURE_SIZE] = { 0 };
	struct lota_ac_info info;
	if (lota_ac_verify_heartbeat(data, sizeof(data), NULL, 0,
				     expected_game_hash, any_rm,
				     &info) != LOTA_AC_ERR_MALFORMED) {
		FAIL("expected LOTA_AC_ERR_MALFORMED");
		return;
	}
	PASS();
}

static void test_verify_size_mismatch(void)
{
	TEST("verify: total_size > actual len -> MALFORMED");
	uint8_t data[LOTA_AC_HEADER_SIZE + 96];
	memset(data, 0, sizeof(data));

	struct lota_ac_heartbeat_wire *hdr =
		(struct lota_ac_heartbeat_wire *)data;
	hdr->magic = LOTA_AC_MAGIC;
	hdr->version = LOTA_AC_VERSION;
	hdr->provider = LOTA_AC_PROVIDER_EAC;
	hdr->total_size = 9999; /* way bigger than actual data */
	hdr->token_size = 128;

	uint8_t expected_game_hash[LOTA_AC_GAME_HASH_SIZE] = { 0 };
	uint8_t any_rm[LOTA_AC_RUNTIME_MEASURE_SIZE] = { 0 };
	struct lota_ac_info info;
	if (lota_ac_verify_heartbeat(data, sizeof(data), NULL, 0,
				     expected_game_hash, any_rm,
				     &info) != LOTA_AC_ERR_MALFORMED) {
		FAIL("expected LOTA_AC_ERR_MALFORMED");
		return;
	}
	PASS();
}

static void test_verify_header_flags_tamper_rejected(void)
{
	TEST("verify: tampered heartbeat without AIK -> INVALID_ARG");
	uint8_t buf[LOTA_AC_MAX_HEARTBEAT];
	size_t written = 0;
	if (build_bound_heartbeat_packet(buf, sizeof(buf), &written,
					 LOTA_AC_PROVIDER_EAC,
					 "test-flags-tamper", 0x07, 1) != 0) {
		FAIL("packet build failed");
		return;
	}

	/* tamper plaintext header flag mirror, keep embedded token unchanged */
	write_le32(buf + 28, 0xdeadbeefU);

	uint8_t expected_game_hash[LOTA_AC_GAME_HASH_SIZE];
	if (compute_game_id_hash_test("test-flags-tamper",
				      expected_game_hash) != 0) {
		FAIL("expected game hash compute failed");
		return;
	}
	uint8_t expected_rm[LOTA_AC_RUNTIME_MEASURE_SIZE];
	if (expected_runtime_measure_test(expected_rm) != 0) {
		FAIL("expected runtime measure compute failed");
		return;
	}

	struct lota_ac_info info;
	if (lota_ac_verify_heartbeat(buf, written, NULL, 0, expected_game_hash,
				     expected_rm,
				     &info) != LOTA_AC_ERR_INVALID_ARG) {
		FAIL("expected LOTA_AC_ERR_INVALID_ARG");
		return;
	}

	PASS();
}

static void test_verify_rejects_unknown_domain_version(void)
{
	TEST("verify: unknown domain_version -> VERSION");
	uint8_t buf[LOTA_AC_MAX_HEARTBEAT];
	uint8_t expected_game_hash[LOTA_AC_GAME_HASH_SIZE];
	size_t written = 0;

	if (build_bound_heartbeat_packet(buf, sizeof(buf), &written,
					 LOTA_AC_PROVIDER_EAC,
					 "test-domain-version", 0x07, 1) != 0) {
		FAIL("packet build failed");
		return;
	}
	if (compute_game_id_hash_test("test-domain-version",
				      expected_game_hash) != 0) {
		FAIL("expected game hash compute failed");
		return;
	}

	/* stamp a domain version that is not in the accepted table */
	write_le32(buf + 74, 0xdeadbeefU);

	uint8_t any_rm[LOTA_AC_RUNTIME_MEASURE_SIZE] = { 0 };
	struct lota_ac_info info;
	if (lota_ac_verify_heartbeat(buf, written, NULL, 0, expected_game_hash,
				     any_rm, &info) != LOTA_AC_ERR_VERSION) {
		FAIL("expected LOTA_AC_ERR_VERSION");
		return;
	}
	PASS();
}

static void test_verify_rejects_runtime_measure_mismatch(void)
{
	TEST("verify: wrong expected runtime measure -> RUNTIME_IMAGE");
	uint8_t buf[LOTA_AC_MAX_HEARTBEAT];
	uint8_t expected_game_hash[LOTA_AC_GAME_HASH_SIZE];
	uint8_t wrong_rm[LOTA_AC_RUNTIME_MEASURE_SIZE];
	size_t written = 0;

	if (build_bound_heartbeat_packet(buf, sizeof(buf), &written,
					 LOTA_AC_PROVIDER_EAC,
					 "test-rm-mismatch", 0x07, 3) != 0) {
		FAIL("packet build failed");
		return;
	}
	if (compute_game_id_hash_test("test-rm-mismatch", expected_game_hash) !=
	    0) {
		FAIL("expected game hash compute failed");
		return;
	}
	if (expected_runtime_measure_test(wrong_rm) != 0) {
		FAIL("expected runtime measure compute failed");
		return;
	}
	/* a verifier expecting a different image must reject this heartbeat */
	wrong_rm[0] ^= 0xFF;

	struct lota_ac_info info;
	if (lota_ac_verify_heartbeat(buf, written, NULL, 0, expected_game_hash,
				     wrong_rm,
				     &info) != LOTA_AC_ERR_RUNTIME_IMAGE) {
		FAIL("expected LOTA_AC_ERR_RUNTIME_IMAGE");
		return;
	}
	PASS();
}

static void test_verify_rejects_runtime_field_tamper(void)
{
	TEST("verify: tampered runtime_measure field -> RUNTIME_IMAGE");
	uint8_t buf[LOTA_AC_MAX_HEARTBEAT];
	uint8_t expected_game_hash[LOTA_AC_GAME_HASH_SIZE];
	uint8_t expected_rm[LOTA_AC_RUNTIME_MEASURE_SIZE];
	size_t written = 0;

	if (build_bound_heartbeat_packet(buf, sizeof(buf), &written,
					 LOTA_AC_PROVIDER_EAC, "test-rm-tamper",
					 0x07, 4) != 0) {
		FAIL("packet build failed");
		return;
	}
	if (compute_game_id_hash_test("test-rm-tamper", expected_game_hash) !=
	    0) {
		FAIL("expected game hash compute failed");
		return;
	}
	if (expected_runtime_measure_test(expected_rm) != 0) {
		FAIL("expected runtime measure compute failed");
		return;
	}

	/* flip a byte of the wire runtime_measure field (offset 78) */
	buf[78] ^= 0xFF;

	struct lota_ac_info info;
	if (lota_ac_verify_heartbeat(buf, written, NULL, 0, expected_game_hash,
				     expected_rm,
				     &info) != LOTA_AC_ERR_RUNTIME_IMAGE) {
		FAIL("expected LOTA_AC_ERR_RUNTIME_IMAGE");
		return;
	}
	PASS();
}

static void test_direct_mode_no_agent(void)
{
	TEST("direct mode: no agent -> ERROR state (graceful)");
	struct lota_ac_config cfg = {
		.struct_size = sizeof(cfg),
		.provider = LOTA_AC_PROVIDER_EAC,
		.game_id = "test-direct",
		.direct = 1,
		.socket_path = "/tmp/lota_nonexistent_socket_for_test",
	};
	struct lota_ac_session *s = lota_ac_init(&cfg);
	if (!s) {
		FAIL("init returned NULL");
		return;
	}
	if (lota_ac_get_state(s) != LOTA_AC_STATE_ERROR) {
		FAIL("expected ERROR state");
		lota_ac_shutdown(s);
		return;
	}
	lota_ac_shutdown(s);
	PASS();
}

/*
 * Why a session refused to start.
 *
 * lota_ac_init() returns NULL for reasons an integrator has to tell apart
 * -- a configuration they got wrong is their bug, an agent that is not there
 * or a publisher nobody has consented to is a state the player acts on
 * -- and it returned the same NULL for all of them.
 * Bringing a client up against the installed SDK on the hardware host took
 * four blind attempts for exactly this reason.
 */
static void test_last_error_init_causes(void)
{
	struct lota_ac_config cfg;

	TEST("last_error: a NULL configuration is an invalid argument");
	lota_ac_init(NULL);
	if (lota_ac_last_error() != LOTA_AC_ERR_INVALID_ARG) {
		FAIL("expected LOTA_AC_ERR_INVALID_ARG");
		return;
	}
	PASS();

	TEST("last_error: an unset struct_size names the struct size");
	memset(&cfg, 0, sizeof(cfg));
	cfg.provider = LOTA_AC_PROVIDER_EAC;
	cfg.game_id = "test-game";
	lota_ac_init(&cfg);
	if (lota_ac_last_error() != LOTA_AC_ERR_CONFIG_SIZE) {
		FAIL("expected LOTA_AC_ERR_CONFIG_SIZE");
		return;
	}
	PASS();

	TEST("last_error: a missing game_id names the game_id");
	memset(&cfg, 0, sizeof(cfg));
	cfg.struct_size = sizeof(cfg);
	cfg.provider = LOTA_AC_PROVIDER_EAC;
	cfg.game_id = "";
	lota_ac_init(&cfg);
	if (lota_ac_last_error() != LOTA_AC_ERR_GAME_ID) {
		FAIL("expected LOTA_AC_ERR_GAME_ID");
		return;
	}
	PASS();

	/* the cause that cost the four attempts: a zeroed provider */
	TEST("last_error: a provider nobody set names the provider");
	memset(&cfg, 0, sizeof(cfg));
	cfg.struct_size = sizeof(cfg);
	cfg.game_id = "test-game";
	lota_ac_init(&cfg);
	if (lota_ac_last_error() != LOTA_AC_ERR_PROVIDER) {
		FAIL("expected LOTA_AC_ERR_PROVIDER");
		return;
	}
	PASS();

	TEST("last_error: a session that started says nothing failed");
	memset(&cfg, 0, sizeof(cfg));
	cfg.struct_size = sizeof(cfg);
	cfg.provider = LOTA_AC_PROVIDER_EAC;
	cfg.game_id = "test-game";
	cfg.token_dir = test_dir;
	{
		struct lota_ac_session *s = lota_ac_init(&cfg);

		if (!s) {
			FAIL("init refused a valid file-mode configuration");
			return;
		}
		if (lota_ac_last_error() != LOTA_AC_ERR_OK) {
			FAIL("expected LOTA_AC_ERR_OK");
			lota_ac_shutdown(s);
			return;
		}
		lota_ac_shutdown(s);
	}
	PASS();
}

/*
 * "The host is not ready" has to be distinguishable from "you called this wrong":
 * one is a screen the player acts on, the other is the integrator's bug.
 */
static void test_last_error_no_agent(void)
{
	TEST("last_error: no agent on the socket is named as such");
	struct lota_ac_config cfg = {
		.struct_size = sizeof(cfg),
		.provider = LOTA_AC_PROVIDER_EAC,
		.game_id = "test-direct",
		.direct = 1,
		.socket_path = "/tmp/lota_nonexistent_socket_for_test",
	};
	struct lota_ac_session *s = lota_ac_init(&cfg);

	if (!s) {
		FAIL("init returned NULL");
		return;
	}
	if (lota_ac_last_error() != LOTA_AC_ERR_NO_AGENT) {
		FAIL("expected LOTA_AC_ERR_NO_AGENT");
		lota_ac_shutdown(s);
		return;
	}
	lota_ac_shutdown(s);
	PASS();
}

/* the publisher is checked once connected; listening is enough */
static void test_last_error_bad_publisher(void)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	struct lota_ac_session *s;
	int fd;

	TEST("last_error: a malformed publisher is an invalid argument");
	if (snprintf(addr.sun_path, sizeof(addr.sun_path), "%s/pub.sock",
		     test_dir) >= (int)sizeof(addr.sun_path)) {
		FAIL("the socket path does not fit");
		return;
	}
	unlink(addr.sun_path);
	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0 || bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
	    listen(fd, 1) != 0) {
		FAIL("cannot listen on a unix socket");
		if (fd >= 0)
			close(fd);
		return;
	}

	struct lota_ac_config cfg = {
		.struct_size = sizeof(cfg),
		.provider = LOTA_AC_PROVIDER_EAC,
		.game_id = "test-direct",
		.direct = 1,
		.socket_path = addr.sun_path,
		.publisher_profile = "zz",
	};
	s = lota_ac_init(&cfg);
	close(fd);
	unlink(addr.sun_path);

	if (!s) {
		FAIL("init returned NULL");
		return;
	}
	if (lota_ac_last_error() != LOTA_AC_ERR_INVALID_ARG) {
		FAIL("expected LOTA_AC_ERR_INVALID_ARG");
		lota_ac_shutdown(s);
		return;
	}
	lota_ac_shutdown(s);
	PASS();
}

/*
 * A beat that cannot be produced says which half failed.
 * The heartbeat path has ten distinct -EIO returns, and the one word
 * "Input/output error" is what the anti-cheat reference reported
 * on the hardware host for all of them.
 */
static void test_last_error_heartbeat_causes(void)
{
	struct lota_ac_config cfg = {
		.struct_size = sizeof(cfg),
		.provider = LOTA_AC_PROVIDER_EAC,
		.game_id = "test-direct",
		.direct = 1,
		.socket_path = "/tmp/lota_nonexistent_socket_for_test",
	};
	struct lota_ac_session *s = lota_ac_init(&cfg);
	uint8_t buf[LOTA_AC_MAX_HEARTBEAT];
	size_t written = 0;

	TEST("last_error: a beat without a session is an invalid argument");
	lota_ac_heartbeat(NULL, buf, sizeof(buf), &written);
	if (lota_ac_last_error() != LOTA_AC_ERR_INVALID_ARG) {
		FAIL("expected LOTA_AC_ERR_INVALID_ARG");
		lota_ac_shutdown(s);
		return;
	}
	PASS();

	TEST("last_error: a beat with no agent behind it names the agent");
	if (!s) {
		FAIL("init returned NULL");
		return;
	}
	lota_ac_heartbeat(s, buf, sizeof(buf), &written);
	if (lota_ac_last_error() != LOTA_AC_ERR_NO_AGENT) {
		FAIL("expected LOTA_AC_ERR_NO_AGENT");
		lota_ac_shutdown(s);
		return;
	}
	PASS();

	lota_ac_shutdown(s);
}

/*
 * A refusing call must leave its own reason, a successful one must clear it.
 * Each case seeds a code no call under test produces, then reads it back.
 */
static void seed_stale_error(void)
{
	struct lota_ac_config cfg;

	memset(&cfg, 0, sizeof(cfg));
	cfg.provider = LOTA_AC_PROVIDER_EAC;
	cfg.game_id = "stale-seed";
	lota_ac_init(&cfg); /* struct_size 0: LOTA_AC_ERR_CONFIG_SIZE */
}

static int last_error_is(int expected, const char *what)
{
	int got = lota_ac_last_error();

	if (got == expected)
		return 1;

	if (got == LOTA_AC_ERR_CONFIG_SIZE)
		printf("FAIL (%s left the seeded error behind)\n", what);
	else
		printf("FAIL (%s left %d, expected %d)\n", what, got, expected);
	return 0;
}

static int rt_count_cb(const char *path, void *user)
{
	(void)path;
	(*(int *)user)++;
	return 0;
}

static void test_last_error_measure_helpers(void)
{
	uint8_t game_hash[LOTA_AC_GAME_HASH_SIZE];
	uint8_t measure[LOTA_AC_RUNTIME_MEASURE_SIZE];
	int objects = 0;

	TEST("last_error: a binding hash without a game id is invalid");
	seed_stale_error();
	lota_ac_compute_game_binding_hash(NULL, "/proc/self/exe", game_hash);
	if (!last_error_is(-EINVAL, "compute_game_binding_hash"))
		return;
	PASS();

	TEST("last_error: a binding hash that was computed clears the last");
	seed_stale_error();
	if (lota_ac_compute_game_binding_hash("test-game", "/proc/self/exe",
					      game_hash) != 0) {
		FAIL("the binding hash could not be computed");
		return;
	}
	if (!last_error_is(LOTA_AC_ERR_OK, "compute_game_binding_hash"))
		return;
	PASS();

	TEST("last_error: a runtime measure of nowhere is invalid");
	seed_stale_error();
	lota_ac_compute_runtime_measure(NULL);
	if (!last_error_is(-EINVAL, "compute_runtime_measure"))
		return;
	PASS();

	TEST("last_error: a runtime measure that was taken clears the last");
	seed_stale_error();
	if (lota_ac_compute_runtime_measure(measure) != 0) {
		FAIL("this process could not measure itself");
		return;
	}
	if (!last_error_is(LOTA_AC_ERR_OK, "compute_runtime_measure"))
		return;
	PASS();

	TEST("last_error: an enumeration with no callback is invalid");
	seed_stale_error();
	lota_ac_list_runtime_objects(NULL, NULL);
	if (!last_error_is(-EINVAL, "list_runtime_objects"))
		return;
	PASS();

	TEST("last_error: an enumeration that ran clears the last");
	seed_stale_error();
	if (lota_ac_list_runtime_objects(rt_count_cb, &objects) != 0 ||
	    objects == 0) {
		FAIL("this process listed no loaded object");
		return;
	}
	if (!last_error_is(LOTA_AC_ERR_OK, "list_runtime_objects"))
		return;
	PASS();

	TEST("last_error: an expected measure over no paths is invalid");
	seed_stale_error();
	lota_ac_compute_expected_runtime_measure(NULL, measure);
	if (!last_error_is(-EINVAL, "compute_expected_runtime_measure"))
		return;
	PASS();

	TEST("last_error: an expected measure that was computed clears it");
	seed_stale_error();
	if (lota_ac_compute_expected_runtime_measure("/proc/self/exe",
						     measure) != 0) {
		FAIL("the expected measure could not be computed");
		return;
	}
	if (!last_error_is(LOTA_AC_ERR_OK, "compute_expected_runtime_measure"))
		return;
	PASS();
}

/* the session-bound calls, two of which an integrator polls in a loop */
static void test_last_error_session_calls(void)
{
	struct lota_ac_config cfg = {
		.struct_size = sizeof(cfg),
		.provider = LOTA_AC_PROVIDER_EAC,
		.game_id = "test-game",
	};
	struct lota_ac_session *s;
	struct lota_ac_info info;

	TEST("last_error: telemetry about no session is invalid");
	seed_stale_error();
	lota_ac_get_info(NULL, &info);
	if (!last_error_is(-EINVAL, "get_info"))
		return;
	PASS();

	TEST("last_error: a refresh of no session is invalid");
	seed_stale_error();
	lota_ac_tick(NULL);
	if (!last_error_is(-EINVAL, "tick"))
		return;
	PASS();

	cfg.token_dir = test_dir;
	s = lota_ac_init(&cfg);
	if (!s) {
		TEST("last_error: a session for the session-bound calls");
		FAIL("init refused a valid file-mode configuration");
		return;
	}

	TEST("last_error: telemetry that was handed over clears the last");
	seed_stale_error();
	if (lota_ac_get_info(s, &info) != 0) {
		FAIL("get_info refused a live session");
		lota_ac_shutdown(s);
		return;
	}
	if (!last_error_is(LOTA_AC_ERR_OK, "get_info")) {
		lota_ac_shutdown(s);
		return;
	}
	PASS();

	TEST("last_error: a refresh that ran clears the last");
	seed_stale_error();
	if (lota_ac_tick(s) != 0) {
		FAIL("tick refused a live session");
		lota_ac_shutdown(s);
		return;
	}
	if (!last_error_is(LOTA_AC_ERR_OK, "tick")) {
		lota_ac_shutdown(s);
		return;
	}
	PASS();

	lota_ac_shutdown(s);
}

/* The server side reads the same accessor after a verdict it did not like */
static void test_last_error_verify_heartbeat(void)
{
	uint8_t game_hash[LOTA_AC_GAME_HASH_SIZE] = { 0 };
	uint8_t measure[LOTA_AC_RUNTIME_MEASURE_SIZE] = { 0 };
	struct lota_ac_info info;
	uint8_t buf[LOTA_AC_HEADER_SIZE] = { 0 };

	TEST("last_error: a verdict on no packet is invalid");
	seed_stale_error();
	lota_ac_verify_heartbeat(NULL, 0, NULL, 0, game_hash, measure, &info);
	if (!last_error_is(LOTA_AC_ERR_INVALID_ARG, "verify_heartbeat"))
		return;
	PASS();

	TEST("last_error: a verdict on a packet that is not one names it");
	seed_stale_error();
	lota_ac_verify_heartbeat(buf, sizeof(buf), NULL, 0, game_hash, measure,
				 &info);
	if (!last_error_is(LOTA_AC_ERR_MALFORMED, "verify_heartbeat"))
		return;
	PASS();
}

/* a code an integrator logs is worth a sentence; a number is not one */
static void test_last_error_strings(void)
{
	static const int codes[] = {
		LOTA_AC_ERR_OK,
		LOTA_AC_ERR_INVALID_ARG,
		LOTA_AC_ERR_CONFIG_SIZE,
		LOTA_AC_ERR_GAME_ID,
		LOTA_AC_ERR_PROVIDER,
		LOTA_AC_ERR_NO_MEMORY,
		LOTA_AC_ERR_INTERNAL,
		LOTA_AC_ERR_NO_AGENT,
		LOTA_AC_ERR_CONSENT_REQUIRED,
		LOTA_AC_ERR_UNKNOWN_PROFILE,
		LOTA_AC_ERR_ACCESS_DENIED,
		LOTA_AC_ERR_TOKEN_DIR,
		LOTA_AC_ERR_NOT_ATTESTED,
		LOTA_AC_ERR_RATE_LIMITED,
		LOTA_AC_ERR_STATUS,
		LOTA_AC_ERR_TOKEN,
		LOTA_AC_ERR_MEASURE,
		LOTA_AC_ERR_SERIALIZE,
		LOTA_AC_ERR_NO_EVIDENCE,
		LOTA_AC_ERR_BAD_EVIDENCE,
	};
	const char *unknown = lota_ac_strerror(-9999);
	size_t i, j;

	TEST("strerror: every code has a sentence of its own");
	for (i = 0; i < sizeof(codes) / sizeof(codes[0]); i++) {
		const char *si = lota_ac_strerror(codes[i]);

		if (!si || !si[0] || strcmp(si, unknown) == 0) {
			FAIL("a code renders as the fallback");
			return;
		}
		for (j = i + 1; j < sizeof(codes) / sizeof(codes[0]); j++) {
			if (strcmp(si, lota_ac_strerror(codes[j])) == 0) {
				FAIL("two codes share a sentence");
				return;
			}
		}
	}
	PASS();

	TEST("strerror: a code from a newer library still prints");
	if (!unknown || !unknown[0]) {
		FAIL("no fallback string");
		return;
	}
	PASS();
}

static void test_state_str(void)
{
	TEST("state_str: all states produce valid strings");
	int ok = 1;
	if (strcmp(lota_ac_state_str(LOTA_AC_STATE_IDLE), "idle") != 0)
		ok = 0;
	if (strcmp(lota_ac_state_str(LOTA_AC_STATE_RUNNING), "running") != 0)
		ok = 0;
	if (strcmp(lota_ac_state_str(LOTA_AC_STATE_TRUSTED), "trusted") != 0)
		ok = 0;
	if (strcmp(lota_ac_state_str(LOTA_AC_STATE_UNTRUSTED), "untrusted") !=
	    0)
		ok = 0;
	if (strcmp(lota_ac_state_str(LOTA_AC_STATE_ERROR), "error") != 0)
		ok = 0;
	if (strcmp(lota_ac_state_str(99), "unknown") != 0)
		ok = 0;
	if (ok)
		PASS();
	else
		FAIL("string mismatch");
}

static void test_provider_str(void)
{
	TEST("provider_str: all providers produce valid strings");
	int ok = 1;
	if (strcmp(lota_ac_provider_str(LOTA_AC_PROVIDER_EAC), "EAC") != 0)
		ok = 0;
	if (strcmp(lota_ac_provider_str(LOTA_AC_PROVIDER_BATTLEYE),
		   "BattlEye") != 0)
		ok = 0;
	if (strcmp(lota_ac_provider_str(99), "unknown") != 0)
		ok = 0;
	if (ok)
		PASS();
	else
		FAIL("string mismatch");
}

static void test_tick_null(void)
{
	TEST("tick(NULL) -> -EINVAL");
	if (lota_ac_tick(NULL) != -EINVAL) {
		FAIL("expected -EINVAL");
		return;
	}
	PASS();
}

/*
 * Emit a wine-hook style lota-status text file at the EAC-expected path.
 * Matches the format produced by src/sdk/lota_wine_hook.c::write_status().
 */
static void write_wine_status_file(const char *dir, uint32_t flags,
				   uint64_t valid_until)
{
	char buf[512];
	int len = snprintf(buf, sizeof(buf),
			   "LOTA_ATTESTED=%d\n"
			   "LOTA_FLAGS=0x%08x\n"
			   "LOTA_VALID_UNTIL=%lu\n"
			   "LOTA_ATTEST_COUNT=%u\n"
			   "LOTA_FAIL_COUNT=%u\n"
			   "LOTA_UPDATED=%lu\n"
			   "LOTA_PID=%d\n",
			   (flags & 0x01) ? 1 : 0, flags,
			   (unsigned long)valid_until, 1u, 0u,
			   (unsigned long)time(NULL), (int)getpid());
	if (len < 0 || (size_t)len >= sizeof(buf))
		return;
	write_test_file(dir, "lota-status", buf, (size_t)len);
}

static int unlink_in_dir(const char *dir, const char *name)
{
	char path[1024];
	if (snprintf(path, sizeof(path), "%s/%s", dir, name) >=
	    (int)sizeof(path))
		return -1;
	return unlink(path);
}

static void test_integration_wine_artifacts_consumed_by_eac(void)
{
	TEST("integration: wine hook artifacts -> EAC TRUSTED");
	char dir[512];
	snprintf(dir, sizeof(dir), "%s/wine_to_eac", test_dir);
	mkdir(dir, 0700);

	const uint32_t attested_flags = 0x07;
	write_wine_status_file(dir, attested_flags,
			       (uint64_t)time(NULL) + 3600);
	write_mock_snapshot(dir, attested_flags);

	struct lota_ac_config cfg = {
		.struct_size = sizeof(cfg),
		.provider = LOTA_AC_PROVIDER_EAC,
		.game_id = "wine-to-eac",
		.token_dir = dir,
	};
	struct lota_ac_session *s = lota_ac_init(&cfg);
	if (!s) {
		FAIL("init failed");
		return;
	}
	if (lota_ac_get_state(s) != LOTA_AC_STATE_TRUSTED) {
		FAIL("expected TRUSTED");
		lota_ac_shutdown(s);
		return;
	}

	struct lota_ac_info info;
	if (lota_ac_get_info(s, &info) != 0 ||
	    info.lota_flags != attested_flags) {
		FAIL("flags not propagated from snapshot");
		lota_ac_shutdown(s);
		return;
	}

	lota_ac_shutdown(s);
	PASS();
}

/*
 * With no token_dir configured the SDK has to look where the hook actually
 * writes -- $XDG_RUNTIME_DIR/lota-hook -- and not in $XDG_RUNTIME_DIR/lota,
 * which belongs to the daemon and holds the container socket.
 */
static void auto_token_dir_is_the_hooks_dir(const char *env)
{
	char xdg[512];
	char hookdir[600];
	char daemondir[600];
	const char *saved_xdg = getenv("XDG_RUNTIME_DIR");
	char saved[512] = { 0 };

	if (saved_xdg)
		snprintf(saved, sizeof(saved), "%s", saved_xdg);

	snprintf(xdg, sizeof(xdg), "%s/auto_xdg", test_dir);
	mkdir(xdg, 0700);
	snprintf(hookdir, sizeof(hookdir), "%s/lota-hook", xdg);
	mkdir(hookdir, 0700);
	snprintf(daemondir, sizeof(daemondir), "%s/lota", xdg);
	mkdir(daemondir, 0700);

	const uint32_t attested_flags = 0x07;
	write_wine_status_file(hookdir, attested_flags,
			       (uint64_t)time(NULL) + 3600);
	write_mock_snapshot(hookdir, attested_flags);

	setenv("XDG_RUNTIME_DIR", xdg, 1);
	if (env)
		setenv("LOTA_HOOK_TOKEN_DIR", env, 1);
	else
		unsetenv("LOTA_HOOK_TOKEN_DIR");

	struct lota_ac_config cfg = {
		.struct_size = sizeof(cfg),
		.provider = LOTA_AC_PROVIDER_EAC,
		.game_id = "auto-token-dir",
		.token_dir = NULL,
	};
	struct lota_ac_session *s = lota_ac_init(&cfg);

	unsetenv("LOTA_HOOK_TOKEN_DIR");
	if (saved[0])
		setenv("XDG_RUNTIME_DIR", saved, 1);
	else
		unsetenv("XDG_RUNTIME_DIR");

	if (!s) {
		FAIL("init failed");
		return;
	}
	if (lota_ac_get_state(s) != LOTA_AC_STATE_TRUSTED) {
		FAIL("did not read the hook's directory");
		lota_ac_shutdown(s);
		return;
	}
	lota_ac_shutdown(s);
	PASS();
}

static void test_auto_token_dir_is_the_hooks_dir(void)
{
	TEST("auto-detected token dir is the hook's, not the daemon's");
	auto_token_dir_is_the_hooks_dir(NULL);
}

/* the hook skips an empty override, so the consumer does too */
static void test_empty_token_dir_override_is_skipped(void)
{
	TEST("an empty LOTA_HOOK_TOKEN_DIR is no override");
	auto_token_dir_is_the_hooks_dir("");
}

static void test_integration_eac_detects_agent_death(void)
{
	TEST("integration: snapshot disappears mid-session -> ERROR");
	char dir[512];
	snprintf(dir, sizeof(dir), "%s/agent_death", test_dir);
	mkdir(dir, 0700);

	write_mock_snapshot(dir, 0x07);

	struct lota_ac_config cfg = {
		.struct_size = sizeof(cfg),
		.provider = LOTA_AC_PROVIDER_EAC,
		.game_id = "agent-death",
		.token_dir = dir,
	};
	struct lota_ac_session *s = lota_ac_init(&cfg);
	if (!s) {
		FAIL("init failed");
		return;
	}
	if (lota_ac_get_state(s) != LOTA_AC_STATE_TRUSTED) {
		FAIL("preconditions: expected TRUSTED");
		lota_ac_shutdown(s);
		return;
	}

	/* simulate wine hook + agent stopping: snapshot pulled off disk */
	if (unlink_in_dir(dir, LOTA_SNAPSHOT_FILE_NAME) != 0) {
		FAIL("unlink snapshot");
		lota_ac_shutdown(s);
		return;
	}

	if (lota_ac_tick(s) != -ENOENT) {
		FAIL("tick did not report the missing snapshot");
		lota_ac_shutdown(s);
		return;
	}
	if (lota_ac_get_state(s) != LOTA_AC_STATE_ERROR) {
		FAIL("expected ERROR after snapshot loss");
		lota_ac_shutdown(s);
		return;
	}

	struct lota_ac_info info;
	if (lota_ac_get_info(s, &info) != 0 || info.lota_flags != 0) {
		FAIL("flags not cleared on agent death");
		lota_ac_shutdown(s);
		return;
	}

	lota_ac_shutdown(s);
	PASS();
}

static void test_integration_eac_detects_attestation_loss(void)
{
	TEST("integration: attestation revoked mid-session -> UNTRUSTED");
	char dir[512];
	snprintf(dir, sizeof(dir), "%s/att_loss", test_dir);
	mkdir(dir, 0700);

	write_mock_snapshot(dir, 0x07);

	struct lota_ac_config cfg = {
		.struct_size = sizeof(cfg),
		.provider = LOTA_AC_PROVIDER_EAC,
		.game_id = "attestation-loss",
		.token_dir = dir,
		.required_flags = 0x07,
	};
	struct lota_ac_session *s = lota_ac_init(&cfg);
	if (!s) {
		FAIL("init failed");
		return;
	}
	if (lota_ac_get_state(s) != LOTA_AC_STATE_TRUSTED) {
		FAIL("preconditions: expected TRUSTED");
		lota_ac_shutdown(s);
		return;
	}

	/* agent still writes snapshots, but attestation flag bit cleared */
	write_mock_snapshot(dir, 0x00);

	if (lota_ac_tick(s) != 0) {
		FAIL("tick reported error");
		lota_ac_shutdown(s);
		return;
	}
	if (lota_ac_get_state(s) != LOTA_AC_STATE_UNTRUSTED) {
		FAIL("expected UNTRUSTED after revocation");
		lota_ac_shutdown(s);
		return;
	}

	lota_ac_shutdown(s);
	PASS();
}

static void test_session_id_unique(void)
{
	TEST("session_id: different sessions have different IDs");
	write_mock_snapshot(test_dir, 0x07);

	struct lota_ac_config cfg = {
		.struct_size = sizeof(cfg),
		.provider = LOTA_AC_PROVIDER_EAC,
		.game_id = "test-unique",
		.token_dir = test_dir,
	};
	struct lota_ac_session *s1 = lota_ac_init(&cfg);
	struct lota_ac_session *s2 = lota_ac_init(&cfg);
	if (!s1 || !s2) {
		FAIL("init failed");
		lota_ac_shutdown(s1);
		lota_ac_shutdown(s2);
		return;
	}

	struct lota_ac_info i1, i2;
	lota_ac_get_info(s1, &i1);
	lota_ac_get_info(s2, &i2);
	lota_ac_shutdown(s1);
	lota_ac_shutdown(s2);

	if (memcmp(i1.session_id, i2.session_id, LOTA_AC_SESSION_ID_SIZE) != 0)
		PASS();
	else
		FAIL("same session_id");
}

/*
 * TRUSTED is documented as "attested", so a host that has never completed a round
 * must not reach it -- least of all under the permissive configuration a first
 * integration reaches for.
 * A status word is non-zero as soon as the agent has a TPM handle, which is not
 * a verdict from anybody.
 */
static void test_unattested_host_is_not_trusted(void)
{
	char dir[512];

	TEST("no ATTESTED flag -> UNTRUSTED even with no requirement");
	snprintf(dir, sizeof(dir), "%s/unattested", test_dir);
	mkdir(dir, 0700);

	/* TPM_OK | IOMMU_OK: the agent is up, nobody has attested it */
	write_mock_snapshot(dir, LOTA_FLAG_TPM_OK | LOTA_FLAG_IOMMU_OK);

	struct lota_ac_config cfg = {
		.struct_size = sizeof(cfg),
		.provider = LOTA_AC_PROVIDER_EAC,
		.game_id = "unattested",
		.token_dir = dir,
		.required_flags = 0,
	};
	struct lota_ac_session *s = lota_ac_init(&cfg);
	if (!s) {
		FAIL("init failed");
		return;
	}

	if (lota_ac_get_state(s) == LOTA_AC_STATE_TRUSTED)
		FAIL("a host that never attested is called trusted");
	else if (lota_ac_get_state(s) != LOTA_AC_STATE_UNTRUSTED)
		FAIL("expected UNTRUSTED");
	else
		PASS();

	lota_ac_shutdown(s);
}

/* required_flags raises the bar; it cannot lower it below attestation */
static void test_required_flags_cannot_drop_attested(void)
{
	char dir[512];

	TEST("required_flags without ATTESTED still needs ATTESTED");
	snprintf(dir, sizeof(dir), "%s/req_no_att", test_dir);
	mkdir(dir, 0700);

	write_mock_snapshot(dir, LOTA_FLAG_TPM_OK | LOTA_FLAG_IOMMU_OK);

	struct lota_ac_config cfg = {
		.struct_size = sizeof(cfg),
		.provider = LOTA_AC_PROVIDER_EAC,
		.game_id = "req-no-att",
		.token_dir = dir,
		.required_flags = LOTA_FLAG_TPM_OK,
	};
	struct lota_ac_session *s = lota_ac_init(&cfg);
	if (!s) {
		FAIL("init failed");
		return;
	}

	if (lota_ac_get_state(s) != LOTA_AC_STATE_UNTRUSTED)
		FAIL("a requirement that omits ATTESTED trusted the host");
	else
		PASS();

	lota_ac_shutdown(s);
}

/*
 * The two roads out of one session have to answer the same thing.
 * Both are local telemetry and neither is authoritative -- that is what
 * the header says about the info road -- so disagreeing buys nothing
 * and costs an integrator the bug.
 */
static void test_info_agrees_with_state(void)
{
	struct lota_ac_info info;
	char dir[512];

	TEST("get_info reports the state get_state reports");
	snprintf(dir, sizeof(dir), "%s/info_agree", test_dir);
	mkdir(dir, 0700);

	write_mock_snapshot(dir, LOTA_FLAG_ATTESTED | LOTA_FLAG_TPM_OK);

	struct lota_ac_config cfg = {
		.struct_size = sizeof(cfg),
		.provider = LOTA_AC_PROVIDER_EAC,
		.game_id = "info-agree",
		.token_dir = dir,
	};
	struct lota_ac_session *s = lota_ac_init(&cfg);
	if (!s) {
		FAIL("init failed");
		return;
	}

	if (lota_ac_get_state(s) != LOTA_AC_STATE_TRUSTED) {
		FAIL("preconditions: expected TRUSTED");
		lota_ac_shutdown(s);
		return;
	}

	if (lota_ac_get_info(s, &info) != 0) {
		FAIL("get_info failed");
		lota_ac_shutdown(s);
		return;
	}

	if (info.state != LOTA_AC_STATE_TRUSTED)
		FAIL("info.state disagrees with get_state");
	else if (!info.trusted)
		FAIL("info.trusted is clear on a trusted session");
	else
		PASS();

	lota_ac_shutdown(s);
}

/* Every code this library defines, for the checks that must cover all of them */
static const int ac_error_codes[] = {
	LOTA_AC_ERR_INVALID_ARG,     LOTA_AC_ERR_MALFORMED,
	LOTA_AC_ERR_VERSION,	     LOTA_AC_ERR_SIG_FAIL,
	LOTA_AC_ERR_NONCE_FAIL,	     LOTA_AC_ERR_EXPIRED,
	LOTA_AC_ERR_CRYPTO,	     LOTA_AC_ERR_CONFIG_SIZE,
	LOTA_AC_ERR_GAME_ID,	     LOTA_AC_ERR_PROVIDER,
	LOTA_AC_ERR_NO_MEMORY,	     LOTA_AC_ERR_INTERNAL,
	LOTA_AC_ERR_NO_AGENT,	     LOTA_AC_ERR_CONSENT_REQUIRED,
	LOTA_AC_ERR_UNKNOWN_PROFILE, LOTA_AC_ERR_ACCESS_DENIED,
	LOTA_AC_ERR_TOKEN_DIR,	     LOTA_AC_ERR_NOT_ATTESTED,
	LOTA_AC_ERR_RATE_LIMITED,    LOTA_AC_ERR_STATUS,
	LOTA_AC_ERR_TOKEN,	     LOTA_AC_ERR_MEASURE,
	LOTA_AC_ERR_SERIALIZE,	     LOTA_AC_ERR_NO_EVIDENCE,
	LOTA_AC_ERR_BAD_EVIDENCE,
};

/* The errno values the measure helpers are documented to return */
static const int helper_errnos[] = {
	EPERM, ENOENT, EIO, E2BIG, ENOEXEC, ENOMEM, EINVAL,
};

static int renders_as_a_verdict(int err)
{
	const char *s = lota_ac_strerror(err);
	size_t i;

	for (i = 0; i < sizeof(ac_error_codes) / sizeof(ac_error_codes[0]);
	     i++) {
		if (strcmp(s, lota_ac_strerror(ac_error_codes[i])) == 0)
			return 1;
	}
	return 0;
}

/*
 * Two numbering spaces must not share a range.
 * The measure helpers return negative errno by their documented contract,
 * so an integrator printing this library's own message for one of them was
 * told about heartbeat nonces and signature failures that never happened.
 */
static void test_errno_is_not_rendered_as_a_verdict(void)
{
	size_t i;

	TEST("strerror: an errno does not render as a verdict");

	for (i = 0; i < sizeof(helper_errnos) / sizeof(helper_errnos[0]); i++) {
		if (renders_as_a_verdict(-helper_errnos[i])) {
			printf("(errno %d) ", helper_errnos[i]);
			FAIL("an errno renders as one of this library's codes");
			return;
		}
	}

	PASS();
}

/* The guard: no code may occupy a number an errno could occupy */
static void test_error_codes_sit_outside_the_errno_range(void)
{
	size_t i;

	TEST("codes: none of them can collide with an errno");

	for (i = 0; i < sizeof(ac_error_codes) / sizeof(ac_error_codes[0]);
	     i++) {
		if (ac_error_codes[i] > -256) {
			printf("(%d) ", ac_error_codes[i]);
			FAIL("a code sits where an errno sits");
			return;
		}
	}

	PASS();
}

/*
 * The trigger, as an integrator meets it: a file that is not an ELF object
 * fails the precompute helper, and the natural next line is to print this
 * library's message for what came back.
 */
static void test_measure_failure_does_not_render_as_a_verdict(void)
{
	uint8_t out[LOTA_AC_RUNTIME_MEASURE_SIZE];
	char path[512];
	const char *vec[1];
	int rc;

	TEST("a failed measurement does not render as a verdict");

	snprintf(path, sizeof(path), "%s/not-an-elf", test_dir);
	write_test_file(test_dir, "not-an-elf", "no", 2);

	vec[0] = path;
	rc = lota_ac_compute_expected_runtime_measure_set(vec, 1, out);
	if (rc == 0) {
		FAIL("preconditions: a non-ELF file was measured");
		return;
	}

	if (renders_as_a_verdict(rc)) {
		printf("(%s) ", lota_ac_strerror(rc));
		FAIL("the failure is reported as a heartbeat verdict");
		return;
	}

	PASS();
}

/*
 * A heartbeat that survives verification: the same packet the bound builder makes,
 * but carrying a token signed by @key over the nonce this packet binds.
 * Nothing short of this reaches the verdict lota_ac_verify_heartbeat() renders,
 * because everything before it refuses first.
 */
static int build_signed_heartbeat_packet(
	EVP_PKEY *key, uint8_t *out, size_t out_cap, size_t *out_len,
	uint8_t provider, const char *game_id, uint32_t flags,
	uint32_t pid_count, uint8_t out_game_hash[LOTA_AC_GAME_HASH_SIZE],
	uint8_t out_rm[LOTA_AC_RUNTIME_MEASURE_SIZE])
{
	uint8_t session_id[LOTA_AC_SESSION_ID_SIZE];
	uint8_t nonce[32];
	uint8_t token[LOTA_TOKEN_MAX_SIZE];
	uint64_t timestamp = (uint64_t)time(NULL);
	size_t token_len = 0;
	size_t total;
	int ret;

	for (int i = 0; i < (int)sizeof(session_id); i++)
		session_id[i] = (uint8_t)(0xA0 + i);

	if (compute_game_id_hash_test(game_id, out_game_hash) != 0)
		return -EIO;
	if (lota_ac_compute_runtime_measure(out_rm) != 0)
		return -EIO;
	if (compute_hb_nonce_test(nonce, session_id, provider, 0, timestamp,
				  out_game_hash, out_rm,
				  LOTA_AC_DOMAIN_VERSION_CURRENT) != 0)
		return -EIO;

	if (pid_count == 0)
		ret = forge_token_sha256(
			key, timestamp + LOTA_SERVER_MAX_TOKEN_AGE_SEC, flags,
			nonce, token, sizeof(token), &token_len);
	else
		ret = forge_token_protected_n(
			key, timestamp + LOTA_SERVER_MAX_TOKEN_AGE_SEC, flags,
			nonce, pid_count, token, sizeof(token), &token_len);
	if (ret != LOTA_OK)
		return -EIO;

	total = LOTA_AC_HEADER_SIZE + token_len;
	if (total > out_cap)
		return -ENOSPC;

	write_le32(out + 0, LOTA_AC_MAGIC);
	out[4] = LOTA_AC_VERSION;
	out[5] = provider;
	write_le16(out + 6, (uint16_t)total);
	memcpy(out + 8, session_id, sizeof(session_id));
	write_le32(out + 24, 0);
	write_le32(out + 28, flags);
	for (int i = 0; i < 8; i++)
		out[32 + i] = (uint8_t)((timestamp >> (8 * i)) & 0xFF);
	memcpy(out + 40, out_game_hash, LOTA_AC_GAME_HASH_SIZE);
	write_le16(out + 72, (uint16_t)token_len);
	write_le32(out + 74, LOTA_AC_DOMAIN_VERSION_CURRENT);
	memcpy(out + 78, out_rm, LOTA_AC_RUNTIME_MEASURE_SIZE);
	memcpy(out + LOTA_AC_HEADER_SIZE, token, token_len);

	*out_len = total;
	return 0;
}

/*
 * The verdict a backend acts on, over a packet with nothing wrong with it.
 *
 * @flags is the status word the token carries. TRUSTED is documented as attested,
 * so a word without LOTA_FLAG_ATTESTED must not reach it however genuine
 * the packet around it is.
 */
static int verified_state(uint32_t flags, uint32_t pid_count,
			  enum lota_ac_state *state, int *trusted)
{
	uint8_t buf[LOTA_AC_HEADER_SIZE + LOTA_TOKEN_MAX_SIZE];
	uint8_t game_hash[LOTA_AC_GAME_HASH_SIZE];
	uint8_t rm[LOTA_AC_RUNTIME_MEASURE_SIZE];
	struct lota_ac_info info;
	EVP_PKEY *key = forge_rsa_key();
	uint8_t *aik_der = NULL;
	size_t aik_len = 0;
	size_t written = 0;
	int ret;

	if (!key)
		return -EIO;

	aik_der = forge_pubkey_der(key, &aik_len);
	if (!aik_der) {
		EVP_PKEY_free(key);
		return -EIO;
	}

	ret = build_signed_heartbeat_packet(key, buf, sizeof(buf), &written,
					    LOTA_AC_PROVIDER_EAC,
					    "verified-trust", flags, pid_count,
					    game_hash, rm);
	if (ret == 0) {
		ret = lota_ac_verify_heartbeat(buf, written, aik_der, aik_len,
					       game_hash, rm, &info);
		if (ret == LOTA_AC_ERR_OK) {
			*state = info.state;
			*trusted = info.trusted;
		}
	}

	free(aik_der);
	EVP_PKEY_free(key);
	return ret;
}

static void test_verified_unattested_host_is_not_trusted(void)
{
	enum lota_ac_state state = LOTA_AC_STATE_IDLE;
	int trusted = -1;
	int ret;

	TEST("verify: a genuine packet from an unattested host is untrusted");

	/* TPM_OK | IOMMU_OK: the agent is up, nobody has attested it */
	ret = verified_state(LOTA_FLAG_TPM_OK | LOTA_FLAG_IOMMU_OK, 0, &state,
			     &trusted);
	if (ret != LOTA_AC_ERR_OK) {
		printf("(rc=%d) ", ret);
		FAIL("preconditions: the packet did not verify");
		return;
	}

	if (trusted || state == LOTA_AC_STATE_TRUSTED)
		FAIL("a host that never attested verified as trusted");
	else if (state != LOTA_AC_STATE_UNTRUSTED)
		FAIL("expected UNTRUSTED");
	else
		PASS();
}

static void test_verified_attested_host_is_trusted(void)
{
	enum lota_ac_state state = LOTA_AC_STATE_IDLE;
	int trusted = -1;
	int ret;

	TEST("verify: a genuine packet from an attested host is trusted");

	ret = verified_state(LOTA_FLAG_ATTESTED | LOTA_FLAG_TPM_OK, 0, &state,
			     &trusted);
	if (ret != LOTA_AC_ERR_OK) {
		printf("(rc=%d) ", ret);
		FAIL("preconditions: the packet did not verify");
		return;
	}

	if (!trusted || state != LOTA_AC_STATE_TRUSTED)
		FAIL("an attested host did not verify as trusted");
	else
		PASS();
}

static void test_verified_full_protected_set(void)
{
	enum lota_ac_state state = LOTA_AC_STATE_IDLE;
	int trusted = -1;
	int ret;

	TEST("verify: a token with the full protected set verifies");

	ret = verified_state(LOTA_FLAG_ATTESTED | LOTA_FLAG_TPM_OK,
			     LOTA_TOKEN_MAX_PROTECT_PIDS, &state, &trusted);
	if (ret != LOTA_AC_ERR_OK) {
		printf("(rc=%d) ", ret);
		FAIL("the packet did not verify");
	} else if (!trusted || state != LOTA_AC_STATE_TRUSTED) {
		FAIL("an attested host did not verify as trusted");
	} else {
		PASS();
	}
}

/* Snapshot holding a token with the full protected set */
static size_t write_full_set_snapshot(const char *dir, uint32_t flags)
{
	static uint8_t buf[LOTA_SNAPSHOT_HEADER_SIZE + LOTA_TOKEN_MAX_SIZE];
	uint8_t nonce[32] = { 0 };
	size_t tok_len = 0;
	EVP_PKEY *key = forge_rsa_key();
	int ret;

	if (!key)
		return 0;
	ret = forge_token_protected_n(key, (uint64_t)time(NULL) + 60, flags,
				      nonce, LOTA_TOKEN_MAX_PROTECT_PIDS,
				      buf + LOTA_SNAPSHOT_HEADER_SIZE,
				      LOTA_TOKEN_MAX_SIZE, &tok_len);
	EVP_PKEY_free(key);
	if (ret != LOTA_OK)
		return 0;

	write_le32(buf + 0, LOTA_SNAPSHOT_MAGIC);
	write_le16(buf + 4, (uint16_t)LOTA_SNAPSHOT_VERSION);
	write_le16(buf + 6, 0);
	write_le32(buf + 8, flags);
	write_le32(buf + 12, (uint32_t)tok_len);
	write_test_file(dir, LOTA_SNAPSHOT_FILE_NAME, buf,
			LOTA_SNAPSHOT_HEADER_SIZE + tok_len);
	return tok_len;
}

static void test_file_mode_full_protected_set(void)
{
	struct lota_ac_config cfg = {
		.struct_size = sizeof(cfg),
		.provider = LOTA_AC_PROVIDER_EAC,
		.game_id = "test-full-set",
		.token_dir = test_dir,
	};
	struct lota_ac_session *s;
	size_t tok_len;
	int ret;

	TEST("file mode: a snapshot with the full protected set is read");

	tok_len = write_full_set_snapshot(test_dir, 0x07);
	if (tok_len <= 1608) {
		FAIL("preconditions: the forged token is not above 1608 bytes");
		return;
	}
	s = lota_ac_init(&cfg);
	if (!s) {
		FAIL("init returned NULL");
		return;
	}

	ret = lota_ac_tick(s);
	if (ret != 0) {
		printf("(rc=%d, err=%d) ", ret, lota_ac_last_error());
		FAIL("the snapshot was refused");
	} else if (lota_ac_get_state(s) != LOTA_AC_STATE_TRUSTED) {
		FAIL("expected TRUSTED");
	} else {
		PASS();
	}
	lota_ac_shutdown(s);
}

/* Hang up on a GET_TOKEN that carries a nonce */
static int full_set_hangup_on_nonce;

/*
 * Answer GET_STATUS and GET_TOKEN with the full protected set.
 * The status word carries a bit the token's flags do not.
 */
static void full_set_agent_serve(int fd)
{
	static uint8_t token[LOTA_IPC_TOKEN_HEADER_SIZE +
			     LOTA_IPC_TOKEN_MAX_PID_LIST_SIZE +
			     LOTA_IPC_TOKEN_MAX_REGISTRY_LIST_SIZE + 64 + 256];
	struct lota_ipc_token_request token_req;
	struct lota_ipc_response resp = {
		.magic = LOTA_IPC_MAGIC,
		.version = LOTA_IPC_VERSION,
		.result = LOTA_IPC_OK,
	};
	struct lota_ipc_status status = {
		.flags = 0x07 | LOTA_FLAG_UPDATE_PENDING,
	};
	struct lota_ipc_token hdr = {
		.valid_until = (uint64_t)time(NULL) + 60,
		.flags = 0x07,
		.attest_size = 64,
		.sig_size = 256,
		.sig_alg = 0x0014,
		.hash_alg = 0x000B,
		.pcr_mask = 0x4001,
		.protect_pid_count = LOTA_IPC_TOKEN_MAX_PROTECT_PIDS,
		.pid_list_size = LOTA_IPC_TOKEN_MAX_PID_LIST_SIZE,
		.runtime_protect_version = LOTA_IPC_RUNTIME_PROTECT_V1,
	};
	struct lota_ipc_request req;
	uint8_t *p;

	while (recv(fd, &req, sizeof(req), MSG_WAITALL) == sizeof(req)) {
		const void *payload = NULL;

		memset(&token_req, 0, sizeof(token_req));
		if (req.payload_len == sizeof(token_req) &&
		    recv(fd, &token_req, sizeof(token_req), MSG_WAITALL) !=
			    sizeof(token_req))
			break;

		resp.payload_len = 0;
		if (req.cmd == LOTA_IPC_CMD_GET_STATUS) {
			payload = &status;
			resp.payload_len = sizeof(status);
		} else if (req.cmd == LOTA_IPC_CMD_GET_TOKEN) {
			static const uint8_t zero[32];

			if (full_set_hangup_on_nonce &&
			    memcmp(token_req.nonce, zero, sizeof(zero)) != 0)
				break;
			memcpy(hdr.client_nonce, token_req.nonce, 32);
			memset(token, 0x5A, sizeof(token));
			memcpy(token, &hdr, sizeof(hdr));
			p = token + sizeof(hdr);
			for (uint32_t i = 0;
			     i < LOTA_IPC_TOKEN_MAX_PROTECT_PIDS; i++, p += 4)
				write_le32(p, 4242 + i);
			payload = token;
			resp.payload_len = sizeof(token);
		}
		if (send(fd, &resp, sizeof(resp), MSG_NOSIGNAL) !=
			    sizeof(resp) ||
		    (resp.payload_len &&
		     send(fd, payload, resp.payload_len, MSG_NOSIGNAL) !=
			     (ssize_t)resp.payload_len))
			break;
	}
}

/* The token in @pkt answers the nonce its header fields give */
static int heartbeat_nonce_matches(const uint8_t *pkt, size_t len)
{
	struct lota_server_claims claims;
	uint8_t nonce[32];
	uint32_t sequence = (uint32_t)pkt[24] | (uint32_t)pkt[25] << 8 |
			    (uint32_t)pkt[26] << 16 | (uint32_t)pkt[27] << 24;
	uint32_t flags = (uint32_t)pkt[28] | (uint32_t)pkt[29] << 8 |
			 (uint32_t)pkt[30] << 16 | (uint32_t)pkt[31] << 24;
	uint64_t timestamp = 0;

	for (int i = 7; i >= 0; i--)
		timestamp = timestamp << 8 | pkt[32 + i];
	if (compute_hb_nonce_test(nonce, pkt + 8, pkt[5], sequence, timestamp,
				  pkt + 40, pkt + 78,
				  LOTA_AC_DOMAIN_VERSION_CURRENT) != 0)
		return 0;
	if (lota_server_parse_token(pkt + LOTA_AC_HEADER_SIZE,
				    len - LOTA_AC_HEADER_SIZE,
				    &claims) != LOTA_SERVER_OK)
		return 0;
	return memcmp(claims.nonce, nonce, sizeof(nonce)) == 0 &&
	       claims.flags == flags;
}

static void test_direct_mode_full_protected_set(void)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	uint8_t buf[LOTA_AC_MAX_HEARTBEAT];
	struct lota_ac_session *s;
	size_t written = 0;
	pid_t agent;
	int ret;
	int fd;

	TEST("direct mode: a token with the full protected set is sent");
	if (snprintf(addr.sun_path, sizeof(addr.sun_path), "%s/full.sock",
		     test_dir) >= (int)sizeof(addr.sun_path)) {
		FAIL("the socket path does not fit");
		return;
	}
	unlink(addr.sun_path);
	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0 || bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
	    listen(fd, 1) != 0) {
		FAIL("cannot listen on a unix socket");
		if (fd >= 0)
			close(fd);
		return;
	}
	/* the second connection loses the agent on the heartbeat's token */
	agent = fork();
	if (agent == 0) {
		for (int n = 0; n < 2; n++) {
			int c = accept(fd, NULL, NULL);

			if (c < 0)
				break;
			full_set_hangup_on_nonce = n;
			full_set_agent_serve(c);
			close(c);
		}
		_exit(0);
	}
	close(fd);
	if (agent < 0) {
		FAIL("fork");
		unlink(addr.sun_path);
		return;
	}

	struct lota_ac_config cfg = {
		.struct_size = sizeof(cfg),
		.provider = LOTA_AC_PROVIDER_EAC,
		.game_id = "test-full-set",
		.direct = 1,
		.socket_path = addr.sun_path,
	};
	s = lota_ac_init(&cfg);
	if (!s) {
		FAIL("init returned NULL");
	} else {
		ret = lota_ac_heartbeat(s, buf, sizeof(buf), &written);
		if (ret != 0) {
			printf("(rc=%d, err=%d) ", ret, lota_ac_last_error());
			FAIL("heartbeat failed");
		} else if (written <= LOTA_AC_HEADER_SIZE + 1608) {
			FAIL("the heartbeat does not carry the whole token");
		} else {
			PASS();
		}

		TEST("direct mode: the heartbeat nonce follows its header");
		if (ret != 0)
			FAIL("no heartbeat was built");
		else if (!heartbeat_nonce_matches(buf, written))
			FAIL("the token's nonce or flags are not the header's");
		else
			PASS();
		lota_ac_shutdown(s);
	}

	TEST("direct mode: a heartbeat that loses the agent sets ERROR");
	s = lota_ac_init(&cfg);
	if (!s) {
		FAIL("init returned NULL");
	} else if (lota_ac_get_state(s) != LOTA_AC_STATE_TRUSTED) {
		FAIL("preconditions: the session did not start TRUSTED");
		lota_ac_shutdown(s);
	} else {
		ret = lota_ac_heartbeat(s, buf, sizeof(buf), &written);
		if (ret != -EIO || lota_ac_last_error() != LOTA_AC_ERR_TOKEN) {
			printf("(rc=%d, err=%d) ", ret, lota_ac_last_error());
			FAIL("expected -EIO and LOTA_AC_ERR_TOKEN");
		} else if (lota_ac_get_state(s) != LOTA_AC_STATE_ERROR) {
			FAIL("the session stayed in its old state");
		} else {
			PASS();
		}
		lota_ac_shutdown(s);
	}
	kill(agent, SIGKILL);
	waitpid(agent, NULL, 0);
	unlink(addr.sun_path);
}

/* Boot evidence */

static void ac_evidence_path(char *out, size_t len)
{
	snprintf(out, len, "%s/%s", test_dir, LOTA_HOOK_BOOT_EVIDENCE_FILE);
}

static struct lota_ac_session *file_mode_session(void)
{
	struct lota_ac_config cfg = {
		.struct_size = sizeof(cfg),
		.provider = LOTA_AC_PROVIDER_EAC,
		.game_id = "test-evidence",
		.token_dir = test_dir,
	};

	write_mock_snapshot(test_dir, 0x07);
	return lota_ac_init(&cfg);
}

static void test_boot_evidence_file_mode(void)
{
	char path[512];
	uint8_t want[40], got[64];
	size_t written = 0;
	struct lota_ac_session *s;
	int ret;

	TEST("boot evidence: file mode hands back the hook's file");
	for (size_t i = 0; i < sizeof(want); i++)
		want[i] = (uint8_t)(0x40 + i);
	ac_evidence_path(path, sizeof(path));
	write_test_file(test_dir, LOTA_HOOK_BOOT_EVIDENCE_FILE, want,
			sizeof(want));

	s = file_mode_session();
	if (!s) {
		FAIL("init returned NULL");
		return;
	}
	ret = lota_ac_boot_evidence(s, got, sizeof(got), &written);
	if (ret != 0 || written != sizeof(want) ||
	    memcmp(got, want, sizeof(want)) != 0)
		FAIL("the evidence is not the file's");
	else
		PASS();

	TEST("boot evidence: a buffer too small is refused");
	ret = lota_ac_boot_evidence(s, got, 16, &written);
	if (ret == -ENOSPC && lota_ac_last_error() == LOTA_AC_ERR_INVALID_ARG)
		PASS();
	else
		FAIL("a short buffer was filled");

	TEST("boot evidence: no file means no evidence");
	unlink(path);
	ret = lota_ac_boot_evidence(s, got, sizeof(got), &written);
	if (ret == -ENODATA && lota_ac_last_error() == LOTA_AC_ERR_NO_EVIDENCE)
		PASS();
	else
		FAIL("a missing file was not NO_EVIDENCE");

	TEST("boot evidence: NULL arguments are refused");
	if (lota_ac_boot_evidence(NULL, got, sizeof(got), &written) ==
		    -EINVAL &&
	    lota_ac_boot_evidence(s, NULL, sizeof(got), &written) == -EINVAL &&
	    lota_ac_boot_evidence(s, got, sizeof(got), NULL) == -EINVAL)
		PASS();
	else
		FAIL("a NULL argument was accepted");

	lota_ac_shutdown(s);
}

static void test_boot_evidence_no_agent(void)
{
	struct lota_ac_config cfg = {
		.struct_size = sizeof(cfg),
		.provider = LOTA_AC_PROVIDER_EAC,
		.game_id = "test-evidence-direct",
		.direct = 1,
		.socket_path = "/tmp/lota_nonexistent_socket_for_test",
	};
	struct lota_ac_session *s = lota_ac_init(&cfg);
	uint8_t buf[64];
	size_t written = 0;

	TEST("boot evidence: direct mode without an agent");
	if (!s) {
		FAIL("init returned NULL");
		return;
	}
	if (lota_ac_boot_evidence(s, buf, sizeof(buf), &written) == -ENOTCONN &&
	    lota_ac_last_error() == LOTA_AC_ERR_NO_AGENT)
		PASS();
	else
		FAIL("expected -ENOTCONN and NO_AGENT");
	lota_ac_shutdown(s);
}

/* PCR 7 alone: a SecureBoot=1 measurement, then the separator */
static size_t secure_boot_evidence(uint8_t *out, struct lota_ac_info *info)
{
	static const uint8_t guid[16] = {
		0x61, 0xdf, 0xe4, 0x8b, 0xca, 0x93, 0xd2, 0x11,
		0xaa, 0x0d, 0x00, 0xe0, 0x98, 0x03, 0x2b, 0x8c,
	};
	static const char name[] = "SecureBoot";
	uint8_t var[64], digests[2][32], chain[64] = { 0 };
	uint8_t separator[4] = { 0 };
	size_t var_len = 0, off;

	memcpy(var, guid, sizeof(guid));
	var_len = sizeof(guid);
	memset(var + var_len, 0, 16);
	var[var_len] = (uint8_t)(sizeof(name) - 1);
	var[var_len + 8] = 1;
	var_len += 16;
	for (size_t i = 0; i < sizeof(name) - 1; i++) {
		var[var_len++] = (uint8_t)name[i];
		var[var_len++] = 0;
	}
	var[var_len++] = 1;

	test_sha256(var, var_len, digests[0]);
	test_sha256(separator, sizeof(separator), digests[1]);
	for (int i = 0; i < 2; i++) {
		memcpy(chain + 32, digests[i], 32);
		test_sha256(chain, sizeof(chain), chain);
	}

	write_le16(out, LOTA_BOOT_EVIDENCE_VERSION);
	write_le16(out + 2, 2);
	write_le32(out + 4, 1u << 7);
	memcpy(out + 8, chain, 32);
	off = 40;
	memcpy(out + off, digests[0], 32);
	write_le16(out + off + 32, (uint16_t)var_len);
	memcpy(out + off + 34, var, var_len);
	off += 34 + var_len;
	memcpy(out + off, digests[1], 32);
	write_le16(out + off + 32, 0);
	off += 34;

	memset(info, 0, sizeof(*info));
	info->pcr_mask = 1u << 7;
	test_sha256(chain, 32, info->pcr_digest);
	return off;
}

static void test_verify_boot_evidence(void)
{
	struct lota_ac_info info;
	uint8_t buf[256];
	size_t len = secure_boot_evidence(buf, &info);
	int sb = -1, ret;

	TEST("verify boot evidence: Secure Boot reads on");
	ret = lota_ac_verify_boot_evidence(&info, buf, len, &sb);
	if (ret == LOTA_AC_ERR_OK && sb == 1)
		PASS();
	else
		FAIL(lota_ac_strerror(ret));

	TEST("verify boot evidence: another boot's digest is refused");
	info.pcr_digest[0] ^= 1;
	sb = -1;
	ret = lota_ac_verify_boot_evidence(&info, buf, len, &sb);
	info.pcr_digest[0] ^= 1;
	if (ret == LOTA_AC_ERR_BAD_EVIDENCE && sb == 0 &&
	    lota_ac_last_error() == LOTA_AC_ERR_BAD_EVIDENCE)
		PASS();
	else
		FAIL("evidence of another boot passed");

	TEST("verify boot evidence: NULL arguments are refused");
	if (lota_ac_verify_boot_evidence(NULL, buf, len, &sb) ==
		    LOTA_AC_ERR_INVALID_ARG &&
	    lota_ac_verify_boot_evidence(&info, NULL, len, &sb) ==
		    LOTA_AC_ERR_INVALID_ARG &&
	    lota_ac_verify_boot_evidence(&info, buf, len, NULL) ==
		    LOTA_AC_ERR_INVALID_ARG)
		PASS();
	else
		FAIL("a NULL argument was accepted");
}

int main(void)
{
	printf("=== LOTA Anti-Cheat Compatibility Tests ===\n\n");

	setup_test_dir();

	printf("Config Validation:\n");
	test_init_null_config();
	test_init_struct_size();
	test_init_empty_game_id();
	test_init_null_game_id();
	test_init_game_id_too_long();
	test_init_invalid_provider();

	printf("\nSession Lifecycle:\n");
	test_init_eac_file_mode();
	test_init_eac_file_mode_snapshot_only();
	test_init_battleye_file_mode();
	test_shutdown_null();
	test_get_state_null();
	test_get_info_null();
	test_get_info_null_info();
	test_get_info_fields();

	printf("\nState Machine:\n");
	test_state_untrusted_zero_flags();
	test_state_required_flags();
	test_state_required_flags_met();
	test_state_no_files();
	test_state_malformed_snapshot();
	test_state_expired_snapshot();
	test_state_each_snapshot_failure_warns_once();

	printf("\nHeartbeat Wire Format:\n");
	test_heartbeat_game_id_hash_domain_separated();
	test_heartbeat_buf_too_small();
	test_heartbeat_null_args();

	printf("\nHeartbeat Verification:\n");
	test_verify_roundtrip();
	test_verify_battleye_roundtrip();
	test_verify_rejects_game_hash_mismatch();
	test_verify_null_data();
	test_verify_null_info();
	test_verify_truncated();
	test_verify_bad_magic();
	test_verify_bad_version();
	test_verify_bad_provider();
	test_verify_size_mismatch();
	test_verify_header_flags_tamper_rejected();
	test_verify_rejects_unknown_domain_version();
	test_verify_rejects_runtime_measure_mismatch();
	test_verify_rejects_runtime_field_tamper();

	printf("\nDirect Mode:\n");
	test_direct_mode_no_agent();

	printf("\nWhy a call failed:\n");
	test_last_error_init_causes();
	test_last_error_no_agent();
	test_last_error_bad_publisher();
	test_last_error_heartbeat_causes();
	test_last_error_measure_helpers();
	test_last_error_session_calls();
	test_last_error_verify_heartbeat();
	test_last_error_strings();

	printf("\nBoot evidence:\n");
	test_boot_evidence_file_mode();
	test_boot_evidence_no_agent();
	test_verify_boot_evidence();

	printf("\nIntegration:\n");
	test_integration_wine_artifacts_consumed_by_eac();
	test_auto_token_dir_is_the_hooks_dir();
	test_empty_token_dir_override_is_skipped();
	test_integration_eac_detects_agent_death();
	test_integration_eac_detects_attestation_loss();

	printf("\nMisc:\n");
	test_state_str();
	test_provider_str();
	test_tick_null();
	test_verified_unattested_host_is_not_trusted();
	test_verified_attested_host_is_trusted();
	test_verified_full_protected_set();
	test_file_mode_full_protected_set();
	test_direct_mode_full_protected_set();
	test_errno_is_not_rendered_as_a_verdict();
	test_error_codes_sit_outside_the_errno_range();
	test_measure_failure_does_not_render_as_a_verdict();
	test_unattested_host_is_not_trusted();
	test_required_flags_cannot_drop_attested();
	test_info_agrees_with_state();
	test_session_id_unique();
	test_runtime_measure_counts_a_vdso_named_object();
	test_runtime_measure_refuses_a_loader_start();

	cleanup_test_dir();

	printf("\n=== Results: %d/%d passed", tests_passed, tests_run);
	if (tests_passed < tests_run)
		printf(" (%d FAILED)", tests_run - tests_passed);
	printf(" ===\n\n");

	return tests_passed < tests_run ? 1 : 0;
}
