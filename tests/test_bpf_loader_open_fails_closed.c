/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * A libbpf call that returns NULL need not set errno, and `return -errno` then
 * reads as success. The calls are wrapped to fail with errno clear; a refusal
 * must still be negative.
 *
 * The map calls are wrapped over a table in memory, so the walks over the
 * per-process maps are checked without a kernel too.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "../src/agent/bpf_loader.h"
#include "../src/agent/policy_sign.h"

static int g_failures;

#define CHECK(cond, msg)                                    \
	do {                                                \
		if (!(cond)) {                              \
			fprintf(stderr, "FAIL: %s\n", msg); \
			g_failures++;                       \
		} else {                                    \
			printf("PASS: %s\n", msg);          \
		}                                           \
	} while (0)

/* --wrap targets need external linkage */
int __wrap_policy_verify_buffer(const uint8_t *data, size_t data_len,
				const char *pubkey_pem_path,
				const uint8_t *sig);
struct bpf_object *
__wrap_bpf_object__open_mem(const void *obj_buf, size_t obj_buf_sz,
			    const struct bpf_object_open_opts *opts);
struct bpf_program *
__wrap_bpf_object__next_program(const struct bpf_object *obj,
				struct bpf_program *prog);
enum bpf_prog_type __wrap_bpf_program__type(const struct bpf_program *prog);
const char *__wrap_bpf_program__name(const struct bpf_program *prog);
struct bpf_link *__wrap_bpf_program__attach(const struct bpf_program *prog);
struct ring_buffer *
__wrap_ring_buffer__new(int map_fd, ring_buffer_sample_fn sample_cb, void *ctx,
			const struct ring_buffer_opts *opts);
int __wrap_bpf_map_get_next_key(int fd, const void *key, void *next_key);
int __wrap_bpf_map_lookup_elem(int fd, const void *key, void *value);
int __wrap_bpf_map_delete_elem(int fd, const void *key);

int __wrap_policy_verify_buffer(const uint8_t *data, size_t data_len,
				const char *pubkey_pem_path, const uint8_t *sig)
{
	(void)data;
	(void)data_len;
	(void)pubkey_pem_path;
	(void)sig;
	return 0;
}

struct bpf_object *
__wrap_bpf_object__open_mem(const void *obj_buf, size_t obj_buf_sz,
			    const struct bpf_object_open_opts *opts)
{
	(void)obj_buf;
	(void)obj_buf_sz;
	(void)opts;
	errno = 0;
	return NULL;
}

/* one program in the object, then the end of the walk */
static int g_fake_prog;

struct bpf_program *
__wrap_bpf_object__next_program(const struct bpf_object *obj,
				struct bpf_program *prog)
{
	(void)obj;
	if (prog)
		return NULL;
	return (struct bpf_program *)&g_fake_prog;
}

enum bpf_prog_type __wrap_bpf_program__type(const struct bpf_program *prog)
{
	(void)prog;
	return BPF_PROG_TYPE_LSM;
}

const char *__wrap_bpf_program__name(const struct bpf_program *prog)
{
	(void)prog;
	return "lota_bprm_check_security";
}

struct bpf_link *__wrap_bpf_program__attach(const struct bpf_program *prog)
{
	(void)prog;
	errno = 0;
	return NULL;
}

struct ring_buffer *__wrap_ring_buffer__new(int map_fd,
					    ring_buffer_sample_fn sample_cb,
					    void *ctx,
					    const struct ring_buffer_opts *opts)
{
	(void)map_fd;
	(void)sample_cb;
	(void)ctx;
	(void)opts;
	errno = 0;
	return NULL;
}

/* one hash map in memory, under whichever fd the context names */
#define FAKE_MAP_FD 7
#define FAKE_MAP_SLOTS 300

/* a task storage map: the key is a pidfd the loader opens for itself */
#define FAKE_TASK_FD 8
static int g_task_marked;

static struct {
	size_t ksz;
	size_t vsz;
	size_t n;
	uint8_t keys[FAKE_MAP_SLOTS][64];
	uint8_t vals[FAKE_MAP_SLOTS][256];
	int gone[FAKE_MAP_SLOTS];
	int deletes;
} g_map;

static int fake_map_find(const void *key)
{
	for (size_t i = 0; i < g_map.n; i++) {
		if (!g_map.gone[i] &&
		    memcmp(g_map.keys[i], key, g_map.ksz) == 0)
			return (int)i;
	}
	return -1;
}

int __wrap_bpf_map_get_next_key(int fd, const void *key, void *next_key)
{
	size_t i = 0;

	if (fd != FAKE_MAP_FD)
		return -EBADF;
	if (key) {
		int at = fake_map_find(key);

		if (at < 0)
			return -ENOENT;
		i = (size_t)at + 1;
	}
	for (; i < g_map.n; i++) {
		if (!g_map.gone[i]) {
			memcpy(next_key, g_map.keys[i], g_map.ksz);
			return 0;
		}
	}
	return -ENOENT;
}

int __wrap_bpf_map_lookup_elem(int fd, const void *key, void *value)
{
	int at = fd == FAKE_MAP_FD ? fake_map_find(key) : -1;

	if (fd == FAKE_TASK_FD) {
		if (g_task_marked)
			return 0;
		errno = ENOENT;
		return -ENOENT;
	}
	if (at < 0)
		return -ENOENT;
	memcpy(value, g_map.vals[at], g_map.vsz);
	return 0;
}

int __wrap_bpf_map_delete_elem(int fd, const void *key)
{
	int at = fd == FAKE_MAP_FD ? fake_map_find(key) : -1;

	if (fd == FAKE_TASK_FD) {
		g_task_marked = 0;
		return 0;
	}
	if (at < 0)
		return -ENOENT;
	g_map.gone[at] = 1;
	g_map.deletes++;
	return 0;
}

static void fake_map_reset(size_t ksz, size_t vsz)
{
	memset(&g_map, 0, sizeof(g_map));
	g_map.ksz = ksz;
	g_map.vsz = vsz;
}

static void fake_map_put(const void *key, const void *val)
{
	memcpy(g_map.keys[g_map.n], key, g_map.ksz);
	memcpy(g_map.vals[g_map.n], val, g_map.vsz);
	g_map.n++;
}

/* odd PIDs run, and only at start time 100 */
static int fake_alive(uint32_t tgid, uint64_t start_ticks)
{
	return (tgid & 1) && start_ticks == 100;
}

static void test_exec_history_walk(void)
{
	struct lota_exec_history_key key;
	struct lota_exec_history_val val;
	struct lota_exec_history_key *keys = NULL;
	struct lota_exec_history_val *vals = NULL;
	struct bpf_loader_ctx ctx;
	size_t n = 99;
	int ret;

	memset(&ctx, 0, sizeof(ctx));
	ctx.exec_history_fd = -1;
	ret = bpf_loader_exec_history(&ctx, fake_alive, &keys, &vals, &n);
	CHECK(ret == -ENOENT && n == 0 && !keys && !vals,
	      "an object without the exec history reports it missing");

	fake_map_reset(sizeof(key), sizeof(val));
	for (uint32_t tgid = 1; tgid <= 4; tgid++) {
		memset(&key, 0, sizeof(key));
		memset(&val, 'x', sizeof(val));
		key.tgid = tgid;
		key.start_ticks = tgid == 3 ? 200 : 100;
		key.ino = 10 + tgid;
		val.size = tgid;
		fake_map_put(&key, &val);
	}

	ctx.exec_history_fd = FAKE_MAP_FD;
	ret = bpf_loader_exec_history(&ctx, fake_alive, &keys, &vals, &n);
	CHECK(ret == 0 && n == 1,
	      "the exec history keeps only the processes still running");
	CHECK(n == 1 && keys[0].tgid == 1 && keys[0].ino == 11 &&
		      vals[0].size == 1,
	      "a kept entry keeps its key and value together");
	CHECK(n == 1 && vals[0].name[sizeof(vals[0].name) - 1] == '\0',
	      "a kept name is terminated");
	CHECK(g_map.deletes == 3 && g_map.gone[1] && g_map.gone[2] &&
		      g_map.gone[3],
	      "an exited process and a reused PID lose their entries");
	free(keys);
	free(vals);
}

static void test_exec_history_past_first_buffer(void)
{
	struct lota_exec_history_key key;
	struct lota_exec_history_val val;
	struct lota_exec_history_key *keys = NULL;
	struct lota_exec_history_val *vals = NULL;
	struct bpf_loader_ctx ctx;
	bool together = true;
	size_t n = 0;
	int ret;

	fake_map_reset(sizeof(key), sizeof(val));
	for (uint32_t i = 0; i < FAKE_MAP_SLOTS; i++) {
		memset(&key, 0, sizeof(key));
		memset(&val, 0, sizeof(val));
		key.tgid = 1;
		key.start_ticks = 100;
		key.ino = i;
		val.size = i;
		fake_map_put(&key, &val);
	}

	memset(&ctx, 0, sizeof(ctx));
	ctx.exec_history_fd = FAKE_MAP_FD;
	ret = bpf_loader_exec_history(&ctx, fake_alive, &keys, &vals, &n);
	CHECK(ret == 0 && n == FAKE_MAP_SLOTS,
	      "a history longer than the first buffer is read whole");
	for (size_t i = 0; i < n; i++)
		together = together && keys[i].ino == i && vals[i].size == i;
	CHECK(together, "growing keeps keys and values together");
	free(keys);
	free(vals);
}

static uint64_t own_start_ticks(void)
{
	unsigned long long ticks = 0;
	char buf[1024];
	char *p;
	FILE *f;

	f = fopen("/proc/self/stat", "r");
	if (!f)
		return 0;
	p = fgets(buf, sizeof(buf), f);
	fclose(f);
	p = p ? strrchr(buf, ')') : NULL;
	if (!p || sscanf(p + 1,
			 " %*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u "
			 "%*u %*u %*d %*d %*d %*d %*d %*d %llu",
			 &ticks) != 1)
		return 0;
	return ticks;
}

static void test_born_protected(void)
{
	struct bpf_loader_ctx ctx;
	uint32_t pid = (uint32_t)getpid();
	uint64_t ticks = own_start_ticks();
	uint64_t val = 0;

	memset(&ctx, 0, sizeof(ctx));
	ctx.loaded = true;
	ctx.born_protected_fd = FAKE_TASK_FD;
	ctx.instance_stops_fd = -1;
	ctx.protected_pids_fd = FAKE_MAP_FD;

	g_task_marked = 0;
	CHECK(bpf_loader_born_protected(&ctx, pid, ticks) == 0,
	      "a process without the mark did not start under protection");

	g_task_marked = 1;
	CHECK(bpf_loader_born_protected(&ctx, pid, ticks) == 1,
	      "the mark is read for the process it was asked about");
	CHECK(bpf_loader_born_protected(&ctx, pid, ticks + 1) == 0,
	      "a successor on the same PID does not lend its mark");
	CHECK(bpf_loader_born_protected(&ctx, pid, 0) == 0,
	      "an unread start time claims nothing");

	ctx.born_protected_fd = -1;
	CHECK(bpf_loader_born_protected(&ctx, pid, ticks) == 0,
	      "without the map nothing is claimed");
	ctx.born_protected_fd = FAKE_TASK_FD;

	fake_map_reset(sizeof(pid), sizeof(val));
	fake_map_put(&pid, &val);
	CHECK(bpf_loader_unprotect_pid(&ctx, pid) == 0 && g_task_marked == 0 &&
		      bpf_loader_born_protected(&ctx, pid, ticks) == 0,
	      "withdrawing protection takes the mark with it");
}

static void test_instance_actors_walk(void)
{
	struct lota_instance_actor_key key;
	struct lota_instance_actor_val val;
	struct lota_instance_actor_key *keys = NULL;
	struct lota_instance_actor_val *vals = NULL;
	struct bpf_loader_ctx ctx;
	size_t n = 99;
	int ret;

	memset(&ctx, 0, sizeof(ctx));
	ctx.instance_actors_fd = -1;
	ret = bpf_loader_instance_actors(&ctx, fake_alive, &keys, &vals, &n);
	CHECK(ret == -ENOENT && n == 0 && !keys && !vals,
	      "an object without the actor record reports it missing");

	/* the root decides whether an actor stays, not the actor */
	fake_map_reset(sizeof(key), sizeof(val));
	for (uint32_t root = 1; root <= 4; root++) {
		memset(&key, 0, sizeof(key));
		memset(&val, 'x', sizeof(val));
		key.root_tgid = root;
		key.root_start_ticks = root == 3 ? 200 : 100;
		key.actor_tgid = 2;
		key.actor_start_ticks = 7;
		key.kind = 1;
		val.count = root;
		fake_map_put(&key, &val);
	}

	ctx.instance_actors_fd = FAKE_MAP_FD;
	ret = bpf_loader_instance_actors(&ctx, fake_alive, &keys, &vals, &n);
	CHECK(ret == 0 && n == 1,
	      "the actor record keeps only instances still running");
	CHECK(n == 1 && keys[0].root_tgid == 1 && keys[0].actor_tgid == 2 &&
		      vals[0].count == 1,
	      "a kept actor keeps its key and value together");
	CHECK(n == 1 && vals[0].comm[sizeof(vals[0].comm) - 1] == '\0' &&
		      vals[0].owner_comm[sizeof(vals[0].owner_comm) - 1] ==
			      '\0',
	      "kept actor names are terminated");
	CHECK(g_map.deletes == 3 && g_map.gone[1] && g_map.gone[2] &&
		      g_map.gone[3],
	      "an exited root and a reused root PID lose their actors");
	free(keys);
	free(vals);
}

static void write_file(const char *path, const void *data, size_t len)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	FILE *f;

	if (fd < 0) {
		fprintf(stderr, "FAIL: open %s: %s\n", path, strerror(errno));
		exit(1);
	}
	f = fdopen(fd, "wb");
	if (!f) {
		close(fd);
		fprintf(stderr, "FAIL: fdopen %s: %s\n", path, strerror(errno));
		exit(1);
	}
	if (len && fwrite(data, 1, len, f) != len) {
		fprintf(stderr, "FAIL: fwrite %s\n", path);
		fclose(f);
		exit(1);
	}
	fclose(f);
}

static int sample_handler(void *ctx, void *data, size_t len)
{
	(void)ctx;
	(void)data;
	(void)len;
	return 0;
}

int main(void)
{
	const char *obj_path = "/tmp/lota_test_open_fails_closed.o";
	const char *sig_path = "/tmp/lota_test_open_fails_closed.o.sig";
	const char *pubkey_path = "dummy-pubkey.pem";
	static const char obj_bytes[] = "VERIFIED-BPF-OBJECT-BYTES";
	uint8_t sig[POLICY_SIG_SIZE] = { 0 };
	struct bpf_loader_ctx ctx;
	int ret;

	write_file(obj_path, obj_bytes, sizeof(obj_bytes) - 1);
	write_file(sig_path, sig, sizeof(sig));

	memset(&ctx, 0, sizeof(ctx));
	errno = 0;
	ret = bpf_loader_load(&ctx, obj_path, pubkey_path);
	CHECK(ret < 0, "an object the library refused to open is a failure");
	CHECK(!ctx.loaded,
	      "a refused open leaves the context reporting nothing loaded");
	CHECK(ctx.obj == NULL, "a refused open leaves no object behind");

	/* context as a successful load leaves it; the attach is refused */
	memset(&ctx, 0, sizeof(ctx));
	ctx.obj = (struct bpf_object *)&g_fake_prog;
	ctx.loaded = true;
	errno = 0;
	ret = bpf_loader_attach(&ctx);
	CHECK(ret < 0, "a program the library refused to attach is a failure");
	CHECK(!ctx.attached,
	      "a refused attach leaves the context reporting nothing attached");

	memset(&ctx, 0, sizeof(ctx));
	ctx.loaded = true;
	ctx.ringbuf_fd = 3;
	errno = 0;
	ret = bpf_loader_setup_ringbuf(&ctx, sample_handler, NULL);
	CHECK(ret < 0,
	      "a ring buffer the library refused to make is a failure");

	unlink(obj_path);
	unlink(sig_path);

	test_exec_history_walk();
	test_exec_history_past_first_buffer();
	test_instance_actors_walk();
	test_born_protected();

	if (g_failures) {
		printf("Failed: %d\n", g_failures);
		return 1;
	}
	printf("All checks passed\n");
	return 0;
}
