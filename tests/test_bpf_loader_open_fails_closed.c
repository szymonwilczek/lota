/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * A libbpf call that returns NULL need not set errno, and `return -errno` then
 * reads as success. The calls are wrapped to fail with errno clear; a refusal
 * must still be negative.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

	if (g_failures) {
		printf("Failed: %d\n", g_failures);
		return 1;
	}
	printf("All checks passed\n");
	return 0;
}
