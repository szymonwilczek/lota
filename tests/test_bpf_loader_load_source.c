/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Regression test for the BPF object verify-then-load path.
 *
 * bpf_loader_load() must hand libbpf the exact bytes whose signature it just
 * verified, via bpf_object__open_mem(), instead re-opening the path with
 * bpf_object__open_file() and loading a copy that was never checked.
 * Latter is a verify-then-reopen TOCTOU: attacker who can swap the file
 * between the two opens loads an unverified object under cover of a valid
 * signature check.
 *
 * libbpf's open calls and the signature verify are interposed with
 * --wrap so the test needs neither a real key nor a live kernel:
 * it asserts the loader called open_mem (not open_file) with the verified bytes
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
#include "test.h"

/* --wrap targets need external linkage */
int __wrap_policy_verify_buffer(const uint8_t *data, size_t data_len,
				const char *pubkey_pem_path,
				const uint8_t *sig);
struct bpf_object *
__wrap_bpf_object__open_file(const char *path,
			     const struct bpf_object_open_opts *opts);
struct bpf_object *
__wrap_bpf_object__open_mem(const void *obj_buf, size_t obj_buf_sz,
			    const struct bpf_object_open_opts *opts);

static int g_open_file_called;
static int g_open_mem_called;
static uint8_t g_mem_buf[256];
static size_t g_mem_len;

/* accept any signature so the test exercises the load path, not crypto */
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
__wrap_bpf_object__open_file(const char *path,
			     const struct bpf_object_open_opts *opts)
{
	(void)path;
	(void)opts;
	g_open_file_called = 1;
	return NULL; /* loader returns early on a NULL object */
}

struct bpf_object *
__wrap_bpf_object__open_mem(const void *obj_buf, size_t obj_buf_sz,
			    const struct bpf_object_open_opts *opts)
{
	(void)opts;
	g_open_mem_called = 1;
	g_mem_len = obj_buf_sz;
	if (obj_buf_sz <= sizeof(g_mem_buf))
		memcpy(g_mem_buf, obj_buf, obj_buf_sz);
	return NULL;
}

static void write_file(const char *path, const void *data, size_t len)
{
	int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
	if (fd < 0) {
		FAIL("open %s: %s", path, strerror(errno));
		exit(1);
	}
	FILE *f = fdopen(fd, "wb");
	if (!f) {
		close(fd);
		FAIL("fdopen %s: %s", path, strerror(errno));
		exit(1);
	}
	if (fwrite(data, 1, len, f) != len) {
		FAIL("fwrite %s", path);
		exit(1);
	}
	fclose(f);
}

int main(void)
{
	const char *obj_path = "/tmp/lota_test_bpf_obj.o";
	const char *sig_path = "/tmp/lota_test_bpf_obj.o.sig";
	const char *pubkey_path = "dummy-pubkey.pem";
	static const char obj_bytes[] = "VERIFIED-BPF-OBJECT-BYTES";
	const size_t obj_len = sizeof(obj_bytes) - 1;
	uint8_t sig[POLICY_SIG_SIZE] = { 0 };

	test_begin("bpf loader load source");
	write_file(obj_path, obj_bytes, obj_len);
	write_file(sig_path, sig, sizeof(sig));

	struct bpf_loader_ctx ctx;
	memset(&ctx, 0, sizeof(ctx));

	/* open is wrapped to return NULL, so the load fails after the open;
	 * return value is irrelevant
	 * the assertion is which open the loader chose and with what bytes */
	(void)bpf_loader_load(&ctx, obj_path, pubkey_path);

	TEST("loader does not re-open the verified path");
	if (g_open_file_called)
		FAIL("verify-then-reopen TOCTOU");
	TEST("loader loads from the verified in-memory buffer");
	if (!g_open_mem_called)
		FAIL("bpf_object__open_mem never called");
	TEST("loaded bytes are the verified bytes");
	if (g_mem_len != obj_len || memcmp(g_mem_buf, obj_bytes, obj_len) != 0)
		FAIL("loaded bytes differ");

	unlink(obj_path);
	unlink(sig_path);
	return test_end();
}
