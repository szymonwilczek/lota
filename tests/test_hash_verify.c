/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - hash_verify unit tests
 *
 * Build:
 *   gcc -Wall -Wextra -Werror -O2 -g -Iinclude -D_GNU_SOURCE \
 *       -o build/test_hash_verify tests/test_hash_verify.c \
 *       src/agent/hash_verify.c -lcrypto
 *
 * Run:
 *   ./build/test_hash_verify
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/types.h>

#include "test.h"
#include "../include/lota.h"
#include "../src/agent/hash_verify.h"

#define ASSERT(cond, msg)          \
	do {                       \
		if (!(cond)) {     \
			FAIL(msg); \
			return;    \
		}                  \
	} while (0)

/* create a temporary file with given content */
static char *create_tmp_file(const char *content, size_t len)
{
	char *path = strdup("/tmp/lota_test_hash_XXXXXX");
	int fd = mkstemp(path);
	if (fd < 0) {
		free(path);
		return NULL;
	}
	if (len > 0) {
		ssize_t w = write(fd, content, len);
		(void)w;
	}
	close(fd);
	return path;
}

static void test_event_no_caching(void)
{
	struct hash_verify_ctx ctx;
	struct lota_exec_event event;
	uint8_t hash1[LOTA_HASH_SIZE], hash2[LOTA_HASH_SIZE];
	uint64_t resolved, errors;
	char *path = NULL;
	int ret;
	int ok = 0;

	TEST("hash_verify_event fail-closed without fs-verity");

	ret = hash_verify_init(&ctx);
	ASSERT(ret == 0, "init failed");

	path = create_tmp_file("cache test content", 18);
	ASSERT(path != NULL, "failed to create temp file");

	memset(&event, 0, sizeof(event));
	event.event_type = LOTA_EVENT_EXEC;
	event.pid = getpid(); /* self PID to ensure /proc/PID/exe exists */

	strncpy(event.filename, "/tmp/ignored", sizeof(event.filename) - 1);

	/* first call */
	ret = hash_verify_event(&ctx, &event, hash1);
	if (ret >= 0) {
		FAIL("expected first hash_verify_event failure without verity");
		goto out;
	}

	hash_verify_stats(&ctx, &resolved, &errors);
	if (resolved != 0) {
		FAIL("expected 0 resolutions");
		goto out;
	}
	if (errors != 1) {
		FAIL("expected 1 error");
		goto out;
	}

	/* second call */
	ret = hash_verify_event(&ctx, &event, hash2);
	if (ret >= 0) {
		FAIL("expected second hash_verify_event failure without verity");
		goto out;
	}

	hash_verify_stats(&ctx, &resolved, &errors);
	if (resolved != 0) {
		FAIL("expected 0 resolutions");
		goto out;
	}
	if (errors != 2) {
		FAIL("expected 2 errors");
		goto out;
	}

	ok = 1;
out:
	hash_verify_cleanup(&ctx);
	if (path) {
		unlink(path);
		free(path);
	}

	if (!ok)
		return;

	PASS();
}

static void test_stats(void)
{
	struct hash_verify_ctx ctx;
	uint64_t r, e;
	int ret;

	TEST("hash_verify_stats correctness");

	ret = hash_verify_init(&ctx);
	ASSERT(ret == 0, "init failed");

	hash_verify_stats(&ctx, &r, &e);
	ASSERT(r == 0 && e == 0, "stats not zero after init");

	/* trigger an error (nonexistent file) */
	{
		struct lota_exec_event event;
		uint8_t hash[LOTA_HASH_SIZE];
		memset(&event, 0, sizeof(event));
		event.event_type = LOTA_EVENT_EXEC;
		strncpy(event.filename, "/tmp/lota_test_nonexistent_99999999",
			sizeof(event.filename) - 1);
		memset(event.hash, 0xFF, LOTA_HASH_SIZE);
		hash_verify_event(&ctx, &event, hash);
	}

	hash_verify_stats(&ctx, &r, &e);
	ASSERT(e == 1, "expected 1 error after bad path");

	hash_verify_cleanup(&ctx);

	PASS();
}

static void test_null_args(void)
{
	struct hash_verify_ctx ctx;
	uint8_t hash[LOTA_HASH_SIZE];
	int ret;

	TEST("NULL argument handling");

	ret = hash_verify_init(NULL);
	ASSERT(ret == -EINVAL, "expected -EINVAL for NULL ctx");

	{
		struct lota_exec_event event;
		memset(&event, 0, sizeof(event));
		ret = hash_verify_event(NULL, &event, hash);
		ASSERT(ret == -EINVAL, "expected -EINVAL for NULL ctx");
	}

	ret = hash_verify_init(&ctx);
	ASSERT(ret == 0, "init failed");
	ret = hash_verify_event(&ctx, NULL, hash);
	ASSERT(ret == -EINVAL, "expected -EINVAL for NULL event");
	hash_verify_cleanup(&ctx);

	PASS();
}

int main(void)
{
	printf("\n=== LOTA Hash Verification Tests ===\n\n");

	test_event_no_caching();
	test_stats();
	test_null_args();

	printf("\n=== Results: %d/%d passed ===\n\n", tests_passed, tests_run);

	return (tests_passed == tests_run) ? 0 : 1;
}
