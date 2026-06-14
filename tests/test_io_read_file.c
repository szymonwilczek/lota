/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for lota_read_file_bounded (io_utils.c), the bounded file
 * reader used to load the CA-issued AIK certificate into attestation
 * reports.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "../src/agent/io_utils.h"

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

static int write_tmp(char *path, size_t path_sz, const void *data, size_t len)
{
	int fd;
	snprintf(path, path_sz, "/tmp/lota-iotest-XXXXXX");
	fd = mkstemp(path);
	if (fd < 0)
		return -errno;
	if (lota_write_full(fd, data, len) < 0) {
		close(fd);
		unlink(path);
		return -EIO;
	}
	close(fd);
	return 0;
}

static void test_reads_full_file(void)
{
	char path[64];
	const uint8_t data[] = { 0x30, 0x82, 0x01, 0x02, 0xAA, 0xBB };
	uint8_t buf[64];
	size_t out = 0;

	if (write_tmp(path, sizeof(path), data, sizeof(data)) < 0) {
		fprintf(stderr, "FAIL: could not create temp file\n");
		g_failures++;
		return;
	}

	CHECK(lota_read_file_bounded(path, buf, sizeof(buf), &out) == 0,
	      "read_file_bounded succeeds on a present file");
	CHECK(out == sizeof(data) && memcmp(buf, data, sizeof(data)) == 0,
	      "read_file_bounded returns the exact file bytes");

	unlink(path);
}

static void test_missing_file_is_absent(void)
{
	uint8_t buf[16];
	size_t out = 123;

	CHECK(lota_read_file_bounded("/tmp/lota-iotest-does-not-exist-xyz", buf,
				     sizeof(buf), &out) == 0,
	      "read_file_bounded treats a missing file as success");
	CHECK(out == 0,
	      "read_file_bounded reports zero length for a missing file");
}

static void test_oversize_rejected(void)
{
	char path[64];
	uint8_t data[32];
	uint8_t buf[16];
	size_t out = 0;

	memset(data, 0x5A, sizeof(data));
	if (write_tmp(path, sizeof(path), data, sizeof(data)) < 0) {
		fprintf(stderr, "FAIL: could not create temp file\n");
		g_failures++;
		return;
	}

	CHECK(lota_read_file_bounded(path, buf, sizeof(buf), &out) == -EMSGSIZE,
	      "read_file_bounded rejects a file larger than the bound");
	CHECK(out == 0, "read_file_bounded leaves length zero on rejection");

	unlink(path);
}

static void test_argument_validation(void)
{
	uint8_t buf[16];
	size_t out = 0;

	CHECK(lota_read_file_bounded(NULL, buf, sizeof(buf), &out) == -EINVAL,
	      "read_file_bounded rejects a nil path");
	CHECK(lota_read_file_bounded("/tmp/x", NULL, sizeof(buf), &out) ==
		      -EINVAL,
	      "read_file_bounded rejects a nil buffer");
	CHECK(lota_read_file_bounded("/tmp/x", buf, sizeof(buf), NULL) ==
		      -EINVAL,
	      "read_file_bounded rejects a nil out_len");
}

int main(void)
{
	printf("=== io_read_file_bounded tests ===\n");
	test_reads_full_file();
	test_missing_file_is_absent();
	test_oversize_rejected();
	test_argument_validation();

	if (g_failures) {
		fprintf(stderr, "\n%d test(s) failed\n", g_failures);
		return 1;
	}
	printf("\nAll io_read_file_bounded tests passed\n");
	return 0;
}
