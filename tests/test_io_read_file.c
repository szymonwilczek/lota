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

#include "test.h"

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
		FAIL("could not create temp file");
		return;
	}

	TEST("read_file_bounded succeeds on a present file");
	if (lota_read_file_bounded(path, buf, sizeof(buf), &out) != 0)
		FAIL("expected: lota_read_file_bounded(path, buf, "
		     "sizeof(buf), &out) == 0");
	TEST("read_file_bounded returns the exact file bytes");
	if (!(out == sizeof(data) && memcmp(buf, data, sizeof(data)) == 0))
		FAIL("expected: out == sizeof(data) && memcmp(buf, data, "
		     "sizeof(data)) == 0");

	unlink(path);
}

static void test_missing_file_is_absent(void)
{
	uint8_t buf[16];
	size_t out = 123;

	TEST("read_file_bounded treats a missing file as success");
	if (lota_read_file_bounded("/tmp/lota-iotest-does-not-exist-xyz", buf,
				   sizeof(buf), &out) != 0)
		FAIL("expected: lota_read_file_bounded(\"/tmp/lota-iotest-does-not-exist-xyz\", "
		     "buf, sizeof(buf), &out) == 0");
	TEST("read_file_bounded reports zero length for a missing file");
	if (out != 0)
		FAIL("expected: out == 0");
}

/* A file that exists and holds nothing has no content to hand back,
 * which is what every caller means by absent -- and it is not the
 * "larger than the bound" the other rejection reports */
static void test_empty_file_is_absent(void)
{
	char path[64];
	uint8_t buf[16];
	size_t out = 123;

	if (write_tmp(path, sizeof(path), "", 0) < 0) {
		FAIL("could not create temp file");
		return;
	}

	TEST("read_file_bounded treats an empty file as success");
	if (lota_read_file_bounded(path, buf, sizeof(buf), &out) != 0)
		FAIL("expected: lota_read_file_bounded(path, buf, "
		     "sizeof(buf), &out) == 0");
	TEST("read_file_bounded reports zero length for an empty file");
	if (out != 0)
		FAIL("expected: out == 0");

	unlink(path);
}

static void test_oversize_rejected(void)
{
	char path[64];
	uint8_t data[32];
	uint8_t buf[16];
	size_t out = 0;

	memset(data, 0x5A, sizeof(data));
	if (write_tmp(path, sizeof(path), data, sizeof(data)) < 0) {
		FAIL("could not create temp file");
		return;
	}

	TEST("read_file_bounded rejects a file larger than the bound");
	if (lota_read_file_bounded(path, buf, sizeof(buf), &out) != -EMSGSIZE)
		FAIL("expected: lota_read_file_bounded(path, buf, "
		     "sizeof(buf), &out) == -EMSGSIZE");
	TEST("read_file_bounded leaves length zero on rejection");
	if (out != 0)
		FAIL("expected: out == 0");

	unlink(path);
}

/* a directory opens O_RDONLY and may report size 0 */
static void test_directory_is_not_absent(void)
{
	char path[] = "/tmp/lota-iotest-dir-XXXXXX";
	uint8_t buf[16];
	size_t out = 0;

	if (!mkdtemp(path)) {
		FAIL("could not create temp dir");
		return;
	}

	TEST("read_file_bounded refuses a directory");
	if (lota_read_file_bounded(path, buf, sizeof(buf), &out) != -EISDIR)
		FAIL("expected: lota_read_file_bounded(path, buf, "
		     "sizeof(buf), &out) == -EISDIR");
	TEST("read_file_bounded leaves length zero for a directory");
	if (out != 0)
		FAIL("expected: out == 0");

	rmdir(path);
}

static void test_argument_validation(void)
{
	uint8_t buf[16];
	size_t out = 0;

	TEST("read_file_bounded rejects a nil path");
	if (lota_read_file_bounded(NULL, buf, sizeof(buf), &out) != -EINVAL)
		FAIL("expected: lota_read_file_bounded(NULL, buf, "
		     "sizeof(buf), &out) == -EINVAL");
	TEST("read_file_bounded rejects a nil buffer");
	if (lota_read_file_bounded("/tmp/x", NULL, sizeof(buf), &out) !=
	    -EINVAL)
		FAIL("expected: lota_read_file_bounded(\"/tmp/x\", NULL, "
		     "sizeof(buf), &out) == -EINVAL");
	TEST("read_file_bounded rejects a nil out_len");
	if (lota_read_file_bounded("/tmp/x", buf, sizeof(buf), NULL) != -EINVAL)
		FAIL("expected: lota_read_file_bounded(\"/tmp/x\", buf, "
		     "sizeof(buf), NULL) == -EINVAL");
}

int main(void)
{
	test_begin("io read file");
	test_reads_full_file();
	test_missing_file_is_absent();
	test_empty_file_is_absent();
	test_oversize_rejected();
	test_directory_is_not_absent();
	test_argument_validation();

	return test_end();
}
