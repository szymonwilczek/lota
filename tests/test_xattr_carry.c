/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for carrying one extended attribute across a replacement.
 *
 * A writer that replaces a file by rename gives the replacement whatever
 * label its parent directory implies, not the one the file it replaced
 * carried.
 * On an SELinux host whose /etc/lota is not itself labelled, a rewritten
 * lota.conf therefore comes back as etc_t where the packaged file was
 * lota_etc_t.
 *
 * The attribute name is a parameter: production carries security.selinux,
 * which an unprivileged process may not set, and these tests carry one they
 * are allowed to.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "../src/agent/io_utils.h"

#include "test.h"

#define TEST_ATTR "user.lota_test_label"

static int make_file(char *path, size_t cap)
{
	int fd;

	snprintf(path, cap, "/tmp/lota-xattr-XXXXXX");
	fd = mkstemp(path);
	if (fd < 0)
		return -errno;
	if (write(fd, "x", 1) != 1) {
		close(fd);
		unlink(path);
		return -EIO;
	}
	close(fd);
	return 0;
}

int main(void)
{
	char from[64], to[64];
	char got[64];
	ssize_t n;

	test_begin("xattr carry");

	if (make_file(from, sizeof(from)) < 0 ||
	    make_file(to, sizeof(to)) < 0) {
		FAIL("could not create temp files");
		return 1;
	}

	if (setxattr(from, TEST_ATTR, "lota_etc_t", 10, 0) < 0) {
		SKIP("%s cannot hold a user extended attribute (%s)", from,
		     strerror(errno));
		goto out;
	}

	TEST("the attribute is carried to the replacement");
	if (lota_copy_xattr(from, to, TEST_ATTR) != 0)
		FAIL("expected: lota_copy_xattr(from, to, TEST_ATTR) == 0");
	n = getxattr(to, TEST_ATTR, got, sizeof(got));
	TEST("the replacement holds exactly what the original held");
	if (!(n == 10 && memcmp(got, "lota_etc_t", 10) == 0))
		FAIL("expected: n == 10 && memcmp(got, \"lota_etc_t\", 10) == "
		     "0");

	/* a file that carries nothing leaves the destination alone */
	if (removexattr(from, TEST_ATTR) == 0) {
		TEST("a source without the attribute is not an error");
		if (lota_copy_xattr(from, to, TEST_ATTR) != 0)
			FAIL("expected: lota_copy_xattr(from, to, TEST_ATTR) == 0");
		TEST("and the destination keeps what it already had");
		if (getxattr(to, TEST_ATTR, got, sizeof(got)) != 10)
			FAIL("expected: getxattr(to, TEST_ATTR, got, sizeof(got)) == "
			     "10");
	}

	TEST("a source that does not exist is reported");
	if (lota_copy_xattr("/tmp/lota-xattr-does-not-exist", to, TEST_ATTR) !=
	    -ENOENT)
		FAIL("expected: lota_copy_xattr(\"/tmp/lota-xattr-does-not-exist\", "
		     "to, TEST_ATTR) == -ENOENT");
	TEST("an unnamed attribute is refused");
	if (lota_copy_xattr(from, to, NULL) != -EINVAL)
		FAIL("expected: lota_copy_xattr(from, to, NULL) == -EINVAL");

out:
	unlink(from);
	unlink(to);

	return test_end();
}
