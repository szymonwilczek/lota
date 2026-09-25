/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for carrying one extended attribute across a replacement.
 *
 * A writer that replaces a file by rename gives the replacement whatever
 * label its parent directory implies, not the one the file it replaced
 * carried.
 * On an SELinux host whose /etc/lota is not itself labelled, a rewritten
 * lota.conf therefore comes back as etc_t where the packaged file was
 * lota_etc_t -- and the policy dontaudits the denial, so nothing says so.
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

static int g_failures;
static int g_skipped;

#define CHECK(cond, msg)                                    \
	do {                                                \
		if (!(cond)) {                              \
			fprintf(stderr, "FAIL: %s\n", msg); \
			g_failures++;                       \
		} else {                                    \
			printf("PASS: %s\n", msg);          \
		}                                           \
	} while (0)

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

	printf("=== extended attribute carry tests ===\n\n");

	if (make_file(from, sizeof(from)) < 0 ||
	    make_file(to, sizeof(to)) < 0) {
		fprintf(stderr, "FAIL: could not create temp files\n");
		return 1;
	}

	if (setxattr(from, TEST_ATTR, "lota_etc_t", 10, 0) < 0) {
		printf("SKIP: %s cannot hold a user extended attribute (%s)\n",
		       from, strerror(errno));
		g_skipped = 1;
		goto out;
	}

	CHECK(lota_copy_xattr(from, to, TEST_ATTR) == 0,
	      "the attribute is carried to the replacement");
	n = getxattr(to, TEST_ATTR, got, sizeof(got));
	CHECK(n == 10 && memcmp(got, "lota_etc_t", 10) == 0,
	      "the replacement holds exactly what the original held");

	/* a file that carries nothing leaves the destination alone */
	if (removexattr(from, TEST_ATTR) == 0) {
		CHECK(lota_copy_xattr(from, to, TEST_ATTR) == 0,
		      "a source without the attribute is not an error");
		CHECK(getxattr(to, TEST_ATTR, got, sizeof(got)) == 10,
		      "and the destination keeps what it already had");
	}

	CHECK(lota_copy_xattr("/tmp/lota-xattr-does-not-exist", to,
			      TEST_ATTR) == -ENOENT,
	      "a source that does not exist is reported");
	CHECK(lota_copy_xattr(from, to, NULL) == -EINVAL,
	      "an unnamed attribute is refused");

out:
	unlink(from);
	unlink(to);

	if (g_skipped && !g_failures) {
		printf("\nSkipped: the filesystem holds no user attributes\n");
		return 0;
	}
	printf("\n%s\n", g_failures ? "FAILURES" : "All tests passed");
	return g_failures ? 1 : 0;
}
