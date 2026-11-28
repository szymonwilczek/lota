/* SPDX-License-Identifier: MIT */
/*
 * Report format for the C test programs:
 *
 *	test_begin("devt");
 *	TEST("MAJOR decodes the /dev/mem major");
 *	if (major != 1)
 *		FAIL("major %u, expected 1", major);
 *	return test_end();
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#ifndef LOTA_TEST_H
#define LOTA_TEST_H

#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TEST_WIDTH 80
#define TEST_NAME_MAX 63
#define TEST_DETAIL_MAX 4096
#define TEST_SUMMARY_FD 3

#define TEST(name) test_open(name)
#define FAIL(...) test_mark(1, __VA_ARGS__)
#define SKIP(...) test_mark(2, __VA_ARGS__)

static struct {
	const char *group;
	pid_t owner;
	int color;
	int run;
	int passed;
	int failed;
	int skipped;
	int open;
	int state; /* 0 pass, 1 fail, 2 skip */
	char name[TEST_NAME_MAX + 1];
	char detail[TEST_DETAIL_MAX];
	size_t detail_len;
} test_g;

static int test_color(void)
{
	const char *mode = getenv("LOTA_TEST_COLOR");
	const char *term = getenv("TERM");
	const char *nc = getenv("NO_COLOR");

	if (mode && strcmp(mode, "always") == 0)
		return 1;
	if (mode && strcmp(mode, "never") == 0)
		return 0;
	if ((nc && *nc) || (term && strcmp(term, "dumb") == 0))
		return 0;
	return isatty(STDOUT_FILENO);
}

static void test_record(const char *fmt, ...)
	__attribute__((format(printf, 1, 2)));

static void test_record(const char *fmt, ...)
{
	const char *path = getenv("LOTA_TEST_SUMMARY");
	va_list ap;
	FILE *f;
	int fd;

	if (!path || !*path)
		return;
	fd = fcntl(TEST_SUMMARY_FD, F_DUPFD_CLOEXEC, 0);
	f = fd >= 0 ? fdopen(fd, "a") : NULL;
	if (!f) {
		if (fd >= 0)
			close(fd);
		return;
	}
	va_start(ap, fmt);
	vfprintf(f, fmt, ap);
	va_end(ap);
	fclose(f);
}

static void test_close(void)
{
	static const char *const word[] = { "PASS", "FAIL", "SKIP" };
	static const char *const ansi[] = { "\033[32m", "\033[1;31m",
					    "\033[90m" };
	size_t len = strlen(test_g.name);
	const char *p, *nl;

	if (!test_g.open)
		return;
	test_g.open = 0;

	printf("  [%3d] %s ", test_g.run, test_g.name);
	for (size_t i = len; i < TEST_NAME_MAX + 3; i++)
		putchar('.');
	if (test_g.color)
		printf(" %s%s\033[0m\n", ansi[test_g.state],
		       word[test_g.state]);
	else
		printf(" %s\n", word[test_g.state]);

	for (p = test_g.detail; *p; p = nl + 1) {
		nl = strchr(p, '\n');
		printf("        %.*s\n", (int)(nl - p), p);
	}
	fflush(stdout);

	if (test_g.state == 0)
		test_g.passed++;
	else if (test_g.state == 1)
		test_g.failed++;
	else
		test_g.skipped++;
	if (test_g.state == 1)
		test_record("F\t%s\t%d\t%s\n", test_g.group, test_g.run,
			    test_g.name);
}

static __attribute__((unused)) void test_open(const char *name)
{
	size_t len = strlen(name);

	test_close();
	test_g.run++;
	test_g.open = 1;
	test_g.state = 0;
	test_g.detail[0] = '\0';
	test_g.detail_len = 0;
	if (len > TEST_NAME_MAX)
		snprintf(test_g.name, sizeof(test_g.name), "%.*s...",
			 TEST_NAME_MAX - 3, name);
	else
		memcpy(test_g.name, name, len + 1);
}

static __attribute__((unused)) void test_mark(int state, const char *fmt, ...)
	__attribute__((format(printf, 2, 3)));

static void test_mark(int state, const char *fmt, ...)
{
	size_t room, n;
	va_list ap;
	int ret;

	if (!test_g.open)
		test_open("(setup)");
	if (state == 1 || test_g.state == 0)
		test_g.state = state;

	room = sizeof(test_g.detail) - test_g.detail_len;
	if (room < 2)
		return;
	va_start(ap, fmt);
	ret = vsnprintf(test_g.detail + test_g.detail_len, room - 1, fmt, ap);
	va_end(ap);
	if (ret < 0)
		return;
	n = (size_t)ret < room - 2 ? (size_t)ret : room - 2;
	test_g.detail_len += n;
	test_g.detail[test_g.detail_len++] = '\n';
	test_g.detail[test_g.detail_len] = '\0';
}

static void test_footer(void)
{
	printf("  %s: %d passed", test_g.group, test_g.passed);
	if (test_g.failed)
		printf(", %d failed", test_g.failed);
	if (test_g.skipped)
		printf(", %d skipped", test_g.skipped);
	printf("\n\n");
	fflush(stdout);
	test_record("G\t%s\t%d\t%d\t%d\n", test_g.group, test_g.passed,
		    test_g.failed, test_g.skipped);
	test_g.group = NULL;
}

static void test_atexit(void)
{
	if (!test_g.group || getpid() != test_g.owner)
		return;
	test_close();
	test_footer();
}

static __attribute__((unused)) void test_begin(const char *group)
{
	size_t len = strlen(group);

	test_g.group = group;
	test_g.owner = getpid();
	test_g.color = test_color();
	printf("-- %s ", group);
	for (size_t i = len + 4; i < TEST_WIDTH; i++)
		putchar('-');
	putchar('\n');
	fflush(stdout);
	atexit(test_atexit);
}

static __attribute__((unused)) int test_end(void)
{
	int failed;

	test_close();
	failed = test_g.failed;
	test_footer();
	return failed ? 1 : 0;
}

#endif /* LOTA_TEST_H */
