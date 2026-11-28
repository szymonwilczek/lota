/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * Unit tests for the free-text fields of a lota-bench session.
 */

#include <string.h>

#include "test.h"
#include "../tools/lota-bench/field.h"

static int cleaned(const char *in, const char *want)
{
	struct bench_field f;

	bench_field_set(&f, in, strlen(in));
	if (!want)
		return !f.set && f.s[0] == '\0';
	return f.set && strcmp(f.s, want) == 0 && bench_field_ok(f.s);
}

static void test_plain(void)
{
	TEST("plain text is kept as it is");
	if (!cleaned("Example Title 2", "Example Title 2") ||
	    !cleaned("1920x1080, high, FSR off", "1920x1080, high, FSR off")) {
		FAIL("changed");
		return;
	}
}

static void test_refused_bytes(void)
{
	TEST("a path, an escape or a quote becomes '_'");
	if (!cleaned("/home/someone/game", "_home_someone_game") ||
	    !cleaned("C:\\Games\\x", "C:_Games_x") ||
	    !cleaned("say \"hi\"", "say _hi_") ||
	    !cleaned("caf\xc3\xa9", "caf__") || !cleaned("a\nb", "a_b") ||
	    !cleaned("a\x7f", "a_")) {
		FAIL("byte kept");
		return;
	}
}

static void test_blanks(void)
{
	TEST("blanks are trimmed and collapsed");
	if (!cleaned("  a \t\t b  ", "a b") || !cleaned("   ", NULL) ||
	    !cleaned("", NULL)) {
		FAIL("blank kept");
		return;
	}
}

static void test_cut(void)
{
	char in[200], want[BENCH_FIELD_MAX + 1];
	struct bench_field f;

	TEST("text is cut at BENCH_FIELD_MAX bytes");
	memset(in, 'x', sizeof(in) - 1);
	in[sizeof(in) - 1] = '\0';
	memset(want, 'x', BENCH_FIELD_MAX);
	want[BENCH_FIELD_MAX] = '\0';
	if (!cleaned(in, want)) {
		FAIL("not cut");
		return;
	}
	/* a blank that would be the last byte is never written */
	memset(in, 'x', BENCH_FIELD_MAX - 1);
	strcpy(in + BENCH_FIELD_MAX - 1, " yz");
	bench_field_set(&f, in, strlen(in));
	if (strlen(f.s) != BENCH_FIELD_MAX - 1 || !bench_field_ok(f.s)) {
		FAIL("blank at the cut");
		return;
	}
}

static void test_len_bounds_input(void)
{
	struct bench_field f;

	TEST("only @len bytes are read");
	bench_field_set(&f, "abc/def", 3);
	if (strcmp(f.s, "abc") != 0) {
		FAIL("read past len");
		return;
	}
}

static void test_ok(void)
{
	char big[BENCH_FIELD_MAX + 2];

	TEST("bench_field_ok refuses what the cleaner never leaves");
	memset(big, 'x', sizeof(big) - 1);
	big[sizeof(big) - 1] = '\0';
	if (bench_field_ok("") || bench_field_ok(" a") ||
	    bench_field_ok("a ") || bench_field_ok("a  b") ||
	    bench_field_ok("a/b") || bench_field_ok("a\\b") ||
	    bench_field_ok("a\"b") || bench_field_ok("a\tb") ||
	    bench_field_ok(big) || !bench_field_ok("a b")) {
		FAIL("wrong verdict");
		return;
	}
}

int main(void)
{
	test_begin("bench field");

	test_plain();
	test_refused_bytes();
	test_blanks();
	test_cut();
	test_len_bounds_input();
	test_ok();

	return test_end();
}
