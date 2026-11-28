// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA - log-string sanitization test
//
// Event records carry attacker-controlled strings:
// process comm set via PR_SET_NAME and a path an attacker can name.
// They reach the log as raw %s.
// Embedded newline forges a whole log line on the stderr fallback and
// ANSI escape rewrites the operator's terminal.
//
// lota_str_sanitize() must fold every control byte to a space, NUL-terminate,
// and never write past out_size.

#include "../src/agent/path_validate.h"
#include "test.h"

#include <string.h>

static void check(const char *name, const char *in, const char *want)
{
	char out[64];

	TEST(name);
	lota_str_sanitize(in, out, sizeof(out));
	if (strcmp(out, want) != 0)
		FAIL("got '%s', want '%s'", out, want);
}

int main(void)
{
	test_begin("path sanitize");

	/* forged log line: the newline must not survive */
	check("newline is folded", "evil\nlota: ERR fake",
	      "evil lota: ERR fake");
	/* ANSI escape (ESC = 0x1b) rewrites the terminal: fold it */
	check("ANSI escape is folded", "x\033[31mPWN\033[0m", "x [31mPWN [0m");
	/* carriage return, tab and DEL are control bytes too */
	check("CR, tab and DEL are folded", "a\rb\tc\177d", "a b c d");
	check("clean string is copied verbatim", "/usr/lib/libc.so.6",
	      "/usr/lib/libc.so.6");
	check("NULL input yields an empty string", NULL, "");

	/* truncation: out_size bounds the copy and still terminates */
	{
		char out[4];

		TEST("out_size bounds the copy and terminates");
		lota_str_sanitize("abcdef", out, sizeof(out));
		if (strcmp(out, "abc") != 0)
			FAIL("got '%s', want 'abc'", out);
	}

	/* out_size == 0 must not write at all */
	{
		char guard[2] = { 'Z', 'Z' };

		TEST("out_size 0 writes nothing");
		lota_str_sanitize("abc", guard, 0);
		if (guard[0] != 'Z' || guard[1] != 'Z')
			FAIL("buffer written");
	}

	return test_end();
}
