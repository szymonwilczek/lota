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

#include <stdio.h>
#include <string.h>

static int check(const char *in, const char *want, size_t out_size)
{
	char out[64];

	if (out_size > sizeof(out)) {
		fprintf(stderr, "FAIL: test buffer too small\n");
		return 1;
	}
	lota_str_sanitize(in, out, out_size);
	if (strcmp(out, want) != 0) {
		fprintf(stderr, "FAIL: in=%p got='%s' want='%s'\n",
			(const void *)in, out, want);
		return 1;
	}
	return 0;
}

int main(void)
{
	int rc = 0;

	/* forged log line: the newline must not survive */
	rc |= check("evil\nlota: ERR fake", "evil lota: ERR fake", 64);
	/* ANSI escape (ESC = 0x1b) rewrites the terminal: fold it */
	rc |= check("x\033[31mPWN\033[0m", "x [31mPWN [0m", 64);
	/* carriage return, tab and DEL are control bytes too */
	rc |= check("a\rb\tc\177d", "a b c d", 64);
	/* clean string is copied verbatim */
	rc |= check("/usr/lib/libc.so.6", "/usr/lib/libc.so.6", 64);
	/* NULL input yields an empty, terminated string */
	rc |= check(NULL, "", 64);

	/* truncation: out_size bounds the copy and still terminates */
	{
		char out[4];

		lota_str_sanitize("abcdef", out, sizeof(out));
		if (strcmp(out, "abc") != 0) {
			fprintf(stderr,
				"FAIL: truncation got='%s' want='abc'\n", out);
			rc = 1;
		}
	}

	/* out_size == 0 must not write at all */
	{
		char guard[2] = { 'Z', 'Z' };

		lota_str_sanitize("abc", guard, 0);
		if (guard[0] != 'Z' || guard[1] != 'Z') {
			fprintf(stderr, "FAIL: out_size==0 wrote to buffer\n");
			rc = 1;
		}
	}

	if (rc == 0)
		printf("path sanitize: ok\n");
	return rc;
}
