/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */

#include "field.h"

#include <string.h>

static bool refused(unsigned char c)
{
	return c < 0x20 || c > 0x7e || c == '/' || c == '\\' || c == '"';
}

void bench_field_set(struct bench_field *f, const char *src, size_t len)
{
	size_t n = 0;
	bool blank = false;

	memset(f, 0, sizeof(*f));
	for (size_t i = 0; i < len && n < BENCH_FIELD_MAX; i++) {
		unsigned char c = (unsigned char)src[i];

		if (c == ' ' || c == '\t') {
			blank = n > 0;
			continue;
		}
		if (blank) {
			/* a blank is never the last byte */
			if (n + 1 == BENCH_FIELD_MAX)
				break;
			f->s[n++] = ' ';
			blank = false;
		}
		f->s[n++] = refused(c) ? '_' : (char)c;
	}
	f->s[n] = '\0';
	f->set = n > 0;
}

bool bench_field_ok(const char *s)
{
	size_t n = strlen(s);

	if (n == 0 || n > BENCH_FIELD_MAX || s[0] == ' ' || s[n - 1] == ' ')
		return false;
	for (size_t i = 0; i < n; i++) {
		if (refused((unsigned char)s[i]))
			return false;
		if (s[i] == ' ' && s[i + 1] == ' ')
			return false;
	}
	return true;
}
