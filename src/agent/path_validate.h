/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
#ifndef LOTA_PATH_VALIDATE_H
#define LOTA_PATH_VALIDATE_H

#include <ctype.h>
#include <stddef.h>
#include <stdbool.h>

static inline bool lota_path_is_abs(const char *p)
{
	return p && p[0] == '/';
}

static inline bool lota_path_has_dotdot_segment(const char *p)
{
	const char *seg = p;

	if (!p)
		return false;

	while (*seg) {
		while (*seg == '/')
			seg++;
		if (*seg == '\0')
			break;

		const char *end = seg;
		while (*end && *end != '/')
			end++;

		if ((end - seg) == 2 && seg[0] == '.' && seg[1] == '.')
			return true;

		seg = end;
	}

	return false;
}

static inline bool lota_str_has_control(const char *s)
{
	if (!s)
		return false;
	for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
		if (iscntrl(*p))
			return true;
	}
	return false;
}

/*
 * Copy in into out, folding every control characterto a single space,
 * and truncating to out_size - 1 bytes.
 * out is always NUL-terminated when out_size > 0
 */
static inline void lota_str_sanitize(const char *in, char *out, size_t out_size)
{
	size_t i = 0;

	if (out_size == 0)
		return;
	if (in) {
		for (; in[i] != '\0' && i + 1 < out_size; i++)
			out[i] = iscntrl((unsigned char)in[i]) ? ' ' : in[i];
	}
	out[i] = '\0';
}

#endif /* LOTA_PATH_VALIDATE_H */
