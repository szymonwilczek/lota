/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Szymon Wilczek */
/*
 * LOTA Agent - integer parsers.
 */

#ifndef LOTA_AGENT_PARSE_UTILS_H
#define LOTA_AGENT_PARSE_UTILS_H

#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>

/* Return: 0, or -1 for NULL, no digits, overflow or trailing characters */
static inline int safe_parse_long(const char *s, long *out)
{
	char *end;
	long v;

	if (!s || !out)
		return -1;

	errno = 0;
	v = strtol(s, &end, 10);
	if (errno != 0 || end == s || *end != '\0')
		return -1;

	*out = v;
	return 0;
}

/* As safe_parse_long(); -1 also for a base strtoul() rejects or a minus sign */
static inline int safe_parse_ulong_base(const char *s, int base,
					unsigned long *out)
{
	char *end;
	unsigned long v;

	if (!s || !out)
		return -1;

	if (!(base == 0 || (base >= 2 && base <= 36)))
		return -1;

	const unsigned char *p = (const unsigned char *)s;
	while (*p && isspace(*p))
		p++;
	if (*p == '-')
		return -1;

	errno = 0;
	v = strtoul(s, &end, base);
	if (errno != 0 || end == s || *end != '\0')
		return -1;

	*out = v;
	return 0;
}

/* As safe_parse_ulong_base() in base 10; -1 also above UINT32_MAX */
static inline int safe_parse_u32_dec(const char *s, uint32_t *out)
{
	unsigned long v;

	if (!s || !out)
		return -1;

	if (safe_parse_ulong_base(s, 10, &v) < 0)
		return -1;

	if (v > UINT32_MAX)
		return -1;

	*out = (uint32_t)v;
	return 0;
}

#endif /* LOTA_AGENT_PARSE_UTILS_H */
