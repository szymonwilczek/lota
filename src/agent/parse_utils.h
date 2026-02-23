/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - Parsing utilities (internal)
 */

#ifndef LOTA_AGENT_PARSE_UTILS_H
#define LOTA_AGENT_PARSE_UTILS_H

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>

/*
 * Safe integer parser.
 * Returns 0 on success, -1 on error (overflow, empty, trailing garbage).
 */
static inline int safe_parse_long(const char *s, long *out) {
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

/*
 * Safe unsigned long parser with an explicit base.
 *
 * Returns 0 on success, -1 on error (overflow, empty, trailing garbage,
 * invalid base, or negative sign).
 */
static inline int safe_parse_ulong_base(const char *s, int base,
                                        unsigned long *out) {
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

#endif /* LOTA_AGENT_PARSE_UTILS_H */
