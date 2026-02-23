/* SPDX-License-Identifier: MIT */
#ifndef LOTA_PATH_VALIDATE_H
#define LOTA_PATH_VALIDATE_H

#include <ctype.h>
#include <stdbool.h>
#include <stddef.h>

static inline bool lota_path_is_abs(const char *p) { return p && p[0] == '/'; }

static inline bool lota_path_has_dotdot_segment(const char *p) {
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

static inline bool lota_str_has_control(const char *s) {
  if (!s)
    return false;
  for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
    if (iscntrl(*p))
      return true;
  }
  return false;
}

#endif /* LOTA_PATH_VALIDATE_H */
