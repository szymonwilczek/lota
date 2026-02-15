/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - net_parse_pin_sha256 fuzz harness (LibFuzzer)
 *
 * Build:
 *   clang -fsanitize=fuzzer,address -g -O1 \
 *     src/agent/fuzz/net_pin_fuzz.c \
 *     -o build/fuzz-net-pin
 *
 * Run:
 *   ./build/fuzz-net-pin -max_len=256
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define NET_PIN_SHA256_LEN 32

static int fuzz_net_parse_pin_sha256(const char *hex, uint8_t *out) {
  size_t i = 0;
  size_t out_idx = 0;
  uint8_t byte;
  int high;

  if (!hex || !out)
    return -EINVAL;

  while (hex[i] != '\0' && out_idx < NET_PIN_SHA256_LEN) {
    if (hex[i] == ':' || hex[i] == ' ') {
      i++;
      continue;
    }

    if (hex[i + 1] == '\0')
      return -EINVAL;

    high = 0;
    byte = 0;

    for (int n = 0; n < 2; n++) {
      char c = hex[i + n];
      uint8_t nibble;

      if (c >= '0' && c <= '9')
        nibble = (uint8_t)(c - '0');
      else if (c >= 'a' && c <= 'f')
        nibble = (uint8_t)(c - 'a' + 10);
      else if (c >= 'A' && c <= 'F')
        nibble = (uint8_t)(c - 'A' + 10);
      else
        return -EINVAL;

      if (n == 0)
        high = nibble;
      else
        byte = (uint8_t)((high << 4) | nibble);
    }

    out[out_idx++] = byte;
    i += 2;
  }

  while (hex[i] == ':' || hex[i] == ' ')
    i++;

  if (out_idx != NET_PIN_SHA256_LEN || hex[i] != '\0')
    return -EINVAL;

  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  uint8_t out[NET_PIN_SHA256_LEN];

  /* need NUL-terminated string */
  if (size > 256)
    return 0;

  char *str = malloc(size + 1);
  if (!str)
    return 0;

  memcpy(str, data, size);
  str[size] = '\0';

  fuzz_net_parse_pin_sha256(str, out);

  free(str);
  return 0;
}
