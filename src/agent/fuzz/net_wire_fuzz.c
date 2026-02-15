/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - Wire protocol parser fuzz harness (LibFuzzer)
 *
 * Build:
 *   clang -fsanitize=fuzzer,address -g -O1 \
 *     src/agent/fuzz/net_wire_fuzz.c \
 *     -o build/fuzz-net-wire
 *
 * Run:
 *   ./build/fuzz-net-wire -max_len=128
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <endian.h>
#include <errno.h>
#include <stdint.h>
#include <string.h>

#define LOTA_MAGIC 0x41544F4C /* "LOTA" */

struct verifier_challenge {
  uint32_t magic;
  uint32_t version;
  uint8_t nonce[32];
  uint32_t pcr_mask;
  uint32_t flags;
};

struct verifier_result {
  uint32_t magic;
  uint32_t version;
  uint32_t result;
  uint32_t flags;
  uint64_t valid_until;
  uint8_t session_token[32];
};

static int parse_challenge(const uint8_t *buf, size_t size,
                           struct verifier_challenge *challenge) {
  if (size < sizeof(struct verifier_challenge))
    return -EINVAL;

  memcpy(&challenge->magic, buf + 0, 4);
  memcpy(&challenge->version, buf + 4, 4);
  memcpy(challenge->nonce, buf + 8, 32);
  memcpy(&challenge->pcr_mask, buf + 40, 4);
  memcpy(&challenge->flags, buf + 44, 4);

  challenge->magic = le32toh(challenge->magic);
  challenge->version = le32toh(challenge->version);
  challenge->pcr_mask = le32toh(challenge->pcr_mask);
  challenge->flags = le32toh(challenge->flags);

  if (challenge->magic != LOTA_MAGIC)
    return -EPROTO;

  return 0;
}

static int parse_result(const uint8_t *buf, size_t size,
                        struct verifier_result *result) {
  if (size < sizeof(struct verifier_result))
    return -EINVAL;

  memcpy(&result->magic, buf + 0, 4);
  memcpy(&result->version, buf + 4, 4);
  memcpy(&result->result, buf + 8, 4);
  memcpy(&result->flags, buf + 12, 4);
  memcpy(&result->valid_until, buf + 16, 8);
  memcpy(result->session_token, buf + 24, 32);

  result->magic = le32toh(result->magic);
  result->version = le32toh(result->version);
  result->result = le32toh(result->result);
  result->flags = le32toh(result->flags);
  result->valid_until = le64toh(result->valid_until);

  if (result->magic != LOTA_MAGIC)
    return -EPROTO;

  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct verifier_challenge challenge;
  struct verifier_result result;

  /* try parsing as challenge */
  parse_challenge(data, size, &challenge);

  /* try parsing as result */
  parse_result(data, size, &result);

  return 0;
}
