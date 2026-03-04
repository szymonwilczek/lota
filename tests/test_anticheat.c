/* SPDX-License-Identifier: MIT */
/*
 * LOTA Anti-Cheat Compatibility Layer — Unit Tests
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <openssl/evp.h>

#include "lota_anticheat.h"
#include "lota_gaming.h"
#include "lota_server.h"
#include "lota_snapshot.h"

static int tests_run;
static int tests_passed;

#define TEST(name)                                                             \
  do {                                                                         \
    tests_run++;                                                               \
    printf("  [%2d] %-55s", tests_run, name);                                  \
  } while (0)

#define PASS()                                                                 \
  do {                                                                         \
    tests_passed++;                                                            \
    printf("PASS\n");                                                          \
  } while (0)

#define FAIL(reason)                                                           \
  do {                                                                         \
    printf("FAIL (%s)\n", reason);                                             \
  } while (0)

static char test_dir[256];

static void setup_test_dir(void) {
  snprintf(test_dir, sizeof(test_dir), "/tmp/lota_test_ac_XXXXXX");
  if (!mkdtemp(test_dir)) {
    perror("mkdtemp");
    exit(1);
  }
}

static void cleanup_test_dir(void) {
  char cmd[512];
  snprintf(cmd, sizeof(cmd), "rm -rf %s", test_dir);
  if (system(cmd) != 0) { /* best effort */
  }
}

static void write_test_file(const char *dir, const char *name, const void *data,
                            size_t len) {
  char path[512];
  snprintf(path, sizeof(path), "%s/%s", dir, name);

  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (fd < 0) {
    perror("write_test_file open");
    return;
  }
  if (write(fd, data, len) != (ssize_t)len)
    perror("write_test_file write");
  close(fd);
}

static size_t build_mock_token(uint8_t *buf, size_t buflen, uint32_t flags,
                               const uint8_t nonce[32]);

static void write_le16(uint8_t *p, uint16_t v) {
  p[0] = (uint8_t)(v & 0xFF);
  p[1] = (uint8_t)((v >> 8) & 0xFF);
}

static void write_le32(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v & 0xFF);
  p[1] = (uint8_t)((v >> 8) & 0xFF);
  p[2] = (uint8_t)((v >> 16) & 0xFF);
  p[3] = (uint8_t)((v >> 24) & 0xFF);
}

static void write_mock_snapshot(const char *dir, uint32_t flags) {
  uint8_t tok[2048];
  size_t tok_len = build_mock_token(tok, sizeof(tok), flags, NULL);
  if (tok_len == 0)
    return;

  uint8_t buf[16 + 2048];
  write_le32(buf + 0, LOTA_SNAPSHOT_MAGIC);
  write_le16(buf + 4, (uint16_t)LOTA_SNAPSHOT_VERSION);
  write_le16(buf + 6, 0);
  write_le32(buf + 8, flags);
  write_le32(buf + 12, (uint32_t)tok_len);
  memcpy(buf + 16, tok, tok_len);

  write_test_file(dir, LOTA_SNAPSHOT_FILE_NAME, buf, 16 + tok_len);
}

static void write_mock_snapshot_no_token(const char *dir, uint32_t flags) {
  uint8_t buf[16];
  write_le32(buf + 0, LOTA_SNAPSHOT_MAGIC);
  write_le16(buf + 4, (uint16_t)LOTA_SNAPSHOT_VERSION);
  write_le16(buf + 6, 0);
  write_le32(buf + 8, flags);
  write_le32(buf + 12, 0);
  write_test_file(dir, LOTA_SNAPSHOT_FILE_NAME, buf, sizeof(buf));
}

/*
 * minimal valid LOTA token wire blob using the gaming SDK
 * attest/sig data is fabricated (not cryptographically valid),
 * but the header satisfies lota_server_parse_token()
 */
static size_t build_mock_token(uint8_t *buf, size_t buflen, uint32_t flags,
                               const uint8_t nonce[32]) {
  struct lota_token tok = {0};
  tok.valid_until = (uint64_t)time(NULL) + 3600;
  tok.flags = flags;
  if (nonce)
    memcpy(tok.nonce, nonce, 32);
  tok.sig_alg = 0x0014;
  tok.hash_alg = 0x000B;
  tok.pcr_mask = 0x4001;

  uint8_t attest[16] = {0xAA};
  uint8_t sig[8] = {0xCC};
  tok.attest_data = attest;
  tok.attest_size = sizeof(attest);
  tok.signature = sig;
  tok.signature_len = sizeof(sig);

  size_t written = 0;
  if (lota_token_serialize(&tok, buf, buflen, &written) != LOTA_OK)
    return 0;
  return written;
}

static int compute_game_id_hash_test(const char *game_id, uint8_t out[32]) {
  static const char domain[] = "lota-ac-game-id:v1";
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  unsigned int out_len = 32;
  int ok;

  if (!ctx)
    return -ENOMEM;

  ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) &&
       EVP_DigestUpdate(ctx, domain, sizeof(domain)) &&
       EVP_DigestUpdate(ctx, game_id, strlen(game_id)) &&
       EVP_DigestFinal_ex(ctx, out, &out_len);

  EVP_MD_CTX_free(ctx);
  return ok ? 0 : -EIO;
}

static int compute_hb_nonce_test(uint8_t out[32], const uint8_t session_id[16],
                                 uint8_t provider, uint32_t sequence,
                                 uint32_t flags, uint64_t timestamp,
                                 const uint8_t game_hash[32]) {
  static const char domain[] = "lota-ac-heartbeat:v1";
  uint8_t seq_le[4], flags_le[4], ts_le[8];
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  unsigned int out_len = 32;
  int ok;

  if (!ctx)
    return -ENOMEM;

  write_le32(seq_le, sequence);
  write_le32(flags_le, flags);
  for (int i = 0; i < 8; i++)
    ts_le[i] = (uint8_t)((timestamp >> (8 * i)) & 0xFF);

  ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) &&
       EVP_DigestUpdate(ctx, domain, sizeof(domain)) &&
       EVP_DigestUpdate(ctx, session_id, 16) &&
       EVP_DigestUpdate(ctx, &provider, 1) &&
       EVP_DigestUpdate(ctx, seq_le, sizeof(seq_le)) &&
       EVP_DigestUpdate(ctx, flags_le, sizeof(flags_le)) &&
       EVP_DigestUpdate(ctx, ts_le, sizeof(ts_le)) &&
       EVP_DigestUpdate(ctx, game_hash, 32) &&
       EVP_DigestFinal_ex(ctx, out, &out_len);

  EVP_MD_CTX_free(ctx);
  return ok ? 0 : -EIO;
}

static int build_bound_heartbeat_packet(uint8_t *out, size_t out_cap,
                                        size_t *out_len, uint8_t provider,
                                        const char *game_id, uint32_t flags,
                                        uint32_t sequence) {
  uint8_t session_id[LOTA_AC_SESSION_ID_SIZE];
  uint8_t game_hash[LOTA_AC_GAME_HASH_SIZE];
  uint8_t nonce[32];
  uint8_t token[2048];
  uint64_t timestamp = (uint64_t)time(NULL);
  size_t token_len;
  size_t total;

  for (int i = 0; i < (int)sizeof(session_id); i++)
    session_id[i] = (uint8_t)(0xA0 + i);

  if (compute_game_id_hash_test(game_id, game_hash) != 0)
    return -EIO;
  if (compute_hb_nonce_test(nonce, session_id, provider, sequence, flags,
                            timestamp, game_hash) != 0)
    return -EIO;

  token_len = build_mock_token(token, sizeof(token), flags, nonce);
  if (token_len == 0)
    return -EIO;

  total = LOTA_AC_HEADER_SIZE + token_len;
  if (total > out_cap)
    return -ENOSPC;

  write_le32(out + 0, LOTA_AC_MAGIC);
  out[4] = LOTA_AC_VERSION;
  out[5] = provider;
  write_le16(out + 6, (uint16_t)total);
  memcpy(out + 8, session_id, sizeof(session_id));
  write_le32(out + 24, sequence);
  write_le32(out + 28, flags);
  for (int i = 0; i < 8; i++)
    out[32 + i] = (uint8_t)((timestamp >> (8 * i)) & 0xFF);
  memcpy(out + 40, game_hash, sizeof(game_hash));
  write_le16(out + 72, (uint16_t)token_len);
  memcpy(out + LOTA_AC_HEADER_SIZE, token, token_len);

  *out_len = total;
  return 0;
}

static void test_init_null_config(void) {
  TEST("init(NULL) -> NULL");
  struct lota_ac_session *s = lota_ac_init(NULL);
  if (s) {
    FAIL("returned non-NULL");
    lota_ac_shutdown(s);
  } else {
    PASS();
  }
}

static void test_init_empty_game_id(void) {
  TEST("init: empty game_id -> NULL");
  struct lota_ac_config cfg = {
      .provider = LOTA_AC_PROVIDER_EAC,
      .game_id = "",
  };
  struct lota_ac_session *s = lota_ac_init(&cfg);
  if (s) {
    FAIL("returned non-NULL");
    lota_ac_shutdown(s);
  } else {
    PASS();
  }
}

static void test_init_null_game_id(void) {
  TEST("init: NULL game_id -> NULL");
  struct lota_ac_config cfg = {
      .provider = LOTA_AC_PROVIDER_EAC,
      .game_id = NULL,
  };
  struct lota_ac_session *s = lota_ac_init(&cfg);
  if (s) {
    FAIL("returned non-NULL");
    lota_ac_shutdown(s);
  } else {
    PASS();
  }
}

static void test_init_game_id_too_long(void) {
  TEST("init: game_id >= 64 chars -> NULL");
  char long_id[128];
  memset(long_id, 'A', sizeof(long_id) - 1);
  long_id[sizeof(long_id) - 1] = '\0';
  struct lota_ac_config cfg = {
      .provider = LOTA_AC_PROVIDER_EAC,
      .game_id = long_id,
  };
  struct lota_ac_session *s = lota_ac_init(&cfg);
  if (s) {
    FAIL("returned non-NULL");
    lota_ac_shutdown(s);
  } else {
    PASS();
  }
}

static void test_init_invalid_provider(void) {
  TEST("init: provider=99 -> NULL");
  struct lota_ac_config cfg = {
      .provider = 99,
      .game_id = "test-game",
      .token_dir = test_dir,
  };
  struct lota_ac_session *s = lota_ac_init(&cfg);
  if (s) {
    FAIL("returned non-NULL");
    lota_ac_shutdown(s);
  } else {
    PASS();
  }
}

static void test_init_eac_file_mode(void) {
  TEST("init: EAC file mode with valid mock data");
  write_mock_snapshot(test_dir, 0x07);

  struct lota_ac_config cfg = {
      .provider = LOTA_AC_PROVIDER_EAC,
      .game_id = "test-game-eac",
      .token_dir = test_dir,
  };
  struct lota_ac_session *s = lota_ac_init(&cfg);
  if (!s) {
    FAIL("returned NULL");
    return;
  }
  enum lota_ac_state state = lota_ac_get_state(s);
  if (state != LOTA_AC_STATE_TRUSTED) {
    FAIL("expected TRUSTED");
    lota_ac_shutdown(s);
    return;
  }
  lota_ac_shutdown(s);
  PASS();
}

static void test_init_eac_file_mode_snapshot_only(void) {
  TEST("init: EAC file mode snapshot-only (atomic)");

  write_mock_snapshot(test_dir, 0x07);

  struct lota_ac_config cfg = {
      .provider = LOTA_AC_PROVIDER_EAC,
      .game_id = "test-game-eac-snap",
      .token_dir = test_dir,
  };
  struct lota_ac_session *s = lota_ac_init(&cfg);
  if (!s) {
    FAIL("returned NULL");
    return;
  }
  enum lota_ac_state state = lota_ac_get_state(s);
  if (state != LOTA_AC_STATE_TRUSTED) {
    FAIL("expected TRUSTED");
    lota_ac_shutdown(s);
    return;
  }
  lota_ac_shutdown(s);
  PASS();
}

static void test_init_battleye_file_mode(void) {
  TEST("init: BattlEye file mode with valid mock data");
  write_mock_snapshot(test_dir, 0x07);

  struct lota_ac_config cfg = {
      .provider = LOTA_AC_PROVIDER_BATTLEYE,
      .game_id = "test-game-be",
      .token_dir = test_dir,
  };
  struct lota_ac_session *s = lota_ac_init(&cfg);
  if (!s) {
    FAIL("returned NULL");
    return;
  }
  if (lota_ac_get_state(s) != LOTA_AC_STATE_TRUSTED) {
    FAIL("expected TRUSTED");
    lota_ac_shutdown(s);
    return;
  }
  lota_ac_shutdown(s);
  PASS();
}

static void test_shutdown_null(void) {
  TEST("shutdown(NULL) does not crash");
  lota_ac_shutdown(NULL);
  PASS();
}

static void test_get_state_null(void) {
  TEST("get_state(NULL) -> IDLE");
  if (lota_ac_get_state(NULL) != LOTA_AC_STATE_IDLE) {
    FAIL("expected IDLE");
    return;
  }
  PASS();
}

static void test_get_info_null(void) {
  TEST("get_info(NULL, ...) -> -EINVAL");
  struct lota_ac_info info;
  if (lota_ac_get_info(NULL, &info) != -EINVAL) {
    FAIL("expected -EINVAL");
    return;
  }
  PASS();
}

static void test_get_info_null_info(void) {
  TEST("get_info(session, NULL) -> -EINVAL");
  write_mock_snapshot(test_dir, 0x07);

  struct lota_ac_config cfg = {
      .provider = LOTA_AC_PROVIDER_EAC,
      .game_id = "test-game",
      .token_dir = test_dir,
  };
  struct lota_ac_session *s = lota_ac_init(&cfg);
  if (!s) {
    FAIL("init failed");
    return;
  }
  if (lota_ac_get_info(s, NULL) != -EINVAL) {
    FAIL("expected -EINVAL");
    lota_ac_shutdown(s);
    return;
  }
  lota_ac_shutdown(s);
  PASS();
}

static void test_get_info_fields(void) {
  TEST("get_info returns correct session fields");
  write_mock_snapshot(test_dir, 0x07);

  struct lota_ac_config cfg = {
      .provider = LOTA_AC_PROVIDER_EAC,
      .game_id = "test-game-info",
      .token_dir = test_dir,
  };
  struct lota_ac_session *s = lota_ac_init(&cfg);
  if (!s) {
    FAIL("init failed");
    return;
  }

  struct lota_ac_info info;
  if (lota_ac_get_info(s, &info) != 0) {
    FAIL("get_info failed");
    lota_ac_shutdown(s);
    return;
  }
  int ok = 1;
  if (info.provider != LOTA_AC_PROVIDER_EAC) {
    ok = 0;
    printf("(provider) ");
  }
  if (info.state != LOTA_AC_STATE_TRUSTED) {
    ok = 0;
    printf("(state) ");
  }
  if (info.session_start == 0) {
    ok = 0;
    printf("(start) ");
  }
  if (info.lota_flags != 0x07) {
    ok = 0;
    printf("(flags) ");
  }
  if (!info.trusted) {
    ok = 0;
    printf("(trusted) ");
  }
  if (info.heartbeat_seq != 0) {
    ok = 0;
    printf("(seq) ");
  }

  lota_ac_shutdown(s);
  if (ok)
    PASS();
  else
    FAIL("field mismatch");
}

static void test_state_untrusted_zero_flags(void) {
  TEST("state: zero flags -> UNTRUSTED");
  write_mock_snapshot(test_dir, 0x00);

  struct lota_ac_config cfg = {
      .provider = LOTA_AC_PROVIDER_EAC,
      .game_id = "test-untrusted",
      .token_dir = test_dir,
  };
  struct lota_ac_session *s = lota_ac_init(&cfg);
  if (!s) {
    FAIL("init failed");
    return;
  }
  /* flags = 0 but token present -> UNTRUSTED */
  if (lota_ac_get_state(s) != LOTA_AC_STATE_UNTRUSTED) {
    FAIL("expected UNTRUSTED");
    lota_ac_shutdown(s);
    return;
  }
  lota_ac_shutdown(s);
  PASS();
}

static void test_state_required_flags(void) {
  TEST("state: missing required flags -> UNTRUSTED");
  write_mock_snapshot(test_dir, 0x03); /* ATTESTED + TPM_OK but no IOMMU */

  struct lota_ac_config cfg = {
      .provider = LOTA_AC_PROVIDER_BATTLEYE,
      .game_id = "test-required",
      .token_dir = test_dir,
      .required_flags = 0x07, /* need ATTESTED + TPM + IOMMU */
  };
  struct lota_ac_session *s = lota_ac_init(&cfg);
  if (!s) {
    FAIL("init failed");
    return;
  }
  if (lota_ac_get_state(s) != LOTA_AC_STATE_UNTRUSTED) {
    FAIL("expected UNTRUSTED");
    lota_ac_shutdown(s);
    return;
  }
  lota_ac_shutdown(s);
  PASS();
}

static void test_state_required_flags_met(void) {
  TEST("state: required flags met -> TRUSTED");
  write_mock_snapshot(test_dir, 0x07);

  struct lota_ac_config cfg = {
      .provider = LOTA_AC_PROVIDER_EAC,
      .game_id = "test-met",
      .token_dir = test_dir,
      .required_flags = 0x07,
  };
  struct lota_ac_session *s = lota_ac_init(&cfg);
  if (!s) {
    FAIL("init failed");
    return;
  }
  if (lota_ac_get_state(s) != LOTA_AC_STATE_TRUSTED) {
    FAIL("expected TRUSTED");
    lota_ac_shutdown(s);
    return;
  }
  lota_ac_shutdown(s);
  PASS();
}

static void test_state_no_files(void) {
  TEST("state: missing files -> ERROR");
  /* use a fresh empty dir */
  char empty_dir[512];
  snprintf(empty_dir, sizeof(empty_dir), "%s/empty", test_dir);
  mkdir(empty_dir, 0700);

  struct lota_ac_config cfg = {
      .provider = LOTA_AC_PROVIDER_EAC,
      .game_id = "test-nofiles",
      .token_dir = empty_dir,
  };
  struct lota_ac_session *s = lota_ac_init(&cfg);
  if (!s) {
    FAIL("init failed");
    return;
  }
  if (lota_ac_get_state(s) != LOTA_AC_STATE_ERROR) {
    FAIL("expected ERROR");
    lota_ac_shutdown(s);
    return;
  }
  lota_ac_shutdown(s);
  PASS();
}

static void test_wire_header_size(void) {
  TEST("wire: header struct == 74 bytes");
  if (sizeof(struct lota_ac_heartbeat_wire) != 74) {
    FAIL("size mismatch");
    return;
  }
  PASS();
}

static void test_heartbeat_generation(void) {
  TEST("heartbeat: file mode replay-safe path disabled");
  write_mock_snapshot(test_dir, 0x07);

  struct lota_ac_config cfg = {
      .provider = LOTA_AC_PROVIDER_EAC,
      .game_id = "test-heartbeat",
      .token_dir = test_dir,
  };
  struct lota_ac_session *s = lota_ac_init(&cfg);
  if (!s) {
    FAIL("init failed");
    return;
  }

  uint8_t buf[LOTA_AC_MAX_HEARTBEAT];
  size_t written = 0;
  int ret = lota_ac_heartbeat(s, buf, sizeof(buf), &written);
  lota_ac_shutdown(s);
  if (ret == -EOPNOTSUPP)
    PASS();
  else
    FAIL("expected -EOPNOTSUPP");
}

static void test_heartbeat_sequence_increments(void) {
  TEST("heartbeat: file mode sequence path blocked");
  write_mock_snapshot(test_dir, 0x07);

  struct lota_ac_config cfg = {
      .provider = LOTA_AC_PROVIDER_EAC,
      .game_id = "test-seq",
      .token_dir = test_dir,
  };
  struct lota_ac_session *s = lota_ac_init(&cfg);
  if (!s) {
    FAIL("init failed");
    return;
  }

  uint8_t buf[LOTA_AC_MAX_HEARTBEAT];
  size_t written;
  const struct lota_ac_heartbeat_wire *hdr =
      (const struct lota_ac_heartbeat_wire *)buf;

  int r0 = lota_ac_heartbeat(s, buf, sizeof(buf), &written);
  int r1 = lota_ac_heartbeat(s, buf, sizeof(buf), &written);
  int r2 = lota_ac_heartbeat(s, buf, sizeof(buf), &written);

  lota_ac_shutdown(s);

  (void)hdr;
  if (r0 == -EOPNOTSUPP && r1 == -EOPNOTSUPP && r2 == -EOPNOTSUPP)
    PASS();
  else
    FAIL("expected -EOPNOTSUPP");
}

static void test_heartbeat_session_id_stable(void) {
  TEST("heartbeat: file mode session heartbeat blocked");
  write_mock_snapshot(test_dir, 0x07);

  struct lota_ac_config cfg = {
      .provider = LOTA_AC_PROVIDER_BATTLEYE,
      .game_id = "test-stable",
      .token_dir = test_dir,
  };
  struct lota_ac_session *s = lota_ac_init(&cfg);
  if (!s) {
    FAIL("init failed");
    return;
  }

  uint8_t buf1[LOTA_AC_MAX_HEARTBEAT], buf2[LOTA_AC_MAX_HEARTBEAT];
  size_t w1, w2;
  int r1 = lota_ac_heartbeat(s, buf1, sizeof(buf1), &w1);
  int r2 = lota_ac_heartbeat(s, buf2, sizeof(buf2), &w2);

  lota_ac_shutdown(s);

  if (r1 == -EOPNOTSUPP && r2 == -EOPNOTSUPP)
    PASS();
  else
    FAIL("expected -EOPNOTSUPP");
}

static void test_heartbeat_game_id_hash(void) {
  TEST("heartbeat: file mode game hash path blocked");
  write_mock_snapshot(test_dir, 0x07);

  uint8_t buf1[LOTA_AC_MAX_HEARTBEAT], buf2[LOTA_AC_MAX_HEARTBEAT];
  size_t w1, w2;

  struct lota_ac_config cfg1 = {
      .provider = LOTA_AC_PROVIDER_EAC,
      .game_id = "game-alpha",
      .token_dir = test_dir,
  };
  struct lota_ac_session *s1 = lota_ac_init(&cfg1);
  int r1 = lota_ac_heartbeat(s1, buf1, sizeof(buf1), &w1);
  lota_ac_shutdown(s1);

  struct lota_ac_config cfg2 = {
      .provider = LOTA_AC_PROVIDER_EAC,
      .game_id = "game-beta",
      .token_dir = test_dir,
  };
  struct lota_ac_session *s2 = lota_ac_init(&cfg2);
  int r2 = lota_ac_heartbeat(s2, buf2, sizeof(buf2), &w2);
  lota_ac_shutdown(s2);

  if (r1 == -EOPNOTSUPP && r2 == -EOPNOTSUPP)
    PASS();
  else
    FAIL("expected -EOPNOTSUPP");
}

static int test_sha256(const void *data, size_t len, uint8_t out[32]) {
  EVP_MD_CTX *ctx = EVP_MD_CTX_new();
  if (!ctx)
    return -ENOMEM;

  unsigned int out_len = 32;
  int ok = EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) &&
           EVP_DigestUpdate(ctx, data, len) &&
           EVP_DigestFinal_ex(ctx, out, &out_len);

  EVP_MD_CTX_free(ctx);
  return ok ? 0 : -EIO;
}

static void test_heartbeat_game_id_hash_domain_separated(void) {
  TEST("heartbeat: game_id_hash is domain-separated");
  uint8_t hdr_hash[LOTA_AC_GAME_HASH_SIZE];
  uint8_t legacy_hash[LOTA_AC_GAME_HASH_SIZE];
  if (compute_game_id_hash_test("game-alpha", hdr_hash) != 0) {
    FAIL("domain hash compute failed");
    return;
  }
  if (test_sha256("game-alpha", strlen("game-alpha"), legacy_hash) != 0) {
    FAIL("legacy hash compute failed");
    return;
  }

  if (memcmp(hdr_hash, legacy_hash, LOTA_AC_GAME_HASH_SIZE) == 0) {
    FAIL("hash matches legacy SHA-256(game_id)");
    return;
  }

  PASS();
}

static void test_heartbeat_buf_too_small(void) {
  TEST("heartbeat: file mode returns -EOPNOTSUPP before size checks");
  write_mock_snapshot(test_dir, 0x07);

  struct lota_ac_config cfg = {
      .provider = LOTA_AC_PROVIDER_EAC,
      .game_id = "test-small",
      .token_dir = test_dir,
  };
  struct lota_ac_session *s = lota_ac_init(&cfg);
  if (!s) {
    FAIL("init failed");
    return;
  }

  uint8_t buf[16]; /* way too small */
  size_t written;
  int ret = lota_ac_heartbeat(s, buf, sizeof(buf), &written);
  lota_ac_shutdown(s);

  if (ret == -EOPNOTSUPP)
    PASS();
  else
    FAIL("expected -EOPNOTSUPP");
}

static void test_heartbeat_no_token(void) {
  TEST("heartbeat: file mode no-token path blocked");
  char empty_dir[512];
  snprintf(empty_dir, sizeof(empty_dir), "%s/notoken", test_dir);
  mkdir(empty_dir, 0700);
  /* snapshot exists, but no token payload */
  write_mock_snapshot_no_token(empty_dir, 0x07);

  struct lota_ac_config cfg = {
      .provider = LOTA_AC_PROVIDER_EAC,
      .game_id = "test-notoken",
      .token_dir = empty_dir,
  };
  struct lota_ac_session *s = lota_ac_init(&cfg);
  if (!s) {
    FAIL("init failed");
    return;
  }

  uint8_t buf[LOTA_AC_MAX_HEARTBEAT];
  size_t written;
  int ret = lota_ac_heartbeat(s, buf, sizeof(buf), &written);
  lota_ac_shutdown(s);

  if (ret == -EOPNOTSUPP)
    PASS();
  else
    FAIL("expected -EOPNOTSUPP");
}

static void test_heartbeat_null_args(void) {
  TEST("heartbeat: NULL arguments -> -EINVAL");
  uint8_t buf[64];
  size_t written;
  int ok = 1;
  if (lota_ac_heartbeat(NULL, buf, sizeof(buf), &written) != -EINVAL)
    ok = 0;

  write_mock_snapshot(test_dir, 0x07);
  struct lota_ac_config cfg = {
      .provider = LOTA_AC_PROVIDER_EAC,
      .game_id = "test-null",
      .token_dir = test_dir,
  };
  struct lota_ac_session *s = lota_ac_init(&cfg);
  if (s) {
    if (lota_ac_heartbeat(s, NULL, 100, &written) != -EINVAL)
      ok = 0;
    if (lota_ac_heartbeat(s, buf, sizeof(buf), NULL) != -EINVAL)
      ok = 0;
    lota_ac_shutdown(s);
  }
  if (ok)
    PASS();
  else
    FAIL("did not return -EINVAL");
}

static void test_verify_roundtrip(void) {
  TEST("verify: nonce-bound heartbeat requires AIK key");
  uint8_t buf[LOTA_AC_MAX_HEARTBEAT];
  size_t written = 0;
  int ret = build_bound_heartbeat_packet(
      buf, sizeof(buf), &written, LOTA_AC_PROVIDER_EAC, "test-verify", 0x07, 0);
  if (ret != 0) {
    FAIL("packet build failed");
    return;
  }

  /* fail closed: cryptographic verification key is mandatory */
  struct lota_ac_info verified;
  ret = lota_ac_verify_heartbeat(buf, written, NULL, 0, &verified);
  if (ret != LOTA_SERVER_ERR_INVALID_ARG) {
    FAIL("expected LOTA_SERVER_ERR_INVALID_ARG");
    return;
  }

  PASS();
}

static void test_verify_battleye_roundtrip(void) {
  TEST("verify: BattlEye heartbeat requires AIK key");
  uint8_t buf[LOTA_AC_MAX_HEARTBEAT];
  size_t written = 0;
  if (build_bound_heartbeat_packet(buf, sizeof(buf), &written,
                                   LOTA_AC_PROVIDER_BATTLEYE, "test-be-verify",
                                   0x1F, 42) != 0) {
    FAIL("packet build failed");
    return;
  }

  struct lota_ac_info info;
  int ret = lota_ac_verify_heartbeat(buf, written, NULL, 0, &info);
  if (ret != LOTA_SERVER_ERR_INVALID_ARG) {
    FAIL("expected LOTA_SERVER_ERR_INVALID_ARG");
    return;
  }
  PASS();
}

static void test_verify_null_data(void) {
  TEST("verify: NULL data -> INVALID_ARG");
  struct lota_ac_info info;
  if (lota_ac_verify_heartbeat(NULL, 100, NULL, 0, &info) !=
      LOTA_AC_ERR_INVALID_ARG) {
    FAIL("expected LOTA_AC_ERR_INVALID_ARG");
    return;
  }
  PASS();
}

static void test_verify_null_info(void) {
  TEST("verify: NULL info -> INVALID_ARG");
  uint8_t data[128] = {0};
  if (lota_ac_verify_heartbeat(data, sizeof(data), NULL, 0, NULL) !=
      LOTA_AC_ERR_INVALID_ARG) {
    FAIL("expected LOTA_AC_ERR_INVALID_ARG");
    return;
  }
  PASS();
}

static void test_verify_truncated(void) {
  TEST("verify: truncated data -> BAD_TOKEN");
  uint8_t data[32] = {0};
  struct lota_ac_info info;
  if (lota_ac_verify_heartbeat(data, sizeof(data), NULL, 0, &info) !=
      LOTA_SERVER_ERR_BAD_TOKEN) {
    FAIL("expected LOTA_SERVER_ERR_BAD_TOKEN");
    return;
  }
  PASS();
}

static void test_verify_bad_magic(void) {
  TEST("verify: bad magic -> BAD_TOKEN");
  uint8_t data[LOTA_AC_HEADER_SIZE + 96];
  memset(data, 0, sizeof(data));

  struct lota_ac_heartbeat_wire *hdr = (struct lota_ac_heartbeat_wire *)data;
  hdr->magic = 0xDEADBEEF;
  hdr->version = LOTA_AC_VERSION;
  hdr->provider = LOTA_AC_PROVIDER_EAC;
  hdr->total_size = sizeof(data);
  hdr->token_size = sizeof(data) - LOTA_AC_HEADER_SIZE;

  struct lota_ac_info info;
  if (lota_ac_verify_heartbeat(data, sizeof(data), NULL, 0, &info) !=
      LOTA_SERVER_ERR_BAD_TOKEN) {
    FAIL("expected LOTA_SERVER_ERR_BAD_TOKEN");
    return;
  }
  PASS();
}

static void test_verify_bad_version(void) {
  TEST("verify: bad version -> BAD_VERSION");
  uint8_t data[LOTA_AC_HEADER_SIZE + 96];
  memset(data, 0, sizeof(data));

  struct lota_ac_heartbeat_wire *hdr = (struct lota_ac_heartbeat_wire *)data;
  hdr->magic = LOTA_AC_MAGIC;
  hdr->version = 99;
  hdr->provider = LOTA_AC_PROVIDER_EAC;
  hdr->total_size = sizeof(data);
  hdr->token_size = sizeof(data) - LOTA_AC_HEADER_SIZE;

  struct lota_ac_info info;
  if (lota_ac_verify_heartbeat(data, sizeof(data), NULL, 0, &info) !=
      LOTA_AC_ERR_VERSION) {
    FAIL("expected LOTA_AC_ERR_VERSION");
    return;
  }
  PASS();
}

static void test_verify_bad_provider(void) {
  TEST("verify: bad provider -> BAD_TOKEN");
  uint8_t data[LOTA_AC_HEADER_SIZE + 96];
  memset(data, 0, sizeof(data));

  struct lota_ac_heartbeat_wire *hdr = (struct lota_ac_heartbeat_wire *)data;
  hdr->magic = LOTA_AC_MAGIC;
  hdr->version = LOTA_AC_VERSION;
  hdr->provider = 42;
  hdr->total_size = sizeof(data);
  hdr->token_size = sizeof(data) - LOTA_AC_HEADER_SIZE;

  struct lota_ac_info info;
  if (lota_ac_verify_heartbeat(data, sizeof(data), NULL, 0, &info) !=
      LOTA_SERVER_ERR_BAD_TOKEN) {
    FAIL("expected LOTA_SERVER_ERR_BAD_TOKEN");
    return;
  }
  PASS();
}

static void test_verify_size_mismatch(void) {
  TEST("verify: total_size > actual len -> BAD_TOKEN");
  uint8_t data[LOTA_AC_HEADER_SIZE + 96];
  memset(data, 0, sizeof(data));

  struct lota_ac_heartbeat_wire *hdr = (struct lota_ac_heartbeat_wire *)data;
  hdr->magic = LOTA_AC_MAGIC;
  hdr->version = LOTA_AC_VERSION;
  hdr->provider = LOTA_AC_PROVIDER_EAC;
  hdr->total_size = 9999; /* way bigger than actual data */
  hdr->token_size = 128;

  struct lota_ac_info info;
  if (lota_ac_verify_heartbeat(data, sizeof(data), NULL, 0, &info) !=
      LOTA_SERVER_ERR_BAD_TOKEN) {
    FAIL("expected LOTA_SERVER_ERR_BAD_TOKEN");
    return;
  }
  PASS();
}

static void test_verify_header_flags_tamper_rejected(void) {
  TEST("verify: tampered heartbeat without AIK -> INVALID_ARG");
  uint8_t buf[LOTA_AC_MAX_HEARTBEAT];
  size_t written = 0;
  if (build_bound_heartbeat_packet(buf, sizeof(buf), &written,
                                   LOTA_AC_PROVIDER_EAC, "test-flags-tamper",
                                   0x07, 1) != 0) {
    FAIL("packet build failed");
    return;
  }

  /* tamper plaintext header flag mirror, keep embedded token unchanged */
  write_le32(buf + 28, 0xdeadbeefU);

  struct lota_ac_info info;
  if (lota_ac_verify_heartbeat(buf, written, NULL, 0, &info) !=
      LOTA_SERVER_ERR_INVALID_ARG) {
    FAIL("expected LOTA_SERVER_ERR_INVALID_ARG");
    return;
  }

  PASS();
}

static void test_direct_mode_no_agent(void) {
  TEST("direct mode: no agent -> ERROR state (graceful)");
  struct lota_ac_config cfg = {
      .provider = LOTA_AC_PROVIDER_EAC,
      .game_id = "test-direct",
      .direct = 1,
      .socket_path = "/tmp/lota_nonexistent_socket_for_test",
  };
  struct lota_ac_session *s = lota_ac_init(&cfg);
  if (!s) {
    FAIL("init returned NULL");
    return;
  }
  if (lota_ac_get_state(s) != LOTA_AC_STATE_ERROR) {
    FAIL("expected ERROR state");
    lota_ac_shutdown(s);
    return;
  }
  lota_ac_shutdown(s);
  PASS();
}

static void test_default_heartbeat_interval(void) {
  TEST("config: default heartbeat interval = 30s");
  if (LOTA_AC_DEFAULT_HEARTBEAT_SEC != 30) {
    FAIL("wrong default");
    return;
  }
  PASS();
}

static void test_state_str(void) {
  TEST("state_str: all states produce valid strings");
  int ok = 1;
  if (strcmp(lota_ac_state_str(LOTA_AC_STATE_IDLE), "idle") != 0)
    ok = 0;
  if (strcmp(lota_ac_state_str(LOTA_AC_STATE_RUNNING), "running") != 0)
    ok = 0;
  if (strcmp(lota_ac_state_str(LOTA_AC_STATE_TRUSTED), "trusted") != 0)
    ok = 0;
  if (strcmp(lota_ac_state_str(LOTA_AC_STATE_UNTRUSTED), "untrusted") != 0)
    ok = 0;
  if (strcmp(lota_ac_state_str(LOTA_AC_STATE_ERROR), "error") != 0)
    ok = 0;
  if (strcmp(lota_ac_state_str(99), "unknown") != 0)
    ok = 0;
  if (ok)
    PASS();
  else
    FAIL("string mismatch");
}

static void test_provider_str(void) {
  TEST("provider_str: all providers produce valid strings");
  int ok = 1;
  if (strcmp(lota_ac_provider_str(LOTA_AC_PROVIDER_EAC), "EAC") != 0)
    ok = 0;
  if (strcmp(lota_ac_provider_str(LOTA_AC_PROVIDER_BATTLEYE), "BattlEye") != 0)
    ok = 0;
  if (strcmp(lota_ac_provider_str(99), "unknown") != 0)
    ok = 0;
  if (ok)
    PASS();
  else
    FAIL("string mismatch");
}

static void test_tick_null(void) {
  TEST("tick(NULL) -> -EINVAL");
  if (lota_ac_tick(NULL) != -EINVAL) {
    FAIL("expected -EINVAL");
    return;
  }
  PASS();
}

static void test_session_id_unique(void) {
  TEST("session_id: different sessions have different IDs");
  write_mock_snapshot(test_dir, 0x07);

  struct lota_ac_config cfg = {
      .provider = LOTA_AC_PROVIDER_EAC,
      .game_id = "test-unique",
      .token_dir = test_dir,
  };
  struct lota_ac_session *s1 = lota_ac_init(&cfg);
  struct lota_ac_session *s2 = lota_ac_init(&cfg);
  if (!s1 || !s2) {
    FAIL("init failed");
    lota_ac_shutdown(s1);
    lota_ac_shutdown(s2);
    return;
  }

  struct lota_ac_info i1, i2;
  lota_ac_get_info(s1, &i1);
  lota_ac_get_info(s2, &i2);
  lota_ac_shutdown(s1);
  lota_ac_shutdown(s2);

  if (memcmp(i1.session_id, i2.session_id, LOTA_AC_SESSION_ID_SIZE) != 0)
    PASS();
  else
    FAIL("same session_id");
}

int main(void) {
  printf("=== LOTA Anti-Cheat Compatibility Tests ===\n\n");

  setup_test_dir();

  printf("Config Validation:\n");
  test_init_null_config();
  test_init_empty_game_id();
  test_init_null_game_id();
  test_init_game_id_too_long();
  test_init_invalid_provider();

  printf("\nSession Lifecycle:\n");
  test_init_eac_file_mode();
  test_init_eac_file_mode_snapshot_only();
  test_init_battleye_file_mode();
  test_shutdown_null();
  test_get_state_null();
  test_get_info_null();
  test_get_info_null_info();
  test_get_info_fields();

  printf("\nState Machine:\n");
  test_state_untrusted_zero_flags();
  test_state_required_flags();
  test_state_required_flags_met();
  test_state_no_files();

  printf("\nHeartbeat Wire Format:\n");
  test_wire_header_size();
  test_heartbeat_generation();
  test_heartbeat_sequence_increments();
  test_heartbeat_session_id_stable();
  test_heartbeat_game_id_hash();
  test_heartbeat_game_id_hash_domain_separated();
  test_heartbeat_buf_too_small();
  test_heartbeat_no_token();
  test_heartbeat_null_args();
  test_default_heartbeat_interval();

  printf("\nHeartbeat Verification:\n");
  test_verify_roundtrip();
  test_verify_battleye_roundtrip();
  test_verify_null_data();
  test_verify_null_info();
  test_verify_truncated();
  test_verify_bad_magic();
  test_verify_bad_version();
  test_verify_bad_provider();
  test_verify_size_mismatch();
  test_verify_header_flags_tamper_rejected();

  printf("\nDirect Mode:\n");
  test_direct_mode_no_agent();

  printf("\nMisc:\n");
  test_state_str();
  test_provider_str();
  test_tick_null();
  test_session_id_unique();

  cleanup_test_dir();

  printf("\n=== Results: %d/%d passed", tests_passed, tests_run);
  if (tests_passed < tests_run)
    printf(" (%d FAILED)", tests_run - tests_passed);
  printf(" ===\n\n");

  return tests_passed < tests_run ? 1 : 0;
}
