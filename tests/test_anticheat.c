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

#include "lota_anticheat.h"
#include "lota_gaming.h"
#include "lota_server.h"

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

/*
 * minimal valid LOTA token wire blob using the gaming SDK
 * attest/sig data is fabricated (not cryptographically valid),
 * but the header satisfies lota_server_parse_token()
 */
static size_t build_mock_token(uint8_t *buf, size_t buflen, uint32_t flags) {
  struct lota_token tok = {0};
  tok.valid_until = (uint64_t)time(NULL) + 3600;
  tok.flags = flags;
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

static void write_mock_status(const char *dir, uint32_t flags) {
  char data[256];
  int n = snprintf(data, sizeof(data),
                   "LOTA_ATTESTED=%d\n"
                   "LOTA_FLAGS=0x%08X\n"
                   "LOTA_VALID_UNTIL=%lu\n"
                   "LOTA_ATTEST_COUNT=1\n"
                   "LOTA_FAIL_COUNT=0\n"
                   "LOTA_UPDATED=%lu\n"
                   "LOTA_PID=%d\n",
                   flags ? 1 : 0, flags, (unsigned long)(time(NULL) + 3600),
                   (unsigned long)time(NULL), (int)getpid());
  write_test_file(dir, "lota-status", data, (size_t)n);
}

static void write_mock_token(const char *dir, uint32_t flags) {
  uint8_t tok[2048];
  size_t tok_len = build_mock_token(tok, sizeof(tok), flags);
  if (tok_len > 0)
    write_test_file(dir, "lota-token.bin", tok, tok_len);
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
  write_mock_status(test_dir, 0x07);
  write_mock_token(test_dir, 0x07);

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

static void test_init_battleye_file_mode(void) {
  TEST("init: BattlEye file mode with valid mock data");
  write_mock_status(test_dir, 0x07);
  write_mock_token(test_dir, 0x07);

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
  write_mock_status(test_dir, 0x07);
  write_mock_token(test_dir, 0x07);

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
  write_mock_status(test_dir, 0x07);
  write_mock_token(test_dir, 0x07);

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
  write_mock_status(test_dir, 0x00);
  write_mock_token(test_dir, 0x07);

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
  write_mock_status(test_dir, 0x03); /* ATTESTED + TPM_OK but no IOMMU */
  write_mock_token(test_dir, 0x03);

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
  write_mock_status(test_dir, 0x07);
  write_mock_token(test_dir, 0x07);

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
  TEST("heartbeat: generates valid packet");
  write_mock_status(test_dir, 0x07);
  write_mock_token(test_dir, 0x07);

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
  if (ret != 0) {
    FAIL("heartbeat failed");
    lota_ac_shutdown(s);
    return;
  }
  if (written < LOTA_AC_HEADER_SIZE) {
    FAIL("too short");
    lota_ac_shutdown(s);
    return;
  }

  const struct lota_ac_heartbeat_wire *hdr =
      (const struct lota_ac_heartbeat_wire *)buf;
  int ok = 1;
  if (hdr->magic != LOTA_AC_MAGIC) {
    ok = 0;
    printf("(magic) ");
  }
  if (hdr->version != LOTA_AC_VERSION) {
    ok = 0;
    printf("(ver) ");
  }
  if (hdr->provider != LOTA_AC_PROVIDER_EAC) {
    ok = 0;
    printf("(prov) ");
  }
  if (hdr->total_size != written) {
    ok = 0;
    printf("(size) ");
  }
  if (hdr->sequence != 0) {
    ok = 0;
    printf("(seq) ");
  }
  if (hdr->token_size == 0) {
    ok = 0;
    printf("(tok) ");
  }

  lota_ac_shutdown(s);
  if (ok)
    PASS();
  else
    FAIL("field mismatch");
}

static void test_heartbeat_sequence_increments(void) {
  TEST("heartbeat: sequence increments per call");
  write_mock_status(test_dir, 0x07);
  write_mock_token(test_dir, 0x07);

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

  lota_ac_heartbeat(s, buf, sizeof(buf), &written);
  uint32_t seq0 = hdr->sequence;

  lota_ac_heartbeat(s, buf, sizeof(buf), &written);
  uint32_t seq1 = hdr->sequence;

  lota_ac_heartbeat(s, buf, sizeof(buf), &written);
  uint32_t seq2 = hdr->sequence;

  lota_ac_shutdown(s);

  if (seq0 == 0 && seq1 == 1 && seq2 == 2)
    PASS();
  else
    FAIL("not monotonic");
}

static void test_heartbeat_session_id_stable(void) {
  TEST("heartbeat: session_id stable across heartbeats");
  write_mock_status(test_dir, 0x07);
  write_mock_token(test_dir, 0x07);

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
  lota_ac_heartbeat(s, buf1, sizeof(buf1), &w1);
  lota_ac_heartbeat(s, buf2, sizeof(buf2), &w2);

  const struct lota_ac_heartbeat_wire *h1 =
      (const struct lota_ac_heartbeat_wire *)buf1;
  const struct lota_ac_heartbeat_wire *h2 =
      (const struct lota_ac_heartbeat_wire *)buf2;

  lota_ac_shutdown(s);

  if (memcmp(h1->session_id, h2->session_id, LOTA_AC_SESSION_ID_SIZE) == 0)
    PASS();
  else
    FAIL("session_id changed");
}

static void test_heartbeat_game_id_hash(void) {
  TEST("heartbeat: game_id_hash differs per game");
  write_mock_status(test_dir, 0x07);
  write_mock_token(test_dir, 0x07);

  uint8_t buf1[LOTA_AC_MAX_HEARTBEAT], buf2[LOTA_AC_MAX_HEARTBEAT];
  size_t w1, w2;

  struct lota_ac_config cfg1 = {
      .provider = LOTA_AC_PROVIDER_EAC,
      .game_id = "game-alpha",
      .token_dir = test_dir,
  };
  struct lota_ac_session *s1 = lota_ac_init(&cfg1);
  lota_ac_heartbeat(s1, buf1, sizeof(buf1), &w1);
  lota_ac_shutdown(s1);

  struct lota_ac_config cfg2 = {
      .provider = LOTA_AC_PROVIDER_EAC,
      .game_id = "game-beta",
      .token_dir = test_dir,
  };
  struct lota_ac_session *s2 = lota_ac_init(&cfg2);
  lota_ac_heartbeat(s2, buf2, sizeof(buf2), &w2);
  lota_ac_shutdown(s2);

  const struct lota_ac_heartbeat_wire *h1 =
      (const struct lota_ac_heartbeat_wire *)buf1;
  const struct lota_ac_heartbeat_wire *h2 =
      (const struct lota_ac_heartbeat_wire *)buf2;

  if (memcmp(h1->game_id_hash, h2->game_id_hash, LOTA_AC_GAME_HASH_SIZE) != 0)
    PASS();
  else
    FAIL("same hash for different games");
}

static void test_heartbeat_buf_too_small(void) {
  TEST("heartbeat: buffer too small -> -ENOSPC");
  write_mock_status(test_dir, 0x07);
  write_mock_token(test_dir, 0x07);

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

  if (ret == -ENOSPC)
    PASS();
  else
    FAIL("expected -ENOSPC");
}

static void test_heartbeat_no_token(void) {
  TEST("heartbeat: no token file -> -ENODATA");
  char empty_dir[512];
  snprintf(empty_dir, sizeof(empty_dir), "%s/notoken", test_dir);
  mkdir(empty_dir, 0700);
  /* write status but no token */
  write_mock_status(empty_dir, 0x07);

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

  if (ret == -ENODATA)
    PASS();
  else
    FAIL("expected -ENODATA");
}

static void test_heartbeat_null_args(void) {
  TEST("heartbeat: NULL arguments -> -EINVAL");
  uint8_t buf[64];
  size_t written;
  int ok = 1;
  if (lota_ac_heartbeat(NULL, buf, sizeof(buf), &written) != -EINVAL)
    ok = 0;

  write_mock_status(test_dir, 0x07);
  write_mock_token(test_dir, 0x07);
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
  TEST("verify: generate -> parse roundtrip");
  write_mock_status(test_dir, 0x07);
  write_mock_token(test_dir, 0x07);

  struct lota_ac_config cfg = {
      .provider = LOTA_AC_PROVIDER_EAC,
      .game_id = "test-verify",
      .token_dir = test_dir,
  };
  struct lota_ac_session *s = lota_ac_init(&cfg);
  if (!s) {
    FAIL("init failed");
    return;
  }

  uint8_t buf[LOTA_AC_MAX_HEARTBEAT];
  size_t written;
  int ret = lota_ac_heartbeat(s, buf, sizeof(buf), &written);
  if (ret != 0) {
    FAIL("heartbeat failed");
    lota_ac_shutdown(s);
    return;
  }

  /* get session info for comparison */
  struct lota_ac_info orig;
  lota_ac_get_info(s, &orig);
  lota_ac_shutdown(s);

  /* verify (parse-only, no AIK) */
  struct lota_ac_info verified;
  ret = lota_ac_verify_heartbeat(buf, written, NULL, 0, &verified);
  if (ret != 0) {
    char reason[64];
    snprintf(reason, sizeof(reason), "verify failed: %d", ret);
    FAIL(reason);
    return;
  }

  int ok = 1;
  if (verified.provider != LOTA_AC_PROVIDER_EAC) {
    ok = 0;
    printf("(prov) ");
  }
  if (memcmp(verified.session_id, orig.session_id, LOTA_AC_SESSION_ID_SIZE) !=
      0) {
    ok = 0;
    printf("(sid) ");
  }
  if (verified.heartbeat_seq != 0) {
    ok = 0;
    printf("(seq) ");
  }
  if (verified.lota_flags != 0x07) {
    ok = 0;
    printf("(flags=%u) ", verified.lota_flags);
  }
  if (!verified.trusted) {
    ok = 0;
    printf("(trusted) ");
  }

  if (ok)
    PASS();
  else
    FAIL("mismatch");
}

static void test_verify_battleye_roundtrip(void) {
  TEST("verify: BattlEye roundtrip");
  write_mock_status(test_dir, 0x1F);
  write_mock_token(test_dir, 0x1F);

  struct lota_ac_config cfg = {
      .provider = LOTA_AC_PROVIDER_BATTLEYE,
      .game_id = "test-be-verify",
      .token_dir = test_dir,
  };
  struct lota_ac_session *s = lota_ac_init(&cfg);
  if (!s) {
    FAIL("init failed");
    return;
  }

  uint8_t buf[LOTA_AC_MAX_HEARTBEAT];
  size_t written;
  lota_ac_heartbeat(s, buf, sizeof(buf), &written);
  lota_ac_shutdown(s);

  struct lota_ac_info info;
  int ret = lota_ac_verify_heartbeat(buf, written, NULL, 0, &info);
  if (ret != 0) {
    FAIL("verify failed");
    return;
  }
  if (info.provider != LOTA_AC_PROVIDER_BATTLEYE) {
    FAIL("wrong provider");
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
  write_mock_status(test_dir, 0x07);
  write_mock_token(test_dir, 0x07);

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
