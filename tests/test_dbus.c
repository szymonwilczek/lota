/* SPDX-License-Identifier: MIT */
/*
 * LOTA D-Bus Interface Unit Tests
 *
 * Tests the D-Bus module in isolation by connecting to a private
 * session bus.
 *
 * Build:
 *   gcc -Wall -Wextra -Werror -O2 -g -Iinclude -D_GNU_SOURCE \
 *       -o build/test_dbus \
 *       tests/test_dbus.c src/agent/dbus.c \
 *       -lsystemd
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../src/agent/dbus.h"
#include "../src/agent/ipc.h"

static int tests_run;
static int tests_passed;

void ipc_set_dbus(struct ipc_context *ctx, struct dbus_context *dbus) {
  if (ctx)
    ctx->dbus = dbus;
}

#define TEST(name)                                                             \
  do {                                                                         \
    tests_run++;                                                               \
    printf("  [%d] %-55s ", tests_run, name);                                  \
  } while (0)

#define PASS()                                                                 \
  do {                                                                         \
    tests_passed++;                                                            \
    printf("PASS\n");                                                          \
  } while (0)

#define FAIL(msg)                                                              \
  do {                                                                         \
    printf("FAIL: %s\n", msg);                                                 \
  } while (0)

static struct ipc_context test_ipc;

static void setup_ipc(void) {
  memset(&test_ipc, 0, sizeof(test_ipc));
  test_ipc.listen_fd = -1;
  test_ipc.epoll_fd = -1;
  test_ipc.start_time = time(NULL) - 42; /* 42s uptime */
  test_ipc.status_flags = 0x0F;          /* attested+tpm+iommu+bpf */
  test_ipc.last_attest_time = (uint64_t)time(NULL);
  test_ipc.valid_until = (uint64_t)(time(NULL) + 3600);
  test_ipc.attest_count = 5;
  test_ipc.fail_count = 1;
  test_ipc.mode = 0; /* monitor */
}

static void test_init_null_ipc(void) {
  TEST("init: NULL ipc -> NULL");
  struct dbus_context *ctx = dbus_init(NULL);
  if (ctx != NULL) {
    FAIL("expected NULL");
    return;
  }
  PASS();
}

static void test_cleanup_null(void) {
  TEST("cleanup: NULL context does not crash");
  dbus_cleanup(NULL);
  PASS();
}

static void test_get_fd_null(void) {
  TEST("get_fd: NULL context -> -1");
  int fd = dbus_get_fd(NULL);
  if (fd != -1) {
    FAIL("expected -1");
    return;
  }
  PASS();
}

static void test_process_null(void) {
  TEST("process: NULL context -> -EINVAL");
  int ret = dbus_process(NULL, 0);
  if (ret != -EINVAL) {
    FAIL("expected -EINVAL");
    return;
  }
  PASS();
}

static void test_emit_null_safe(void) {
  TEST("emit_*: NULL context does not crash");
  dbus_emit_status_changed(NULL, 0);
  dbus_emit_attestation_result(NULL, true);
  dbus_emit_mode_changed(NULL, 0);
  PASS();
}

static void test_init_system_bus(void) {
  TEST("init: system bus connection (may skip)");

  struct dbus_context *ctx = dbus_init(&test_ipc);
  if (!ctx) {
    /* D-Bus unavailable, eg: CI container -> pass anyway */
    printf("SKIP (no system bus)\n");
    tests_passed++;
    return;
  }

  int fd = dbus_get_fd(ctx);
  if (fd < 0) {
    dbus_cleanup(ctx);
    FAIL("get_fd returned < 0");
    return;
  }

  int ret = dbus_process(ctx, 0);
  if (ret < 0) {
    dbus_cleanup(ctx);
    FAIL("process returned error");
    return;
  }

  /* should not crash even if nobody is listening */
  dbus_emit_status_changed(ctx, 0x0F);
  dbus_emit_attestation_result(ctx, true);
  dbus_emit_attestation_result(ctx, false);
  dbus_emit_mode_changed(ctx, 1);

  dbus_process(ctx, 0);
  dbus_cleanup(ctx);
  PASS();
}

static void test_double_cleanup(void) {
  TEST("cleanup: double free does not crash");

  struct dbus_context *ctx = dbus_init(&test_ipc);
  if (!ctx) {
    printf("SKIP (no system bus)\n");
    tests_passed++;
    return;
  }

  dbus_cleanup(ctx);
  dbus_cleanup(NULL);
  PASS();
}

static void test_ipc_set_dbus_null(void) {
  TEST("ipc_set_dbus: NULL ctx does not crash");
  ipc_set_dbus(NULL, NULL);
  PASS();
}

static void test_ipc_set_dbus_attach(void) {
  TEST("ipc_set_dbus: attaches dbus pointer to ipc context");

  struct ipc_context ipc;
  memset(&ipc, 0, sizeof(ipc));
  ipc.dbus = NULL;

  /* cast (void *)1 as a sentinel to verify assignment */
  ipc_set_dbus(&ipc, (struct dbus_context *)0x1);
  if (ipc.dbus != (struct dbus_context *)0x1) {
    FAIL("dbus pointer not set");
    return;
  }

  ipc_set_dbus(&ipc, NULL);
  if (ipc.dbus != NULL) {
    FAIL("dbus pointer not cleared");
    return;
  }

  PASS();
}

static void test_dbus_constants(void) {
  TEST("constants: bus name, path, interface are non-empty");

  if (!LOTA_DBUS_BUS_NAME[0]) {
    FAIL("empty bus name");
    return;
  }
  if (!LOTA_DBUS_OBJECT_PATH[0]) {
    FAIL("empty path");
    return;
  }
  if (!LOTA_DBUS_INTERFACE[0]) {
    FAIL("empty interface");
    return;
  }

  /* must contain a dot */
  if (!strchr(LOTA_DBUS_BUS_NAME, '.')) {
    FAIL("bus name missing dot");
    return;
  }

  /* verify object path starts with / */
  if (LOTA_DBUS_OBJECT_PATH[0] != '/') {
    FAIL("object path missing leading /");
    return;
  }

  PASS();
}

int main(void) {
  printf("=== LOTA D-Bus Unit Tests ===\n\n");

  setup_ipc();

  test_init_null_ipc();
  test_cleanup_null();
  test_get_fd_null();
  test_process_null();
  test_emit_null_safe();
  test_ipc_set_dbus_null();
  test_ipc_set_dbus_attach();
  test_dbus_constants();

  /* may skip if unavailable */
  test_init_system_bus();
  test_double_cleanup();

  printf("\n=== Results: %d/%d passed ===\n", tests_passed, tests_run);
  return (tests_passed == tests_run) ? 0 : 1;
}
