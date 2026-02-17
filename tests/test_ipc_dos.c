/* SPDX-License-Identifier: MIT */
/*
 * IPC DoS / Concurrency Test
 *
 * Verifies that the agent can handle more than 64 concurrent connections.
 *
 * Usage:
 *   1. Start agent: sudo ./build/lota-agent --test-ipc
 *   2. Run test: ./build/test_ipc_dos
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "../include/lota_gaming.h"

#define TEST_CONNECTIONS 100
#define LOTA_SOCKET_PATH "/run/lota/lota.sock"

static struct lota_client *clients[TEST_CONNECTIONS];

int main(void) {
  int i;
  int success_count = 0;
  int ret;
  struct lota_status status;

  printf("=== IPC DoS / Concurrency Test ===\n");
  printf("Target: %d concurrent connections\n\n", TEST_CONNECTIONS);

  printf("Opening connections...\n");
  for (i = 0; i < TEST_CONNECTIONS; i++) {
    clients[i] = lota_connect();
    if (clients[i]) {
      success_count++;
      if (i % 10 == 0)
        printf(".");
    } else {
      printf("X");
      fprintf(stderr, "\nFailed to connect client %d\n", i);
      break;
    }
  }
  printf("\n\nEstablished %d/%d connections.\n", success_count,
         TEST_CONNECTIONS);

  if (success_count < 65) {
    printf("FAIL: Failed to exceed old limit of 64 connections.\n");
    goto cleanup;
  }

  printf("Verifying last connection (%d)...\n", success_count - 1);
  ret = lota_get_status(clients[success_count - 1], &status);
  if (ret == 0) {
    printf("PASS: Last connection is alive and responding.\n");
  } else {
    printf("FAIL: Last connection failed to query status: %s\n",
           lota_strerror(ret));
  }

  printf("Closing connections...\n");
cleanup:
  for (i = 0; i < success_count; i++) {
    if (clients[i]) {
      lota_disconnect(clients[i]);
      clients[i] = NULL;
    }
  }

  printf("Done.\n");
  return (success_count == TEST_CONNECTIONS) ? 0 : 1;
}
