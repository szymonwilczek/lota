/* SPDX-License-Identifier: MIT */
/*
 * LOTA IPC Test Client
 *
 * Usage: ./lota-ipc-test [ping|status|token]
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "../include/lota_ipc.h"

static int connect_to_agent(void) {
  struct sockaddr_un addr;
  int fd;

  fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) {
    perror("socket");
    return -1;
  }

  memset(&addr, 0, sizeof(addr));
  addr.sun_family = AF_UNIX;
  strncpy(addr.sun_path, LOTA_IPC_SOCKET_PATH, sizeof(addr.sun_path) - 1);

  if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
    perror("connect");
    close(fd);
    return -1;
  }

  return fd;
}

static int send_request(int fd, uint32_t cmd, const void *payload,
                        uint32_t len) {
  struct lota_ipc_request req = {
      .magic = LOTA_IPC_MAGIC,
      .version = LOTA_IPC_VERSION,
      .cmd = cmd,
      .payload_len = len,
  };

  if (send(fd, &req, sizeof(req), 0) != sizeof(req)) {
    perror("send header");
    return -1;
  }

  if (len > 0 && payload) {
    if (send(fd, payload, len, 0) != (ssize_t)len) {
      perror("send payload");
      return -1;
    }
  }

  return 0;
}

static int recv_response(int fd, struct lota_ipc_response *resp, void *payload,
                         uint32_t max_payload) {
  ssize_t n;

  n = recv(fd, resp, sizeof(*resp), 0);
  if (n != sizeof(*resp)) {
    if (n < 0)
      perror("recv header");
    else
      fprintf(stderr, "Short read: %zd\n", n);
    return -1;
  }

  if (resp->magic != LOTA_IPC_MAGIC) {
    fprintf(stderr, "Bad magic: 0x%08X\n", resp->magic);
    return -1;
  }

  if (resp->payload_len > 0 && payload) {
    uint32_t to_read = resp->payload_len;
    if (to_read > max_payload)
      to_read = max_payload;

    n = recv(fd, payload, to_read, 0);
    if (n != (ssize_t)to_read) {
      perror("recv payload");
      return -1;
    }
  }

  return 0;
}

static const char *result_str(uint32_t result) {
  switch (result) {
  case LOTA_IPC_OK:
    return "OK";
  case LOTA_IPC_ERR_UNKNOWN_CMD:
    return "UNKNOWN_CMD";
  case LOTA_IPC_ERR_BAD_REQUEST:
    return "BAD_REQUEST";
  case LOTA_IPC_ERR_NOT_ATTESTED:
    return "NOT_ATTESTED";
  case LOTA_IPC_ERR_TPM_FAILURE:
    return "TPM_FAILURE";
  case LOTA_IPC_ERR_INTERNAL:
    return "INTERNAL";
  default:
    return "???";
  }
}

static int do_ping(int fd) {
  struct lota_ipc_response resp;
  struct lota_ipc_ping_response ping;

  printf("Sending PING...\n");

  if (send_request(fd, LOTA_IPC_CMD_PING, NULL, 0) < 0)
    return 1;

  if (recv_response(fd, &resp, &ping, sizeof(ping)) < 0)
    return 1;

  printf("Response: %s\n", result_str(resp.result));
  if (resp.result == LOTA_IPC_OK) {
    printf("  Agent PID: %u\n", ping.pid);
    printf("  Uptime: %lu seconds\n", (unsigned long)ping.uptime_sec);
  }

  return resp.result == LOTA_IPC_OK ? 0 : 1;
}

static int do_status(int fd) {
  struct lota_ipc_response resp;
  struct lota_ipc_status status;

  printf("Sending GET_STATUS...\n");

  if (send_request(fd, LOTA_IPC_CMD_GET_STATUS, NULL, 0) < 0)
    return 1;

  if (recv_response(fd, &resp, &status, sizeof(status)) < 0)
    return 1;

  printf("Response: %s\n", result_str(resp.result));
  if (resp.result == LOTA_IPC_OK) {
    printf("  Flags: 0x%08X\n", status.flags);
    printf("    ATTESTED:    %s\n",
           (status.flags & LOTA_STATUS_ATTESTED) ? "YES" : "no");
    printf("    TPM_OK:      %s\n",
           (status.flags & LOTA_STATUS_TPM_OK) ? "YES" : "no");
    printf("    IOMMU_OK:    %s\n",
           (status.flags & LOTA_STATUS_IOMMU_OK) ? "YES" : "no");
    printf("    BPF_LOADED:  %s\n",
           (status.flags & LOTA_STATUS_BPF_LOADED) ? "YES" : "no");
    printf("    SECURE_BOOT: %s\n",
           (status.flags & LOTA_STATUS_SECURE_BOOT) ? "YES" : "no");
    printf("  Mode: %u\n", status.mode);
    printf("  Last attestation: %lu\n", (unsigned long)status.last_attest_time);
    printf("  Valid until: %lu\n", (unsigned long)status.valid_until);
    printf("  Success count: %u\n", status.attest_count);
    printf("  Failure count: %u\n", status.fail_count);
  }

  return resp.result == LOTA_IPC_OK ? 0 : 1;
}

static int do_token(int fd) {
  struct lota_ipc_response resp;
  struct lota_ipc_token token;

  printf("Sending GET_TOKEN...\n");

  if (send_request(fd, LOTA_IPC_CMD_GET_TOKEN, NULL, 0) < 0)
    return 1;

  if (recv_response(fd, &resp, &token, sizeof(token)) < 0)
    return 1;

  printf("Response: %s\n", result_str(resp.result));
  if (resp.result == LOTA_IPC_OK) {
    printf("  Issued at: %lu\n", (unsigned long)token.issued_at);
    printf("  Valid until: %lu\n", (unsigned long)token.valid_until);
    printf("  Flags: 0x%08X\n", token.flags);
    printf("  Signature length: %u\n", token.signature_len);
  }

  return resp.result == LOTA_IPC_OK ? 0 : 1;
}

static void usage(const char *prog) {
  fprintf(stderr, "Usage: %s [ping|status|token]\n", prog);
  fprintf(stderr, "\nCommands:\n");
  fprintf(stderr, "  ping   - Check if agent is alive\n");
  fprintf(stderr, "  status - Get attestation status\n");
  fprintf(stderr, "  token  - Get attestation token\n");
}

int main(int argc, char *argv[]) {
  const char *cmd = "status";
  int fd;
  int ret;

  if (argc > 1) {
    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
      usage(argv[0]);
      return 0;
    }
    cmd = argv[1];
  }

  printf("Connecting to %s...\n", LOTA_IPC_SOCKET_PATH);
  fd = connect_to_agent();
  if (fd < 0) {
    fprintf(stderr, "Failed to connect to LOTA agent.\n");
    fprintf(stderr, "Is lota-agent running?\n");
    return 1;
  }
  printf("Connected!\n\n");

  if (strcmp(cmd, "ping") == 0) {
    ret = do_ping(fd);
  } else if (strcmp(cmd, "status") == 0) {
    ret = do_status(fd);
  } else if (strcmp(cmd, "token") == 0) {
    ret = do_token(fd);
  } else {
    fprintf(stderr, "Unknown command: %s\n", cmd);
    usage(argv[0]);
    ret = 1;
  }

  close(fd);
  return ret;
}
