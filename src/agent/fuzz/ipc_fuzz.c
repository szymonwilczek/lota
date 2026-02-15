// SPDX-License-Identifier: MIT
// LOTA Agent - IPC Fuzz Harness

#include "../bpf_loader.h"
#include "../hash_verify.h"
#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>

// Mocks
static const uint8_t *g_fuzz_data;
static size_t g_fuzz_size;
static size_t g_fuzz_pos;

ssize_t fuzz_recv(int sockfd, void *buf, size_t len, int flags) {
  (void)sockfd;
  (void)flags;

  if (g_fuzz_pos >= g_fuzz_size)
    return 0; // EOF

  size_t available = g_fuzz_size - g_fuzz_pos;
  size_t to_read = (len < available) ? len : available;

  memcpy(buf, g_fuzz_data + g_fuzz_pos, to_read);
  g_fuzz_pos += to_read;
  return (ssize_t)to_read;
}

ssize_t fuzz_send(int sockfd, const void *buf, size_t len, int flags) {
  (void)sockfd;
  (void)buf;
  (void)flags;
  return len; // pretend that sent everything
}

int fuzz_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) {
  (void)epfd;
  (void)op;
  (void)fd;
  (void)event;
  return 0;
}

#define recv fuzz_recv
#define send fuzz_send
#define epoll_ctl fuzz_epoll_ctl

struct tpm_context g_tpm_ctx;
struct bpf_loader_ctx g_bpf_ctx;
struct ipc_context g_ipc_ctx;
struct hash_verify_ctx g_hash_ctx;
struct dbus_context *g_dbus_ctx;
int g_mode = 0;
volatile sig_atomic_t g_running = 1;

int self_measure(struct tpm_context *ctx) {
  (void)ctx;
  return 0;
}
void setup_container_listener(struct ipc_context *ctx) { (void)ctx; }
void setup_dbus(struct ipc_context *ctx) { (void)ctx; }
int ipc_init_or_activate(struct ipc_context *ctx) {
  (void)ctx;
  return -1;
}

#include "../ipc.c"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  struct ipc_context ctx;
  struct ipc_client *client;

  g_fuzz_data = data;
  g_fuzz_size = size;
  g_fuzz_pos = 0;

  memset(&ctx, 0, sizeof(ctx));
  ctx.epoll_fd = 100; // fake FD
  ctx.running = true;

  // reset globals
  for (int i = 0; i < MAX_CLIENTS; i++)
    clients[i] = NULL;
  client_count = 0;

  client = client_create(50, 1000, 1000, 1234); // fake FD 50, UID/GID/PID
  if (!client)
    return 0;

  for (int i = 0; i < 100; i++) {
    if (g_fuzz_pos >= g_fuzz_size && client->recv_len == 0)
      break;

    int ret = handle_client_read(&ctx, client);
    if (ret < 0)
      break; // error or disconnect

    if (client->send_len > 0) {
      handle_client_write(&ctx, client);
    }
  }

  client_destroy(client);

  return 0;
}
