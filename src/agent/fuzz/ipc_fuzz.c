/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - IPC Fuzz Harness
 */

#include "../agent.h"
#include "../test_servers.h"
#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>

/*
 * Mocks
 */
static const uint8_t *g_fuzz_data;
static size_t g_fuzz_size;
static size_t g_fuzz_pos;

static ssize_t fuzz_recv(int sockfd, void *buf, size_t len, int flags)
{
	(void)sockfd;
	(void)flags;

	if (g_fuzz_pos >= g_fuzz_size)
		return 0;

	size_t available = g_fuzz_size - g_fuzz_pos;
	size_t to_read = (len < available) ? len : available;

	memcpy(buf, g_fuzz_data + g_fuzz_pos, to_read);
	g_fuzz_pos += to_read;
	return (ssize_t)to_read;
}

static ssize_t fuzz_send(int sockfd, const void *buf, size_t len, int flags)
{
	(void)sockfd;
	(void)buf;
	(void)flags;
	return len;
}

static int fuzz_epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
	(void)epfd;
	(void)op;
	(void)fd;
	(void)event;
	return 0;
}

#define recv fuzz_recv
#define send fuzz_send
#define epoll_ctl fuzz_epoll_ctl

struct agent_globals g_agent = {
    .running = 1,
    .dbus_ctx = NULL,
    .mode = 0,
};

/* self_measure, setup_dbus, setup_container_listener and
 * ipc_init_or_activate now come from main_utils.o, which the fuzz link
 * pulls in -- defining them here too would clash. Only the symbols no
 * linked object provides are stubbed below.
 *
 * diagnostics.c references the test servers, which are filtered out of the
 * fuzz link, so stub those.
 */
int run_ipc_test_server(const struct lota_config *cfg)
{
	(void)cfg;
	return -1;
}
int run_signed_ipc_test_server(const struct lota_config *cfg)
{
	(void)cfg;
	return -1;
}

#include "../ipc.c"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct ipc_context ctx;
	struct ipc_client *client;

	g_fuzz_data = data;
	g_fuzz_size = size;
	g_fuzz_pos = 0;

	/* clients now live on the context (client_list/count/map) */
	memset(&ctx, 0, sizeof(ctx));
	ctx.epoll_fd = 100;
	ctx.running = true;

	client = client_create(&ctx, 50, 1000, 1000, 1234);
	if (!client)
		return 0;

	for (int i = 0; i < 100; i++) {
		if (g_fuzz_pos >= g_fuzz_size && client->recv_len == 0)
			break;

		int ret = handle_client_read(&ctx, client);
		if (ret < 0)
			break;

		if (client->send_len > 0) {
			handle_client_write(&ctx, client);
		}
	}

	client_destroy(&ctx, client);

	return 0;
}
