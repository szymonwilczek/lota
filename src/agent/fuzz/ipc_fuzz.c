/* SPDX-License-Identifier: MIT */
/*
 * LOTA Agent - IPC Fuzz Harness
 *
 * Drives the local IPC request parser the agent exposes on its control
 * socket. Raw bytes almost never satisfy the magic/version header, so the
 * harness frames the fuzz input into one or more well-formed IPC requests:
 * a fuzzer-chosen command, a fuzzer-chosen payload length, and a payload
 * carved from the input. That carries control past the header gate into
 * validate_request_payload_len(), the per-command dispatch, and -- when the
 * input packs several requests back to back -- the pipelined-leftover
 * memmove in handle_client_read(). The peer identity is set to this process
 * so the same-UID / PID-stability / agent-self checks run for real instead
 * of bailing on a bogus credential.
 */

#include "../agent.h"
#include "../test_servers.h"
#include "../../../include/lota_ipc.h"
#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

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

	/*
	 * hand back short reads so the recv-accumulation loop
	 * (partial header, partial payload) is exercised,
	 * not just one-shot deliveries
	 */
	if (to_read > 61)
		to_read = 61;

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
 * pulls in -- defining them here too would clash.
 * Only the symbols no linked object provides are stubbed below.
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

/*
 * Frame a sequence of well-formed IPC requests into out[].
 *
 * Each consumes a command selector byte and a 2-byte payload length from
 * the fuzz input, then that many payload bytes, so libFuzzer drives both
 * the command and the length the validator checks.
 * Returns the total framed size.
 */
static size_t build_frames(const uint8_t *data, size_t size, uint8_t *out,
			   size_t out_cap)
{
	static const uint32_t cmds[] = {
	    LOTA_IPC_CMD_PING,	      LOTA_IPC_CMD_GET_STATUS,
	    LOTA_IPC_CMD_GET_TOKEN,   LOTA_IPC_CMD_SUBSCRIBE,
	    LOTA_IPC_CMD_PROTECT_PID, LOTA_IPC_CMD_UNPROTECT_PID,
	    LOTA_IPC_CMD_SHUTDOWN,    0xDEADBEEF /* unknown cmd path */
	};
	size_t in = 0;
	size_t off = 0;

	while (in + 3 <= size && off + LOTA_IPC_REQUEST_SIZE < out_cap) {
		uint32_t cmd =
		    cmds[data[in] % (sizeof(cmds) / sizeof(cmds[0]))];
		uint32_t plen =
		    (uint32_t)data[in + 1] | ((uint32_t)data[in + 2] << 8);
		in += 3;

		if (plen > LOTA_IPC_MAX_PAYLOAD)
			plen = LOTA_IPC_MAX_PAYLOAD;
		if (plen > size - in)
			plen = (uint32_t)(size - in);
		if (off + LOTA_IPC_REQUEST_SIZE + plen > out_cap)
			break;

		struct lota_ipc_request req = {
		    .magic = LOTA_IPC_MAGIC,
		    .version = LOTA_IPC_VERSION,
		    .cmd = cmd,
		    .payload_len = plen,
		};
		memcpy(out + off, &req, sizeof(req));
		off += sizeof(req);
		memcpy(out + off, data + in, plen);
		off += plen;
		in += plen;
	}

	return off;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	static uint8_t
	    feed[4 * (sizeof(struct lota_ipc_request) + LOTA_IPC_MAX_PAYLOAD)];
	struct ipc_context ctx;
	struct ipc_client *client;
	size_t feed_len;

	feed_len = build_frames(data, size, feed, sizeof(feed));

	g_fuzz_data = feed;
	g_fuzz_size = feed_len;
	g_fuzz_pos = 0;

	/* clients now live on the context (client_list/count/map) */
	memset(&ctx, 0, sizeof(ctx));
	ctx.epoll_fd = 100;
	ctx.running = true;

	/*
	 * Present this process as the peer so same-UID, PID-stability and
	 * agent-self authorization run their real checks instead of failing on
	 * a synthetic credential.
	 */
	client = client_create(&ctx, 50, geteuid(), getegid(), getpid());
	if (!client)
		return 0;
	read_pid_start_time_ticks(getpid(), &client->peer_start_time_ticks);

	for (int i = 0; i < 512; i++) {
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
