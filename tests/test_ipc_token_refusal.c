/* SPDX-License-Identifier: MIT */
/*
 * Tests that a standing token refusal is journalled once per connection,
 * driven through ipc_process(), while the client is still refused every round.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <errno.h>
#include <stdarg.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#include "../include/lota_ipc.h"
#include "../src/agent/agent.h"
#include "../src/agent/bpf_loader.h"
#include "../src/agent/dbus.h"
#include "../src/agent/enroll.h"
#include "../src/agent/attest_targets.h"
#include "../src/agent/ipc.h"
#include "../src/agent/journal.h"
#include "../src/agent/profile.h"
#include "../src/agent/runtime_image_measure.h"
#include "../src/agent/tpm.h"

/* Layers below the socket, stubbed as a host with no enrollment */
struct agent_globals g_agent;

const char *tpm_strerror(int err)
{
	(void)err;
	return "test";
}

bool tpm_is_locked_out(const struct tpm_context *ctx)
{
	(void)ctx;
	return false;
}

/* Nothing latches a lockout here; only for linking */
void tpm_reset_lockout_state(struct tpm_context *ctx)
{
	(void)ctx;
}

int tpm_quote(struct tpm_context *ctx, const uint8_t *nonce, uint32_t pcr_mask,
	      struct tpm_quote_response *response)
{
	(void)ctx;
	(void)nonce;
	(void)pcr_mask;
	(void)response;
	return -ENOTSUP;
}

int tpm_bind_profile(struct tpm_context *ctx, const struct profile_paths *paths)
{
	(void)ctx;
	(void)paths;
	return -ENOTSUP;
}

/* No TPM, so the census refuses and the bind goes on */
int tpm_aik_slot_census(struct tpm_context *ctx, const char *base_dir,
			struct profile_aik_slots *out)
{
	(void)ctx;
	(void)base_dir;
	(void)out;
	return -ENOTSUP;
}

int bpf_loader_measure_verity_digest(const char *path,
				     struct lota_verity_digest_key *out)
{
	(void)path;
	(void)out;
	return -ENOTSUP;
}

int bpf_loader_protect_pid(struct bpf_loader_ctx *ctx, uint32_t pid)
{
	(void)ctx;
	(void)pid;
	return -ENOTSUP;
}

int bpf_loader_unprotect_pid(struct bpf_loader_ctx *ctx, uint32_t pid)
{
	(void)ctx;
	(void)pid;
	return -ENOTSUP;
}

int dbus_get_fd(struct dbus_context *ctx)
{
	(void)ctx;
	return -1;
}

int dbus_process(struct dbus_context *ctx, uint64_t timeout_us)
{
	(void)ctx;
	(void)timeout_us;
	return 0;
}

void dbus_emit_status_changed(struct dbus_context *ctx, uint32_t flags)
{
	(void)ctx;
	(void)flags;
}

void dbus_emit_attestation_result(struct dbus_context *ctx, bool success)
{
	(void)ctx;
	(void)success;
}

void dbus_emit_mode_changed(struct dbus_context *ctx, uint8_t mode)
{
	(void)ctx;
	(void)mode;
}

void dbus_emit_rotation_changed(struct dbus_context *ctx)
{
	(void)ctx;
}

/* No enrollment on disk, which is the state a first session finds */
int enroll_state_load_path(const char *path, struct enroll_state *out)
{
	(void)path;
	(void)out;
	return -ENOENT;
}

int lota_runtime_measure_pid(pid_t pid,
			     uint8_t out_digest[LOTA_RUNTIME_IMAGE_DIGEST_SIZE],
			     struct lota_runtime_measure_coverage *cov,
			     struct lota_runtime_measure_failure *fail)
{
	(void)pid;
	(void)out_digest;
	(void)cov;
	(void)fail;
	return -ENOTSUP;
}

/* Every PID fully measured; counts the walks */
static int coverage_walks;

int lota_runtime_coverage_pid(pid_t pid,
			      struct lota_runtime_measure_coverage *cov)
{
	(void)pid;
	coverage_walks++;
	if (cov) {
		memset(cov, 0, sizeof(*cov));
		cov->measured = 4;
	}
	return 0;
}

void lota_rt_failure_reason(const struct lota_runtime_measure_failure *fail,
			    int err, char *buf, size_t buflen)
{
	(void)fail;
	(void)err;
	if (buf && buflen)
		buf[0] = '\0';
}

/* Counts the agent's journal lines instead of writing them */
static int journal_lines;
static char last_line[512];

__attribute__((format(printf, 5, 6))) void
journal_print(const char *file, int line, const char *func, int priority,
	      const char *fmt, ...)
{
	va_list ap;

	(void)file;
	(void)line;
	(void)func;
	(void)priority;

	va_start(ap, fmt);
	vsnprintf(last_line, sizeof(last_line), fmt, ap);
	va_end(ap);

	if (strstr(last_line, "Refusing GET_TOKEN"))
		journal_lines++;
}

void journal_init(const char *ident)
{
	(void)ident;
}

void journal_set_level(int priority)
{
	(void)priority;
}

bool journal_use_journal(void)
{
	return false;
}

void journal_detached_from_terminal(void)
{
}

static int tests_run;
static int tests_passed;

#define TEST(name)                                         \
	do {                                               \
		tests_run++;                               \
		printf("  [%2d] %-58s ", tests_run, name); \
	} while (0)

#define PASS()                    \
	do {                      \
		tests_passed++;   \
		printf("PASS\n"); \
	} while (0)

#define FAIL(msg)                          \
	do {                               \
		printf("FAIL: %s\n", msg); \
	} while (0)

static char test_socket[108];

/* A listening socket the tests own, so no root and no /run/lota */
static int listener_open(void)
{
	struct sockaddr_un addr;
	int fd;

	snprintf(test_socket, sizeof(test_socket), "/tmp/lota-refusal-%d.sock",
		 (int)getpid());
	unlink(test_socket);

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", test_socket);

	if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		int ret = -errno;

		close(fd);
		return ret;
	}

	if (listen(fd, 8) < 0) {
		int ret = -errno;

		close(fd);
		return ret;
	}

	return fd;
}

static int client_open(void)
{
	struct sockaddr_un addr;
	int fd;

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", test_socket);

	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		int ret = -errno;

		close(fd);
		return ret;
	}

	return fd;
}

static int send_request(int fd, uint32_t cmd, const void *payload, uint32_t len)
{
	struct lota_ipc_request req = {
		.magic = LOTA_IPC_MAGIC,
		.version = LOTA_IPC_VERSION,
		.cmd = cmd,
		.payload_len = len,
	};

	if (write(fd, &req, sizeof(req)) != (ssize_t)sizeof(req))
		return -errno;

	if (len && write(fd, payload, len) != (ssize_t)len)
		return -errno;

	return 0;
}

/* Read one frame, pumping the daemon's loop until it answers */
static int read_frame(struct ipc_context *ctx, int fd,
		      struct lota_ipc_response *resp, uint8_t *payload,
		      size_t payload_max, int passes)
{
	for (int i = 0; i < passes; i++) {
		struct pollfd pfd = { .fd = fd, .events = POLLIN };

		if (poll(&pfd, 1, 0) > 0) {
			ssize_t n = read(fd, resp, sizeof(*resp));

			if (n != (ssize_t)sizeof(*resp))
				return -EIO;
			if (resp->payload_len > payload_max)
				return -E2BIG;
			if (resp->payload_len &&
			    read(fd, payload, resp->payload_len) !=
				    (ssize_t)resp->payload_len)
				return -EIO;
			return 0;
		}
		ipc_process(ctx, 10);
	}

	return -ETIMEDOUT;
}

/* One GET_TOKEN; returns the result code the client got */
static int ask_for_token(struct ipc_context *ctx, int fd)
{
	struct lota_ipc_response resp;
	uint8_t payload[LOTA_IPC_MAX_PAYLOAD];
	struct lota_ipc_token_request req;
	int ret;

	memset(&req, 0, sizeof(req));

	ret = send_request(fd, LOTA_IPC_CMD_GET_TOKEN, &req, sizeof(req));
	if (ret < 0)
		return ret;

	ret = read_frame(ctx, fd, &resp, payload, sizeof(payload), 64);
	if (ret < 0)
		return ret;

	return (int)resp.result;
}

/* Two publishers, so a connection naming none cannot get a token */
static struct attest_target g_profiles[2];

static void publishers(struct ipc_context *ctx)
{
	snprintf(g_profiles[0].server, sizeof(g_profiles[0].server), "one");
	snprintf(g_profiles[1].server, sizeof(g_profiles[1].server), "two");

	/* both attested: only the missing publisher refuses */
	g_profiles[0].attested = true;
	g_profiles[1].attested = true;
	g_profiles[0].valid_until = (uint64_t)time(NULL) + 3600;
	g_profiles[1].valid_until = g_profiles[0].valid_until;
	ipc_set_profiles(ctx, g_profiles, 2);

	ipc_update_status(ctx, LOTA_STATUS_TPM_OK | LOTA_STATUS_ATTESTED, 0);
}

/* An unchanged refusal is written once; the client is refused every round */
static void test_a_standing_refusal_is_written_once(struct ipc_context *ctx)
{
	int fd;
	int i;

	TEST("a refusal that has not changed is written once");

	fd = client_open();
	if (fd < 0) {
		FAIL("connect");
		return;
	}

	journal_lines = 0;
	for (i = 0; i < 15; i++) {
		int rc = ask_for_token(ctx, fd);

		if (rc < 0) {
			FAIL("the client got no answer at all");
			close(fd);
			return;
		}
		if (rc == LOTA_IPC_OK) {
			FAIL("a connection that named no publisher got a token");
			close(fd);
			return;
		}
	}
	close(fd);

	if (journal_lines != 1) {
		char msg[128];

		snprintf(msg, sizeof(msg),
			 "fifteen refused rounds wrote %d lines",
			 journal_lines);
		FAIL(msg);
		return;
	}

	PASS();
}

/* The answer stands per connection: a second title is news */
static void test_a_second_connection_is_its_own_news(struct ipc_context *ctx)
{
	int fd;

	TEST("another connection refused the same way is written too");

	fd = client_open();
	if (fd < 0) {
		FAIL("connect");
		return;
	}

	journal_lines = 0;
	if (ask_for_token(ctx, fd) < 0) {
		FAIL("the client got no answer at all");
		close(fd);
		return;
	}
	ask_for_token(ctx, fd);
	close(fd);

	if (journal_lines != 1) {
		char msg[128];

		snprintf(msg, sizeof(msg),
			 "a new connection's refusal wrote %d lines",
			 journal_lines);
		FAIL(msg);
		return;
	}

	PASS();
}

int main(void)
{
	struct ipc_context ctx;
	int listen_fd;

	printf("=== What the journal says about a refused token ===\n\n");

	listen_fd = listener_open();
	if (listen_fd < 0) {
		printf("SKIP: cannot create a Unix socket in /tmp (%s)\n",
		       strerror(-listen_fd));
		return 0;
	}

	if (ipc_init_activated(&ctx, listen_fd) < 0) {
		printf("SKIP: ipc_init_activated failed\n");
		close(listen_fd);
		unlink(test_socket);
		return 0;
	}

	publishers(&ctx);

	test_a_standing_refusal_is_written_once(&ctx);
	test_a_second_connection_is_its_own_news(&ctx);

	ipc_cleanup(&ctx);
	unlink(test_socket);

	printf("\n%d/%d tests passed\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
