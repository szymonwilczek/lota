/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for last_attest_time in the IPC status answer.
 *
 * Only a completed round sets it. Session changes and rounds with no
 * evidence (a session-gated host's steady state) recompute the status word
 * and must leave it alone. Driven through ipc_process() over a socket.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <errno.h>
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
#include "../src/agent/ipc.h"
#include "../src/agent/profile.h"
#include "../src/agent/runtime_image_measure.h"
#include "../src/agent/tpm.h"

/* stubs: a host with no enrollment */
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

/* nothing latches here; only for the link */
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

/* no TPM: the census refuses and the bind goes on */
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

void lota_rt_measure_round_begin(void)
{
}

int lota_rt_measure_round_end(size_t *released)
{
	if (released)
		*released = 0;
	return 0;
}

int lota_runtime_coverage_pid(pid_t pid,
			      struct lota_runtime_measure_coverage *cov)
{
	(void)pid;
	(void)cov;
	return -ENOTSUP;
}

void lota_rt_failure_reason(const struct lota_runtime_measure_failure *fail,
			    int err, char *buf, size_t buflen)
{
	(void)fail;
	(void)err;
	if (buf && buflen)
		buf[0] = '\0';
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

/* test-owned socket: no root, no /run/lota */
static int listener_open(void)
{
	struct sockaddr_un addr;
	int fd;

	snprintf(test_socket, sizeof(test_socket), "/tmp/lota-attime-%d.sock",
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

/* pump ipc_process() until a frame arrives */
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

/* status as a title reads it */
static int read_status(struct ipc_context *ctx, struct lota_ipc_status *out)
{
	struct lota_ipc_response resp;
	uint8_t payload[LOTA_IPC_MAX_PAYLOAD];
	int fd;
	int ret;

	fd = client_open();
	if (fd < 0)
		return fd;

	ret = send_request(fd, LOTA_IPC_CMD_GET_STATUS, NULL, 0);
	if (ret >= 0)
		ret = read_frame(ctx, fd, &resp, payload, sizeof(payload), 64);
	close(fd);

	if (ret < 0)
		return ret;
	if (resp.result != LOTA_IPC_OK)
		return -EPROTO;
	if (resp.payload_len != sizeof(*out))
		return -EPROTO;

	memcpy(out, payload, sizeof(*out));
	return 0;
}

/* SYNC_ATTEST as the attest loop sends it */
static int sync_loop(struct ipc_context *ctx, uint32_t attest_count,
		     uint32_t fail_count, uint64_t last_attest_time)
{
	uint8_t buf[sizeof(struct lota_ipc_attest_sync)];
	struct lota_ipc_attest_sync sync;
	struct lota_ipc_response resp;
	uint8_t payload[LOTA_IPC_MAX_PAYLOAD];
	int fd;
	int ret;

	memset(&sync, 0, sizeof(sync));
	sync.attest_count = attest_count;
	sync.fail_count = fail_count;
	sync.last_attest_time = last_attest_time;
	memcpy(buf, &sync, sizeof(sync));

	fd = client_open();
	if (fd < 0)
		return fd;

	ret = send_request(fd, LOTA_IPC_CMD_SYNC_ATTEST, buf, sizeof(buf));
	if (ret >= 0)
		ret = read_frame(ctx, fd, &resp, payload, sizeof(payload), 64);
	close(fd);

	if (ret < 0)
		return ret;

	return resp.result == LOTA_IPC_OK ? 0 : -EPROTO;
}

/* a session-gated host with no title: no attestation, no time */
static void test_never_attested_reports_no_time(struct ipc_context *ctx)
{
	struct lota_ipc_status st;

	TEST("a host that has never attested reports no time");

	ipc_update_status(ctx, LOTA_STATUS_TPM_OK, 0);
	if (read_status(ctx, &st) < 0) {
		FAIL("status");
		return;
	}
	if (st.attest_count != 0) {
		FAIL("the fixture already counts an attestation");
		return;
	}
	if (st.last_attest_time != 0) {
		FAIL("a machine that attested nothing names a time it did");
		return;
	}

	PASS();
}

static void test_completed_round_sets_the_time(struct ipc_context *ctx)
{
	struct lota_ipc_status st;
	uint64_t when = (uint64_t)time(NULL) - 90;

	TEST("a round the loop completed sets the time");

	if (sync_loop(ctx, 1, 0, when) < 0) {
		FAIL("sync");
		return;
	}
	if (read_status(ctx, &st) < 0) {
		FAIL("status");
		return;
	}
	if (st.last_attest_time != when) {
		FAIL("the answer is not the time the round was attested");
		return;
	}

	PASS();
}

/* a session opening or closing recomputes the status, not the time */
static void test_recompute_keeps_the_time(struct ipc_context *ctx)
{
	struct lota_ipc_status st;
	uint64_t when = (uint64_t)time(NULL) - 90;

	TEST("a status recomputation is not an attestation");

	if (sync_loop(ctx, 1, 0, when) < 0) {
		FAIL("sync");
		return;
	}

	ipc_update_status(ctx, LOTA_STATUS_TPM_OK, 0);

	if (read_status(ctx, &st) < 0) {
		FAIL("status");
		return;
	}
	if (st.last_attest_time != when) {
		FAIL("the recomputation moved the attestation time");
		return;
	}

	PASS();
}

/* a round with no evidence syncs time zero; the old time stands */
static void test_idle_round_keeps_the_time(struct ipc_context *ctx)
{
	struct lota_ipc_status st;
	uint64_t when = (uint64_t)time(NULL) - 90;

	TEST("a round that attested nothing does not move the time");

	if (sync_loop(ctx, 1, 0, when) < 0) {
		FAIL("sync");
		return;
	}
	if (sync_loop(ctx, 1, 0, 0) < 0) {
		FAIL("idle sync");
		return;
	}
	if (read_status(ctx, &st) < 0) {
		FAIL("status");
		return;
	}
	if (st.last_attest_time != when) {
		FAIL("an idle round is reported as an attestation");
		return;
	}

	PASS();
}

int main(void)
{
	struct ipc_context ctx;
	int listen_fd;

	printf("=== Status attestation-time tests ===\n\n");

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

	test_never_attested_reports_no_time(&ctx);
	test_completed_round_sets_the_time(&ctx);
	test_recompute_keeps_the_time(&ctx);
	test_idle_round_keeps_the_time(&ctx);

	ipc_cleanup(&ctx);
	unlink(test_socket);

	printf("\n%d/%d tests passed\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
