/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for a TPM lockout the attestation loop observed reaching the
 * daemon's status word and GET_TOKEN. The daemon's own TPM context sees
 * nothing (tpm_is_locked_out() stub returns false).
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

/* no TPM: the census refuses, so the bind goes ahead */
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
		printf("  [%2d] %-62s ", tests_run, name); \
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

/* The publisher whose verdict makes the host attested in these tests */
static const char *const test_profile_hex = "aabbccddeeff0011"
					    "2233445566778899"
					    "aabbccddeeff0011"
					    "2233445566778899";

static char test_socket[108];

static int listener_open(void)
{
	struct sockaddr_un addr;
	int fd;

	snprintf(test_socket, sizeof(test_socket), "/tmp/lota-lockout-%d.sock",
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

static int read_frame(struct ipc_context *ctx, int fd,
		      struct lota_ipc_response *resp, uint8_t *payload,
		      size_t payload_max, int passes)
{
	for (int i = 0; i < passes; i++) {
		struct pollfd pfd = { .fd = fd, .events = POLLIN };
		ssize_t n;

		ipc_process(ctx, 10);

		if (poll(&pfd, 1, 0) <= 0)
			continue;

		n = read(fd, resp, sizeof(*resp));
		if (n != (ssize_t)sizeof(*resp))
			return -EIO;

		if (resp->magic != LOTA_IPC_MAGIC)
			return -EBADMSG;

		if (resp->payload_len > payload_max)
			return -EMSGSIZE;

		if (resp->payload_len && read(fd, payload, resp->payload_len) !=
						 (ssize_t)resp->payload_len)
			return -EIO;

		return 0;
	}

	return -ETIMEDOUT;
}

/* one loop sync with an attested verdict, so GET_TOKEN reaches the gate */
static int sync_round(struct ipc_context *ctx, int fd, uint32_t host_flags)
{
	uint8_t buf[sizeof(struct lota_ipc_attest_sync) +
		    sizeof(struct lota_ipc_attest_verdict)];
	struct lota_ipc_attest_verdict verdict;
	struct lota_ipc_attest_sync sync;
	struct lota_ipc_response resp;
	uint8_t payload[LOTA_IPC_MAX_PAYLOAD];
	int ret;

	memset(&sync, 0, sizeof(sync));
	sync.count = 1;
	sync.attest_count = 1;
	sync.last_attest_time = (uint64_t)time(NULL);
	sync.host_flags = host_flags;

	memset(&verdict, 0, sizeof(verdict));
	for (size_t i = 0; i < sizeof(verdict.profile_id); i++) {
		unsigned int byte;

		if (sscanf(test_profile_hex + i * 2, "%2x", &byte) != 1)
			return -EINVAL;
		verdict.profile_id[i] = (uint8_t)byte;
	}
	verdict.attested = 1;
	verdict.valid_until = (uint64_t)time(NULL) + 3600;

	memcpy(buf, &sync, sizeof(sync));
	memcpy(buf + sizeof(sync), &verdict, sizeof(verdict));

	ret = send_request(fd, LOTA_IPC_CMD_SYNC_ATTEST, buf, sizeof(buf));
	if (ret < 0)
		return ret;

	ret = read_frame(ctx, fd, &resp, payload, sizeof(payload), 64);
	if (ret < 0)
		return ret;

	return resp.result == LOTA_IPC_OK ? 0 : -EACCES;
}

/* What a title asking for a token is told */
static int token_result(struct ipc_context *ctx, uint32_t *result)
{
	struct lota_ipc_response resp;
	uint8_t payload[LOTA_IPC_MAX_PAYLOAD];
	int fd, ret;

	fd = client_open();
	if (fd < 0)
		return fd;

	ret = send_request(fd, LOTA_IPC_CMD_GET_TOKEN, NULL, 0);
	if (ret >= 0)
		ret = read_frame(ctx, fd, &resp, payload, sizeof(payload), 64);
	close(fd);

	if (ret < 0)
		return ret;

	*result = resp.result;
	return 0;
}

static void
test_the_published_word_carries_the_loops_lockout(struct ipc_context *ctx,
						  int loop_fd)
{
	TEST("a lockout the loop observed reaches the published status word");

	if (sync_round(ctx, loop_fd, LOTA_STATUS_TPM_LOCKOUT) < 0) {
		FAIL("sync refused");
		return;
	}

	if (!(ctx->status_flags & LOTA_STATUS_TPM_LOCKOUT)) {
		FAIL("the daemon publishes a word with the lockout bit clear");
		return;
	}
	PASS();
}

/* not NOT_ATTESTED: a lapsed verdict on a healthy host answers that too */
static void
test_a_title_is_refused_with_the_lockout_code(struct ipc_context *ctx)
{
	uint32_t result = 0;

	TEST("a title asking during a lockout is told it is a lockout");

	if (token_result(ctx, &result) < 0) {
		FAIL("no answer to GET_TOKEN");
		return;
	}

	if (result == LOTA_IPC_ERR_NOT_ATTESTED) {
		FAIL("a locked chip is reported as an unattested host");
		return;
	}
	if (result != LOTA_IPC_ERR_TPM_LOCKOUT) {
		FAIL("the refusal does not name the lockout");
		return;
	}
	PASS();
}

/* a sticky bit would refuse tokens until the daemon restarts */
static void test_a_cleared_lockout_clears_the_word(struct ipc_context *ctx,
						   int loop_fd)
{
	uint32_t result = 0;

	TEST("the bit clears when the loop stops observing the lockout");

	if (sync_round(ctx, loop_fd, 0) < 0) {
		FAIL("sync refused");
		return;
	}

	if (ctx->status_flags & LOTA_STATUS_TPM_LOCKOUT) {
		FAIL("the bit outlived the lockout");
		return;
	}

	if (token_result(ctx, &result) < 0) {
		FAIL("no answer to GET_TOKEN");
		return;
	}
	if (result == LOTA_IPC_ERR_TPM_LOCKOUT) {
		FAIL("a recovered host is still refused for a lockout");
		return;
	}
	PASS();
}

int main(void)
{
	struct ipc_context ctx;
	struct attest_target *profiles;
	int listen_fd, loop_fd;

	printf("=== TPM lockout across the agent's two units ===\n\n");

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

	profiles = calloc(1, sizeof(*profiles));
	if (!profiles) {
		printf("FAIL: out of memory\n");
		ipc_cleanup(&ctx);
		unlink(test_socket);
		return 1;
	}
	profiles->has_profile = true;
	snprintf(profiles->label, sizeof(profiles->label), "test publisher");
	snprintf(profiles->paths.id, sizeof(profiles->paths.id), "%s",
		 test_profile_hex);
	ipc_set_profiles(&ctx, profiles, 1);

	loop_fd = client_open();
	if (loop_fd < 0) {
		printf("SKIP: cannot connect to the test socket\n");
		ipc_cleanup(&ctx);
		free(profiles);
		unlink(test_socket);
		return 0;
	}

	test_the_published_word_carries_the_loops_lockout(&ctx, loop_fd);
	test_a_title_is_refused_with_the_lockout_code(&ctx);
	test_a_cleared_lockout_clears_the_word(&ctx, loop_fd);

	close(loop_fd);
	ipc_cleanup(&ctx);
	free(profiles);
	unlink(test_socket);

	printf("\n=== %d/%d passed ===\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
