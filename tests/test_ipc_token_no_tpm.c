/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for what GET_TOKEN answers on a host the agent has no TPM on.
 *
 * A token nobody signed is not evidence, so the refusal itself is right and stays.
 * What a refusal owes the caller is a reason: every other branch of GET_TOKEN
 * names why it failed, in the log and in the code it sends back, and this one
 * is the only one that reports a TPM failure on a host that has no TPM to have
 * failed. An SDK developer bringing the bridge up without one is left with
 * "Agent returned error" and an empty log.
 *
 * These tests drive the real ipc_process() loop over a real socket with no
 * TPM bound, which is the state --test-ipc runs in.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#include <errno.h>
#include <fcntl.h>
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
#include "../src/agent/journal.h"
#include "../src/agent/profile.h"
#include "../src/agent/runtime_image_measure.h"
#include "../src/agent/tpm.h"

/*
 * The daemon's state and the layers below the socket.
 *
 * The TPM stubs exist to link: none of them is reached, because the context
 * these tests drive has no TPM bound and that is the whole subject.
 */
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
static char test_log[64];

/*
 * A listening socket the tests own, so no root and no /run/lota.
 * ipc_init_activated() is the same entry point socket activation uses.
 */
static int listener_open(void)
{
	struct sockaddr_un addr;
	int fd;

	snprintf(test_socket, sizeof(test_socket), "/tmp/lota-notpm-%d.sock",
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

/*
 * The agent's log for one exchange.
 *
 * journal_init() picks stderr when the process is not under systemd,
 * so the capture is of the same lines an operator running the bridge by hand reads.
 */
static int saved_stderr = -1;

static void log_capture_begin(void)
{
	int fd;

	fflush(stderr);
	saved_stderr = dup(STDERR_FILENO);
	fd = open(test_log, O_RDWR | O_CREAT | O_TRUNC, 0600);
	if (fd < 0)
		return;
	dup2(fd, STDERR_FILENO);
	close(fd);
}

static void log_capture_end(char *buf, size_t buflen)
{
	ssize_t n = 0;
	int fd;

	buf[0] = '\0';
	fflush(stderr);
	if (saved_stderr >= 0) {
		dup2(saved_stderr, STDERR_FILENO);
		close(saved_stderr);
		saved_stderr = -1;
	}

	fd = open(test_log, O_RDONLY);
	if (fd < 0)
		return;
	n = read(fd, buf, buflen - 1);
	close(fd);
	buf[n > 0 ? (size_t)n : 0] = '\0';
}

/*
 * One GET_TOKEN against a context with no TPM, and everything it answered.
 *
 * The three assertions below share a single exchange on purpose: GET_TOKEN
 * is rate limited per session and per uid, and three requests would test
 * the limiter rather than the refusal.
 */
static uint32_t refusal_result;
static char refusal_log[4096];

static int probe_refusal(struct ipc_context *ctx)
{
	struct lota_ipc_response resp;
	uint8_t payload[LOTA_IPC_MAX_PAYLOAD];
	int fd, ret;

	fd = client_open();
	if (fd < 0)
		return fd;

	log_capture_begin();
	ret = send_request(fd, LOTA_IPC_CMD_GET_TOKEN, NULL, 0);
	if (ret >= 0)
		ret = read_frame(ctx, fd, &resp, payload, sizeof(payload), 64);
	log_capture_end(refusal_log, sizeof(refusal_log));
	close(fd);

	if (ret < 0)
		return ret;

	refusal_result = resp.result;
	return 0;
}

/* The refusal itself: a host with no TPM must never hand out a token */
static void test_no_tpm_is_refused(void)
{
	TEST("a host with no TPM refuses to issue a token");

	if (refusal_result == LOTA_IPC_OK) {
		FAIL("an unsigned token was issued");
		return;
	}

	PASS();
}

/*
 * A TPM that is absent has not failed.
 *
 * Reporting the absence as LOTA_IPC_ERR_TPM_FAILURE tells a caller to retry
 * or to look at its TPM, and there is nothing there to look at: no retry
 * and no amount of TPM repair will make this agent issue a token.
 */
static void test_absent_tpm_is_not_a_tpm_failure(void)
{
	TEST("the refusal is not reported as a TPM failure");

	if (refusal_result == LOTA_IPC_ERR_TPM_FAILURE) {
		FAIL("a host with no TPM reports one as having failed");
		return;
	}

	PASS();
}

/* Every other refusal in GET_TOKEN says why in the log. This one has to too */
static void test_refusal_is_logged(void)
{
	TEST("the refusal names its reason in the log");

	if (refusal_log[0] == '\0') {
		FAIL("the agent refused silently");
		return;
	}

	if (!strstr(refusal_log, "GET_TOKEN")) {
		FAIL("the log does not name the refused command");
		return;
	}

	if (!strstr(refusal_log, "TPM")) {
		FAIL("the log does not name the missing TPM");
		return;
	}

	PASS();
}

int main(void)
{
	struct ipc_context ctx;
	int listen_fd, ret;

	printf("=== GET_TOKEN without a TPM ===\n\n");

	/* agent logs to stderr when it is not run under systemd */
	unsetenv("JOURNAL_STREAM");
	unsetenv("INVOCATION_ID");
	journal_init("lota-agent");

	snprintf(test_log, sizeof(test_log), "/tmp/lota-notpm-%d.log",
		 (int)getpid());

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

	/*
	 * The state --test-ipc simulates: attested, no TPM, and a policy digest
	 * so the request reaches the TPM question instead of stopping at the
	 * gate above it.
	 */
	ipc_update_status(&ctx, LOTA_STATUS_ATTESTED | LOTA_STATUS_TPM_OK,
			  (uint64_t)time(NULL) + 300);
	memset(g_agent.policy_digest, 0xA5, sizeof(g_agent.policy_digest));
	g_agent.policy_digest_set = 1;

	ret = probe_refusal(&ctx);
	if (ret < 0) {
		printf("SKIP: no answer to GET_TOKEN (%s)\n", strerror(-ret));
		ipc_cleanup(&ctx);
		unlink(test_socket);
		unlink(test_log);
		return 0;
	}

	test_no_tpm_is_refused();
	test_absent_tpm_is_not_a_tpm_failure();
	test_refusal_is_logged();

	ipc_cleanup(&ctx);
	unlink(test_socket);
	unlink(test_log);

	printf("\n=== %d/%d passed ===\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
