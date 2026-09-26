/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for the push notification the attestation loop sleeps on.
 *
 * The loop subscribes by syncing and then waits on the connection instead of
 * the clock, so a session opening reaches it at once.
 * That only holds if the daemon actually writes the notification out,
 * and if the request the loop sends next is still answered afterwards.
 *
 * Driven against the real ipc_process() event loop:
 * what was wrong lived in the epoll arming, which no hand-written server
 * reproduces.
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

/*
 * The daemon's state and the layers below the socket.
 *
 * These tests are about what the event loop writes to a connection,
 * so the TPM, the BPF map, D-Bus and the runtime measurement are stubbed to
 * the answers a host with no enrollment gives. Nothing here decides a verdict.
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

/* The publisher a title names in these tests, and its hex form */
static const uint8_t test_profile_id[32] = {
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
	0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
	0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
};
static const char *const test_profile_hex = "1122334455667788"
					    "99aabbccddeeff00"
					    "1122334455667788"
					    "99aabbccddeeff00";

static char test_socket[108];

/*
 * A listening socket the tests own, so no root and no /run/lota.
 * ipc_init_activated() is the same entry point socket activation uses.
 */
static int listener_open(void)
{
	struct sockaddr_un addr;
	int fd;

	snprintf(test_socket, sizeof(test_socket), "/tmp/lota-notify-%d.sock",
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

/*
 * Read one frame with a deadline.
 * The deadline is what the assertions are about: the daemon either writes
 * within a pass of the event loop or the caller is waiting on the clock.
 */
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

/* The loop's half of a round: hand over the verdicts, read back the sessions */
static int send_sync(int fd)
{
	uint8_t buf[sizeof(struct lota_ipc_attest_sync)];
	struct lota_ipc_attest_sync sync;

	memset(&sync, 0, sizeof(sync));
	memcpy(buf, &sync, sizeof(sync));

	return send_request(fd, LOTA_IPC_CMD_SYNC_ATTEST, buf, sizeof(buf));
}

/*
 * One publisher, agreed to, session-gated -- the shape a title finds on
 * a consumer host. The consent is written by the agent's own recorder
 * so the daemon reads back what it writes rather than what this file thinks
 * it writes.
 */
static int profile_init(struct attest_target *target)
{
	char base[64];
	int ret;

	memset(target, 0, sizeof(*target));
	target->has_profile = true;
	target->session_gated = true;
	snprintf(target->label, sizeof(target->label), "test publisher");

	snprintf(base, sizeof(base), "/tmp/lota-notify-%d.profiles",
		 (int)getpid());
	ret = profile_paths_from_id(base, test_profile_hex, &target->paths);
	if (ret < 0)
		return ret;

	return profile_consent_record(&target->paths, geteuid());
}

static void profile_forget(struct attest_target *target)
{
	char base[64];

	profile_consent_forget(&target->paths);
	rmdir(target->paths.dir);
	snprintf(base, sizeof(base), "/tmp/lota-notify-%d.profiles",
		 (int)getpid());
	rmdir(base);
}

/*
 * A session opening has to reach the loop while it waits on the connection.
 *
 * The loop syncs (which subscribes it), a title binds itself to the publisher
 * on a second connection, and the notification must arrive without the loop
 * sending anything else -- that is the whole point of sleeping on the socket
 * instead of the clock.
 */
static void test_session_notification_is_delivered(struct ipc_context *ctx)
{
	struct lota_ipc_response resp;
	struct lota_ipc_set_profile set;
	uint8_t payload[LOTA_IPC_MAX_PAYLOAD];
	int loop_fd, title_fd;

	TEST("a session opening is pushed to the sleeping loop");

	loop_fd = client_open();
	if (loop_fd < 0) {
		FAIL("connect");
		return;
	}

	if (send_sync(loop_fd) < 0) {
		FAIL("sync request");
		close(loop_fd);
		return;
	}
	if (read_frame(ctx, loop_fd, &resp, payload, sizeof(payload), 64) < 0) {
		FAIL("sync answer");
		close(loop_fd);
		return;
	}
	if (resp.result != LOTA_IPC_OK) {
		FAIL("sync refused");
		close(loop_fd);
		return;
	}

	title_fd = client_open();
	if (title_fd < 0) {
		FAIL("title connect");
		close(loop_fd);
		return;
	}

	memset(&set, 0, sizeof(set));
	memcpy(set.profile_id, test_profile_id, sizeof(set.profile_id));
	if (send_request(title_fd, LOTA_IPC_CMD_SET_PROFILE, &set,
			 sizeof(set)) < 0) {
		FAIL("set profile");
		goto out;
	}
	if (read_frame(ctx, title_fd, &resp, payload, sizeof(payload), 64) <
		    0 ||
	    resp.result != LOTA_IPC_OK) {
		FAIL("set profile refused");
		goto out;
	}

	if (read_frame(ctx, loop_fd, &resp, payload, sizeof(payload), 64) < 0) {
		FAIL("no notification: the loop sleeps out its interval");
		goto out;
	}

	if (resp.result != LOTA_IPC_NOTIFY) {
		FAIL("frame is not a notification");
		goto out;
	}

	{
		struct lota_ipc_notify notify;

		if (resp.payload_len < sizeof(notify)) {
			FAIL("notification is short");
			goto out;
		}
		memcpy(&notify, payload, sizeof(notify));
		if (!(notify.events & LOTA_IPC_EVENT_PROFILE)) {
			FAIL("notification does not name the publisher event");
			goto out;
		}
	}

	PASS();
out:
	close(title_fd);
	close(loop_fd);
}

/*
 * The round after a notification still has to be answered.
 *
 * A notification the daemon queued and the loop has not read yet is a response
 * in flight on that connection; the request behind it must not be left there.
 * The loop reads a refusal to answer as a wedged peer, drops the connection
 * and holds off for thirty seconds -- with the sessions it needs on the other
 * side of it.
 */
static void test_sync_after_notification_is_answered(struct ipc_context *ctx)
{
	struct lota_ipc_response resp;
	struct lota_ipc_set_profile set;
	uint8_t payload[LOTA_IPC_MAX_PAYLOAD];
	int loop_fd, title_fd;
	bool answered = false;

	TEST("the sync after a session opening is answered");

	loop_fd = client_open();
	if (loop_fd < 0) {
		FAIL("connect");
		return;
	}

	if (send_sync(loop_fd) < 0 ||
	    read_frame(ctx, loop_fd, &resp, payload, sizeof(payload), 64) < 0) {
		FAIL("first sync");
		close(loop_fd);
		return;
	}

	title_fd = client_open();
	if (title_fd < 0) {
		FAIL("title connect");
		close(loop_fd);
		return;
	}

	memset(&set, 0, sizeof(set));
	memcpy(set.profile_id, test_profile_id, sizeof(set.profile_id));
	if (send_request(title_fd, LOTA_IPC_CMD_SET_PROFILE, &set,
			 sizeof(set)) < 0 ||
	    read_frame(ctx, title_fd, &resp, payload, sizeof(payload), 64) <
		    0 ||
	    resp.result != LOTA_IPC_OK) {
		FAIL("set profile");
		goto out;
	}

	/*
	 * The loop syncs without draining first, which is what it does when
	 * the notification lands while a round is already running.
	 */
	if (send_sync(loop_fd) < 0) {
		FAIL("second sync");
		goto out;
	}

	for (int frame = 0; frame < 4 && !answered; frame++) {
		if (read_frame(ctx, loop_fd, &resp, payload, sizeof(payload),
			       64) < 0)
			break;
		if (resp.result != LOTA_IPC_NOTIFY)
			answered = true;
	}

	if (!answered) {
		FAIL("no answer: the loop times out and drops the connection");
		goto out;
	}

	if (resp.result != LOTA_IPC_OK) {
		FAIL("sync refused");
		goto out;
	}

	{
		struct lota_ipc_attest_sync_response out_hdr;
		struct lota_ipc_profile_demand demand;

		if (resp.payload_len < sizeof(out_hdr) + sizeof(demand)) {
			FAIL("answer carries no publisher");
			goto out;
		}
		memcpy(&out_hdr, payload, sizeof(out_hdr));
		memcpy(&demand, payload + sizeof(out_hdr), sizeof(demand));

		if (out_hdr.count != 1 || demand.sessions != 1) {
			FAIL("the open session is not reported to the loop");
			goto out;
		}
	}

	PASS();
out:
	close(title_fd);
	close(loop_fd);
}

int main(void)
{
	struct ipc_context ctx;
	struct attest_target *profiles;
	int listen_fd;

	printf("=== IPC push notification tests ===\n\n");

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
	if (profile_init(profiles) < 0) {
		printf("SKIP: cannot record consent under /tmp\n");
		ipc_cleanup(&ctx);
		free(profiles);
		unlink(test_socket);
		return 0;
	}
	ipc_set_profiles(&ctx, profiles, 1);

	test_session_notification_is_delivered(&ctx);
	test_sync_after_notification_is_answered(&ctx);

	ipc_cleanup(&ctx);
	profile_forget(profiles);
	free(profiles);
	unlink(test_socket);

	printf("\n=== %d/%d passed ===\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
