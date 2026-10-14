/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for what a publisher-list reload does to connections already open.
 *
 * A title binds itself to a publisher once, with SET_PROFILE at connect time,
 * and never sends another. The daemon re-reads the list on SIGHUP -- which is
 * what --add-publisher tells the operator to trigger -- and rebuilding the list
 * must not cost the titles that are already playing their publisher or their
 * session: reporting is session-gated, so a session count that goes back to
 * zero stops the host reporting for a publisher whose title never stopped.
 *
 * The binding therefore cannot be only a pointer into the list being replaced.
 * These tests drive the real ipc_process() loop and read the session count back
 * the way the attestation loop does, through SYNC_ATTEST.
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
 * These tests are about what the event loop writes to a connection, so the TPM,
 * the BPF map, D-Bus and the runtime measurement are stubbed to the answers
 * a host with no enrollment gives. Nothing here decides a verdict.
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

	snprintf(test_socket, sizeof(test_socket), "/tmp/lota-reload-%d.sock",
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

	snprintf(base, sizeof(base), "/tmp/lota-reload-%d.profiles",
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
	snprintf(base, sizeof(base), "/tmp/lota-reload-%d.profiles",
		 (int)getpid());
	rmdir(base);
}

/* The second publisher, for the case where the bound one leaves the list */
static const uint8_t other_profile_id[32] = {
	0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11, 0x22, 0x33, 0x44,
	0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
};
static const char *const other_profile_hex = "aabbccddeeff0011"
					     "2233445566778899"
					     "aabbccddeeff0011"
					     "2233445566778899";

/* Same shape as profile_init(), for a publisher named by @hex */
static int profile_init_id(struct attest_target *target, const char *hex)
{
	char base[64];
	int ret;

	memset(target, 0, sizeof(*target));
	target->has_profile = true;
	target->session_gated = true;
	snprintf(target->label, sizeof(target->label), "test publisher");

	snprintf(base, sizeof(base), "/tmp/lota-reload-%d.profiles",
		 (int)getpid());
	ret = profile_paths_from_id(base, hex, &target->paths);
	if (ret < 0)
		return ret;

	return profile_consent_record(&target->paths, geteuid());
}

/* A title that names @id and is answered, as one playing right now would be */
static int title_bind(struct ipc_context *ctx, const uint8_t id[32])
{
	struct lota_ipc_response resp;
	struct lota_ipc_set_profile set;
	uint8_t payload[LOTA_IPC_MAX_PAYLOAD];
	int fd;

	fd = client_open();
	if (fd < 0)
		return fd;

	memset(&set, 0, sizeof(set));
	memcpy(set.profile_id, id, sizeof(set.profile_id));

	if (send_request(fd, LOTA_IPC_CMD_SET_PROFILE, &set, sizeof(set)) < 0 ||
	    read_frame(ctx, fd, &resp, payload, sizeof(payload), 64) < 0 ||
	    resp.result != LOTA_IPC_OK) {
		close(fd);
		return -EIO;
	}

	return fd;
}

/*
 * The session count for @id as the attestation loop reads it.
 *
 * Sessions are what the reporting gate consults, so this is the number
 * the defect moved: the loop asks over its own connection and believes the answer.
 * Notifications may be queued ahead of the answer, exactly as in a live round.
 */
static int sessions_for(struct ipc_context *ctx, int loop_fd,
			const uint8_t id[32])
{
	struct lota_ipc_attest_sync_response hdr;
	struct lota_ipc_response resp;
	uint8_t payload[LOTA_IPC_MAX_PAYLOAD];
	bool answered = false;

	if (send_sync(loop_fd) < 0)
		return -EIO;

	for (int frame = 0; frame < 8 && !answered; frame++) {
		if (read_frame(ctx, loop_fd, &resp, payload, sizeof(payload),
			       64) < 0)
			return -ETIMEDOUT;
		if (resp.result != LOTA_IPC_NOTIFY)
			answered = true;
	}

	if (!answered || resp.result != LOTA_IPC_OK)
		return -EIO;

	if (resp.payload_len < sizeof(hdr))
		return -EBADMSG;
	memcpy(&hdr, payload, sizeof(hdr));

	for (uint32_t i = 0; i < hdr.count; i++) {
		struct lota_ipc_profile_demand demand;
		size_t off = sizeof(hdr) + i * sizeof(demand);

		if (off + sizeof(demand) > resp.payload_len)
			return -EBADMSG;
		memcpy(&demand, payload + off, sizeof(demand));

		if (memcmp(demand.profile_id, id, sizeof(demand.profile_id)) ==
		    0)
			return (int)demand.sessions;
	}

	return -ENOENT;
}

/*
 * A title that is playing keeps its publisher across a reload.
 *
 * The list is rebuilt in fresh memory, which is the hard case and the one
 * the old pointer-dropping guarded against: the binding has to be re-resolved
 * by the publisher the connection named, not carried as an address.
 */
static void test_binding_survives_reload(struct ipc_context *ctx,
					 struct attest_target *rebuilt)
{
	int loop_fd, title_fd, sessions;

	TEST("a playing title keeps its publisher across a reload");

	loop_fd = client_open();
	if (loop_fd < 0) {
		FAIL("connect");
		return;
	}

	title_fd = title_bind(ctx, test_profile_id);
	if (title_fd < 0) {
		FAIL("title bind");
		close(loop_fd);
		return;
	}

	sessions = sessions_for(ctx, loop_fd, test_profile_id);
	if (sessions != 1) {
		FAIL("the session is not open before the reload");
		goto out;
	}

	ipc_set_profiles(ctx, rebuilt, 1);

	sessions = sessions_for(ctx, loop_fd, test_profile_id);
	if (sessions < 0) {
		FAIL("the publisher is gone from the list after the reload");
		goto out;
	}
	if (sessions != 1) {
		FAIL("the session is dropped, so reporting stops while the "
		     "title plays");
		goto out;
	}

	PASS();
out:
	close(title_fd);
	close(loop_fd);
}

/*
 * A publisher the operator removed does take its session with it.
 *
 * The point of keeping bindings is not to keep them forever: a connection
 * whose publisher is no longer configured has nothing left to be bound to.
 */
static void test_removed_publisher_unbinds(struct ipc_context *ctx,
					   struct attest_target *replacement)
{
	int loop_fd, title_fd, sessions;

	TEST("a publisher dropped from the list takes its session with it");

	loop_fd = client_open();
	if (loop_fd < 0) {
		FAIL("connect");
		return;
	}

	title_fd = title_bind(ctx, test_profile_id);
	if (title_fd < 0) {
		FAIL("title bind");
		close(loop_fd);
		return;
	}

	ipc_set_profiles(ctx, replacement, 1);

	sessions = sessions_for(ctx, loop_fd, test_profile_id);
	if (sessions != -ENOENT) {
		FAIL("the removed publisher is still reported");
		goto out;
	}

	sessions = sessions_for(ctx, loop_fd, other_profile_id);
	if (sessions != 0) {
		FAIL("the replacement publisher inherited a session that named "
		     "another");
		goto out;
	}

	PASS();
out:
	close(title_fd);
	close(loop_fd);
}

int main(void)
{
	struct attest_target *profiles, *rebuilt, *replacement;
	struct ipc_context ctx;
	int listen_fd;

	printf("=== IPC publisher-reload binding tests ===\n\n");

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
	rebuilt = calloc(1, sizeof(*rebuilt));
	replacement = calloc(1, sizeof(*replacement));
	if (!profiles || !rebuilt || !replacement) {
		printf("FAIL: out of memory\n");
		ipc_cleanup(&ctx);
		free(profiles);
		free(rebuilt);
		free(replacement);
		unlink(test_socket);
		return 1;
	}

	if (profile_init(profiles) < 0 ||
	    profile_init_id(rebuilt, test_profile_hex) < 0 ||
	    profile_init_id(replacement, other_profile_hex) < 0) {
		printf("SKIP: cannot record consent under /tmp\n");
		ipc_cleanup(&ctx);
		free(profiles);
		free(rebuilt);
		free(replacement);
		unlink(test_socket);
		return 0;
	}

	ipc_set_profiles(&ctx, profiles, 1);

	test_binding_survives_reload(&ctx, rebuilt);
	test_removed_publisher_unbinds(&ctx, replacement);

	ipc_cleanup(&ctx);
	profile_forget(replacement);
	profile_forget(profiles);
	free(profiles);
	free(rebuilt);
	free(replacement);
	unlink(test_socket);

	printf("\n=== %d/%d passed ===\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
