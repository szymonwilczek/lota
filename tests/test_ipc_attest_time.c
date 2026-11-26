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

#include "test.h"
#include "../include/lota_ipc.h"
#include "../src/agent/agent.h"
#include "../src/agent/bpf_loader.h"
#include "../src/agent/dbus.h"
#include "../src/agent/enroll.h"
#include "../src/agent/ipc.h"
#include "../src/agent/profile.h"
#include "../src/agent/runtime_image_measure.h"
#include "../src/agent/tpm.h"
#include "../src/agent/boot_evidence.h"

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

int boot_evidence_collect(struct tpm_context *tpm, uint32_t pcr_mask,
			  uint8_t *out, size_t out_size, size_t *out_len)
{
	(void)tpm;
	(void)pcr_mask;
	(void)out;
	(void)out_size;
	(void)out_len;
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

int bpf_loader_born_protected(struct bpf_loader_ctx *ctx, uint32_t pid,
			      uint64_t start_ticks)
{
	(void)ctx;
	(void)pid;
	(void)start_ticks;
	return 0;
}

int bpf_loader_get_refusal(struct bpf_loader_ctx *ctx, int pidfd,
			   uint64_t *at_ns, char *object, size_t len)
{
	(void)ctx;
	(void)pidfd;
	(void)at_ns;
	(void)object;
	(void)len;
	return -ENOENT;
}

int bpf_loader_task_instance(struct bpf_loader_ctx *ctx, int pidfd,
			     uint32_t pid, uint32_t *root_tgid,
			     uint64_t *root_start_ticks)
{
	(void)ctx;
	(void)pidfd;
	(void)pid;
	(void)root_tgid;
	(void)root_start_ticks;
	return 0;
}

int bpf_loader_instance_stopped_ms(struct bpf_loader_ctx *ctx, uint32_t pid,
				   uint64_t *ms)
{
	(void)ctx;
	(void)pid;
	*ms = 0;
	return 0;
}

int bpf_loader_adopt_instance_member(struct bpf_loader_ctx *ctx, uint32_t pid,
				     struct bpf_instance_member *member)
{
	(void)ctx;
	(void)pid;
	(void)member;
	return 0;
}

int bpf_loader_exec_history(struct bpf_loader_ctx *ctx,
			    int (*alive)(uint32_t tgid, uint64_t start_ticks),
			    struct lota_exec_history_key **keys,
			    struct lota_exec_history_val **vals, size_t *n)
{
	(void)ctx;
	(void)alive;
	*keys = NULL;
	*vals = NULL;
	*n = 0;
	return -ENOENT;
}

int bpf_loader_instance_actors(struct bpf_loader_ctx *ctx,
			       int (*alive)(uint32_t tgid,
					    uint64_t start_ticks),
			       struct lota_instance_actor_key **keys,
			       struct lota_instance_actor_val **vals, size_t *n)
{
	(void)ctx;
	(void)alive;
	*keys = NULL;
	*vals = NULL;
	*n = 0;
	return -ENOENT;
}

int bpf_loader_get_extended_stats(struct bpf_loader_ctx *ctx,
				  struct bpf_extended_stats *stats)
{
	(void)ctx;
	memset(stats, 0, sizeof(*stats));
	return 0;
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

void dbus_emit_status_changed(struct dbus_context *ctx)
{
	(void)ctx;
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

/* No enrollment on disk, which is the state a first session finds */
int enroll_state_load_path(const char *path, struct enroll_state *out)
{
	(void)path;
	(void)out;
	return -ENOENT;
}

int lota_runtime_measure_pid_objects(
	pid_t pid, uint8_t out_digest[LOTA_RUNTIME_IMAGE_DIGEST_SIZE],
	struct lota_runtime_measure_coverage *cov,
	struct lota_runtime_measure_failure *fail,
	struct lota_rt_object_record *objs, size_t *n_objs)
{
	(void)pid;
	(void)out_digest;
	(void)cov;
	(void)fail;
	(void)objs;
	if (n_objs)
		*n_objs = 0;
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

/* the round publishes the word from scratch; the loss outlives it */
static void test_events_lost_outlives_a_round(struct ipc_context *ctx)
{
	struct lota_ipc_status st;
	uint64_t until = (uint64_t)time(NULL) + 600;

	TEST("a lost event stays in the status and leaves the window alone");

	ipc_update_status(ctx, LOTA_STATUS_TPM_OK, until);
	ipc_set_events_lost(ctx);

	if (read_status(ctx, &st) < 0) {
		FAIL("status");
		return;
	}
	if (!(st.flags & LOTA_STATUS_EVENTS_LOST)) {
		FAIL("the loss did not reach the status");
		return;
	}
	if (st.valid_until != until) {
		FAIL("the loss moved the validity window");
		return;
	}

	ipc_update_status(ctx, LOTA_STATUS_TPM_OK, until);

	if (read_status(ctx, &st) < 0) {
		FAIL("status");
		return;
	}
	if (!(st.flags & LOTA_STATUS_EVENTS_LOST)) {
		FAIL("a round erased the loss");
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
	test_events_lost_outlives_a_round(&ctx);

	ipc_cleanup(&ctx);
	unlink(test_socket);

	printf("\n%d/%d tests passed\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
