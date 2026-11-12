/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for the cost of the coverage bit in the IPC status answer.
 *
 * Deciding the bit walks the mappings of every protected process, which takes
 * seconds for a game. GET_STATUS is served on the shared IPC thread, so it
 * must not walk per request. Driven through ipc_process() over a socket,
 * counting the walks.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <errno.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
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

/* No TPM: the census refuses and bind proceeds without it */
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

/* StatusChanged signals sent */
static int status_changed;

void dbus_emit_status_changed(struct dbus_context *ctx)
{
	(void)ctx;
	status_changed++;
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

/* Every PID but partial_pid fully measured; counts the walks */
static int coverage_walks;
static pid_t partial_pid = -1;

int lota_runtime_coverage_pid(pid_t pid,
			      struct lota_runtime_measure_coverage *cov)
{
	coverage_walks++;
	if (cov) {
		memset(cov, 0, sizeof(*cov));
		cov->measured = 4;
		if (pid == partial_pid)
			cov->unmeasurable = 1;
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

static char test_socket[108];

/* Private socket: no root, no /run/lota */
static int listener_open(void)
{
	struct sockaddr_un addr;
	int fd;

	snprintf(test_socket, sizeof(test_socket), "/tmp/lota-covcost-%d.sock",
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

/* Pump ipc_process() until one response frame arrives */
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

static int read_status(struct ipc_context *ctx, struct lota_ipc_status *out)
{
	struct lota_ipc_response resp = { 0 };
	uint8_t payload[LOTA_IPC_MAX_PAYLOAD];
	int fd;
	int ret;

	fd = client_open();
	if (fd < 0)
		return fd;

	ret = send_request(fd, LOTA_IPC_CMD_GET_STATUS, NULL, 0);
	if (ret == 0)
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

/* Protected set = this process, alive for the whole run */
static int protect_self(void)
{
	uint32_t *pids;

	pids = calloc(1, sizeof(*pids));
	if (!pids)
		return -ENOMEM;

	pids[0] = (uint32_t)getpid();

	g_agent.policy_protect_pids = pids;
	g_agent.policy_protect_pid_count = 1;
	g_agent.policy_protect_epoch = 1;
	return 0;
}

/* Protected set unchanged across the three answers: one walk serves all */
static void test_repeat_answers_share_one_walk(struct ipc_context *ctx)
{
	struct lota_ipc_status st;

	TEST("repeated status answers cost one walk between them");

	coverage_walks = 0;
	ipc_update_status(ctx, LOTA_STATUS_TPM_OK, 0);

	for (int i = 0; i < 3; i++) {
		if (read_status(ctx, &st) < 0) {
			FAIL("status");
			return;
		}
		if (!(st.flags & LOTA_STATUS_IMAGE_FULLY_MEASURED)) {
			FAIL("a fully measured host is reported as not");
			return;
		}
	}

	if (coverage_walks != 1) {
		char msg[128];

		snprintf(msg, sizeof(msg),
			 "three answers walked the protected set %d times",
			 coverage_walks);
		FAIL(msg);
		return;
	}

	PASS();
}

/* The walk belongs to the set, not to the caller */
static void test_second_caller_pays_nothing(struct ipc_context *ctx)
{
	struct lota_ipc_status st;
	int before;

	TEST("a second caller does not pay for the first caller's walk");

	if (read_status(ctx, &st) < 0) {
		FAIL("status");
		return;
	}
	before = coverage_walks;

	if (read_status(ctx, &st) < 0) {
		FAIL("status");
		return;
	}

	if (coverage_walks != before) {
		FAIL("the second answer walked the protected set again");
		return;
	}

	PASS();
}

/* A new mapping may lack a digest and bumps no epoch: forget must re-walk */
static void test_mapping_change_costs_a_fresh_walk(struct ipc_context *ctx)
{
	struct lota_ipc_status st;
	int before;

	TEST("a protected process mapping an object is walked again");

	if (read_status(ctx, &st) < 0) {
		FAIL("status");
		return;
	}
	before = coverage_walks;

	ipc_runtime_coverage_forget();

	if (read_status(ctx, &st) < 0) {
		FAIL("status");
		return;
	}
	if (coverage_walks != before + 1) {
		FAIL("the answer after a mapping change reused the old verdict");
		return;
	}

	PASS();
}

/* Membership changes bump the epoch, which alone forces a re-walk */
static void test_set_change_costs_a_fresh_walk(struct ipc_context *ctx)
{
	struct lota_ipc_status st;
	int before;

	TEST("a change to the protected set is walked again");

	if (read_status(ctx, &st) < 0) {
		FAIL("status");
		return;
	}
	before = coverage_walks;

	g_agent.policy_protect_epoch += 1;

	if (read_status(ctx, &st) < 0) {
		FAIL("status");
		return;
	}
	if (coverage_walks != before + 1) {
		FAIL("the answer after a set change reused the old verdict");
		return;
	}

	PASS();
}

/* Each call one second past the last, so every tick is due */
static uint64_t tick_now(void)
{
	static uint64_t now = 1000ULL * 1000 * 1000;

	now += 1000ULL * 1000 * 1000;
	return now;
}

static bool host_fully_measured(struct ipc_context *ctx)
{
	return ipc_host_status_flags(ctx) & LOTA_STATUS_IMAGE_FULLY_MEASURED;
}

/* A mapping bumps no epoch and calls no status update: the tick announces */
static void test_mapping_loss_is_announced(struct ipc_context *ctx)
{
	int before;

	TEST("a protected mapping that ends full coverage is announced");

	ipc_status_tick(ctx, tick_now());
	if (!host_fully_measured(ctx)) {
		FAIL("the host is not fully measured to begin with");
		return;
	}
	before = status_changed;

	partial_pid = getpid();
	ipc_runtime_coverage_forget();
	ipc_status_tick(ctx, tick_now());
	partial_pid = -1;

	if (status_changed != before + 1) {
		FAIL("full coverage was lost without StatusChanged");
		return;
	}
	if (host_fully_measured(ctx)) {
		FAIL("the announced word still claims full coverage");
		return;
	}

	ipc_runtime_coverage_forget();
	ipc_status_tick(ctx, tick_now());
	if (status_changed != before + 2) {
		FAIL("the return to full coverage was not announced");
		return;
	}

	PASS();
}

/* A burst of mappings within one tick costs one walk */
static void test_mappings_within_a_tick_share_one_walk(struct ipc_context *ctx)
{
	uint64_t now = tick_now();
	int before;

	TEST("mappings within one tick are folded once");

	ipc_status_tick(ctx, now);
	before = coverage_walks;

	for (int i = 0; i < 5; i++) {
		ipc_runtime_coverage_forget();
		ipc_status_tick(ctx, now + 1);
	}
	if (coverage_walks != before) {
		FAIL("a tick that was not due walked the protected set");
		return;
	}
	if (ipc_status_timeout_ms(ctx, now + 1) <= 0) {
		FAIL("the forgotten verdict is not left for the next tick");
		return;
	}

	ipc_status_tick(ctx, tick_now());
	if (coverage_walks != before + 1) {
		FAIL("the due tick did not fold the forgotten verdict once");
		return;
	}

	PASS();
}

/* An exited PID is dropped by the fold alone; the tick must run it */
static void test_protected_exit_is_announced(struct ipc_context *ctx)
{
	uint32_t *pids;
	pid_t child;
	int before;

	TEST("the exit of a partly measured protected PID is announced");

	child = fork();
	if (child < 0) {
		FAIL("fork");
		return;
	}
	if (child == 0) {
		pause();
		_exit(0);
	}

	pids = realloc(g_agent.policy_protect_pids, 2 * sizeof(*pids));
	if (!pids) {
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
		FAIL("out of memory");
		return;
	}
	pids[1] = (uint32_t)child;
	g_agent.policy_protect_pids = pids;
	g_agent.policy_protect_pid_count = 2;
	g_agent.policy_protect_epoch += 1;
	partial_pid = child;

	ipc_status_tick(ctx, tick_now());
	if (host_fully_measured(ctx)) {
		FAIL("a partly measured member left the host fully measured");
		goto out;
	}
	before = status_changed;

	kill(child, SIGKILL);
	waitpid(child, NULL, 0);
	child = -1;

	ipc_status_tick(ctx, tick_now());
	if (g_agent.policy_protect_pid_count != 1) {
		FAIL("the tick did not drop the exited PID");
		goto out;
	}
	if (status_changed != before + 1 || !host_fully_measured(ctx)) {
		FAIL("the regained full coverage was not announced");
		goto out;
	}

	PASS();
out:
	if (child > 0) {
		kill(child, SIGKILL);
		waitpid(child, NULL, 0);
	}
	partial_pid = -1;
}

int main(void)
{
	struct ipc_context ctx;
	int listen_fd;

	printf("=== Status coverage-cost tests ===\n\n");

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

	if (protect_self() < 0) {
		printf("SKIP: out of memory building the protected set\n");
		ipc_cleanup(&ctx);
		close(listen_fd);
		unlink(test_socket);
		return 0;
	}

	test_repeat_answers_share_one_walk(&ctx);
	test_second_caller_pays_nothing(&ctx);
	test_mapping_change_costs_a_fresh_walk(&ctx);
	test_set_change_costs_a_fresh_walk(&ctx);
	test_mapping_loss_is_announced(&ctx);
	test_mappings_within_a_tick_share_one_walk(&ctx);
	test_protected_exit_is_announced(&ctx);

	ipc_cleanup(&ctx);
	unlink(test_socket);

	printf("\n%d/%d tests passed\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
