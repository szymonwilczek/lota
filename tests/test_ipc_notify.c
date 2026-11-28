/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for the push notifications the daemon writes out.
 *
 * Two callers wait on them. The attestation loop subscribes by syncing
 * and then waits on the connection instead of the clock, so a session opening
 * reaches it at once. A title subscribes through the SDK, which the header
 * offers to every integrator in place of polling the status word.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */

#include <errno.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
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

/* nothing here latches a lockout; linked only */
void tpm_reset_lockout_state(struct tpm_context *ctx)
{
	(void)ctx;
}

/* set while a test signs tokens: an empty quote over the asked PCRs */
static bool tpm_signs;

int tpm_quote(struct tpm_context *ctx, const uint8_t *nonce, uint32_t pcr_mask,
	      struct tpm_quote_response *response)
{
	(void)ctx;
	(void)nonce;
	if (!tpm_signs)
		return -ENOTSUP;
	memset(response, 0, sizeof(*response));
	response->pcr_mask = pcr_mask;
	return 0;
}

int tpm_bind_profile(struct tpm_context *ctx, const struct profile_paths *paths)
{
	(void)ctx;
	(void)paths;
	return tpm_signs ? 0 : -ENOTSUP;
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
	return 0;
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

/* The instance root of each PID a test places; any other PID has none */
static struct {
	uint32_t pid;
	uint32_t root;
} instance_of[4];

int bpf_loader_task_instance(struct bpf_loader_ctx *ctx, int pidfd,
			     uint32_t pid, uint32_t *root_tgid,
			     uint64_t *root_start_ticks)
{
	(void)ctx;
	(void)pidfd;
	for (size_t i = 0; i < sizeof(instance_of) / sizeof(instance_of[0]);
	     i++) {
		if (instance_of[i].pid == 0 || instance_of[i].pid != pid)
			continue;
		*root_tgid = instance_of[i].root;
		*root_start_ticks = 1;
		return 1;
	}
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

/*
 * The adoption pass runs between the owner read and the signal of
 * TERMINATE_PROTECTED; a victim set here dies and is reaped in that window.
 */
static pid_t terminate_victim;

int bpf_loader_adopt_instance_member(struct bpf_loader_ctx *ctx, uint32_t pid,
				     struct bpf_instance_member *member)
{
	(void)ctx;
	(void)pid;
	(void)member;
	if (terminate_victim > 0) {
		kill(terminate_victim, SIGKILL);
		waitpid(terminate_victim, NULL, 0);
		terminate_victim = 0;
	}
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

/*
 * What the daemon asked D-Bus to emit.
 *
 * The bus itself is out of scope here -- test_dbus.c drives a real one.
 * What these tests are about is whether the daemon ever asks.
 */
static int dbus_attest_emitted;
static bool dbus_attest_last_success;

void dbus_emit_attestation_result(struct dbus_context *ctx, bool success)
{
	(void)ctx;
	dbus_attest_emitted++;
	dbus_attest_last_success = success;
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

/* A second publisher on the same host */
static const uint8_t other_profile_id[32] = {
	0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1,
	0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1,
	0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1, 0xa1,
};
static const char *const other_profile_hex = "a1a1a1a1a1a1a1a1"
					     "a1a1a1a1a1a1a1a1"
					     "a1a1a1a1a1a1a1a1"
					     "a1a1a1a1a1a1a1a1";

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
static int send_sync_counted(int fd, uint32_t attest_count, uint32_t fail_count)
{
	uint8_t buf[sizeof(struct lota_ipc_attest_sync)];
	struct lota_ipc_attest_sync sync;

	memset(&sync, 0, sizeof(sync));
	sync.attest_count = attest_count;
	sync.fail_count = fail_count;
	sync.last_attest_time = (uint64_t)time(NULL);
	memcpy(buf, &sync, sizeof(sync));

	return send_request(fd, LOTA_IPC_CMD_SYNC_ATTEST, buf, sizeof(buf));
}

static int send_sync(int fd)
{
	return send_sync_counted(fd, 0, 0);
}

/*
 * One publisher, agreed to, session-gated -- the shape a title finds on
 * a consumer host. The consent is written by the agent's own recorder
 * so the daemon reads back what it writes rather than what this file thinks
 * it writes.
 */
static int profile_init(struct attest_target *target, const char *hex)
{
	char base[64];
	int ret;

	memset(target, 0, sizeof(*target));
	target->has_profile = true;
	target->session_gated = true;
	snprintf(target->label, sizeof(target->label), "test publisher");

	snprintf(base, sizeof(base), "/tmp/lota-notify-%d.profiles",
		 (int)getpid());
	ret = profile_paths_from_id(base, hex, &target->paths);
	if (ret < 0)
		return ret;

	return profile_consent_record(&target->paths, geteuid());
}

static void profile_forget(struct attest_target *target)
{
	char base[64];

	unlink(target->paths.consent);
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

out:
	close(title_fd);
	close(loop_fd);
}

/*
 * The client outside the agent cannot report through shared memory,
 * so its exit code carries the wire result. These sit above every result
 * code so a failure to get that far is never read as an answer from the daemon.
 */
#define CHILD_ERR_CONNECT 0x41
#define CHILD_ERR_SEND 0x42
#define CHILD_ERR_NO_ANSWER 0x43
#define CHILD_ERR_NO_NOTIFY 0x44
#define CHILD_ERR_NOT_NOTIFY 0x45

/* Read one frame on the client side, which has no event loop to drive */
static int client_read_frame(int fd, struct lota_ipc_response *resp,
			     uint8_t *payload, size_t payload_max,
			     int timeout_ms)
{
	struct pollfd pfd = { .fd = fd, .events = POLLIN };

	if (poll(&pfd, 1, timeout_ms) <= 0)
		return -ETIMEDOUT;

	if (read(fd, resp, sizeof(*resp)) != (ssize_t)sizeof(*resp))
		return -EIO;
	if (resp->magic != LOTA_IPC_MAGIC)
		return -EBADMSG;
	if (resp->payload_len > payload_max)
		return -EMSGSIZE;
	if (resp->payload_len &&
	    read(fd, payload, resp->payload_len) != (ssize_t)resp->payload_len)
		return -EIO;

	return 0;
}

/*
 * The client a title runs: subscribe, say so on the pipe, wait for one push.
 *
 * Forked because the guard is about the peer's identity, and a connection opened
 * here carries the daemon's own pid, which no title ever does.
 */
static void subscriber_child(uint32_t mask, int ready_fd, uint32_t await_event)
{
	struct lota_ipc_subscribe_request sub = { .event_mask = mask };
	struct lota_ipc_response resp;
	uint8_t payload[LOTA_IPC_MAX_PAYLOAD];
	struct lota_ipc_notify notify;
	int fd;

	fd = client_open();
	if (fd < 0)
		_exit(CHILD_ERR_CONNECT);

	if (send_request(fd, LOTA_IPC_CMD_SUBSCRIBE, &sub, sizeof(sub)) < 0)
		_exit(CHILD_ERR_SEND);

	if (client_read_frame(fd, &resp, payload, sizeof(payload), 2000) < 0)
		_exit(CHILD_ERR_NO_ANSWER);

	if (resp.result != LOTA_IPC_OK || !await_event)
		_exit((int)resp.result);

	if (write(ready_fd, "s", 1) != 1)
		_exit(CHILD_ERR_SEND);

	if (client_read_frame(fd, &resp, payload, sizeof(payload), 2000) < 0)
		_exit(CHILD_ERR_NO_NOTIFY);

	if (resp.result != LOTA_IPC_NOTIFY || resp.payload_len < sizeof(notify))
		_exit(CHILD_ERR_NOT_NOTIFY);

	memcpy(&notify, payload, sizeof(notify));
	_exit((notify.events & await_event) ? 0 : CHILD_ERR_NOT_NOTIFY);
}

#define CHILD_ERR_VIEW_DIFFERS 0x46

/*
 * A title bound to the test publisher: subscribe, wait for one push, then ask
 * GET_STATUS on the same connection; both answers must carry the same word.
 */
static void title_view_child(int ready_fd)
{
	struct lota_ipc_subscribe_request sub = {
		.event_mask = LOTA_IPC_EVENT_STATUS,
	};
	struct lota_ipc_set_profile set;
	struct lota_ipc_response resp;
	uint8_t payload[LOTA_IPC_MAX_PAYLOAD];
	struct lota_ipc_notify notify;
	struct lota_ipc_status st;
	int fd;

	fd = client_open();
	if (fd < 0)
		_exit(CHILD_ERR_CONNECT);

	memset(&set, 0, sizeof(set));
	memcpy(set.profile_id, test_profile_id, sizeof(set.profile_id));
	if (send_request(fd, LOTA_IPC_CMD_SET_PROFILE, &set, sizeof(set)) < 0)
		_exit(CHILD_ERR_SEND);
	if (client_read_frame(fd, &resp, payload, sizeof(payload), 2000) < 0)
		_exit(CHILD_ERR_NO_ANSWER);
	if (resp.result != LOTA_IPC_OK)
		_exit((int)resp.result);

	if (send_request(fd, LOTA_IPC_CMD_SUBSCRIBE, &sub, sizeof(sub)) < 0)
		_exit(CHILD_ERR_SEND);
	if (client_read_frame(fd, &resp, payload, sizeof(payload), 2000) < 0)
		_exit(CHILD_ERR_NO_ANSWER);
	if (resp.result != LOTA_IPC_OK)
		_exit((int)resp.result);

	if (write(ready_fd, "s", 1) != 1)
		_exit(CHILD_ERR_SEND);

	if (client_read_frame(fd, &resp, payload, sizeof(payload), 2000) < 0)
		_exit(CHILD_ERR_NO_NOTIFY);
	if (resp.result != LOTA_IPC_NOTIFY || resp.payload_len < sizeof(notify))
		_exit(CHILD_ERR_NOT_NOTIFY);
	memcpy(&notify, payload, sizeof(notify));

	if (send_request(fd, LOTA_IPC_CMD_GET_STATUS, NULL, 0) < 0)
		_exit(CHILD_ERR_SEND);
	if (client_read_frame(fd, &resp, payload, sizeof(payload), 2000) < 0)
		_exit(CHILD_ERR_NO_ANSWER);
	if (resp.result != LOTA_IPC_OK || resp.payload_len < sizeof(st))
		_exit(CHILD_ERR_NO_ANSWER);
	memcpy(&st, payload, sizeof(st));

	if (notify.flags != st.flags || notify.valid_until != st.valid_until)
		_exit(CHILD_ERR_VIEW_DIFFERS);
	_exit(0);
}

/* Drive the daemon until the forked client is done, and report what it said */
static int pump_until_exit(struct ipc_context *ctx, pid_t pid, int passes)
{
	for (int i = 0; i < passes; i++) {
		int status;

		if (waitpid(pid, &status, WNOHANG) == pid)
			return WIFEXITED(status) ? WEXITSTATUS(status) : -EINTR;

		ipc_process(ctx, 10);
	}

	kill(pid, SIGKILL);
	waitpid(pid, NULL, 0);
	return -ETIMEDOUT;
}

/*
 * The subscription the SDK header sells has to work for the caller it is sold
 * to. A title reads the same status word through GET_STATUS whenever it asks,
 * so refusing to push it changes nothing but the cost of learning it.
 */
static void test_outside_client_may_subscribe(struct ipc_context *ctx)
{
	pid_t pid;
	int rc;

	TEST("a client outside the agent may subscribe");

	pid = fork();
	if (pid < 0) {
		FAIL("fork");
		return;
	}
	if (pid == 0)
		subscriber_child(LOTA_IPC_EVENT_STATUS | LOTA_IPC_EVENT_ATTEST |
					 LOTA_IPC_EVENT_MODE,
				 -1, 0);

	rc = pump_until_exit(ctx, pid, 256);
	if (rc == LOTA_IPC_ERR_ACCESS_DENIED) {
		FAIL("refused: only the daemon's own pid may subscribe");
		return;
	}
	if (rc != LOTA_IPC_OK) {
		FAIL("subscribe was not answered with OK");
		return;
	}
}

/* Subscribing is worth nothing unless the event then arrives unasked */
static void test_outside_client_is_notified(struct ipc_context *ctx)
{
	int ready[2];
	pid_t pid;
	int rc;

	TEST("a status change is pushed to that client");

	if (pipe(ready) < 0) {
		FAIL("pipe");
		return;
	}

	pid = fork();
	if (pid < 0) {
		FAIL("fork");
		close(ready[0]);
		close(ready[1]);
		return;
	}
	if (pid == 0) {
		close(ready[0]);
		subscriber_child(LOTA_IPC_EVENT_STATUS, ready[1],
				 LOTA_IPC_EVENT_STATUS);
	}
	close(ready[1]);

	/* nothing may change before the client is on the list */
	for (int i = 0; i < 256; i++) {
		struct pollfd pfd = { .fd = ready[0], .events = POLLIN };

		if (poll(&pfd, 1, 0) > 0)
			break;
		ipc_process(ctx, 10);
	}
	close(ready[0]);

	ipc_update_status(ctx, ctx->status_flags ^ LOTA_STATUS_TPM_OK, 0);

	rc = pump_until_exit(ctx, pid, 256);
	if (rc == CHILD_ERR_NO_NOTIFY) {
		FAIL("no push: the client has to poll after all");
		return;
	}
	if (rc != 0) {
		FAIL("the pushed frame is not the status event");
		return;
	}
}

/*
 * The host attests for another publisher while a bit every view shares moves;
 * the title's publisher holds no verdict, so its push must not say otherwise.
 */
static void test_title_push_carries_its_publisher_view(struct ipc_context *ctx)
{
	uint32_t saved_flags = ctx->status_flags;
	uint64_t saved_valid = ctx->valid_until;
	int ready[2];
	pid_t pid;
	int rc;

	TEST("a title's push carries the word GET_STATUS gives it");

	if (pipe(ready) < 0) {
		FAIL("pipe");
		return;
	}

	pid = fork();
	if (pid < 0) {
		FAIL("fork");
		close(ready[0]);
		close(ready[1]);
		return;
	}
	if (pid == 0) {
		close(ready[0]);
		title_view_child(ready[1]);
	}
	close(ready[1]);

	for (int i = 0; i < 256; i++) {
		struct pollfd pfd = { .fd = ready[0], .events = POLLIN };

		if (poll(&pfd, 1, 0) > 0)
			break;
		ipc_process(ctx, 10);
	}
	close(ready[0]);

	ipc_update_status(ctx,
			  (ctx->status_flags | LOTA_STATUS_ATTESTED) ^
				  LOTA_STATUS_UPDATE_PENDING,
			  (uint64_t)time(NULL) + 300);

	rc = pump_until_exit(ctx, pid, 256);
	ipc_update_status(ctx, saved_flags, saved_valid);
	if (rc == CHILD_ERR_VIEW_DIFFERS) {
		FAIL("the push carries the host verdict, not the publisher's");
		return;
	}
	if (rc != 0) {
		FAIL("the title did not get its push and its status");
		return;
	}
}

/*
 * The publisher event is the loop's own business: it carries which titles hold
 * a session and which publisher this host has never enrolled with, and the loop
 * is subscribed to it by the act of syncing. A title asking for it alone
 * is asking for something it can never be given, and hears so.
 */
static void test_publisher_event_stays_reserved(struct ipc_context *ctx)
{
	pid_t pid;
	int rc;

	TEST("the publisher event stays reserved to the loop");

	pid = fork();
	if (pid < 0) {
		FAIL("fork");
		return;
	}
	if (pid == 0)
		subscriber_child(LOTA_IPC_EVENT_PROFILE, -1, 0);

	rc = pump_until_exit(ctx, pid, 256);
	if (rc != LOTA_IPC_ERR_BAD_REQUEST) {
		FAIL("a reserved-only mask is not refused as a bad request");
		return;
	}
}

/*
 * A round the loop completed has to leave the daemon, on both roads.
 *
 * The loop hands its tallies over in the sync; the daemon assigned them
 * and told nobody, so a subscribed title heard nothing and the bus carried
 * no AttestationResult even though AttestCount had visibly moved.
 */
static void test_attest_round_is_reported(struct ipc_context *ctx)
{
	struct lota_ipc_response resp;
	uint8_t payload[LOTA_IPC_MAX_PAYLOAD];
	int ready[2];
	pid_t pid;
	int loop_fd;
	int rc;

	TEST("a completed round is pushed and put on the bus");

	dbus_attest_emitted = 0;
	dbus_attest_last_success = false;

	if (pipe(ready) < 0) {
		FAIL("pipe");
		return;
	}

	pid = fork();
	if (pid < 0) {
		FAIL("fork");
		close(ready[0]);
		close(ready[1]);
		return;
	}
	if (pid == 0) {
		close(ready[0]);
		subscriber_child(LOTA_IPC_EVENT_ATTEST, ready[1],
				 LOTA_IPC_EVENT_ATTEST);
	}
	close(ready[1]);

	for (int i = 0; i < 256; i++) {
		struct pollfd pfd = { .fd = ready[0], .events = POLLIN };

		if (poll(&pfd, 1, 0) > 0)
			break;
		ipc_process(ctx, 10);
	}
	close(ready[0]);

	loop_fd = client_open();
	if (loop_fd < 0) {
		FAIL("loop connect");
		goto reap;
	}

	if (send_sync_counted(loop_fd, ctx->attest_count + 1, ctx->fail_count) <
		    0 ||
	    read_frame(ctx, loop_fd, &resp, payload, sizeof(payload), 64) < 0 ||
	    resp.result != LOTA_IPC_OK) {
		FAIL("sync");
		close(loop_fd);
		goto reap;
	}

	rc = pump_until_exit(ctx, pid, 256);
	close(loop_fd);

	if (rc == CHILD_ERR_NO_NOTIFY) {
		FAIL("no push: a subscribed title sleeps through the round");
		return;
	}
	if (rc != 0) {
		FAIL("the pushed frame is not the attestation event");
		return;
	}
	if (dbus_attest_emitted != 1) {
		FAIL("the daemon never asks D-Bus to emit the result");
		return;
	}
	if (!dbus_attest_last_success) {
		FAIL("the emitted result is not the success that happened");
		return;
	}

	return;
reap:
	kill(pid, SIGKILL);
	waitpid(pid, NULL, 0);
}

/* A round that failed is reported as one, not merely counted */
static void test_failed_round_is_reported(struct ipc_context *ctx)
{
	struct lota_ipc_response resp;
	uint8_t payload[LOTA_IPC_MAX_PAYLOAD];
	int loop_fd;

	TEST("a failed round reaches the bus as a failure");

	dbus_attest_emitted = 0;
	dbus_attest_last_success = true;

	loop_fd = client_open();
	if (loop_fd < 0) {
		FAIL("loop connect");
		return;
	}

	if (send_sync_counted(loop_fd, ctx->attest_count, ctx->fail_count + 1) <
		    0 ||
	    read_frame(ctx, loop_fd, &resp, payload, sizeof(payload), 64) < 0 ||
	    resp.result != LOTA_IPC_OK) {
		FAIL("sync");
		close(loop_fd);
		return;
	}
	close(loop_fd);

	if (dbus_attest_emitted != 1) {
		FAIL("the daemon never asks D-Bus to emit the result");
		return;
	}
	if (dbus_attest_last_success) {
		FAIL("a failed round is emitted as a success");
		return;
	}
}

/* Nothing happened, so nothing is announced */
static void test_repeated_sync_announces_nothing(struct ipc_context *ctx)
{
	struct lota_ipc_response resp;
	uint8_t payload[LOTA_IPC_MAX_PAYLOAD];
	int loop_fd;

	TEST("a sync that completed no round announces nothing");

	dbus_attest_emitted = 0;

	loop_fd = client_open();
	if (loop_fd < 0) {
		FAIL("loop connect");
		return;
	}

	if (send_sync_counted(loop_fd, ctx->attest_count, ctx->fail_count) <
		    0 ||
	    read_frame(ctx, loop_fd, &resp, payload, sizeof(payload), 64) < 0 ||
	    resp.result != LOTA_IPC_OK) {
		FAIL("sync");
		close(loop_fd);
		return;
	}
	close(loop_fd);

	if (dbus_attest_emitted != 0) {
		FAIL("an idle sync is announced as a round");
		return;
	}
}

static pid_t protected_child(void)
{
	pid_t pid = fork();

	if (pid == 0) {
		for (;;)
			pause();
	}
	if (pid < 0)
		return -1;

	g_agent.policy_protect_pids = calloc(1, sizeof(uint32_t));
	if (!g_agent.policy_protect_pids) {
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
		return -1;
	}
	g_agent.policy_protect_pids[0] = (uint32_t)pid;
	g_agent.policy_protect_pid_count = 1;
	return pid;
}

static void protected_forget(void)
{
	free(g_agent.policy_protect_pids);
	g_agent.policy_protect_pids = NULL;
	g_agent.policy_protect_pid_count = 0;
}

/* TERMINATE_PROTECTED for @pid; @others, if set, gets the count it reports */
static int terminate_request_counted(struct ipc_context *ctx, pid_t pid,
				     uint32_t *result, uint32_t *others)
{
	struct lota_ipc_terminate_request req = {
		.pid = (uint32_t)pid,
		.signal = SIGTERM,
	};
	struct lota_ipc_terminate_response body;
	struct lota_ipc_response resp;
	uint8_t payload[LOTA_IPC_MAX_PAYLOAD];
	int fd, ret;

	fd = client_open();
	if (fd < 0)
		return fd;

	ret = send_request(fd, LOTA_IPC_CMD_TERMINATE_PROTECTED, &req,
			   sizeof(req));
	if (ret == 0)
		ret = read_frame(ctx, fd, &resp, payload, sizeof(payload), 64);
	close(fd);
	if (ret == 0)
		*result = resp.result;
	if (ret == 0 && others && resp.result == LOTA_IPC_OK) {
		if (resp.payload_len < sizeof(body))
			return -EIO;
		memcpy(&body, payload, sizeof(body));
		*others = body.other_protect_pid_count;
	}
	return ret;
}

static int terminate_request(struct ipc_context *ctx, pid_t pid,
			     uint32_t *result)
{
	return terminate_request_counted(ctx, pid, result, NULL);
}

static void test_terminate_reaches_the_target(struct ipc_context *ctx)
{
	uint32_t result = 0;
	int status = 0;
	pid_t pid;

	TEST("TERMINATE_PROTECTED ends a live protected process");

	pid = protected_child();
	if (pid < 0) {
		FAIL("cannot fork a protected process");
		return;
	}

	if (terminate_request(ctx, pid, &result) < 0) {
		FAIL("terminate request");
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
		goto out;
	}
	if (result != LOTA_IPC_OK) {
		FAIL("a live protected process is refused");
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
		goto out;
	}
	if (waitpid(pid, &status, 0) != pid || !WIFSIGNALED(status) ||
	    WTERMSIG(status) != SIGTERM) {
		FAIL("the process did not die of SIGTERM");
		goto out;
	}

out:
	protected_forget();
}

/*
 * A target reaped after the owner read leaves its number free for another
 * process; the request must not reach anything by that number.
 */
static void test_terminate_target_reaped_mid_request(struct ipc_context *ctx)
{
	uint32_t result = 0;
	pid_t pid;

	TEST("a target reaped before the signal is answered as gone");

	pid = protected_child();
	if (pid < 0) {
		FAIL("cannot fork a protected process");
		return;
	}
	terminate_victim = pid;

	if (terminate_request(ctx, pid, &result) < 0) {
		FAIL("terminate request");
		goto out;
	}
	if (terminate_victim != 0) {
		FAIL("the target was not reaped inside the request");
		goto out;
	}
	if (result != LOTA_IPC_ERR_BAD_REQUEST) {
		FAIL("a reaped target is not answered as a missing process");
		goto out;
	}

out:
	if (terminate_victim > 0) {
		kill(terminate_victim, SIGKILL);
		waitpid(terminate_victim, NULL, 0);
		terminate_victim = 0;
	}
	protected_forget();
}

/* A title of @id: binds to its publisher, protects itself, then waits */
static void game_child(const uint8_t id[32], int ready_fd)
{
	struct lota_ipc_pid_request req = { .pid = 0 };
	struct lota_ipc_response resp;
	uint8_t payload[LOTA_IPC_MAX_PAYLOAD];
	struct lota_ipc_set_profile set;
	int fd;

	fd = client_open();
	if (fd < 0)
		_exit(CHILD_ERR_CONNECT);

	memset(&set, 0, sizeof(set));
	memcpy(set.profile_id, id, sizeof(set.profile_id));
	if (send_request(fd, LOTA_IPC_CMD_SET_PROFILE, &set, sizeof(set)) < 0 ||
	    client_read_frame(fd, &resp, payload, sizeof(payload), 2000) < 0 ||
	    resp.result != LOTA_IPC_OK)
		_exit(CHILD_ERR_NO_ANSWER);

	if (send_request(fd, LOTA_IPC_CMD_PROTECT_PID, &req, sizeof(req)) < 0 ||
	    client_read_frame(fd, &resp, payload, sizeof(payload), 2000) < 0)
		_exit(CHILD_ERR_NO_ANSWER);
	if (write(ready_fd, &resp.result, sizeof(resp.result)) !=
	    sizeof(resp.result))
		_exit(CHILD_ERR_SEND);
	for (;;)
		pause();
}

/* The status word a connection bound to @id reads */
static int status_for(struct ipc_context *ctx, const uint8_t id[32],
		      uint32_t *flags)
{
	struct lota_ipc_set_profile set;
	struct lota_ipc_response resp;
	uint8_t payload[LOTA_IPC_MAX_PAYLOAD];
	struct lota_ipc_status st;
	int fd, ret;

	fd = client_open();
	if (fd < 0)
		return fd;

	memset(&set, 0, sizeof(set));
	memcpy(set.profile_id, id, sizeof(set.profile_id));
	ret = send_request(fd, LOTA_IPC_CMD_SET_PROFILE, &set, sizeof(set));
	if (ret == 0)
		ret = read_frame(ctx, fd, &resp, payload, sizeof(payload), 64);
	if (ret == 0 && resp.result != LOTA_IPC_OK)
		ret = -EACCES;
	if (ret == 0)
		ret = send_request(fd, LOTA_IPC_CMD_GET_STATUS, NULL, 0);
	if (ret == 0)
		ret = read_frame(ctx, fd, &resp, payload, sizeof(payload), 64);
	close(fd);
	if (ret == 0 &&
	    (resp.result != LOTA_IPC_OK || resp.payload_len < sizeof(st)))
		ret = -EIO;
	if (ret == 0) {
		memcpy(&st, payload, sizeof(st));
		*flags = st.flags;
	}
	return ret;
}

/*
 * Drain the pushes waiting on @fd; fail on one whose word equals the one
 * before it, which tells the title only that a bit hidden from it moved.
 */
static int drain_status_pushes(struct ipc_context *ctx, int fd, uint32_t *last)
{
	struct lota_ipc_response resp;
	uint8_t payload[LOTA_IPC_MAX_PAYLOAD];
	struct lota_ipc_notify notify;

	while (read_frame(ctx, fd, &resp, payload, sizeof(payload), 32) == 0) {
		if (resp.result != LOTA_IPC_NOTIFY ||
		    resp.payload_len < sizeof(notify))
			return -EBADMSG;
		memcpy(&notify, payload, sizeof(notify));
		if (notify.flags == *last)
			return -EEXIST;
		*last = notify.flags;
	}
	return 0;
}

/* A STATUS subscription bound to @id, with the word it starts from */
static int status_subscriber(struct ipc_context *ctx, const uint8_t *id,
			     uint32_t *flags)
{
	struct lota_ipc_subscribe_request sub = {
		.event_mask = LOTA_IPC_EVENT_STATUS,
	};
	struct lota_ipc_set_profile set;
	struct lota_ipc_response resp;
	uint8_t payload[LOTA_IPC_MAX_PAYLOAD];
	struct lota_ipc_status st;
	int fd, ret;

	fd = client_open();
	if (fd < 0)
		return fd;

	memset(&set, 0, sizeof(set));
	memcpy(set.profile_id, id, sizeof(set.profile_id));
	ret = send_request(fd, LOTA_IPC_CMD_SET_PROFILE, &set, sizeof(set));
	if (ret == 0)
		ret = read_frame(ctx, fd, &resp, payload, sizeof(payload), 64);
	if (ret == 0 && resp.result != LOTA_IPC_OK)
		ret = -EACCES;
	if (ret == 0)
		ret = send_request(fd, LOTA_IPC_CMD_GET_STATUS, NULL, 0);
	if (ret == 0)
		ret = read_frame(ctx, fd, &resp, payload, sizeof(payload), 64);
	if (ret == 0 &&
	    (resp.result != LOTA_IPC_OK || resp.payload_len < sizeof(st)))
		ret = -EIO;
	if (ret == 0) {
		memcpy(&st, payload, sizeof(st));
		*flags = st.flags;
		ret = send_request(fd, LOTA_IPC_CMD_SUBSCRIBE, &sub,
				   sizeof(sub));
	}
	if (ret == 0)
		ret = read_frame(ctx, fd, &resp, payload, sizeof(payload), 64);
	if (ret == 0 && resp.result != LOTA_IPC_OK)
		ret = -EIO;
	if (ret < 0) {
		close(fd);
		return ret;
	}
	return fd;
}

/*
 * Ending a process protected for one publisher is that publisher's news and
 * the host's; a title of another publisher on the same host reads nothing.
 */
static void test_terminate_flags_the_owner_publisher(struct ipc_context *ctx,
						     struct attest_target *one)
{
	struct attest_target two[2];
	uint32_t result = 0xFFFFFFFF;
	uint32_t mine = 0, theirs = 0, seen = 0, owner_seen = 0;
	bool saved_snapshot = g_agent.policy_snapshot_set;
	bool saved_digest = g_agent.policy_digest_set;
	bool saved_host = ctx->protected_terminated;
	uint32_t saved_flags = ctx->status_flags;
	int ready[2];
	int sub = -1, owner_sub = -1;
	pid_t pid;

	TEST("ending another publisher's process leaves this one's word clear");

	two[0] = *one;
	if (profile_init(&two[1], other_profile_hex) < 0) {
		FAIL("cannot record the second publisher's consent");
		return;
	}
	ipc_set_profiles(ctx, two, 2);
	ctx->protected_terminated = false;
	ctx->status_flags &= ~(uint32_t)LOTA_STATUS_PROTECTED_TERMINATED;
	ipc_update_status(ctx, ctx->status_flags, ctx->valid_until);
	g_agent.policy_snapshot_set = 1;
	g_agent.policy_digest_set = 1;

	sub = status_subscriber(ctx, test_profile_id, &seen);
	owner_sub = status_subscriber(ctx, other_profile_id, &owner_seen);
	if (sub < 0 || owner_sub < 0) {
		FAIL("no status subscription for this publisher");
		goto out;
	}

	if (pipe(ready) < 0) {
		FAIL("pipe");
		goto out;
	}
	pid = fork();
	if (pid == 0) {
		close(ready[0]);
		game_child(other_profile_id, ready[1]);
	}
	close(ready[1]);
	if (pid < 0) {
		close(ready[0]);
		FAIL("fork");
		goto out;
	}

	for (int i = 0; i < 256; i++) {
		struct pollfd pfd = { .fd = ready[0], .events = POLLIN };

		if (poll(&pfd, 1, 0) > 0) {
			if (read(ready[0], &result, sizeof(result)) !=
			    sizeof(result))
				result = 0xFFFFFFFF;
			break;
		}
		ipc_process(ctx, 10);
	}
	close(ready[0]);

	if (result != LOTA_IPC_OK) {
		FAIL("the title could not protect itself");
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
		goto out;
	}
	if (drain_status_pushes(ctx, sub, &seen) < 0 ||
	    drain_status_pushes(ctx, owner_sub, &owner_seen) < 0) {
		FAIL("a push before the termination repeats the word");
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
		goto out;
	}
	if (terminate_request(ctx, pid, &result) < 0 || result != LOTA_IPC_OK) {
		FAIL("the protected title was not ended");
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
		goto out;
	}
	waitpid(pid, NULL, 0);

	if (drain_status_pushes(ctx, sub, &seen) < 0) {
		FAIL("this publisher was told that another one's bit moved");
		goto out;
	}
	if (drain_status_pushes(ctx, owner_sub, &owner_seen) < 0 ||
	    !(owner_seen & LOTA_STATUS_PROTECTED_TERMINATED)) {
		FAIL("the owner publisher was not told of its termination");
		goto out;
	}
	if (status_for(ctx, test_profile_id, &mine) < 0 ||
	    status_for(ctx, other_profile_id, &theirs) < 0) {
		FAIL("no status for a publisher's connection");
		goto out;
	}
	if (mine & LOTA_STATUS_PROTECTED_TERMINATED)
		FAIL("another publisher's termination reached this one");
	else if (!(theirs & LOTA_STATUS_PROTECTED_TERMINATED))
		FAIL("the owner publisher does not read its termination");
	else if (!(ctx->status_flags & LOTA_STATUS_PROTECTED_TERMINATED))
		FAIL("the host word does not carry the termination");

out:
	if (sub >= 0)
		close(sub);
	if (owner_sub >= 0)
		close(owner_sub);
	protected_forget();
	g_agent.policy_snapshot_set = saved_snapshot;
	g_agent.policy_digest_set = saved_digest;
	ctx->protected_terminated = saved_host;
	ctx->status_flags = saved_flags;
	ipc_set_profiles(ctx, one, 1);
	profile_forget(&two[1]);
}

/* The PIDs a token for this process carries, bound to @id or to no one */
static int token_pids(struct ipc_context *ctx, const uint8_t *id,
		      uint32_t *pids, uint32_t max, uint32_t *count)
{
	struct lota_ipc_token_request req;
	struct lota_ipc_set_profile set;
	struct lota_ipc_response resp = { 0 };
	uint8_t payload[LOTA_IPC_MAX_PAYLOAD];
	struct lota_ipc_token token;
	int fd, ret = 0;

	fd = client_open();
	if (fd < 0)
		return fd;

	if (id) {
		memset(&set, 0, sizeof(set));
		memcpy(set.profile_id, id, sizeof(set.profile_id));
		ret = send_request(fd, LOTA_IPC_CMD_SET_PROFILE, &set,
				   sizeof(set));
		if (ret == 0)
			ret = read_frame(ctx, fd, &resp, payload,
					 sizeof(payload), 64);
		if (ret == 0 && resp.result != LOTA_IPC_OK)
			ret = -EACCES;
	}
	memset(&req, 0, sizeof(req));
	if (ret == 0)
		ret = send_request(fd, LOTA_IPC_CMD_GET_TOKEN, &req,
				   sizeof(req));
	if (ret == 0)
		ret = read_frame(ctx, fd, &resp, payload, sizeof(payload), 64);
	close(fd);
	if (ret < 0)
		return ret;
	if (resp.result != LOTA_IPC_OK)
		return -(int)resp.result;
	if (resp.payload_len < sizeof(token))
		return -EIO;
	memcpy(&token, payload, sizeof(token));
	if (token.protect_pid_count > max ||
	    sizeof(token) + token.protect_pid_count * sizeof(uint32_t) >
		    resp.payload_len)
		return -E2BIG;
	for (uint32_t i = 0; i < token.protect_pid_count; i++)
		memcpy(&pids[i], payload + sizeof(token) + i * sizeof(uint32_t),
		       sizeof(uint32_t));
	*count = token.protect_pid_count;
	return 0;
}

/* The answer GET_REGISTRY gives this process for page 0 of @pid */
static int registry_result(struct ipc_context *ctx, pid_t pid, uint32_t *result)
{
	struct lota_ipc_registry_request req = { .pid = (uint32_t)pid };
	struct lota_ipc_response resp;
	uint8_t payload[LOTA_IPC_MAX_PAYLOAD];
	int fd, ret;

	fd = client_open();
	if (fd < 0)
		return fd;

	ret = send_request(fd, LOTA_IPC_CMD_GET_REGISTRY, &req, sizeof(req));
	if (ret == 0)
		ret = read_frame(ctx, fd, &resp, payload, sizeof(payload), 64);
	close(fd);
	if (ret == 0)
		*result = resp.result;
	return ret;
}

/* Fork a title of @id that protects itself; its PID, or -1 */
static pid_t game_started(struct ipc_context *ctx, const uint8_t id[32])
{
	uint32_t result = 0xFFFFFFFF;
	int ready[2];
	pid_t pid;

	if (pipe(ready) < 0)
		return -1;
	pid = fork();
	if (pid == 0) {
		close(ready[0]);
		game_child(id, ready[1]);
	}
	close(ready[1]);
	if (pid < 0) {
		close(ready[0]);
		return -1;
	}

	for (int i = 0; i < 256; i++) {
		struct pollfd pfd = { .fd = ready[0], .events = POLLIN };

		if (poll(&pfd, 1, 0) > 0) {
			if (read(ready[0], &result, sizeof(result)) !=
			    sizeof(result))
				result = 0xFFFFFFFF;
			break;
		}
		ipc_process(ctx, 10);
	}
	close(ready[0]);

	if (result != LOTA_IPC_OK) {
		kill(pid, SIGKILL);
		waitpid(pid, NULL, 0);
		return -1;
	}
	return pid;
}

/*
 * A token and GET_REGISTRY answer for the caller's own instance. Here the test
 * process shares an instance with a title of one publisher; a title of the
 * other publisher, same uid, runs in an instance of its own.
 */
static void test_token_holds_the_callers_instance(struct ipc_context *ctx,
						  struct attest_target *one)
{
	static struct tpm_context tpm_stub;
	struct attest_target two[2];
	bool saved_snapshot = g_agent.policy_snapshot_set;
	bool saved_digest = g_agent.policy_digest_set;
	uint32_t saved_flags = ctx->status_flags;
	uint32_t pids[8], count = 0, mine_reg = 0, theirs_reg = 0;
	pid_t mine = -1, theirs = -1, sibling = -1, gone;
	uint32_t result = 0, others = 0;
	const char *why = NULL;

	TEST("a token and the registry answer only for the caller's instance");

	two[0] = *one;
	if (profile_init(&two[1], other_profile_hex) < 0) {
		FAIL("cannot record the second publisher's consent");
		return;
	}
	for (int i = 0; i < 2; i++) {
		two[i].attested = true;
		two[i].valid_until = (uint64_t)time(NULL) + 3600;
	}
	ipc_set_profiles(ctx, two, 2);
	ipc_update_status(ctx, LOTA_STATUS_TPM_OK | LOTA_STATUS_ATTESTED, 0);
	ipc_set_tpm(ctx, &tpm_stub, 0x1);
	tpm_signs = true;
	g_agent.policy_snapshot_set = 1;
	g_agent.policy_digest_set = 1;

	mine = game_started(ctx, test_profile_id);
	theirs = game_started(ctx, other_profile_id);
	if (mine < 0 || theirs < 0) {
		why = "a title could not protect itself";
		goto out;
	}
	instance_of[0].pid = (uint32_t)getpid();
	instance_of[0].root = (uint32_t)mine;
	instance_of[1].pid = (uint32_t)mine;
	instance_of[1].root = (uint32_t)mine;
	instance_of[2].pid = (uint32_t)theirs;
	instance_of[2].root = (uint32_t)theirs;

	/* naming the other title's publisher reaches none of its processes */
	if (token_pids(ctx, other_profile_id, pids, 8, &count) < 0) {
		why = "no token for a caller naming the other publisher";
		goto out;
	}
	if (count != 1 || pids[0] != (uint32_t)mine) {
		why = "a token named for the other publisher left its instance";
		goto out;
	}
	if (registry_result(ctx, mine, &mine_reg) < 0 ||
	    registry_result(ctx, theirs, &theirs_reg) < 0) {
		why = "no GET_REGISTRY answer";
		goto out;
	}
	if (mine_reg != LOTA_IPC_OK) {
		why = "GET_REGISTRY refused a process of the caller's instance";
		goto out;
	}
	if (theirs_reg != LOTA_IPC_ERR_ACCESS_DENIED) {
		why = "GET_REGISTRY answered for another instance";
		goto out;
	}

	/* naming no one, on a host of one publisher */
	ipc_set_profiles(ctx, two, 1);
	if (token_pids(ctx, NULL, pids, 8, &count) < 0) {
		why = "no token for an unnamed caller";
		goto out;
	}
	if (count != 1 || pids[0] != (uint32_t)mine) {
		why = "an unnamed caller's token left its instance";
		goto out;
	}

	/* a caller of no instance reads no one's processes */
	instance_of[0].pid = 0;
	if (token_pids(ctx, NULL, pids, 8, &count) < 0) {
		why = "no token for a caller of no instance";
		goto out;
	}
	if (count != 0) {
		why = "a caller of no instance got protected PIDs";
		goto out;
	}
	if (registry_result(ctx, mine, &mine_reg) < 0 ||
	    mine_reg != LOTA_IPC_ERR_ACCESS_DENIED) {
		why = "GET_REGISTRY answered a caller of no instance";
		goto out;
	}

	/* ending one process counts the rest of its instance only */
	sibling = game_started(ctx, test_profile_id);
	if (sibling < 0) {
		why = "a second process of the title could not protect itself";
		goto out;
	}
	instance_of[3].pid = (uint32_t)sibling;
	instance_of[3].root = (uint32_t)mine;
	if (terminate_request_counted(ctx, sibling, &result, &others) < 0 ||
	    result != LOTA_IPC_OK) {
		why = "the second process of the title was not ended";
		goto out;
	}
	waitpid(sibling, NULL, 0);
	sibling = -1;
	if (others != 1) {
		why = "other processes counted past the target's instance";
		goto out;
	}

	/* a measured process that exited has no registry */
	instance_of[0].pid = (uint32_t)getpid();
	if (token_pids(ctx, NULL, pids, 8, &count) < 0 ||
	    registry_result(ctx, mine, &mine_reg) < 0 ||
	    mine_reg != LOTA_IPC_OK) {
		why = "no registry for the caller's live title";
		goto out;
	}
	kill(mine, SIGKILL);
	waitpid(mine, NULL, 0);
	gone = mine;
	mine = -1;
	if (registry_result(ctx, gone, &mine_reg) < 0 ||
	    mine_reg != LOTA_IPC_ERR_NOT_PROTECTED) {
		why = "GET_REGISTRY answered for a process that exited";
		goto out;
	}

out:
	if (why)
		FAIL("%s", why);
	memset(instance_of, 0, sizeof(instance_of));
	if (sibling > 0) {
		kill(sibling, SIGKILL);
		waitpid(sibling, NULL, 0);
	}
	for (int i = 0; i < 2; i++) {
		pid_t pid = i ? theirs : mine;

		if (pid > 0) {
			kill(pid, SIGKILL);
			waitpid(pid, NULL, 0);
		}
	}
	tpm_signs = false;
	ipc_set_tpm(ctx, NULL, 0);
	protected_forget();
	g_agent.policy_snapshot_set = saved_snapshot;
	g_agent.policy_digest_set = saved_digest;
	ctx->status_flags = saved_flags;
	ipc_set_profiles(ctx, one, 1);
	profile_forget(&two[1]);
}

/*
 * A title hears STATUS when its own word moves: not when the host verdict
 * moves for another publisher, and also when only its publisher's moves.
 */
static void test_status_push_follows_the_title_word(struct ipc_context *ctx,
						    struct attest_target *one)
{
	struct lota_ipc_response resp;
	uint8_t payload[LOTA_IPC_MAX_PAYLOAD];
	struct lota_ipc_notify notify;
	uint32_t saved_flags = ctx->status_flags;
	uint64_t saved_valid = ctx->valid_until;
	bool saved_attested = one->attested;
	uint64_t saved_until = one->valid_until;
	uint32_t seen = 0;
	int sub;

	TEST("STATUS reaches a title when its own word moves, and only then");

	one->attested = false;
	ipc_update_status(ctx, ctx->status_flags & ~LOTA_STATUS_ATTESTED,
			  saved_valid);
	sub = status_subscriber(ctx, test_profile_id, &seen);
	if (sub < 0) {
		FAIL("no status subscription for this publisher");
		goto out;
	}
	if (drain_status_pushes(ctx, sub, &seen) < 0) {
		FAIL("a push before the change repeats the word");
		goto out;
	}

	ipc_update_status(ctx, ctx->status_flags | LOTA_STATUS_ATTESTED,
			  (uint64_t)time(NULL) + 300);
	if (drain_status_pushes(ctx, sub, &seen) < 0) {
		FAIL("another publisher's verdict reached this title");
		goto out;
	}

	one->attested = true;
	one->valid_until = (uint64_t)time(NULL) + 300;
	ipc_update_status(ctx, ctx->status_flags, ctx->valid_until);
	if (read_frame(ctx, sub, &resp, payload, sizeof(payload), 32) < 0 ||
	    resp.result != LOTA_IPC_NOTIFY ||
	    resp.payload_len < sizeof(notify)) {
		FAIL("its own publisher's verdict was not pushed");
		goto out;
	}
	memcpy(&notify, payload, sizeof(notify));
	if (!(notify.flags & LOTA_STATUS_ATTESTED))
		FAIL("the push does not carry its publisher's verdict");

out:
	if (sub >= 0)
		close(sub);
	one->attested = saved_attested;
	one->valid_until = saved_until;
	ipc_update_status(ctx, saved_flags, saved_valid);
}

/*
 * The PID in TERMINATE_PROTECTED is read in the agent's namespace;
 * a caller in a PID namespace below it is refused before any process is named.
 */
static void test_terminate_from_nested_namespace(struct ipc_context *ctx)
{
	uint32_t result = 0xFFFFFFFF;
	int pfd[2];
	int status = 0;
	pid_t child;

	TEST("TERMINATE_PROTECTED from a nested PID namespace is refused");

	if (pipe(pfd) < 0) {
		FAIL("pipe");
		return;
	}
	child = fork();
	if (child == 0) {
		struct lota_ipc_terminate_request req = {
			.pid = 1,
			.signal = SIGTERM,
		};
		struct lota_ipc_response resp;
		uint8_t payload[LOTA_IPC_MAX_PAYLOAD];
		pid_t gc;

		close(pfd[0]);
		if (unshare(CLONE_NEWUSER | CLONE_NEWPID) < 0)
			_exit(77);
		gc = fork();
		if (gc == 0) {
			int fd = client_open();

			if (fd < 0 ||
			    send_request(fd, LOTA_IPC_CMD_TERMINATE_PROTECTED,
					 &req, sizeof(req)) < 0 ||
			    client_read_frame(fd, &resp, payload,
					      sizeof(payload), 2000) < 0)
				_exit(1);
			_exit(write(pfd[1], &resp.result,
				    sizeof(resp.result)) ==
					      sizeof(resp.result) ?
				      0 :
				      1);
		}
		_exit(gc > 0 && waitpid(gc, &status, 0) == gc &&
				      WIFEXITED(status) ?
			      WEXITSTATUS(status) :
			      1);
	}
	close(pfd[1]);
	if (child < 0) {
		close(pfd[0]);
		FAIL("fork");
		return;
	}

	for (int i = 0; i < 300; i++) {
		ipc_process(ctx, 10);
		if (waitpid(child, &status, WNOHANG) == child)
			break;
	}
	if (read(pfd[0], &result, sizeof(result)) != sizeof(result))
		result = 0xFFFFFFFF;
	close(pfd[0]);

	if (WIFEXITED(status) && WEXITSTATUS(status) == 77) {
		SKIP("no user and PID namespace here");
	} else if (result != LOTA_IPC_ERR_ACCESS_DENIED) {
		FAIL("a PID from a nested namespace reached the policy");
	}
}

int main(void)
{
	struct ipc_context ctx;
	struct attest_target *profiles;
	int listen_fd;

	test_begin("ipc notify");

	listen_fd = listener_open();
	if (listen_fd < 0) {
		SKIP("cannot create a Unix socket in /tmp (%s)",
		     strerror(-listen_fd));
		return 0;
	}

	if (ipc_init_activated(&ctx, listen_fd) < 0) {
		SKIP("ipc_init_activated failed");
		close(listen_fd);
		unlink(test_socket);
		return 0;
	}

	profiles = calloc(1, sizeof(*profiles));
	if (!profiles) {
		FAIL("out of memory");
		ipc_cleanup(&ctx);
		unlink(test_socket);
		return 1;
	}
	if (profile_init(profiles, test_profile_hex) < 0) {
		SKIP("cannot record consent under /tmp");
		ipc_cleanup(&ctx);
		free(profiles);
		unlink(test_socket);
		return 0;
	}
	ipc_set_profiles(&ctx, profiles, 1);

	test_outside_client_may_subscribe(&ctx);
	test_outside_client_is_notified(&ctx);
	test_publisher_event_stays_reserved(&ctx);
	test_attest_round_is_reported(&ctx);
	test_failed_round_is_reported(&ctx);
	test_repeated_sync_announces_nothing(&ctx);
	test_session_notification_is_delivered(&ctx);
	test_sync_after_notification_is_answered(&ctx);
	test_title_push_carries_its_publisher_view(&ctx);
	test_terminate_reaches_the_target(&ctx);
	test_terminate_target_reaped_mid_request(&ctx);
	test_terminate_flags_the_owner_publisher(&ctx, profiles);
	test_status_push_follows_the_title_word(&ctx, profiles);
	test_terminate_from_nested_namespace(&ctx);
	test_token_holds_the_callers_instance(&ctx, profiles);

	ipc_cleanup(&ctx);
	profile_forget(profiles);
	free(profiles);
	unlink(test_socket);

	return test_end();
}
