/* SPDX-License-Identifier: MIT */
/*
 * Unit tests for what an extra listener does to a path somebody else serves.
 *
 * The container socket under /run/user/<uid> is laid down by the running daemon
 * and is the only way a Proton title reaches the agent. A diagnostic server
 * brought up beside that daemon binds the same path: it unlinked the name,
 * took it for as long as it ran, and unlinked it again on the way out, leaving
 * the daemon holding a listening fd on an inode nothing can reach.
 * The directory never disappeared, so the watch that lays the socket down never
 * fires again, and the host has no container path until the next boot.
 *
 * The primary socket already answers this question: a path something is still
 * answering on is not ours to take. These tests hold the extra listeners to
 * the same rule, driven against the real ipc_add_listener() over real sockets.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

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
 * These tests never get as far as a request, so the stubs exist to link
 * and nothing here reaches one.
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
static char victim_socket[108];

static int listener_at(const char *path)
{
	struct sockaddr_un addr;
	int fd;

	unlink(path);

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);

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

/* Whether @path answers a connection, which is what a title needs of it */
static bool connectable(const char *path)
{
	struct sockaddr_un addr;
	int fd;
	bool ok;

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return false;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, sizeof(addr.sun_path), "%s", path);

	ok = connect(fd, (struct sockaddr *)&addr, sizeof(addr)) == 0;
	close(fd);
	return ok;
}

/*
 * The defect: a second server takes the container path from the daemon
 * serving it, and nothing tells the daemon.
 */
static void test_live_listener_is_not_taken(struct ipc_context *ctx)
{
	int victim_fd, ret;

	TEST("a path another process serves is refused");

	victim_fd = listener_at(victim_socket);
	if (victim_fd < 0) {
		FAIL("cannot lay down the socket to protect");
		return;
	}

	ret = ipc_add_listener(ctx, victim_socket);
	if (ret == 0) {
		FAIL("took a socket another process is answering on");
		ipc_remove_listener(ctx, victim_socket);
		close(victim_fd);
		unlink(victim_socket);
		return;
	}
	if (ret != -EADDRINUSE) {
		FAIL("refused for the wrong reason");
		close(victim_fd);
		unlink(victim_socket);
		return;
	}

	PASS();
	close(victim_fd);
	unlink(victim_socket);
}

/*
 * A refusal that unlinked the name first would leave the daemon holding
 * a listening fd nothing can reach, which is the state this refuses to leave.
 */
static void test_refusal_leaves_the_socket_connectable(struct ipc_context *ctx)
{
	int victim_fd;

	TEST("the refused socket still answers afterwards");

	victim_fd = listener_at(victim_socket);
	if (victim_fd < 0) {
		FAIL("cannot lay down the socket to protect");
		return;
	}

	ipc_add_listener(ctx, victim_socket);

	if (!connectable(victim_socket))
		FAIL("the socket is gone or no longer answers");
	else
		PASS();

	ipc_remove_listener(ctx, victim_socket);
	close(victim_fd);
	unlink(victim_socket);
}

/*
 * A socket file left by an unclean stop is what the unlink is for,
 * and recovering from one must go on working: nothing answers on it,
 * so it is not somebody's listener.
 */
static void
test_stale_socket_file_is_not_mistaken_for_a_listener(struct ipc_context *ctx)
{
	int fd, ret;

	TEST("a leftover socket file is not read as a live listener");

	fd = listener_at(victim_socket);
	if (fd < 0) {
		FAIL("cannot lay down the leftover socket");
		return;
	}
	close(fd); /* the file survives the listener, as after a crash */

	if (connectable(victim_socket)) {
		FAIL("the leftover still answers");
		unlink(victim_socket);
		return;
	}

	/*
	 * Binding it needs the 'lota' group and CAP_CHOWN, which a test run
	 * has no claim to, so the assertion is on the reason: whatever else
	 * stops it, the live-listener guard must not.
	 */
	ret = ipc_add_listener(ctx, victim_socket);
	if (ret == -EADDRINUSE)
		FAIL("a leftover was refused as somebody's listener");
	else
		PASS();

	if (ret == 0)
		ipc_remove_listener(ctx, victim_socket);
	unlink(victim_socket);
}

int main(void)
{
	struct ipc_context ctx;
	int listen_fd;

	printf("=== Extra IPC listeners against a path in use ===\n\n");

	/* the agent logs to stderr when it is not run under systemd */
	unsetenv("JOURNAL_STREAM");
	unsetenv("INVOCATION_ID");
	journal_init("lota-agent");

	snprintf(test_socket, sizeof(test_socket), "/tmp/lota-extra-%d.sock",
		 (int)getpid());
	snprintf(victim_socket, sizeof(victim_socket),
		 "/tmp/lota-extra-victim-%d.sock", (int)getpid());

	listen_fd = listener_at(test_socket);
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

	test_live_listener_is_not_taken(&ctx);
	test_refusal_leaves_the_socket_connectable(&ctx);
	test_stale_socket_file_is_not_mistaken_for_a_listener(&ctx);

	ipc_cleanup(&ctx);
	unlink(test_socket);
	unlink(victim_socket);

	printf("\n=== %d/%d passed ===\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
