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
 * The other half is the daemon's own socket being taken from underneath it
 * -- a socket unit restart unlinks the path and binds a new inode at the same
 * name, and the listening fd survives that without a hint. Those tests drive
 * ipc_socket_was_replaced(), which is what the daemon asks before it rebinds.
 *
 * Copyright (C) 2026 Szymon Wilczek
 */
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "test.h"
#include "../src/agent/agent.h"
#include "../src/agent/bpf_loader.h"
#include "../src/agent/dbus.h"
#include "../src/agent/enroll.h"
#include "../src/agent/ipc.h"
#include "../src/agent/journal.h"
#include "../src/agent/profile.h"
#include "../src/agent/runtime_image_measure.h"
#include "../src/agent/tpm.h"
#include "../src/agent/boot_evidence.h"

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

/* nothing here latches a lockout; linked only */
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

int bpf_loader_born_protected(struct bpf_loader_ctx *ctx, uint32_t pid,
			      uint64_t start_ticks)
{
	(void)ctx;
	(void)pid;
	(void)start_ticks;
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

int bpf_loader_adopt_instance_member(struct bpf_loader_ctx *ctx, uint32_t pid)
{
	(void)ctx;
	(void)pid;
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

/*
 * A socket unit restart unlinks the path the daemon is bound to and binds a new
 * inode at the same name. The listening fd survives it, so the daemon goes on
 * accepting on a socket no title can name -- and nothing fails, which is why
 * the identity of the file has to be checked rather than the descriptor.
 */
static void test_untouched_socket_is_not_replaced(void)
{
	struct stat st;
	int fd;

	TEST("an untouched socket is not reported replaced");

	fd = listener_at(victim_socket);
	if (fd < 0 || stat(victim_socket, &st) < 0) {
		FAIL("cannot lay down a socket to watch");
		if (fd >= 0)
			close(fd);
		return;
	}

	if (ipc_socket_was_replaced(victim_socket, st.st_dev, st.st_ino))
		FAIL("a socket nobody touched was reported replaced");
	else
		PASS();

	close(fd);
	unlink(victim_socket);
}

static void test_unlinked_socket_is_replaced(void)
{
	struct stat st;
	int fd;

	TEST("an unlinked socket is reported replaced");

	fd = listener_at(victim_socket);
	if (fd < 0 || stat(victim_socket, &st) < 0) {
		FAIL("cannot lay down a socket to watch");
		if (fd >= 0)
			close(fd);
		return;
	}

	unlink(victim_socket);

	if (ipc_socket_was_replaced(victim_socket, st.st_dev, st.st_ino))
		PASS();
	else
		FAIL("an unlinked socket was reported as still ours");

	close(fd);
}

/*
 * The case that costs a host: the name is there, the mode is right,
 * and it is a different socket. Only the inode says so.
 */
static void test_rebound_socket_is_replaced(void)
{
	struct stat before;
	int old_fd, new_fd;

	TEST("a socket replaced at the same path is reported replaced");

	old_fd = listener_at(victim_socket);
	if (old_fd < 0 || stat(victim_socket, &before) < 0) {
		FAIL("cannot lay down a socket to watch");
		if (old_fd >= 0)
			close(old_fd);
		return;
	}

	/* what the socket unit does: unlink, then bind a fresh one */
	new_fd = listener_at(victim_socket);
	if (new_fd < 0) {
		FAIL("cannot rebind the path");
		close(old_fd);
		return;
	}

	if (ipc_socket_was_replaced(victim_socket, before.st_dev,
				    before.st_ino))
		PASS();
	else
		FAIL("a socket bound over ours was reported as still ours");

	close(old_fd);
	close(new_fd);
	unlink(victim_socket);
}

/*
 * A socket-activated start can find the path already gone, and then there is
 * no identity to compare against. Recovering from that would mean binding over
 * whatever is there on the first event, which is the takeover the primary
 * socket refuses.
 */
static void test_unrecorded_identity_is_not_a_replacement(void)
{
	TEST("no recorded identity is not a replacement");

	if (ipc_socket_was_replaced(victim_socket, 0, 0))
		FAIL("an unrecorded listener was reported replaced");
	else
		PASS();
}

/*
 * A login's runtime directory can be replaced by logind's tmpfs between
 * the directory being made and the socket being bound in it. The caller
 * knows that is a login still mounting and retries, so a failed bind is
 * returned, not logged.
 */
static void test_bind_failure_is_left_to_the_caller(struct ipc_context *ctx)
{
	char path[108];
	FILE *cap;
	long said;
	int saved_fd, ret;

	TEST("a socket with no directory -> -ENOENT, nothing said");

	snprintf(path, sizeof(path), "/tmp/lota-extra-nodir-%d/lota.sock",
		 (int)getpid());

	cap = tmpfile();
	if (!cap) {
		FAIL("cannot capture stderr");
		return;
	}
	fflush(stderr);
	saved_fd = dup(STDERR_FILENO);
	if (saved_fd < 0) {
		FAIL("cannot capture stderr");
		fclose(cap);
		return;
	}
	dup2(fileno(cap), STDERR_FILENO);

	ret = ipc_add_listener(ctx, path);

	fflush(stderr);
	dup2(saved_fd, STDERR_FILENO);
	close(saved_fd);
	said = lseek(fileno(cap), 0, SEEK_END);
	fclose(cap);

	if (ret == 0) {
		FAIL("bound a socket in a directory that does not exist");
		ipc_remove_listener(ctx, path);
		return;
	}
	if (ret != -ENOENT) {
		FAIL("expected -ENOENT");
		return;
	}
	if (said != 0) {
		FAIL("wrote to stderr, so the caller cannot keep a pending login quiet");
		return;
	}
	PASS();
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
	test_bind_failure_is_left_to_the_caller(&ctx);
	test_untouched_socket_is_not_replaced();
	test_unlinked_socket_is_replaced();
	test_rebound_socket_is_replaced();
	test_unrecorded_identity_is_not_a_replacement();

	ipc_cleanup(&ctx);
	unlink(test_socket);
	unlink(victim_socket);

	printf("\n=== %d/%d passed ===\n", tests_passed, tests_run);
	return tests_passed == tests_run ? 0 : 1;
}
